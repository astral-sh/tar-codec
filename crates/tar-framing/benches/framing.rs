use std::{hint::black_box, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tar_framing::{
    BLOCK_SIZE, MemberKind,
    logical::TarReader,
    write::{PaxMember, end_marker_bytes, frame_pax_member_into},
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

const LARGE_FILE_BYTES: usize = 16 * 1024 * 1024;
const SMALL_FILE_BYTES: usize = 1024;
const SMALL_FILE_COUNT: usize = 1024;
const SMALL_DIRECTORY_COUNT: usize = 32;
const PAYLOAD_CHUNK_BYTES: usize = 1024 * 1024;

struct Entry {
    path: String,
    data: Vec<u8>,
}

struct Fixture {
    id: &'static str,
    entries: Vec<Entry>,
    payload_bytes: u64,
    archive: Vec<u8>,
}

impl Fixture {
    fn benchmark_id(&self) -> String {
        format!("{}-{}-entries", self.id, self.entries.len())
    }

    fn entry_throughput(&self) -> Throughput {
        Throughput::Elements(
            u64::try_from(self.entries.len()).expect("fixture entry count should be representable"),
        )
    }

    fn payload_throughput(&self) -> Throughput {
        Throughput::ElementsAndBytes {
            elements: u64::try_from(self.entries.len())
                .expect("fixture entry count should be representable"),
            bytes: self.payload_bytes,
        }
    }
}

#[derive(Clone, Copy)]
enum DecodeMode {
    Block,
    Chunk,
    Skip,
}

impl DecodeMode {
    fn id(self) -> &'static str {
        match self {
            Self::Block => "next_block",
            Self::Chunk => "next_chunk",
            Self::Skip => "skip",
        }
    }
}

fn runtime() -> Runtime {
    RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime should build")
}

fn payload(size: usize, salt: usize) -> Vec<u8> {
    (0..size)
        .map(|index| {
            u8::try_from((index + salt) % 251).expect("payload byte should be representable")
        })
        .collect()
}

fn fixtures() -> Vec<Fixture> {
    vec![
        fixture(
            "large",
            vec![Entry {
                path: "payload.bin".to_owned(),
                data: payload(LARGE_FILE_BYTES, 0),
            }],
        ),
        fixture(
            "many-small",
            (0..SMALL_FILE_COUNT)
                .map(|index| Entry {
                    path: format!(
                        "directory-{:02}/file-{index:04}.txt",
                        index % SMALL_DIRECTORY_COUNT
                    ),
                    data: payload(SMALL_FILE_BYTES, index),
                })
                .collect(),
        ),
    ]
}

fn fixture(id: &'static str, entries: Vec<Entry>) -> Fixture {
    let payload_bytes = entries.iter().fold(0_u64, |total, entry| {
        total
            .checked_add(
                u64::try_from(entry.data.len())
                    .expect("fixture payload length should be representable"),
            )
            .expect("fixture payload byte count should be representable")
    });
    let archive = archive(&entries);
    Fixture {
        id,
        entries,
        payload_bytes,
        archive,
    }
}

fn archive(entries: &[Entry]) -> Vec<u8> {
    let mut archive = Vec::new();
    let mut framing = Vec::new();
    for (sequence, entry) in entries.iter().enumerate() {
        frame_pax_member_into(
            u64::try_from(sequence).expect("fixture sequence should be representable"),
            PaxMember {
                path: &entry.path,
                kind: MemberKind::Regular,
                size: u64::try_from(entry.data.len())
                    .expect("fixture payload length should be representable"),
                link_path: None,
                executable: false,
            },
            &mut framing,
        )
        .expect("fixture entry should frame");
        archive.extend_from_slice(&framing);
        archive.extend_from_slice(&entry.data);
        append_padding(&mut archive, entry.data.len());
    }
    archive.extend_from_slice(end_marker_bytes());
    archive
}

fn append_padding(archive: &mut Vec<u8>, payload_len: usize) {
    let remainder = payload_len % BLOCK_SIZE;
    if remainder != 0 {
        archive.resize(archive.len() + BLOCK_SIZE - remainder, 0);
    }
}

fn encode_pax_framing(fixture: &Fixture) -> usize {
    let mut framing = Vec::new();
    let mut bytes = 0;
    for (sequence, entry) in fixture.entries.iter().enumerate() {
        frame_pax_member_into(
            u64::try_from(sequence).expect("fixture sequence should be representable"),
            PaxMember {
                path: &entry.path,
                kind: MemberKind::Regular,
                size: u64::try_from(entry.data.len())
                    .expect("fixture payload length should be representable"),
                link_path: None,
                executable: false,
            },
            &mut framing,
        )
        .expect("fixture entry should frame");
        bytes += framing.len();
    }
    bytes
}

async fn decode_payload(fixture: &Fixture, mode: DecodeMode) -> (u64, u64) {
    let mut reader = TarReader::new(fixture.archive.as_slice());
    let mut entries = 0_u64;
    let mut payload_bytes = 0_u64;
    let mut chunk = Vec::new();
    while let Some(frame) = reader
        .next_frame()
        .await
        .expect("fixture archive should decode")
    {
        let mut member = frame;
        entries += 1;
        match mode {
            DecodeMode::Block => {
                while let Some(block) = member
                    .payload
                    .next_block()
                    .await
                    .expect("fixture payload block should decode")
                {
                    payload_bytes += u64::try_from(block.len)
                        .expect("payload block length should be representable");
                }
            }
            DecodeMode::Chunk => {
                while member
                    .payload
                    .next_chunk(&mut chunk, PAYLOAD_CHUNK_BYTES)
                    .await
                    .expect("fixture payload chunk should decode")
                {
                    payload_bytes += u64::try_from(chunk.len())
                        .expect("payload chunk length should be representable");
                }
            }
            DecodeMode::Skip => {
                payload_bytes += member.header.effective_size;
                member
                    .payload
                    .skip()
                    .await
                    .expect("fixture payload should skip");
            }
        }
    }
    (entries, payload_bytes)
}

fn bench_encode_pax_framing(criterion: &mut Criterion, fixtures: &[Fixture]) {
    let mut group = criterion.benchmark_group("encode_pax_framing");
    for fixture in fixtures {
        group.throughput(fixture.entry_throughput());
        group.bench_with_input(
            BenchmarkId::from_parameter(fixture.benchmark_id()),
            fixture,
            |bencher, fixture| bencher.iter(|| black_box(encode_pax_framing(fixture))),
        );
    }
    group.finish();
}

fn bench_decode_payload(criterion: &mut Criterion, runtime: &Runtime, fixtures: &[Fixture]) {
    let mut group = criterion.benchmark_group("decode_payload");
    group.measurement_time(Duration::from_secs(6));
    for fixture in fixtures {
        group.throughput(fixture.payload_throughput());
        for mode in [DecodeMode::Block, DecodeMode::Chunk, DecodeMode::Skip] {
            group.bench_with_input(
                BenchmarkId::new(mode.id(), fixture.benchmark_id()),
                fixture,
                |bencher, fixture| {
                    bencher
                        .to_async(runtime)
                        .iter(|| async { black_box(decode_payload(fixture, mode).await) });
                },
            );
        }
    }
    group.finish();
}

fn framing(criterion: &mut Criterion) {
    let runtime = runtime();
    let fixtures = fixtures();
    bench_encode_pax_framing(criterion, &fixtures);
    bench_decode_payload(criterion, &runtime, &fixtures);
}

criterion_group!(benches, framing);
criterion_main!(benches);
