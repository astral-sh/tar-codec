use std::{hint::black_box, sync::Arc, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tar_framing::{
    BLOCK_SIZE, PaxKeyword, UstarKind,
    logical::TarReader,
    write::{PaxMember, append_pax_record, end_marker_bytes, frame_pax_member_into},
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

const LARGE_FILE_BYTES: usize = 16 * 1024 * 1024;
const SMALL_FILE_BYTES: usize = 1024;
const SMALL_FILE_COUNT: usize = 1024;
const SMALL_DIRECTORY_COUNT: usize = 32;
const DECIMAL_WIDTH_MEMBER_TARGET: usize = 1280;
const SEQUENCE_BOUNDARY_REPETITIONS: usize = 64;
const MEMBER_SHAPE_REPETITIONS: usize = 128;
const MEMBER_SHAPE_COUNT: usize = 7;
const MIXED_METADATA_MEMBER_COUNT: usize = 12 * 1024;
const SEQUENCE_BOUNDARY_VALUES: [u64; 14] = [
    0, 1, 9, 10, 11, 99, 100, 101, 999, 1_000, 1_001, 9_999, 10_000, 10_001,
];
// Keep common small sizes dense while retaining several large-file widths.
const MIXED_FILE_SIZES: [u64; 32] = [
    0,
    0,
    1,
    8,
    64,
    128,
    255,
    511,
    512,
    1_023,
    1_024,
    2_048,
    4_096,
    4_096,
    8_192,
    16_384,
    32_768,
    65_535,
    65_536,
    131_072,
    262_144,
    1_048_576,
    1_048_593,
    4_194_304,
    16_777_216,
    99_999_999,
    100_000_000,
    1_000_000_000,
    4_294_967_296,
    99_999_999_999,
    999_999_999_999,
    1_099_511_627_793,
];
const PAYLOAD_CHUNK_BYTES: usize = 1024 * 1024;
const GLOBAL_PAX_RECORD_COUNTS: [usize; 4] = [128, 256, 512, 1024];
const SIZE_RANGE: std::ops::Range<usize> = 124..136;
const CHECKSUM_RANGE: std::ops::Range<usize> = 148..156;
const TYPEFLAG_OFFSET: usize = 156;
const IDENTITY_RANGE: std::ops::Range<usize> = 257..265;

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

struct FramingMember {
    sequence: u64,
    path: String,
    kind: UstarKind,
    size: u64,
    link_path: Option<String>,
    executable: bool,
}

struct FramingFixture {
    id: &'static str,
    members: Vec<FramingMember>,
}

impl FramingFixture {
    fn benchmark_id(&self) -> String {
        format!("{}-{}-members", self.id, self.members.len())
    }

    fn throughput(&self) -> Throughput {
        Throughput::Elements(
            u64::try_from(self.members.len())
                .expect("framing fixture member count should be representable"),
        )
    }
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

fn framing_fixtures() -> Vec<FramingFixture> {
    // These fixtures declare sizes without allocating payload bytes, allowing
    // the framing hot path to cover the full u64 range economically.
    let mut fixtures = decimal_width_fixtures();
    fixtures.extend([
        sequence_boundary_fixture(),
        member_shape_fixture(),
        mixed_metadata_fixture(),
    ]);
    fixtures
}

fn decimal_width_fixtures() -> Vec<FramingFixture> {
    [
        ("decimal-widths-1-4", 1, 4),
        ("decimal-widths-5-7", 5, 7),
        ("decimal-width-8", 8, 8),
        ("decimal-widths-9-11", 9, 11),
        ("decimal-widths-12-20", 12, 20),
    ]
    .into_iter()
    .map(|(id, minimum_digit_count, maximum_digit_count)| {
        decimal_width_fixture(id, minimum_digit_count, maximum_digit_count)
    })
    .collect()
}

fn decimal_width_fixture(
    id: &'static str,
    minimum_digit_count: u32,
    maximum_digit_count: u32,
) -> FramingFixture {
    let digit_width_count = usize::try_from(maximum_digit_count - minimum_digit_count + 1)
        .expect("decimal-width fixture range should be representable");
    let repetitions = DECIMAL_WIDTH_MEMBER_TARGET / (digit_width_count * 2);
    let mut members = Vec::with_capacity(repetitions * digit_width_count * 2);
    for repetition in 0..repetitions {
        for digit_count in minimum_digit_count..=maximum_digit_count {
            let minimum = if digit_count == 1 {
                0
            } else {
                10_u64.pow(digit_count - 1)
            };
            let maximum = if digit_count == 20 {
                u64::MAX
            } else {
                10_u64.pow(digit_count) - 1
            };
            for (edge, size) in [("minimum", minimum), ("maximum", maximum)] {
                let sequence = u64::try_from(members.len())
                    .expect("decimal-width fixture sequence should be representable");
                members.push(FramingMember {
                    sequence,
                    path: format!("metadata/width-{digit_count:02}/{edge}-{repetition:02}.bin"),
                    kind: UstarKind::Regular,
                    size,
                    link_path: None,
                    executable: false,
                });
            }
        }
    }
    FramingFixture { id, members }
}

fn sequence_boundary_fixture() -> FramingFixture {
    let mut members =
        Vec::with_capacity(SEQUENCE_BOUNDARY_REPETITIONS * SEQUENCE_BOUNDARY_VALUES.len());
    for repetition in 0..SEQUENCE_BOUNDARY_REPETITIONS {
        for sequence in SEQUENCE_BOUNDARY_VALUES {
            members.push(FramingMember {
                sequence,
                path: format!("metadata/sequence-{sequence:05}/entry-{repetition:02}.bin"),
                kind: UstarKind::Regular,
                size: 123_456,
                link_path: None,
                executable: false,
            });
        }
    }
    FramingFixture {
        id: "sequence-boundaries",
        members,
    }
}

fn member_shape_fixture() -> FramingFixture {
    let mut members = Vec::with_capacity(MEMBER_SHAPE_REPETITIONS * MEMBER_SHAPE_COUNT);
    for repetition in 0..MEMBER_SHAPE_REPETITIONS {
        let sequence = 50_000
            + u64::try_from(repetition * MEMBER_SHAPE_COUNT)
                .expect("member-shape fixture sequence should be representable");
        members.extend([
            FramingMember {
                sequence,
                path: format!("metadata/empty-{repetition:03}"),
                kind: UstarKind::Regular,
                size: 0,
                link_path: None,
                executable: false,
            },
            FramingMember {
                sequence: sequence + 1,
                path: format!("metadata/bin/tool-{repetition:03}"),
                kind: UstarKind::Regular,
                size: 123_456,
                link_path: None,
                executable: true,
            },
            FramingMember {
                sequence: sequence + 2,
                path: format!("metadata/directory-{repetition:03}"),
                kind: UstarKind::Directory,
                size: 0,
                link_path: None,
                executable: false,
            },
            FramingMember {
                sequence: sequence + 3,
                path: format!("metadata/link-{repetition:03}"),
                kind: UstarKind::SymbolicLink,
                size: 0,
                link_path: Some("metadata/bin/tool".to_owned()),
                executable: false,
            },
            FramingMember {
                sequence: sequence + 4,
                path: format!("metadata/long-link-{repetition:03}"),
                kind: UstarKind::SymbolicLink,
                size: 0,
                link_path: Some(format!("target/{}", "t".repeat(120))),
                executable: false,
            },
            FramingMember {
                sequence: sequence + 5,
                path: format!("{}/{}-{repetition:03}", "p".repeat(120), "n".repeat(80)),
                kind: UstarKind::Regular,
                size: 9_999_999,
                link_path: None,
                executable: false,
            },
            FramingMember {
                sequence: sequence + 6,
                path: format!("{}/{}-{repetition:03}", "f".repeat(156), "n".repeat(101)),
                kind: UstarKind::Regular,
                size: 10_000_000,
                link_path: None,
                executable: false,
            },
        ]);
    }
    FramingFixture {
        id: "member-shapes",
        members,
    }
}

fn mixed_metadata_fixture() -> FramingFixture {
    let mut members = Vec::with_capacity(MIXED_METADATA_MEMBER_COUNT);
    for index in 0..MIXED_METADATA_MEMBER_COUNT {
        let sequence =
            u64::try_from(index).expect("mixed-metadata sequence should be representable");
        let path = if index % 1_024 == 17 {
            format!("{}/{}-{index:05}", "f".repeat(156), "n".repeat(101))
        } else if index % 256 == 19 {
            format!("{}/{}-{index:05}", "p".repeat(120), "n".repeat(80))
        } else {
            format!(
                "package/directory-{:02}/entry-{index:05}",
                index % SMALL_DIRECTORY_COUNT
            )
        };
        let (kind, size, link_path) = match index % 64 {
            0 => (UstarKind::Directory, 0, None),
            1 => (
                UstarKind::SymbolicLink,
                0,
                Some(format!("package/target-{:05}", index.saturating_sub(1))),
            ),
            2 => (
                UstarKind::SymbolicLink,
                0,
                Some(format!("target/{}", "t".repeat(120))),
            ),
            _ => (
                UstarKind::Regular,
                MIXED_FILE_SIZES[index.wrapping_mul(17) % MIXED_FILE_SIZES.len()],
                None,
            ),
        };
        members.push(FramingMember {
            sequence,
            path,
            kind,
            size,
            link_path,
            executable: matches!(kind, UstarKind::Regular) && index % 11 == 0,
        });
    }
    FramingFixture {
        id: "mixed-metadata",
        members,
    }
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
                kind: UstarKind::Regular,
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

fn pax_record(keyword: PaxKeyword, value: &str) -> Vec<u8> {
    let mut record = Vec::new();
    append_pax_record(&mut record, &keyword, value.as_bytes())
        .expect("benchmark PAX record keyword should be valid");
    record
}

fn global_pax_header(payload_len: usize) -> [u8; BLOCK_SIZE] {
    let mut header = [0; BLOCK_SIZE];
    header[..10].copy_from_slice(b"pax-global");
    let size = format!("{:011o}\0", payload_len);
    header[SIZE_RANGE].copy_from_slice(size.as_bytes());
    header[TYPEFLAG_OFFSET] = b'g';
    header[IDENTITY_RANGE].copy_from_slice(b"ustar\x0000");
    header[CHECKSUM_RANGE].fill(b' ');
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let checksum = format!("{checksum:06o}\0 ");
    header[CHECKSUM_RANGE].copy_from_slice(checksum.as_bytes());
    header
}

fn append_global_pax(archive: &mut Vec<u8>, payload: &[u8]) {
    archive.extend_from_slice(&global_pax_header(payload.len()));
    archive.extend_from_slice(payload);
    append_padding(archive, payload.len());
}

fn global_pax_archive(record_count: usize, replace: bool) -> Vec<u8> {
    let payload = (0..record_count).fold(Vec::new(), |mut payload, index| {
        payload.extend_from_slice(&pax_record(
            PaxKeyword::Vendor {
                vendor: Arc::from("ACME"),
                name: Arc::from(format!("attribute{index}")),
            },
            "initial",
        ));
        payload
    });
    let mut archive = Vec::new();
    append_global_pax(&mut archive, &payload);
    if replace {
        let replacement = (0..record_count).fold(Vec::new(), |mut payload, index| {
            payload.extend_from_slice(&pax_record(
                PaxKeyword::Vendor {
                    vendor: Arc::from("ACME"),
                    name: Arc::from(format!("attribute{index}")),
                },
                "replacement",
            ));
            payload
        });
        append_global_pax(&mut archive, &replacement);
    }
    archive.resize(archive.len() + 2 * BLOCK_SIZE, 0);
    archive
}

fn encode_pax_framing(fixture: &Fixture) -> usize {
    let mut framing = Vec::new();
    let mut bytes = 0;
    for (sequence, entry) in fixture.entries.iter().enumerate() {
        frame_pax_member_into(
            u64::try_from(sequence).expect("fixture sequence should be representable"),
            PaxMember {
                path: &entry.path,
                kind: UstarKind::Regular,
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

fn encode_pax_metadata(fixture: &FramingFixture) -> usize {
    let mut framing = Vec::new();
    let mut bytes = 0;
    for member in &fixture.members {
        frame_pax_member_into(
            member.sequence,
            PaxMember {
                path: &member.path,
                kind: member.kind,
                size: member.size,
                link_path: member.link_path.as_deref(),
                executable: member.executable,
            },
            &mut framing,
        )
        .expect("metadata fixture member should frame");
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

async fn decode_trailing_global_pax(archive: &[u8]) -> usize {
    let mut reader = TarReader::new(archive);
    assert!(
        reader
            .next_frame()
            .await
            .expect("global pax fixture should decode")
            .is_none()
    );
    archive.len()
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

fn bench_encode_pax_metadata(criterion: &mut Criterion, fixtures: &[FramingFixture]) {
    let mut group = criterion.benchmark_group("encode_pax_metadata");
    for fixture in fixtures {
        group.throughput(fixture.throughput());
        group.bench_with_input(
            BenchmarkId::from_parameter(fixture.benchmark_id()),
            fixture,
            |bencher, fixture| bencher.iter(|| black_box(encode_pax_metadata(fixture))),
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

fn bench_global_pax_updates(criterion: &mut Criterion, runtime: &Runtime) {
    let mut group = criterion.benchmark_group("global_pax_updates");
    for record_count in GLOBAL_PAX_RECORD_COUNTS {
        for (mode, replace) in [("unique", false), ("replace", true)] {
            let archive = global_pax_archive(record_count, replace);
            let updates = if replace {
                record_count * 2
            } else {
                record_count
            };
            group.throughput(Throughput::Elements(
                u64::try_from(updates).expect("fixture record count should be representable"),
            ));
            group.bench_with_input(
                BenchmarkId::new(mode, record_count),
                &archive,
                |bencher, archive| {
                    bencher.to_async(runtime).iter(|| async {
                        black_box(decode_trailing_global_pax(black_box(archive)).await)
                    });
                },
            );
        }
    }
    group.finish();
}

fn framing(criterion: &mut Criterion) {
    let runtime = runtime();
    let fixtures = fixtures();
    let framing_fixtures = framing_fixtures();
    bench_encode_pax_framing(criterion, &fixtures);
    bench_encode_pax_metadata(criterion, &framing_fixtures);
    bench_decode_payload(criterion, &runtime, &fixtures);
    bench_global_pax_updates(criterion, &runtime);
}

criterion_group!(benches, framing);
criterion_main!(benches);
