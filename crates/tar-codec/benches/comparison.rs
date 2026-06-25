mod support;

use std::{
    fs,
    hint::black_box,
    io::{self, Write},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use support::{
    Entry, SMALL_FILE_BYTES, SMALL_FILE_COUNT, configure_tar_header, payload, payload_throughput,
    runtime, ustar_archive_entries,
};
use tar_codec::{
    Archive as _, ArchiveBuilder as _, EntryMetadata, TarArchive, TarEncoder,
    extract::ExtractPolicy,
};
use tempfile::{TempDir, tempdir};
use tokio::{io::AsyncWrite, runtime::Runtime};

const LARGE_FILE_BYTES: usize = 16 * 1024 * 1024;
const SMALL_DIRECTORY_COUNT: usize = 32;

#[derive(Default)]
/// A sink for measuring framing work without touching payload bytes.
struct FramingSink {
    bytes_written: u64,
}

impl FramingSink {
    fn record_write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let len = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("write length cannot be represented"))?;
        self.bytes_written = self
            .bytes_written
            .checked_add(len)
            .ok_or_else(|| io::Error::other("counting writer overflow"))?;
        Ok(buffer.len())
    }
}

impl Write for FramingSink {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.record_write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncWrite for FramingSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.record_write(buffer))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Fixture {
    _temp: TempDir,
    id: &'static str,
    source: PathBuf,
    entries: Vec<Entry>,
    payload_bytes: u64,
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
        payload_throughput(self.entries.len(), self.payload_bytes)
    }
}

struct DecodeInput {
    id: &'static str,
    bytes: Vec<u8>,
}

fn fixtures() -> Vec<Fixture> {
    vec![
        fixture(
            "large",
            vec![("payload.bin".to_owned(), payload(LARGE_FILE_BYTES, 0))],
        ),
        fixture(
            "many-small",
            (0..SMALL_FILE_COUNT)
                .map(|index| {
                    (
                        format!(
                            "directory-{:02}/file-{index:04}.txt",
                            index % SMALL_DIRECTORY_COUNT
                        ),
                        payload(SMALL_FILE_BYTES, index),
                    )
                })
                .collect(),
        ),
    ]
}

fn fixture(id: &'static str, files: Vec<(String, Vec<u8>)>) -> Fixture {
    let temp = tempdir().expect("fixture temporary directory should be created");
    let source = temp.path().join(id);
    fs::create_dir(&source).expect("fixture root should be created");
    let mut payload_bytes = 0;
    let entries = files
        .into_iter()
        .map(|(relative_path, data)| {
            let path = source.join(&relative_path);
            fs::create_dir_all(path.parent().expect("fixture file should have a parent"))
                .expect("fixture parent directories should be created");
            fs::write(&path, &data).expect("fixture file should be written");
            payload_bytes +=
                u64::try_from(data.len()).expect("fixture payload length should be representable");
            Entry {
                archive_path: format!("{id}/{relative_path}"),
                data,
            }
        })
        .collect();
    Fixture {
        _temp: temp,
        id,
        source,
        entries,
        payload_bytes,
    }
}

async fn encode_entries_tar_codec(fixture: &Fixture) -> u64 {
    let mut sink = FramingSink::default();
    let mut encoder = TarEncoder::new(&mut sink).builder();
    for entry in &fixture.entries {
        encoder
            .add_file(
                &entry.archive_path,
                entry.data.as_slice(),
                EntryMetadata::default(),
            )
            .await
            .expect("tar-codec should encode fixture entry");
    }
    encoder
        .finish()
        .await
        .expect("tar-codec archive should finish");
    sink.bytes_written
}

fn encode_entries_tar(fixture: &Fixture) -> u64 {
    let mut builder = tar::Builder::new(FramingSink::default());
    for entry in &fixture.entries {
        let mut header = tar::Header::new_ustar();
        configure_tar_header(&mut header, entry.data.len());
        builder
            .append_data(&mut header, &entry.archive_path, entry.data.as_slice())
            .expect("tar should encode fixture entry");
    }
    builder
        .into_inner()
        .expect("tar archive should finish")
        .bytes_written
}

async fn encode_entries_tokio_tar(fixture: &Fixture) -> u64 {
    let mut builder = tokio_tar::Builder::new(FramingSink::default());
    for entry in &fixture.entries {
        let mut header = tokio_tar::Header::new_ustar();
        configure_tokio_tar_header(&mut header, entry.data.len());
        builder
            .append_data(&mut header, &entry.archive_path, entry.data.as_slice())
            .await
            .expect("astral-tokio-tar should encode fixture entry");
    }
    builder
        .into_inner()
        .await
        .expect("astral-tokio-tar archive should finish")
        .bytes_written
}

async fn encode_directory_tar_codec(fixture: &Fixture) -> u64 {
    let mut sink = FramingSink::default();
    let mut encoder = TarEncoder::new(&mut sink).builder();
    encoder
        .add_directory_all(&fixture.source)
        .await
        .expect("tar-codec should encode fixture directory");
    encoder
        .finish()
        .await
        .expect("tar-codec archive should finish");
    sink.bytes_written
}

fn encode_directory_tar(fixture: &Fixture) -> u64 {
    let mut builder = tar::Builder::new(FramingSink::default());
    builder.follow_symlinks(false);
    builder
        .append_dir_all(fixture.id, &fixture.source)
        .expect("tar should encode fixture directory");
    builder
        .into_inner()
        .expect("tar archive should finish")
        .bytes_written
}

async fn encode_directory_tokio_tar(fixture: &Fixture) -> u64 {
    let mut builder = tokio_tar::Builder::new(FramingSink::default());
    builder.follow_symlinks(false);
    builder
        .append_dir_all(fixture.id, &fixture.source)
        .await
        .expect("astral-tokio-tar should encode fixture directory");
    builder
        .into_inner()
        .await
        .expect("astral-tokio-tar archive should finish")
        .bytes_written
}

fn configure_tokio_tar_header(header: &mut tokio_tar::Header, payload_len: usize) {
    header.set_size(u64::try_from(payload_len).expect("payload length should be representable"));
    header.set_mode(0o644);
    header.set_cksum();
}

async fn pax_archive(fixture: &Fixture) -> Vec<u8> {
    pax_archive_entries(&fixture.entries).await
}

async fn pax_archive_entries(entries: &[Entry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder();
    for entry in entries {
        encoder
            .add_file(
                &entry.archive_path,
                entry.data.as_slice(),
                EntryMetadata::default(),
            )
            .await
            .expect("tar-codec should encode pax fixture entry");
    }
    encoder
        .finish()
        .await
        .expect("tar-codec pax archive should finish");
    bytes
}

fn ustar_archive(fixture: &Fixture) -> Vec<u8> {
    ustar_archive_entries(&fixture.entries)
}

fn bench_encode_entries_framing(
    criterion: &mut Criterion,
    runtime: &Runtime,
    fixtures: &[Fixture],
) {
    let mut group = criterion.benchmark_group("encode_entries_framing");
    for fixture in fixtures {
        group.throughput(fixture.entry_throughput());
        let benchmark_id = fixture.benchmark_id();
        group.bench_with_input(
            BenchmarkId::new("tar-codec", &benchmark_id),
            fixture,
            |bencher, fixture| {
                bencher
                    .to_async(runtime)
                    .iter(|| async { black_box(encode_entries_tar_codec(fixture).await) });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("tar", &benchmark_id),
            fixture,
            |bencher, fixture| {
                bencher.iter(|| black_box(encode_entries_tar(fixture)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("astral-tokio-tar", &benchmark_id),
            fixture,
            |bencher, fixture| {
                bencher
                    .to_async(runtime)
                    .iter(|| async { black_box(encode_entries_tokio_tar(fixture).await) });
            },
        );
    }
    group.finish();
}

fn bench_encode_directory(criterion: &mut Criterion, runtime: &Runtime, fixtures: &[Fixture]) {
    let mut group = criterion.benchmark_group("encode_directory");
    group.measurement_time(Duration::from_secs(6));
    for fixture in fixtures {
        group.throughput(fixture.payload_throughput());
        let benchmark_id = fixture.benchmark_id();
        group.bench_with_input(
            BenchmarkId::new("tar-codec", &benchmark_id),
            fixture,
            |bencher, fixture| {
                bencher
                    .to_async(runtime)
                    .iter(|| async { black_box(encode_directory_tar_codec(fixture).await) });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("tar", &benchmark_id),
            fixture,
            |bencher, fixture| {
                bencher.iter(|| black_box(encode_directory_tar(fixture)));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("astral-tokio-tar", &benchmark_id),
            fixture,
            |bencher, fixture| {
                bencher
                    .to_async(runtime)
                    .iter(|| async { black_box(encode_directory_tokio_tar(fixture).await) });
            },
        );
    }
    group.finish();
}

fn bench_extract(criterion: &mut Criterion, runtime: &Runtime, fixtures: &[Fixture]) {
    let mut group = criterion.benchmark_group("extract");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(6));
    for fixture in fixtures {
        let inputs = [
            DecodeInput {
                id: "pax",
                bytes: runtime.block_on(pax_archive(fixture)),
            },
            DecodeInput {
                id: "ustar",
                bytes: ustar_archive(fixture),
            },
        ];
        for input in &inputs {
            group.throughput(fixture.payload_throughput());
            let benchmark_id = format!("{}/{}", input.id, fixture.benchmark_id());
            group.bench_with_input(
                BenchmarkId::new("tar-codec", &benchmark_id),
                input,
                |bencher, input| {
                    bencher.to_async(runtime).iter_batched_ref(
                        || tempdir().expect("temporary extraction directory should be created"),
                        |temp| {
                            let destination = temp.path().join("out");
                            async move {
                                TarArchive::new(input.bytes.as_slice())
                                    .extract_in(destination, ExtractPolicy::default())
                                    .await
                                    .expect("tar-codec should extract fixture archive");
                            }
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
            group.bench_with_input(
                BenchmarkId::new("tar", &benchmark_id),
                input,
                |bencher, input| {
                    bencher.iter_batched_ref(
                        || tempdir().expect("temporary extraction directory should be created"),
                        |temp| {
                            let destination = temp.path().join("out");
                            tar::Archive::new(input.bytes.as_slice())
                                .unpack(destination)
                                .expect("tar should extract fixture archive");
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
            group.bench_with_input(
                BenchmarkId::new("astral-tokio-tar", &benchmark_id),
                input,
                |bencher, input| {
                    bencher.to_async(runtime).iter_batched_ref(
                        || tempdir().expect("temporary extraction directory should be created"),
                        |temp| {
                            let destination = temp.path().join("out");
                            async move {
                                tokio_tar::Archive::new(input.bytes.as_slice())
                                    .unpack(destination)
                                    .await
                                    .expect("astral-tokio-tar should extract fixture archive");
                            }
                        },
                        BatchSize::PerIteration,
                    );
                },
            );
        }
    }
    group.finish();
}

fn comparison(criterion: &mut Criterion) {
    let runtime = runtime();
    let fixtures = fixtures();
    bench_encode_entries_framing(criterion, &runtime, &fixtures);
    bench_encode_directory(criterion, &runtime, &fixtures);
    bench_extract(criterion, &runtime, &fixtures);
}

criterion_group!(benches, comparison);
criterion_main!(benches);
