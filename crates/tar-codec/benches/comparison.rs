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
use tar_codec::{
    Archive as _, ArchiveBuilder as _, EntryMetadata, TarArchive, TarEncoder,
    extract::ExtractPolicy,
};
use tempfile::{TempDir, tempdir};
use tokio::{
    io::AsyncWrite,
    runtime::{Builder as RuntimeBuilder, Runtime},
};

const LARGE_FILE_BYTES: usize = 16 * 1024 * 1024;
const SMALL_FILE_BYTES: usize = 1024;
const SMALL_FILE_COUNT: usize = 1024;
const SMALL_DIRECTORY_COUNT: usize = 32;
const DIRECTORY_HEAVY_FILE_COUNT: usize = 256;
const BUFFERED_BOUNDARY_FILE_COUNT: usize = 16;
const DUPLICATE_FILE_COUNT: usize = 256;

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

struct Entry {
    archive_path: String,
    data: Vec<u8>,
}

struct Fixture {
    _temp: TempDir,
    id: &'static str,
    source: PathBuf,
    entries: Vec<Entry>,
    payload_bytes: u64,
}

struct ExtractionFixture {
    id: &'static str,
    entries: Vec<Entry>,
    payload_bytes: u64,
    prepopulate_destination: bool,
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

impl ExtractionFixture {
    fn benchmark_id(&self) -> String {
        format!("{}-{}-entries", self.id, self.entries.len())
    }

    fn payload_throughput(&self) -> Throughput {
        payload_throughput(self.entries.len(), self.payload_bytes)
    }
}

fn payload_throughput(entry_count: usize, payload_bytes: u64) -> Throughput {
    let elements = u64::try_from(entry_count).expect("fixture entry count should be representable");
    if payload_bytes == 0 {
        Throughput::Elements(elements)
    } else {
        Throughput::ElementsAndBytes {
            elements,
            bytes: payload_bytes,
        }
    }
}

struct DecodeInput {
    id: &'static str,
    bytes: Vec<u8>,
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

fn extraction_filesystem_fixtures() -> Vec<ExtractionFixture> {
    // Decompose fixed root setup, per-file work, directory topology,
    // replacement behavior, and the buffered/streamed size boundary.
    vec![
        extraction_fixture("empty-archive", Vec::new()),
        extraction_fixture(
            "flat-empty",
            (0..SMALL_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "flat-empty-directory-control",
            (0..DIRECTORY_HEAVY_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "shared-parent-empty",
            (0..DIRECTORY_HEAVY_FILE_COUNT)
                .map(|index| (format!("directory/file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "unique-parent-empty",
            (0..DIRECTORY_HEAVY_FILE_COUNT)
                .map(|index| (format!("directory-{index:04}/file.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "flat-small",
            (0..SMALL_FILE_COUNT)
                .map(|index| {
                    (
                        format!("file-{index:04}.txt"),
                        payload(SMALL_FILE_BYTES, index),
                    )
                })
                .collect(),
        ),
        extraction_fixture(
            "duplicate-empty",
            (0..DUPLICATE_FILE_COUNT * 2)
                .map(|index| {
                    (
                        format!("file-{:04}.txt", index % DUPLICATE_FILE_COUNT),
                        Vec::new(),
                    )
                })
                .collect(),
        ),
        prepopulated_extraction_fixture(
            "ambient-empty",
            (0..DUPLICATE_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.txt"), Vec::new()))
                .collect(),
        ),
        extraction_fixture(
            "flat-buffered-boundary",
            (0..BUFFERED_BOUNDARY_FILE_COUNT)
                .map(|index| (format!("file-{index:04}.bin"), payload(1024 * 1024, index)))
                .collect(),
        ),
        extraction_fixture(
            "flat-streamed-boundary",
            (0..BUFFERED_BOUNDARY_FILE_COUNT)
                .map(|index| {
                    (
                        format!("file-{index:04}.bin"),
                        payload(1024 * 1024 + 1, index),
                    )
                })
                .collect(),
        ),
    ]
}

fn extraction_fixture(id: &'static str, files: Vec<(String, Vec<u8>)>) -> ExtractionFixture {
    let payload_bytes = files.iter().fold(0_u64, |total, (_, data)| {
        total
            .checked_add(
                u64::try_from(data.len()).expect("fixture payload length should be representable"),
            )
            .expect("fixture payload byte count should be representable")
    });
    ExtractionFixture {
        id,
        entries: files
            .into_iter()
            .map(|(archive_path, data)| Entry { archive_path, data })
            .collect(),
        payload_bytes,
        prepopulate_destination: false,
    }
}

fn prepopulated_extraction_fixture(
    id: &'static str,
    files: Vec<(String, Vec<u8>)>,
) -> ExtractionFixture {
    ExtractionFixture {
        prepopulate_destination: true,
        ..extraction_fixture(id, files)
    }
}

fn extraction_temp(fixture: &ExtractionFixture) -> TempDir {
    let temp = tempdir().expect("temporary extraction directory should be created");
    if fixture.prepopulate_destination {
        let destination = temp.path().join("out");
        fs::create_dir(&destination).expect("prepopulated destination should be created");
        for entry in &fixture.entries {
            let path = destination.join(&entry.archive_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .expect("prepopulated destination parent should be created");
            }
            fs::write(path, b"ambient").expect("ambient fixture file should be written");
        }
    }
    temp
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
            .add_entry(&entry.archive_path, &entry.data, EntryMetadata::default())
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
        .add_directory(&fixture.source)
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

fn configure_tar_header(header: &mut tar::Header, payload_len: usize) {
    header.set_size(u64::try_from(payload_len).expect("payload length should be representable"));
    header.set_mode(0o644);
    header.set_cksum();
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
            .add_entry(&entry.archive_path, &entry.data, EntryMetadata::default())
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

fn ustar_archive_entries(entries: &[Entry]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        let mut header = tar::Header::new_ustar();
        configure_tar_header(&mut header, entry.data.len());
        builder
            .append_data(&mut header, &entry.archive_path, entry.data.as_slice())
            .expect("tar should encode ustar fixture entry");
    }
    builder
        .into_inner()
        .expect("tar ustar archive should finish")
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

fn bench_extract_filesystem(
    criterion: &mut Criterion,
    runtime: &Runtime,
    fixtures: &[ExtractionFixture],
) {
    let mut group = criterion.benchmark_group("extract_filesystem");
    group
        .sample_size(20)
        .measurement_time(Duration::from_secs(4));
    for fixture in fixtures {
        if !fixture.entries.is_empty() {
            group.throughput(fixture.payload_throughput());
        }
        // Use one-header USTAR members so metadata framing does not obscure
        // filesystem and task-scheduling costs.
        let input = ustar_archive_entries(&fixture.entries);
        let benchmark_id = fixture.benchmark_id();
        group.bench_with_input(
            BenchmarkId::new("tar-codec", &benchmark_id),
            &input,
            |bencher, input| {
                bencher.to_async(runtime).iter_batched_ref(
                    || extraction_temp(fixture),
                    |temp| {
                        let destination = temp.path().join("out");
                        async move {
                            TarArchive::new(input.as_slice())
                                .extract_in(destination, ExtractPolicy::default())
                                .await
                                .expect("tar-codec should extract filesystem fixture");
                        }
                    },
                    BatchSize::PerIteration,
                );
            },
        );
        // Keep the default tar policy alongside a leaner reference that
        // disables tar's additional mtime restoration. Other metadata semantics
        // still differ between the extractors.
        for (implementation, preserve_mtime) in [("tar", true), ("tar-no-mtime", false)] {
            group.bench_with_input(
                BenchmarkId::new(implementation, &benchmark_id),
                &input,
                move |bencher, input| {
                    bencher.iter_batched_ref(
                        || extraction_temp(fixture),
                        |temp| {
                            let destination = temp.path().join("out");
                            let mut archive = tar::Archive::new(input.as_slice());
                            archive.set_preserve_mtime(preserve_mtime);
                            archive
                                .unpack(destination)
                                .expect("tar should extract filesystem fixture");
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
    bench_extract_filesystem(criterion, &runtime, &extraction_filesystem_fixtures());
}

criterion_group!(benches, comparison);
criterion_main!(benches);
