mod support;

use std::{fs, time::Duration};

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use support::{
    Entry, SMALL_FILE_BYTES, SMALL_FILE_COUNT, payload, payload_throughput, runtime,
    ustar_archive_entries,
};
use tar_codec::{Archive as _, TarArchive, extract::ExtractPolicy};
use tempfile::{TempDir, tempdir};
use tokio::runtime::Runtime;

const DIRECTORY_HEAVY_FILE_COUNT: usize = 256;
const BUFFERED_BOUNDARY_FILE_COUNT: usize = 16;
const DUPLICATE_FILE_COUNT: usize = 256;

struct ExtractionFixture {
    id: &'static str,
    entries: Vec<Entry>,
    payload_bytes: u64,
    prepopulate_destination: bool,
}

impl ExtractionFixture {
    fn benchmark_id(&self) -> String {
        format!("{}-{}-entries", self.id, self.entries.len())
    }

    fn payload_throughput(&self) -> Throughput {
        payload_throughput(self.entries.len(), self.payload_bytes)
    }
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

fn extraction_filesystem(criterion: &mut Criterion) {
    let runtime = runtime();
    bench_extract_filesystem(criterion, &runtime, &extraction_filesystem_fixtures());
}

criterion_group!(benches, extraction_filesystem);
criterion_main!(benches);
