pub mod support;

use std::{collections::VecDeque, io::Read as _, path::Path, sync::mpsc, thread};
#[cfg(unix)]
use std::{env, os::unix::fs::PermissionsExt as _, process::Command};

use archive_trait::{
    Archive, ExtractError, ExtractPolicyViolation, Member, SpecialKind,
    extract::{ExtractPolicy, LinkPolicy, SymlinkPolicy},
};
use cap_std::{ambient_authority, fs::Dir};
use support::{TestArchive, TestEntry, TestError, TestPayload, entry};
use tempfile::tempdir;
use tokio::{runtime::Builder, sync::oneshot};

struct GatedArchive {
    entries: VecDeque<TestEntry>,
    root_opened: Option<oneshot::Sender<()>>,
    resume: Option<oneshot::Receiver<()>>,
    last_member: Option<oneshot::Sender<()>>,
}

impl Archive for GatedArchive {
    type Error = TestError;
    type Payload<'a> = TestPayload;

    async fn next_member<'a>(
        &'a mut self,
    ) -> Result<Option<Member<Self::Payload<'a>>>, Self::Error> {
        if let Some(root_opened) = self.root_opened.take() {
            if root_opened.send(()).is_err() {
                return Err(TestError);
            }
            if let Some(resume) = self.resume.take()
                && resume.await.is_err()
            {
                return Err(TestError);
            }
        }
        let entry = self.entries.pop_front();
        if entry.is_some()
            && self.entries.is_empty()
            && let Some(last_member) = self.last_member.take()
            && last_member.send(()).is_err()
        {
            return Err(TestError);
        }
        match entry {
            Some(entry) => entry.map(Some),
            None => Ok(None),
        }
    }
}

#[tokio::test]
async fn extracts_common_members_and_streams_payload_sizes() {
    const SMALL_BYTES: usize = 128 * 1024 + 7;
    const BUFFERED_BOUNDARY_BYTES: usize = 1024 * 1024;
    const LARGE_BYTES: usize = 1024 * 1024 + 7;

    let small = patterned_payload(SMALL_BYTES);
    let buffered_boundary = patterned_payload(BUFFERED_BOUNDARY_BYTES);
    let large = patterned_payload(LARGE_BYTES);
    let archive = TestArchive::new([
        entry::directory("bin"),
        entry::executable("bin/tool", b"run"),
        entry::file("same", b"old"),
        entry::file("same", b"new"),
        entry::file("empty", b""),
        entry::file("unicodé/文件", b"utf8"),
        entry::file("small", small.clone()),
        entry::file("buffered-boundary", buffered_boundary.clone()),
        entry::file("large", large.clone()),
    ]);
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    archive
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("archive should extract");

    for (path, expected) in [
        ("bin/tool", &b"run"[..]),
        ("same", &b"new"[..]),
        ("empty", &b""[..]),
        ("unicodé/文件", &b"utf8"[..]),
        ("small", small.as_slice()),
        ("buffered-boundary", buffered_boundary.as_slice()),
        ("large", large.as_slice()),
    ] {
        assert_eq!(
            std::fs::read(destination.join(path)).expect("file should be readable"),
            expected
        );
    }
    #[cfg(unix)]
    {
        assert_ne!(
            std::fs::metadata(destination.join("bin/tool"))
                .expect("tool metadata should be readable")
                .permissions()
                .mode()
                & 0o111,
            0
        );
    }
}

#[tokio::test]
async fn streaming_payload_reuses_initialized_chunk_buffer() {
    const PAYLOAD_BYTES: usize = 1024 * 1024 + 7;

    let expected = patterned_payload(PAYLOAD_BYTES);
    let archive = TestArchive::new([entry::reuse_checked_file("file", expected.clone())]);
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    archive
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("streaming extraction should reuse its chunk buffer");
    assert_eq!(
        std::fs::read(destination.join("file")).expect("file should be readable"),
        expected
    );
}

#[tokio::test]
async fn extracts_through_deep_ambient_and_created_path() {
    const COMPONENT: &str = "segment";
    const AMBIENT_DIRECTORY_COMPONENTS: usize = 320;
    const DIRECTORY_COMPONENTS: usize = 640;
    const CLEANUP_STACK_BYTES: usize = 16 * 1024 * 1024;

    let mut path = format!("{COMPONENT}/").repeat(DIRECTORY_COMPONENTS);
    path.push_str("file");
    assert!(
        path.len() > 4_096,
        "test path should exceed common PATH_MAX"
    );
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    std::fs::create_dir(&destination).expect("destination should be created");

    let mut directory = Dir::open_ambient_dir(&destination, ambient_authority())
        .expect("destination capability should be opened");
    for _ in 0..AMBIENT_DIRECTORY_COMPONENTS {
        directory
            .create_dir(COMPONENT)
            .expect("deep ambient directory should be created");
        directory = directory
            .open_dir(COMPONENT)
            .expect("deep ambient directory should be opened");
    }
    drop(directory);

    TestArchive::new([entry::file(&path, b"contents")])
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("deep path should reuse ambient parents and create missing parents");

    let mut directory = Dir::open_ambient_dir(&destination, ambient_authority())
        .expect("destination capability should be opened");
    for _ in 0..DIRECTORY_COMPONENTS {
        directory = directory
            .open_dir(COMPONENT)
            .expect("deep directory should be opened");
    }
    let mut contents = Vec::new();
    directory
        .open("file")
        .expect("deep file should be opened")
        .read_to_end(&mut contents)
        .expect("deep file should be read");
    assert_eq!(contents, b"contents");

    // Recursive removal at this depth needs more than the test thread's stack.
    drop(directory);
    let cleanup_root = Dir::open_ambient_dir(temp.path(), ambient_authority())
        .expect("temporary directory capability should be opened");
    thread::Builder::new()
        .stack_size(CLEANUP_STACK_BYTES)
        .spawn(move || cleanup_root.remove_dir_all("out"))
        .expect("deep cleanup thread should start")
        .join()
        .expect("deep cleanup thread should not panic")
        .expect("deep destination should be removed");
}

fn patterned_payload(size: usize) -> Vec<u8> {
    (0..size)
        .map(|index| u8::try_from(index % 251).expect("payload byte should fit"))
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn extraction_bounds_open_directory_handles() {
    const CHILD_ENVIRONMENT: &str = "ARCHIVE_TRAIT_LOW_NOFILE_CHILD";
    const DIRECTORY_COUNT: usize = 128;
    const TEST_NAME: &str = "extraction_bounds_open_directory_handles";

    // Lowering the process-wide descriptor limit would interfere with parallel
    // tests, so re-run only this test in a constrained child process. The
    // environment marker distinguishes that child from the parent invocation.
    if env::var_os(CHILD_ENVIRONMENT).is_none() {
        let executable = env::current_exe().expect("test executable should be available");
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "ulimit -n 64 && exec \"$0\" --exact {TEST_NAME} --nocapture"
            ))
            .arg(executable)
            .env(CHILD_ENVIRONMENT, "1")
            .status()
            .expect("limited test process should run");
        assert!(status.success(), "limited test process should succeed");
        return;
    }

    let archive = TestArchive::new(
        (0..DIRECTORY_COUNT)
            .map(|index| entry::file(&format!("directory-{index:03}/file"), index.to_le_bytes())),
    );
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    archive
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("archive should extract under a low file descriptor limit");

    for index in 0..DIRECTORY_COUNT {
        assert_eq!(
            std::fs::read(destination.join(format!("directory-{index:03}/file")))
                .expect("extracted file should be readable"),
            index.to_le_bytes()
        );
    }
}

#[tokio::test]
async fn name_validation_covers_member_and_link_values() {
    let temp = tempdir().expect("temporary directory should be created");
    let policy = ExtractPolicy::default().link_policy(
        LinkPolicy::default()
            .allow_hard_links(true)
            .symlink_policy(SymlinkPolicy::Skip),
    );
    for (case, member, context) in [
        ("member", entry::file(" rejected", b""), "member path"),
        (
            "symbolic",
            entry::symbolic_link("link", " rejected"),
            "symbolic-link target",
        ),
        (
            "hard",
            entry::hard_link("link", " rejected", b""),
            "hard-link target",
        ),
    ] {
        assert!(matches!(
            TestArchive::new([member])
                .extract_in(temp.path().join(case), policy)
                .await,
            Err(ExtractError::PolicyViolation {
                violation: ExtractPolicyViolation::NameRejected {
                    context: actual,
                    ..
                },
                ..
            }) if actual == context
        ));
    }

    let destination = temp.path().join("disabled");
    TestArchive::new([entry::file(" allowed", b"ok")])
        .extract_in(&destination, ExtractPolicy::default().name_validator(None))
        .await
        .expect("disabled validation should accept boundary whitespace");
    assert_eq!(
        std::fs::read(destination.join(" allowed")).expect("file should be readable"),
        b"ok"
    );
}

#[tokio::test]
async fn payload_errors_flush_prior_files_before_returning() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");

    let result = TestArchive::new([
        entry::file("created", b"kept"),
        entry::invalid_file("invalid", b""),
    ])
    .extract_in(&destination, ExtractPolicy::default())
    .await;

    assert!(matches!(result, Err(ExtractError::Archive(_))));
    assert_eq!(
        std::fs::read(destination.join("created")).expect("prior file should remain"),
        b"kept"
    );
    assert!(!destination.join("invalid").exists());
}

#[tokio::test]
async fn rejects_invalid_destinations_unsafe_special_and_colliding_members() {
    let temp = tempdir().expect("temporary directory should be created");
    let file_destination = temp.path().join("file-destination");
    std::fs::write(&file_destination, b"keep").expect("destination file should be written");
    assert!(matches!(
        TestArchive::new([entry::file("file", b"archive")])
            .extract_in(&file_destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::Filesystem { .. })
    ));
    assert_eq!(
        std::fs::read(&file_destination).expect("destination file should remain readable"),
        b"keep"
    );

    for (case, path) in [
        ("leading-parent", "../escape"),
        ("absolute", "/escape"),
        ("backslash", r"nested\escape"),
    ] {
        assert!(matches!(
            TestArchive::new([entry::file(path, b"")])
                .extract_in(
                    temp.path().join(case),
                    ExtractPolicy::default().name_validator(None),
                )
                .await,
            Err(ExtractError::UnsafePath { .. })
        ));
    }
    assert!(!temp.path().join("escape").exists());

    assert!(matches!(
        TestArchive::new([entry::special("device", SpecialKind::CharacterDevice)])
            .extract_in(temp.path().join("special"), ExtractPolicy::default())
            .await,
        Err(ExtractError::UnsupportedMember {
            kind: SpecialKind::CharacterDevice,
            ..
        })
    ));

    let destination = temp.path().join("collision");
    std::fs::create_dir(&destination).expect("destination should be created");
    std::fs::write(destination.join("file"), b"ambient").expect("ambient file should be written");
    assert!(matches!(
        TestArchive::new([entry::file("file", b"archive")])
            .extract_in(
                &destination,
                ExtractPolicy::default().allow_overwrites(false),
            )
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("file")
    ));
}

#[tokio::test]
async fn archive_errors_flush_prior_buffered_files() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("partial");
    let result = TestArchive::new([entry::file("created", b"kept"), entry::error()])
        .extract_in(&destination, ExtractPolicy::default())
        .await;

    assert!(matches!(result, Err(ExtractError::Archive(_))));
    assert_eq!(
        std::fs::read(destination.join("created")).expect("created file should remain"),
        b"kept"
    );
}

#[test]
fn cancelling_extraction_stops_pending_buffered_files() {
    let temp = tempdir().expect("temporary directory should be created");
    let destination = temp.path().join("out");
    let (root_opened_sender, root_opened_receiver) = oneshot::channel();
    let (resume_sender, resume_receiver) = oneshot::channel();
    let (last_member_sender, last_member_receiver) = oneshot::channel();
    let archive = GatedArchive {
        entries: (0..64)
            .map(|index| entry::file(&format!("file-{index}"), b"contents"))
            .collect(),
        root_opened: Some(root_opened_sender),
        resume: Some(resume_receiver),
        last_member: Some(last_member_sender),
    };
    let extraction_destination = destination.clone();

    let runtime = Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()
        .expect("test runtime should be created");
    runtime.block_on(async move {
        let extraction = tokio::spawn(async move {
            archive
                .extract_in(extraction_destination, ExtractPolicy::default())
                .await
        });
        root_opened_receiver
            .await
            .expect("extraction root should be opened");

        let (release_worker_sender, release_worker_receiver) = mpsc::channel();
        let (worker_started_sender, worker_started_receiver) = oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            if worker_started_sender.send(()).is_err() {
                return false;
            }
            release_worker_receiver.recv().is_ok()
        });
        let worker_started = worker_started_receiver.await;
        let resumed = resume_sender.send(());
        let reached_last_member = last_member_receiver.await;

        extraction.abort();
        let extraction_result = extraction.await;
        let worker_released = release_worker_sender.send(());
        let worker_result = worker.await;

        assert!(worker_started.is_ok());
        assert!(resumed.is_ok());
        assert!(reached_last_member.is_ok());
        assert!(matches!(
            extraction_result,
            Err(error) if error.is_cancelled()
        ));
        assert!(worker_released.is_ok());
        assert!(matches!(worker_result, Ok(true)));
    });
    drop(runtime);

    assert_eq!(
        std::fs::read_dir(destination)
            .expect("destination should be readable")
            .count(),
        0
    );
}

#[cfg(windows)]
#[tokio::test]
async fn destination_junctions_are_rejected_as_parents_and_roots() {
    let temp = tempdir().expect("temporary directory should be created");
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).expect("outside directory should be created");
    std::fs::write(outside.join("keep"), b"keep").expect("outside file should be written");

    let destination = temp.path().join("parent");
    std::fs::create_dir(&destination).expect("destination should be created");
    junction::create(&outside, destination.join("junction"))
        .expect("parent junction should be created");
    assert!(matches!(
        TestArchive::new([entry::file("junction/file", b"archive")])
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::PathCollision { path }) if path == Path::new("junction")
    ));
    assert!(!outside.join("file").exists());

    let destination = temp.path().join("root-junction");
    junction::create(&outside, &destination).expect("root junction should be created");
    assert!(matches!(
        TestArchive::new([entry::file("file", b"archive")])
            .extract_in(&destination, ExtractPolicy::default())
            .await,
        Err(ExtractError::Filesystem { .. })
    ));
    assert_eq!(
        std::fs::read(outside.join("keep")).expect("outside file should remain readable"),
        b"keep"
    );
    assert!(!outside.join("file").exists());
}
