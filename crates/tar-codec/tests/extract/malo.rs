//! Testcases from the "malo" project:
//! <https://github.com/fastzip/malo/tree/main/tar>

use tar_codec::decode::{Archive, DecodeError, DecodePolicy};
use tar_framing::{FrameError, FrameErrorInner, MemberKind};
use tempfile::tempdir;

const DIRECTORY_WITH_EMBEDDED_HEADER: &[u8] =
    include_bytes!("../assets/malo/dir_with_embedded_header.tar");
const PAX_PATH_TRAILING_SLASH_FILE: &[u8] =
    include_bytes!("../assets/malo/pax_path_trailing_slash_file.tar");

#[tokio::test]
async fn rejects_directory_with_embedded_header_without_writing_members() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    assert!(matches!(
        Archive::new(DIRECTORY_WITH_EMBEDDED_HEADER)
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::Framing(FrameError {
            position: 0,
            inner: FrameErrorInner::InvalidMemberSize {
                kind: MemberKind::Directory,
                size: 512,
            },
        }))
    ));
    assert!(destination.is_dir());
    assert!(std::fs::read_dir(destination).unwrap().next().is_none());
}

#[tokio::test]
async fn rejects_trailing_separator_on_regular_file_without_writing_members() {
    let temp = tempdir().unwrap();
    let destination = temp.path().join("out");
    assert!(matches!(
        Archive::new(PAX_PATH_TRAILING_SLASH_FILE)
            .extract(&destination, DecodePolicy::default())
            .await,
        Err(DecodeError::UnsafePath {
            position: 1024,
            context: "member path",
            value,
            reason: "only a directory may have a trailing separator",
        }) if value == "file.txt/"
    ));
    assert!(destination.is_dir());
    assert!(std::fs::read_dir(destination).unwrap().next().is_none());
}
