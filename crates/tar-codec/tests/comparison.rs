use std::{fs, path::Path};

use tar_codec::{
    Archive as _, ArchiveBuilder as _, EntryMetadata, TarArchive, TarEncoder,
    extract::ExtractPolicy,
};
use tempfile::tempdir;

const ENTRIES: &[(&str, &[u8])] = &[
    ("tree/README.md", b"hello\n"),
    ("tree/src/lib.rs", b"pub fn answer() -> u8 { 42 }\n"),
];

#[tokio::test]
async fn extracts_pax_and_ustar_archives_across_crates() {
    let archives = [
        pax_archive().await,
        tar_ustar_archive(),
        tokio_tar_ustar_archive().await,
    ];
    for archive in archives {
        assert_tar_codec_extracts(&archive).await;
        assert_tar_extracts(&archive);
        assert_tokio_tar_extracts(&archive).await;
    }
}

async fn pax_archive() -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = TarEncoder::new(&mut bytes).builder();
    for (path, data) in ENTRIES {
        encoder
            .add_file(path, *data, EntryMetadata::default())
            .await
            .expect("tar-codec should encode pax test entry");
    }
    encoder
        .finish()
        .await
        .expect("tar-codec pax archive should finish");
    bytes
}

fn tar_ustar_archive() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, data) in ENTRIES {
        let mut header = tar::Header::new_ustar();
        configure_tar_header(&mut header, data.len());
        builder
            .append_data(&mut header, path, *data)
            .expect("tar should encode ustar test entry");
    }
    builder
        .into_inner()
        .expect("tar ustar archive should finish")
}

async fn tokio_tar_ustar_archive() -> Vec<u8> {
    let mut builder = tokio_tar::Builder::new(Vec::new());
    for (path, data) in ENTRIES {
        let mut header = tokio_tar::Header::new_ustar();
        configure_tokio_tar_header(&mut header, data.len());
        builder
            .append_data(&mut header, path, *data)
            .await
            .expect("astral-tokio-tar should encode ustar test entry");
    }
    builder
        .into_inner()
        .await
        .expect("astral-tokio-tar ustar archive should finish")
}

fn configure_tar_header(header: &mut tar::Header, payload_len: usize) {
    header.set_size(u64::try_from(payload_len).expect("payload length should be representable"));
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
}

fn configure_tokio_tar_header(header: &mut tokio_tar::Header, payload_len: usize) {
    header.set_size(u64::try_from(payload_len).expect("payload length should be representable"));
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
}

async fn assert_tar_codec_extracts(archive: &[u8]) {
    let temp = tempdir().expect("temporary extraction directory should be created");
    let destination = temp.path().join("out");
    TarArchive::new(archive)
        .extract_in(&destination, ExtractPolicy::default())
        .await
        .expect("tar-codec should extract archive");
    assert_contents(&destination);
}

fn assert_tar_extracts(archive: &[u8]) {
    let temp = tempdir().expect("temporary extraction directory should be created");
    let destination = temp.path().join("out");
    tar::Archive::new(archive)
        .unpack(&destination)
        .expect("tar should extract archive");
    assert_contents(&destination);
}

async fn assert_tokio_tar_extracts(archive: &[u8]) {
    let temp = tempdir().expect("temporary extraction directory should be created");
    let destination = temp.path().join("out");
    tokio_tar::Archive::new(archive)
        .unpack(&destination)
        .await
        .expect("astral-tokio-tar should extract archive");
    assert_contents(&destination);
}

fn assert_contents(destination: &Path) {
    for (path, data) in ENTRIES {
        assert_eq!(
            fs::read(destination.join(path)).expect("extracted file should be readable"),
            *data
        );
    }
}
