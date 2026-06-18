//! Shared fixtures for the headline and filesystem extraction benchmarks.

use criterion::Throughput;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

pub(crate) const SMALL_FILE_BYTES: usize = 1024;
pub(crate) const SMALL_FILE_COUNT: usize = 1024;

pub(crate) struct Entry {
    pub(crate) archive_path: String,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn payload_throughput(entry_count: usize, payload_bytes: u64) -> Throughput {
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

pub(crate) fn runtime() -> Runtime {
    RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime should build")
}

pub(crate) fn payload(size: usize, salt: usize) -> Vec<u8> {
    (0..size)
        .map(|index| {
            u8::try_from((index + salt) % 251).expect("payload byte should be representable")
        })
        .collect()
}

pub(crate) fn configure_tar_header(header: &mut tar::Header, payload_len: usize) {
    header.set_size(u64::try_from(payload_len).expect("payload length should be representable"));
    header.set_mode(0o644);
    header.set_cksum();
}

pub(crate) fn ustar_archive_entries(entries: &[Entry]) -> Vec<u8> {
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
