use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    BLOCK_SIZE,
    stream::{
        CHECKSUM_RANGE, GNU_IDENTITY, IDENTITY_RANGE, POSIX_IDENTITY, SIZE_RANGE, TYPEFLAG_OFFSET,
    },
};

pub(crate) struct ChunkedReader {
    bytes: Vec<u8>,
    position: usize,
    max_chunk: usize,
}

impl ChunkedReader {
    pub(crate) fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            bytes,
            position: 0,
            max_chunk,
        }
    }
}

impl AsyncRead for ChunkedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position == self.bytes.len() {
            return Poll::Ready(Ok(()));
        }
        let len = self
            .max_chunk
            .min(buffer.remaining())
            .min(self.bytes.len() - self.position);
        let start = self.position;
        let end = start + len;
        buffer.put_slice(&self.bytes[start..end]);
        self.position = end;
        Poll::Ready(Ok(()))
    }
}

pub(crate) fn set_checksum(block: &mut [u8; BLOCK_SIZE]) {
    block[CHECKSUM_RANGE].fill(b' ');
    let checksum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    let encoded = format!("{checksum:06o}\0 ");
    block[CHECKSUM_RANGE].copy_from_slice(encoded.as_bytes());
}

pub(crate) fn header(typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
    let mut block = [0; BLOCK_SIZE];
    block[..4].copy_from_slice(b"file");
    let encoded_size = format!("{size:011o}\0");
    block[SIZE_RANGE].copy_from_slice(encoded_size.as_bytes());
    block[TYPEFLAG_OFFSET] = typeflag;
    block[IDENTITY_RANGE].copy_from_slice(POSIX_IDENTITY);
    set_checksum(&mut block);
    block
}

pub(crate) fn gnu_header(typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
    let mut block = header(typeflag, size);
    block[IDENTITY_RANGE].copy_from_slice(GNU_IDENTITY);
    set_checksum(&mut block);
    block
}

pub(crate) fn gnu_base256_header(typeflag: u8, size: u64) -> [u8; BLOCK_SIZE] {
    let mut block = gnu_header(typeflag, 0);
    block[SIZE_RANGE].fill(0);
    block[SIZE_RANGE.start] = 0x80;
    block[SIZE_RANGE.end - size.to_be_bytes().len()..SIZE_RANGE.end]
        .copy_from_slice(&size.to_be_bytes());
    set_checksum(&mut block);
    block
}

pub(crate) fn data(value: &[u8]) -> [u8; BLOCK_SIZE] {
    let mut block = [0; BLOCK_SIZE];
    block[..value.len()].copy_from_slice(value);
    block
}

pub(crate) fn record(keyword: &str, value: &str) -> Vec<u8> {
    let suffix = format!(" {keyword}={value}\n");
    let mut len = suffix.len() + 1;
    loop {
        let encoded = format!("{len}{suffix}");
        if encoded.len() == len {
            return encoded.into_bytes();
        }
        len = encoded.len();
    }
}

pub(crate) fn append_block(bytes: &mut Vec<u8>, block: &[u8; BLOCK_SIZE]) {
    bytes.extend_from_slice(block);
}

pub(crate) fn append_payload(bytes: &mut Vec<u8>, payload: &[u8]) {
    for chunk in payload.chunks(BLOCK_SIZE) {
        append_block(bytes, &data(chunk));
    }
}

pub(crate) fn append_terminator(bytes: &mut Vec<u8>) {
    append_block(bytes, &[0; BLOCK_SIZE]);
    append_block(bytes, &[0; BLOCK_SIZE]);
}

pub(crate) fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let waker = std::task::Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("test reader is never pending"),
    }
}
