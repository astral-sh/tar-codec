use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use crate::{
    BLOCK_SIZE, Block, FrameError,
    header::{
        GNU_IDENTITY, IDENTITY_RANGE, POSIX_IDENTITY, SIZE_RANGE, TYPEFLAG_OFFSET, encode_checksum,
        encode_octal,
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

pub(crate) fn set_checksum(block: &mut Block) {
    encode_checksum(block);
}

pub(crate) fn header(typeflag: u8, size: u64) -> Block {
    let mut block = [0; BLOCK_SIZE];
    block[..4].copy_from_slice(b"file");
    assert!(encode_octal(&mut block[SIZE_RANGE], size));
    block[TYPEFLAG_OFFSET] = typeflag;
    block[IDENTITY_RANGE].copy_from_slice(POSIX_IDENTITY);
    set_checksum(&mut block);
    block
}

pub(crate) fn gnu_header(typeflag: u8, size: u64) -> Block {
    let mut block = header(typeflag, size);
    block[IDENTITY_RANGE].copy_from_slice(GNU_IDENTITY);
    set_checksum(&mut block);
    block
}

pub(crate) fn gnu_base256_header(typeflag: u8, size: u64) -> Block {
    let mut block = gnu_header(typeflag, 0);
    block[SIZE_RANGE].fill(0);
    block[SIZE_RANGE.start] = 0x80;
    block[SIZE_RANGE.end - size.to_be_bytes().len()..SIZE_RANGE.end]
        .copy_from_slice(&size.to_be_bytes());
    set_checksum(&mut block);
    block
}

pub(crate) fn record(keyword: &str, value: &str) -> Vec<u8> {
    raw_record(keyword.as_bytes(), value.as_bytes())
}

pub(crate) fn raw_record(keyword: &[u8], value: &[u8]) -> Vec<u8> {
    let suffix = [b" ".as_slice(), keyword, b"=", value, b"\n"].concat();
    let mut len = suffix.len() + 1;
    loop {
        let mut record = len.to_string().into_bytes();
        record.extend_from_slice(&suffix);
        if record.len() == len {
            return record;
        }
        len = record.len();
    }
}

pub(crate) fn append_block(bytes: &mut Vec<u8>, block: &Block) {
    bytes.extend_from_slice(block);
}

pub(crate) fn append_payload(bytes: &mut Vec<u8>, payload: &[u8]) {
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(BLOCK_SIZE), 0);
}

pub(crate) fn append_posix(bytes: &mut Vec<u8>, typeflag: u8, payload: &[u8]) {
    append_block(bytes, &header(typeflag, payload.len() as u64));
    append_payload(bytes, payload);
}

pub(crate) fn append_gnu(bytes: &mut Vec<u8>, typeflag: u8, payload: &[u8]) {
    append_block(bytes, &gnu_header(typeflag, payload.len() as u64));
    append_payload(bytes, payload);
}

pub(crate) fn append_terminator(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len() + 2 * BLOCK_SIZE, 0);
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

pub(crate) fn ready_ok<F, T>(future: F) -> T
where
    F: Future<Output = Result<T, FrameError>>,
{
    match ready(future) {
        Ok(value) => value,
        Err(error) => panic!("test future returned error: {error:?}"),
    }
}
