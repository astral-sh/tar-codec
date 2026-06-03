use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

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
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.position == self.bytes.len() {
            return Poll::Ready(Ok(()));
        }
        let len = self
            .max_chunk
            .min(buffer.remaining())
            .min(self.bytes.len() - self.position);
        let end = self.position + len;
        buffer.put_slice(&self.bytes[self.position..end]);
        self.position = end;
        Poll::Ready(Ok(()))
    }
}
