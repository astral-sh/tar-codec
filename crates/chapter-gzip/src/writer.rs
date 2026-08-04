use std::{
    future::poll_fn,
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll, ready},
};

use flate2::{Compression, Crc, write::DeflateEncoder};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{GZIP_HEADER, marker};

const MAX_INPUT_CHUNK_BYTES: usize = 64 * 1024;

/// An asynchronous gzip writer containing independently decompressible chapters.
///
/// The first write starts a chapter implicitly. Call [`Self::start_chapter`]
/// between application-level records to create additional chapter boundaries.
pub struct ChapteredGzipWriter<W> {
    inner: W,
    encoder: Option<DeflateEncoder<Vec<u8>>>,
    level: Compression,
    checksum: Crc,
    pending: Vec<u8>,
    pending_offset: usize,
    compressed_position: u64,
    previous_boundary: u64,
    chapter_count: usize,
    flush_in_progress: bool,
    finalized: bool,
    closed: bool,
}

impl<W> ChapteredGzipWriter<W> {
    /// Creates a writer using the requested DEFLATE compression level.
    pub fn new(inner: W, level: Compression) -> Self {
        Self {
            inner,
            encoder: Some(DeflateEncoder::new(Vec::new(), level)),
            level,
            checksum: Crc::new(),
            pending: GZIP_HEADER.to_vec(),
            pending_offset: 0,
            compressed_position: 0,
            previous_boundary: 0,
            chapter_count: 0,
            flush_in_progress: false,
            finalized: false,
            closed: false,
        }
    }

    /// Returns the number of chapters started so far.
    pub fn chapter_count(&self) -> usize {
        self.chapter_count
    }

    fn ensure_active(&self) -> io::Result<()> {
        if self.finalized || self.closed {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "chaptered gzip writer is already finished",
            ))
        } else {
            Ok(())
        }
    }

    fn append_compressed(&mut self, compressed: &[u8]) -> io::Result<()> {
        let length = u64::try_from(compressed.len())
            .map_err(|_| io::Error::other("compressed chapter length overflowed"))?;
        self.compressed_position = self
            .compressed_position
            .checked_add(length)
            .ok_or_else(|| io::Error::other("compressed chapter position overflowed"))?;
        self.pending.extend_from_slice(compressed);
        Ok(())
    }

    fn collect_encoder_output(&mut self) -> io::Result<()> {
        let Some(encoder) = self.encoder.as_mut() else {
            return Err(io::Error::other("chapter compressor is unavailable"));
        };
        let output = encoder.get_mut();
        let length = u64::try_from(output.len())
            .map_err(|_| io::Error::other("compressed chapter length overflowed"))?;
        self.compressed_position = self
            .compressed_position
            .checked_add(length)
            .ok_or_else(|| io::Error::other("compressed chapter position overflowed"))?;
        self.pending.extend_from_slice(output);
        output.clear();
        Ok(())
    }

    fn finish_current_block(&mut self) -> io::Result<()> {
        let Some(encoder) = self.encoder.take() else {
            return Err(io::Error::other("chapter compressor is unavailable"));
        };
        let output = encoder.flush_finish()?;
        self.append_compressed(&output)
    }

    fn prepare_final_blocks(&mut self) -> io::Result<()> {
        if self.finalized {
            return Ok(());
        }
        if self.chapter_count == 0 {
            self.chapter_count = 1;
        }
        self.finish_current_block()?;
        let distance = self
            .compressed_position
            .checked_sub(self.previous_boundary)
            .ok_or_else(|| io::Error::other("chapter boundary distance underflowed"))?;
        let boundary = marker::encode(true, distance)?;
        self.append_compressed(boundary.as_bytes())?;
        self.pending
            .extend_from_slice(&self.checksum.sum().to_le_bytes());
        self.pending
            .extend_from_slice(&self.checksum.amount().to_le_bytes());
        self.finalized = true;
        Ok(())
    }
}

impl<W: AsyncWrite + Unpin> ChapteredGzipWriter<W> {
    /// Starts the first chapter or inserts a boundary before the next chapter.
    ///
    /// The boundary is flushed to the underlying writer before this returns.
    pub async fn start_chapter(&mut self) -> io::Result<()> {
        self.ensure_active()?;
        if self.chapter_count == 0 {
            self.chapter_count = 1;
        } else {
            self.finish_current_block()?;
            let distance = self
                .compressed_position
                .checked_sub(self.previous_boundary)
                .ok_or_else(|| io::Error::other("chapter boundary distance underflowed"))?;
            self.previous_boundary = self.compressed_position;
            let boundary = marker::encode(false, distance)?;
            self.append_compressed(boundary.as_bytes())?;
            self.encoder = Some(DeflateEncoder::new(Vec::new(), self.level));
            self.chapter_count = self
                .chapter_count
                .checked_add(1)
                .ok_or_else(|| io::Error::other("chapter count overflowed"))?;
        }

        poll_fn(|context| self.poll_drain_pending(context)).await
    }

    /// Finalizes the DEFLATE stream, writes its gzip trailer, and returns the sink.
    pub async fn finish(mut self) -> io::Result<W> {
        self.shutdown().await?;
        Ok(self.inner)
    }

    fn poll_drain_pending(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_offset < self.pending.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(context, &self.pending[self.pending_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "chaptered gzip sink accepted zero bytes",
                )));
            }
            self.pending_offset += written;
        }
        self.pending.clear();
        self.pending_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ChapteredGzipWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.ensure_active()?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }

        ready!(self.poll_drain_pending(context))?;
        if self.chapter_count == 0 {
            self.chapter_count = 1;
        }

        let Some(encoder) = self.encoder.as_mut() else {
            return Poll::Ready(Err(io::Error::other("chapter compressor is unavailable")));
        };
        let length = bytes.len().min(MAX_INPUT_CHUNK_BYTES);
        let written = encoder.write(&bytes[..length])?;
        if written == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "chapter compressor accepted zero bytes",
            )));
        }
        self.checksum.update(&bytes[..written]);
        self.collect_encoder_output()?;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.ensure_active()?;
        if !self.flush_in_progress {
            if let Some(encoder) = self.encoder.as_mut() {
                encoder.flush()?;
            }
            self.collect_encoder_output()?;
            self.flush_in_progress = true;
        }

        ready!(self.poll_drain_pending(context))?;
        ready!(Pin::new(&mut self.inner).poll_flush(context))?;
        self.flush_in_progress = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }

        self.prepare_final_blocks()?;
        ready!(self.poll_drain_pending(context))?;
        ready!(Pin::new(&mut self.inner).poll_shutdown(context))?;
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}
