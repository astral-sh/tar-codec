//! Asynchronous chapter indexing and decoding.
//!
//! The backward-linked chapter discovery algorithm is adapted from David
//! Tolnay's `chapter-tgz` (MIT OR Apache-2.0):
//! <https://github.com/dtolnay/chapter-tgz>.

use std::{
    io::{self, Cursor, SeekFrom},
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};

use async_compression::tokio::bufread::{DeflateDecoder, GzipDecoder};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, BufReader, Chain, ReadBuf, Take,
};

use crate::{GZIP_HEADER, marker};

type CompletedDeflate<R> = BufReader<Chain<Take<R>, Cursor<[u8; 2]>>>;

/// Compressed-byte boundaries discovered without decompressing chapter contents.
#[derive(Clone, Debug)]
pub struct ChapterIndex {
    boundaries: Vec<u64>,
    chaptered: bool,
}

impl ChapterIndex {
    /// Returns the number of independently readable chapters.
    pub fn chapter_count(&self) -> usize {
        self.boundaries.len().saturating_sub(1)
    }

    /// Reports whether the source contains recognized chapter markers.
    pub fn is_chaptered(&self) -> bool {
        self.chaptered
    }

    /// Returns a chapter's compressed-byte range in the original source.
    pub fn chapter_range(&self, index: usize) -> Option<Range<u64>> {
        let start = *self.boundaries.get(index)?;
        let end = *self.boundaries.get(index.checked_add(1)?)?;
        Some(start..end)
    }
}

/// An indexed asynchronous gzip reader supporting individual chapter access.
pub struct ChapteredGzipReader<R> {
    source: R,
    index: ChapterIndex,
}

impl<R: AsyncRead + AsyncSeek + Unpin> ChapteredGzipReader<R> {
    /// Builds the chapter index with one bounded read and seek per chapter.
    ///
    /// An ordinary gzip source without chapter markers is exposed as one chapter.
    pub async fn open(mut source: R) -> io::Result<Self> {
        let start = source.stream_position().await?;
        let mut header = [0; GZIP_HEADER.len()];
        let has_expected_header =
            source.read_exact(&mut header).await.is_ok() && header == GZIP_HEADER;
        let end = source.seek(SeekFrom::End(0)).await?;

        let boundaries = if has_expected_header {
            read_boundaries(&mut source, start, end).await?
        } else {
            None
        };
        let index = if let Some(boundaries) = boundaries {
            ChapterIndex {
                boundaries,
                chaptered: true,
            }
        } else {
            ChapterIndex {
                boundaries: vec![start, end],
                chaptered: false,
            }
        };
        source.seek(SeekFrom::Start(start)).await?;

        Ok(Self { source, index })
    }

    /// Returns the discovered compressed-byte chapter index.
    pub fn index(&self) -> &ChapterIndex {
        &self.index
    }

    /// Returns the number of independently readable chapters.
    pub fn chapter_count(&self) -> usize {
        self.index.chapter_count()
    }

    /// Borrows the original source and opens one chapter as an [`AsyncRead`].
    pub async fn read_chapter(&mut self, chapter: usize) -> io::Result<ChapterReader<&mut R>> {
        let range = self.index.chapter_range(chapter).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "chapter index is out of bounds",
            )
        })?;
        open_chapter(&mut self.source, range, self.index.chaptered).await
    }

    /// Opens a chapter using a separately positioned source for parallel reads.
    ///
    /// The supplied source must refer to the same compressed bytes used to
    /// construct this index and must have an independent seek position.
    pub async fn read_chapter_from<S>(
        &self,
        chapter: usize,
        source: S,
    ) -> io::Result<ChapterReader<S>>
    where
        S: AsyncRead + AsyncSeek + Unpin,
    {
        let range = self.index.chapter_range(chapter).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "chapter index is out of bounds",
            )
        })?;
        open_chapter(source, range, self.index.chaptered).await
    }

    /// Returns the original compressed source without changing its contents.
    pub fn into_inner(self) -> R {
        self.source
    }
}

async fn read_boundaries<R: AsyncRead + AsyncSeek + Unpin>(
    source: &mut R,
    start: u64,
    end: u64,
) -> io::Result<Option<Vec<u64>>> {
    let window_length = marker::MAX_MARKER_BYTES as u64 + 4;
    let Some(window_start) = end.checked_sub(window_length) else {
        return Ok(None);
    };
    if window_start < start {
        return Ok(None);
    }

    source.seek(SeekFrom::Start(window_start)).await?;
    let mut window = [0; marker::MAX_MARKER_BYTES];
    if source.read_exact(&mut window).await.is_err() {
        return Ok(None);
    }
    let Some((offset, mut distance)) = marker::decode_final(&window) else {
        return Ok(None);
    };
    let Some(mut boundary) = window_start.checked_add(offset as u64) else {
        return Ok(None);
    };
    let mut boundaries = vec![boundary];

    loop {
        let Some(previous) = boundary.checked_sub(distance) else {
            return Ok(None);
        };
        if previous == start {
            break;
        }
        boundaries.push(previous);
        if previous == start + GZIP_HEADER.len() as u64 {
            break;
        }
        source.seek(SeekFrom::Start(previous)).await?;
        if source
            .read_exact(&mut window[..marker::MAX_PREFIX_READ_BYTES])
            .await
            .is_err()
        {
            return Ok(None);
        }
        let Some(previous_distance) = marker::decode_boundary(&window) else {
            return Ok(None);
        };
        boundary = previous;
        distance = previous_distance;
    }

    boundaries.reverse();
    Ok(Some(boundaries))
}

async fn open_chapter<R: AsyncRead + AsyncSeek + Unpin>(
    mut source: R,
    range: Range<u64>,
    chaptered: bool,
) -> io::Result<ChapterReader<R>> {
    source.seek(SeekFrom::Start(range.start)).await?;
    let length = range.end.saturating_sub(range.start);
    let decoder = if chaptered {
        let completed = source.take(length).chain(Cursor::new([0x03, 0x00]));
        ChapterDecoder::Deflate(DeflateDecoder::new(BufReader::new(completed)))
    } else {
        ChapterDecoder::Gzip(GzipDecoder::new(BufReader::new(source.take(length))))
    };
    Ok(ChapterReader { decoder })
}

/// An asynchronously decoded chapter of the original uncompressed byte stream.
///
/// A chaptered read does not validate the archive-wide gzip checksum because
/// that checksum covers every chapter together.
pub struct ChapterReader<R> {
    decoder: ChapterDecoder<R>,
}

enum ChapterDecoder<R> {
    Deflate(DeflateDecoder<CompletedDeflate<R>>),
    Gzip(GzipDecoder<BufReader<Take<R>>>),
}

impl<R: AsyncRead + Unpin> AsyncRead for ChapterReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.decoder {
            ChapterDecoder::Deflate(decoder) => Pin::new(decoder).poll_read(context, buffer),
            ChapterDecoder::Gzip(decoder) => Pin::new(decoder).poll_read(context, buffer),
        }
    }
}
