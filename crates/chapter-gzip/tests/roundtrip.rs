use std::{
    io::{self, Cursor, Read, Write},
    pin::Pin,
    task::{Context, Poll},
};

use chapter_gzip::{ChapteredGzipReader, ChapteredGzipWriter, Compression};
use flate2::{read::GzDecoder, write::GzEncoder};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn chapters_remain_one_ordinary_gzip_stream() -> TestResult {
    let mut writer = ChapteredGzipWriter::new(Vec::new(), Compression::fast());
    writer.start_chapter().await?;
    writer.write_all(b"first chapter").await?;
    writer.start_chapter().await?;
    writer.write_all(b"second chapter").await?;
    writer.start_chapter().await?;
    writer.write_all(b"third chapter").await?;

    let compressed = writer.finish().await?;
    let mut decoded = Vec::new();
    GzDecoder::new(compressed.as_slice()).read_to_end(&mut decoded)?;

    assert_eq!(decoded, b"first chaptersecond chapterthird chapter");
    Ok(())
}

#[tokio::test]
async fn indexes_and_reads_individual_chapters() -> TestResult {
    let mut writer = ChapteredGzipWriter::new(Vec::new(), Compression::default());
    writer.write_all(b"alpha").await?;
    writer.start_chapter().await?;
    writer.write_all(b"beta").await?;
    writer.start_chapter().await?;
    writer.write_all(b"gamma").await?;
    assert_eq!(writer.chapter_count(), 3);

    let compressed = writer.finish().await?;
    let mut archive = ChapteredGzipReader::open(Cursor::new(compressed)).await?;
    assert!(archive.index().is_chaptered());
    assert_eq!(archive.chapter_count(), 3);

    for (index, expected) in [(2, "gamma"), (0, "alpha"), (1, "beta")] {
        let mut chapter = archive.read_chapter(index).await?;
        let mut decoded = String::new();
        chapter.read_to_string(&mut decoded).await?;
        assert_eq!(decoded, expected);
    }

    assert!(archive.read_chapter(3).await.is_err());
    Ok(())
}

#[tokio::test]
async fn ordinary_gzip_falls_back_to_one_chapter() -> TestResult {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    Write::write_all(&mut encoder, b"an ordinary gzip stream")?;
    let compressed = encoder.finish()?;

    let mut archive = ChapteredGzipReader::open(Cursor::new(compressed)).await?;
    assert!(!archive.index().is_chaptered());
    assert_eq!(archive.chapter_count(), 1);

    let mut decoded = String::new();
    archive
        .read_chapter(0)
        .await?
        .read_to_string(&mut decoded)
        .await?;
    assert_eq!(decoded, "an ordinary gzip stream");
    Ok(())
}

#[tokio::test]
async fn separately_positioned_sources_can_read_concurrently() -> TestResult {
    let mut writer = ChapteredGzipWriter::new(Vec::new(), Compression::fast());
    writer.write_all(b"left").await?;
    writer.start_chapter().await?;
    writer.write_all(b"right").await?;
    let compressed = writer.finish().await?;

    let archive = ChapteredGzipReader::open(Cursor::new(compressed.as_slice())).await?;
    let left = archive.read_chapter_from(0, Cursor::new(compressed.as_slice()));
    let right = archive.read_chapter_from(1, Cursor::new(compressed.as_slice()));
    let (left, right) = tokio::join!(left, right);
    let mut left = left?;
    let mut right = right?;
    let mut left_bytes = Vec::new();
    let mut right_bytes = Vec::new();
    let (left_result, right_result) = tokio::join!(
        left.read_to_end(&mut left_bytes),
        right.read_to_end(&mut right_bytes)
    );
    left_result?;
    right_result?;

    assert_eq!(left_bytes, b"left");
    assert_eq!(right_bytes, b"right");
    Ok(())
}

#[tokio::test]
async fn empty_chapters_and_flushes_preserve_boundaries() -> TestResult {
    let mut writer = ChapteredGzipWriter::new(Vec::new(), Compression::default());
    writer.start_chapter().await?;
    writer.start_chapter().await?;
    writer.write_all(b"content").await?;
    writer.flush().await?;
    writer.start_chapter().await?;
    let compressed = writer.finish().await?;

    let mut archive = ChapteredGzipReader::open(Cursor::new(compressed)).await?;
    assert_eq!(archive.chapter_count(), 3);
    for (index, expected) in [(0, ""), (1, "content"), (2, "")] {
        let mut chapter = archive.read_chapter(index).await?;
        let mut decoded = String::new();
        chapter.read_to_string(&mut decoded).await?;
        assert_eq!(decoded, expected);
    }
    Ok(())
}

#[tokio::test]
async fn an_empty_stream_is_a_valid_single_chapter() -> io::Result<()> {
    let compressed = ChapteredGzipWriter::new(Vec::new(), Compression::default())
        .finish()
        .await?;

    let mut archive = ChapteredGzipReader::open(Cursor::new(compressed)).await?;
    assert_eq!(archive.chapter_count(), 1);
    let mut chapter = archive.read_chapter(0).await?;
    let mut decoded = Vec::new();
    chapter.read_to_end(&mut decoded).await?;
    assert!(decoded.is_empty());
    Ok(())
}

#[tokio::test]
async fn handles_partial_writes_and_pending_output() -> TestResult {
    let mut writer = ChapteredGzipWriter::new(ThrottledWriter::default(), Compression::fast());
    let first = vec![b'a'; 128 * 1024];
    writer.write_all(&first).await?;
    writer.start_chapter().await?;
    writer.write_all(b"second").await?;
    let compressed = writer.finish().await?.bytes;

    let mut archive = ChapteredGzipReader::open(Cursor::new(compressed)).await?;
    assert_eq!(archive.chapter_count(), 2);

    let mut decoded = Vec::new();
    archive
        .read_chapter(0)
        .await?
        .read_to_end(&mut decoded)
        .await?;
    assert_eq!(decoded, first);
    Ok(())
}

#[derive(Default)]
struct ThrottledWriter {
    bytes: Vec<u8>,
    pending: bool,
}

impl AsyncWrite for ThrottledWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending {
            self.pending = true;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }

        self.pending = false;
        let length = bytes.len().min(7);
        self.bytes.extend_from_slice(&bytes[..length]);
        Poll::Ready(Ok(length))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
