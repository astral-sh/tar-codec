//! Filesystem backends for archive extraction.

use std::{
    fs::File,
    io::{self, Write as _},
    mem,
    path::Path,
    sync::Arc,
};

use tokio::task::{JoinError, JoinHandle};

use crate::{ExtractError, MemberPayload};

// Balance reusable-buffer initialization against blocking write cadence.
const STREAMING_PAYLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;
// Bound direct source-backed writes without introducing a copied staging buffer.
const DIRECT_PAYLOAD_WRITE_BYTES: usize = 256 * 1024;

/// Executes filesystem operations during extraction.
pub(super) trait FilesystemIo {
    /// Runs a filesystem operation.
    async fn run<T, F>(operation: F) -> Result<T, JoinError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static;

    /// Writes a file's payload.
    async fn write_payload<P: MemberPayload>(
        payload: P,
        buffer: &mut Vec<u8>,
        path: &Path,
        file: File,
    ) -> Result<(), ExtractError<P::Error>>;
}

/// Runs filesystem operations on a blocking pool.
pub(super) struct BlockingPool;

impl FilesystemIo for BlockingPool {
    async fn run<T, F>(operation: F) -> Result<T, JoinError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        tokio::task::spawn_blocking(operation).await
    }

    async fn write_payload<P: MemberPayload>(
        mut payload: P,
        buffer: &mut Vec<u8>,
        path: &Path,
        file: File,
    ) -> Result<(), ExtractError<P::Error>> {
        let file = Arc::new(file);
        let mut pending = None::<JoinHandle<io::Result<Vec<u8>>>>;
        let mut reusable = Vec::new();

        loop {
            let next = payload
                .next_chunk(buffer, STREAMING_PAYLOAD_CHUNK_BYTES)
                .await;
            if let Some(task) = pending.take() {
                reusable = task
                    .await
                    .map_err(ExtractError::BlockingTask)?
                    .map_err(|source| {
                        ExtractError::filesystem("write file", path.to_owned(), source)
                    })?;
            }
            if !next.map_err(ExtractError::Archive)? {
                break;
            }

            let replacement_len = buffer.len();
            let chunk = mem::take(buffer);
            let file = Arc::clone(&file);
            pending = Some(tokio::task::spawn_blocking(move || {
                (&*file).write_all(&chunk)?;
                Ok(chunk)
            }));
            if reusable.is_empty() {
                reusable.resize(replacement_len, 0);
            }
            *buffer = mem::take(&mut reusable);
        }

        Ok(())
    }
}

/// Runs filesystem operations on the calling thread.
pub(super) struct Inline;

impl FilesystemIo for Inline {
    async fn run<T, F>(operation: F) -> Result<T, JoinError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        Ok(operation())
    }

    async fn write_payload<P: MemberPayload>(
        mut payload: P,
        buffer: &mut Vec<u8>,
        path: &Path,
        mut file: File,
    ) -> Result<(), ExtractError<P::Error>> {
        if let Some(contents) = payload.remaining_bytes() {
            for chunk in contents.chunks(DIRECT_PAYLOAD_WRITE_BYTES) {
                file.write_all(chunk).map_err(|source| {
                    ExtractError::filesystem("write file", path.to_owned(), source)
                })?;
            }
            return payload.skip().await.map_err(ExtractError::Archive);
        }

        while payload
            .next_chunk(buffer, STREAMING_PAYLOAD_CHUNK_BYTES)
            .await
            .map_err(ExtractError::Archive)?
        {
            file.write_all(buffer).map_err(|source| {
                ExtractError::filesystem("write file", path.to_owned(), source)
            })?;
        }

        Ok(())
    }
}
