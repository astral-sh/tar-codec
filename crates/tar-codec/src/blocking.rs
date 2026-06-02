//! Helpers for synchronous work that owns reusable payload buffers.
//!
//! Encoding and extraction use synchronous [`std::fs`] and [`cap_std::fs`]
//! operations in otherwise asynchronous APIs. Those operations run through
//! [`tokio::task::spawn_blocking`] so filesystem latency does not occupy a
//! Tokio async worker thread.
//!
//! Some of that work also reads or writes payload bytes using a buffer reused
//! across archive members. A blocking task requires owned `'static` state, so
//! callers cannot borrow their buffer into the task. This module centralizes
//! moving the buffer into the task and returning it with the operation result,
//! preserving its allocation after both success and ordinary operation errors.

use tokio::task::JoinError;

/// Runs one synchronous operation on Tokio's blocking pool and returns its buffer.
///
/// `buffer` is moved into the `'static` closure required by
/// [`tokio::task::spawn_blocking`], then returned alongside the operation
/// result. The helper does not clear or otherwise reset the buffer, allowing
/// each operation to decide which contents should remain available to its
/// caller.
///
/// If the blocking task cannot be joined, its moved buffer cannot be
/// recovered. In that case, this returns a new empty buffer and converts the
/// [`JoinError`] into `E`.
pub(crate) async fn with_reusable_buffer<T, E, F>(
    mut buffer: Vec<u8>,
    operation: F,
) -> (Vec<u8>, Result<T, E>)
where
    T: Send + 'static,
    E: From<JoinError> + Send + 'static,
    F: FnOnce(&mut Vec<u8>) -> Result<T, E> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let result = operation(&mut buffer);
        (buffer, result)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => (Vec::new(), Err(error.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Eq, PartialEq)]
    enum TestError {
        Operation,
        BlockingTask,
    }

    impl From<JoinError> for TestError {
        fn from(_: JoinError) -> Self {
            Self::BlockingTask
        }
    }

    #[tokio::test]
    async fn returns_reusable_buffer_after_success() {
        let mut buffer = Vec::with_capacity(64);
        buffer.extend_from_slice(b"old");
        let capacity = buffer.capacity();

        let (buffer, result) = with_reusable_buffer(buffer, |buffer| {
            buffer.clear();
            buffer.extend_from_slice(b"new");
            Ok::<_, TestError>(())
        })
        .await;

        assert_eq!(result, Ok(()));
        assert_eq!(buffer, b"new");
        assert_eq!(buffer.capacity(), capacity);
    }

    #[tokio::test]
    async fn returns_reusable_buffer_after_operation_error() {
        let mut buffer = Vec::with_capacity(64);
        buffer.extend_from_slice(b"old");
        let capacity = buffer.capacity();

        let (buffer, result) = with_reusable_buffer(buffer, |buffer| {
            buffer.clear();
            buffer.extend_from_slice(b"new");
            Err::<(), _>(TestError::Operation)
        })
        .await;

        assert_eq!(result, Err(TestError::Operation));
        assert_eq!(buffer, b"new");
        assert_eq!(buffer.capacity(), capacity);
    }
}
