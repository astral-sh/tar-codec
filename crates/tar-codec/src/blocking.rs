use tokio::task::JoinError;

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
