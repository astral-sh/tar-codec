//! Cancellation-aware ownership of spawned tasks.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::{JoinError, JoinHandle};

/// Aborts a spawned task when its owning operation is dropped.
pub(crate) struct PendingTask<T>(pub(crate) JoinHandle<T>);

impl<T> Future for PendingTask<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().0).poll(context)
    }
}

impl<T> Drop for PendingTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
