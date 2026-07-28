//! Synchronous execution of asynchronous archive operations.

use std::{
    io, process,
    sync::{Mutex, OnceLock},
};

use pyo3::{exceptions::PyRuntimeError, prelude::*};
use tokio::runtime::Runtime;

#[derive(Clone, Copy)]
struct ProcessRuntime {
    process_id: u32,
    runtime: &'static Runtime,
}

static RUNTIME: OnceLock<io::Result<Mutex<ProcessRuntime>>> = OnceLock::new();

fn build_runtime() -> io::Result<&'static Runtime> {
    // Never drop an inherited runtime after fork: its worker threads no longer exist.
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map(|runtime| &*Box::leak(Box::new(runtime)))
}

fn runtime() -> PyResult<ProcessRuntime> {
    let process_id = process::id();
    let runtime = RUNTIME
        .get_or_init(|| {
            build_runtime().map(|runtime| {
                Mutex::new(ProcessRuntime {
                    process_id,
                    runtime,
                })
            })
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))?;
    let mut runtime = runtime
        .lock()
        .map_err(|_| PyRuntimeError::new_err("the tar runtime registry is poisoned"))?;
    if runtime.process_id != process_id {
        *runtime = ProcessRuntime {
            process_id,
            runtime: build_runtime()?,
        };
    }
    Ok(*runtime)
}

/// A synchronized archive runtime.
pub(crate) struct Blocking<T> {
    runtime: ProcessRuntime,
    state: Mutex<T>,
}

impl<T: Send> Blocking<T> {
    /// Creates a synchronized archive runtime.
    pub(crate) fn new(state: T) -> PyResult<Self> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(PyRuntimeError::new_err(
                "a tar stream callback cannot re-enter an active tar operation",
            ));
        }

        Ok(Self {
            runtime: runtime()?,
            state: Mutex::new(state),
        })
    }

    /// Runs an operation without holding the Python interpreter lock.
    pub(crate) fn with<R, F>(&self, py: Python<'_>, operation: F) -> PyResult<R>
    where
        R: Send,
        F: FnOnce(&Runtime, &mut T) -> PyResult<R> + Send,
    {
        py.detach(move || {
            if tokio::runtime::Handle::try_current().is_ok() {
                return Err(PyRuntimeError::new_err(
                    "a tar stream callback cannot re-enter an active tar operation",
                ));
            }

            let runtime = if self.runtime.process_id == process::id() {
                self.runtime.runtime
            } else {
                runtime()?.runtime
            };
            self.state
                .lock()
                .map_err(|_| PyRuntimeError::new_err("the tar state is poisoned"))
                .and_then(|mut state| operation(runtime, &mut state))
        })
    }
}
