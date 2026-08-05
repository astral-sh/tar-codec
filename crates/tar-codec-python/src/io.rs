//! Python binary-stream adapters.

use std::{
    cell::RefCell,
    error::Error,
    io::{self, Cursor},
    marker::PhantomData,
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

use pyo3::{
    IntoPyObjectExt,
    buffer::PyBuffer,
    exceptions::{PyAttributeError, PyOverflowError, PyTypeError, PyValueError},
    intern,
    prelude::*,
    pybacked::PyBackedBytes,
    sync::critical_section::with_critical_section,
    types::{PyByteArray, PyBytes, PyMemoryView, PyModule, PySlice, PyString},
};
use tar_framing::BLOCK_SIZE;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Maximum Python stream read size.
pub(crate) const MAX_PYTHON_STREAM_READ_BYTES: usize = 4 * 1024 * 1024;
/// Maximum Python stream write size.
const MAX_PYTHON_STREAM_WRITE_BYTES: usize = 1024 * 1024;
/// Maximum in-memory Python write size.
#[cfg(target_os = "macos")]
const MAX_PYTHON_MEMORY_WRITE_BYTES: usize = usize::MAX;
#[cfg(not(target_os = "macos"))]
const MAX_PYTHON_MEMORY_WRITE_BYTES: usize = MAX_PYTHON_STREAM_WRITE_BYTES;

thread_local! {
    static PYTHON_WRITE_SOURCES: RefCell<Vec<PyBackedBytes>> = const {
        RefCell::new(Vec::new())
    };
}

/// Whether a Python input supplies an archive or a member payload.
pub(crate) enum InputPurpose {
    /// Preserve zero-copy access to a complete in-memory archive.
    Archive,
    /// Stream only the requested bytes from a member payload.
    Payload,
}

/// An archive or payload input.
pub(crate) enum Input {
    /// In-memory bytes and an optional source stream.
    Memory(MemoryInput),
    /// A filesystem path.
    Path(PathBuf),
    /// A Python binary stream.
    Stream(Arc<Py<PyAny>>),
}

/// An in-memory archive or payload input.
pub(crate) struct MemoryInput {
    pub(crate) bytes: PyBackedBytes,
    pub(crate) stream: Option<Arc<Py<PyAny>>>,
    pub(crate) position: usize,
}

/// An asynchronous archive reader.
pub(crate) enum Reader {
    /// An in-memory source.
    Memory(InMemoryReader),
    /// A filesystem source.
    File(tokio::fs::File),
    /// A Python binary stream.
    Stream(StreamReader),
}

/// An in-memory archive reader.
pub(crate) struct InMemoryReader {
    bytes: Cursor<PyBackedBytes>,
    stream: Option<Arc<Py<PyAny>>>,
}

/// A Python binary-stream reader.
pub(crate) struct StreamReader {
    source: Arc<Py<PyAny>>,
    /// Probe lazily so builder validation precedes Python stream callbacks.
    readinto: Option<bool>,
    block: Option<PythonReadBuffer>,
    buffer: Option<PythonReadBuffer>,
}

/// A reusable Python read buffer.
struct PythonReadBuffer {
    bytes: Py<PyByteArray>,
    export: PyBuffer<u8>,
}

/// An archive destination.
pub(crate) enum OutputTarget {
    /// A filesystem path.
    Path(PathBuf),
    /// A Python binary stream.
    Stream(PythonWriter),
}

/// A Python binary-stream writer.
pub(crate) struct PythonWriter {
    /// The output stream.
    pub(crate) sink: Arc<Py<PyAny>>,
    /// The maximum bytes written per callback.
    max_write_bytes: usize,
}

/// An asynchronous archive writer.
pub(crate) enum Output {
    /// A filesystem destination.
    File(tokio::fs::File),
    /// A Python binary stream.
    Stream(PythonWriter),
}

/// A Python payload retained during writing.
pub(crate) struct PythonWriteSource(PhantomData<Rc<()>>);

impl PythonWriteSource {
    /// Retains a Python payload for the current thread.
    pub(crate) fn new(py: Python<'_>, source: &PyBackedBytes) -> Self {
        PYTHON_WRITE_SOURCES.with(|sources| sources.borrow_mut().push(source.clone_ref(py)));
        Self(PhantomData)
    }
}

impl Drop for PythonWriteSource {
    fn drop(&mut self) {
        PYTHON_WRITE_SOURCES.with(|sources| {
            let _ = sources.borrow_mut().pop();
        });
    }
}

/// Converts a Python buffer to immutable bytes.
pub(crate) fn parse_bytes(source: &Bound<'_, PyAny>) -> PyResult<Option<PyBackedBytes>> {
    if let Ok(bytes) = source.cast::<PyBytes>() {
        return Ok(Some(bytes.clone().into()));
    }

    if source.is_instance_of::<PyByteArray>() {
        let buffer = PyBuffer::<u8>::get(source)?;
        let bytes = PyBytes::new_with(source.py(), buffer.item_count(), |bytes| {
            with_critical_section(source, || buffer.copy_to_slice(source.py(), bytes))
        })?;
        return Ok(Some(bytes.into()));
    }

    if source.is_instance_of::<PyMemoryView>() {
        // Reuse immutable bytes without copying only when the view spans the
        // entire contiguous backing: read-only views can alias mutable storage,
        // and slices or strides can change the represented archive.
        let backing = source.getattr(intern!(source.py(), "obj"))?;
        if let Ok(bytes) = backing.cast::<PyBytes>()
            && source
                .getattr(intern!(source.py(), "c_contiguous"))?
                .extract::<bool>()?
            && source
                .getattr(intern!(source.py(), "nbytes"))?
                .extract::<usize>()?
                == bytes.as_bytes().len()
        {
            return Ok(Some(bytes.clone().into()));
        }

        let bytes = source
            .call_method0(intern!(source.py(), "tobytes"))?
            .cast_into::<PyBytes>()?;
        return Ok(Some(bytes.into()));
    }

    Ok(None)
}

/// Parses an archive or payload input.
pub(crate) fn parse_input(
    py: Python<'_>,
    source: &Bound<'_, PyAny>,
    purpose: InputPurpose,
) -> PyResult<Input> {
    if let Some(bytes) = parse_bytes(source)? {
        return Ok(Input::Memory(MemoryInput {
            bytes,
            stream: None,
            position: 0,
        }));
    }

    if source.is_instance_of::<PyString>() || source.hasattr(intern!(py, "__fspath__"))? {
        return source.extract::<PathBuf>().map(Input::Path);
    }

    if source.is_exact_instance(&PyModule::import(py, "_io")?.getattr(intern!(py, "BytesIO"))?) {
        return match purpose {
            InputPurpose::Archive => Ok(Input::Memory(MemoryInput {
                bytes: source
                    .call_method0(intern!(py, "getvalue"))?
                    .cast_into::<PyBytes>()?
                    .into(),
                stream: Some(Arc::new(source.clone().unbind())),
                position: source
                    .call_method0(intern!(py, "tell"))?
                    .extract::<usize>()?,
            })),
            InputPurpose::Payload => Ok(Input::Stream(Arc::new(source.clone().unbind()))),
        };
    }

    match source.getattr(intern!(py, "read")) {
        Ok(read) if read.is_callable() => Ok(Input::Stream(Arc::new(source.clone().unbind()))),
        Ok(_) => Err(PyTypeError::new_err(
            "a binary input stream's read attribute must be callable",
        )),
        Err(error) if error.is_instance_of::<PyAttributeError>(py) => Err(PyTypeError::new_err(
            "expected bytes, bytearray, memoryview, a filesystem path, or a binary stream with read(size)",
        )),
        Err(error) => Err(error),
    }
}

/// Parses an archive destination.
pub(crate) fn parse_output(py: Python<'_>, sink: &Bound<'_, PyAny>) -> PyResult<OutputTarget> {
    if sink.is_instance_of::<PyString>() || sink.hasattr(intern!(py, "__fspath__"))? {
        return sink.extract::<PathBuf>().map(OutputTarget::Path);
    }

    match sink.getattr(intern!(py, "write")) {
        Ok(write) if write.is_callable() => Ok(OutputTarget::Stream(PythonWriter {
            max_write_bytes: if sink
                .is_exact_instance(&PyModule::import(py, "_io")?.getattr(intern!(py, "BytesIO"))?)
            {
                MAX_PYTHON_MEMORY_WRITE_BYTES
            } else {
                MAX_PYTHON_STREAM_WRITE_BYTES
            },
            sink: Arc::new(sink.clone().unbind()),
        })),
        Ok(_) => Err(PyTypeError::new_err(
            "a binary output stream's write attribute must be callable",
        )),
        Err(error) if error.is_instance_of::<PyAttributeError>(py) => Err(PyTypeError::new_err(
            "expected a filesystem path or a binary stream with write(data)",
        )),
        Err(error) => Err(error),
    }
}

impl Input {
    /// Opens the archive input.
    pub(crate) async fn into_reader(self) -> io::Result<Reader> {
        match self {
            Self::Memory(input) => {
                let mut bytes = Cursor::new(input.bytes);
                bytes.set_position(input.position as u64);
                Ok(Reader::Memory(InMemoryReader {
                    bytes,
                    stream: input.stream,
                }))
            }
            Self::Path(path) => tokio::fs::File::open(path).await.map(Reader::File),
            Self::Stream(source) => Ok(Reader::Stream(StreamReader {
                source,
                readinto: None,
                block: None,
                buffer: None,
            })),
        }
    }
}

impl OutputTarget {
    /// Opens the archive destination.
    pub(crate) async fn into_output(self) -> io::Result<Output> {
        match self {
            Self::Path(path) => tokio::fs::File::create(path).await.map(Output::File),
            Self::Stream(sink) => Ok(Output::Stream(sink)),
        }
    }
}

/// Wraps a Python callback exception as an I/O error.
pub(crate) fn python_io_error(error: PyErr) -> io::Error {
    io::Error::other(error)
}

/// Recovers a Python callback exception from an error chain.
pub(crate) fn original_python_error(error: &(dyn Error + 'static)) -> Option<PyErr> {
    let mut current = Some(error);

    while let Some(source) = current {
        if let Some(error) = source.downcast_ref::<PyErr>() {
            return Some(Python::attach(|py| error.clone_ref(py)));
        }

        if let Some(error) = source.downcast_ref::<io::Error>()
            && let Some(inner) = error.get_ref()
            && let Some(original) = original_python_error(inner)
        {
            return Some(original);
        }

        current = source.source();
    }

    None
}

/// Converts an I/O error to its original Python exception or `OSError`.
pub(crate) fn into_python_io_error(error: io::Error) -> PyErr {
    original_python_error(&error).unwrap_or_else(|| PyErr::from(error))
}

fn poll_python<T>(operation: impl FnOnce(Python<'_>) -> PyResult<T>) -> Poll<io::Result<T>> {
    Poll::Ready(Python::attach(operation).map_err(python_io_error))
}

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Memory(reader) => Pin::new(reader).poll_read(context, buffer),
            Self::File(reader) => Pin::new(reader).poll_read(context, buffer),
            Self::Stream(source) => poll_python_read(source, buffer),
        }
    }
}

impl Reader {
    /// Skips an in-memory payload without copying it.
    pub(crate) fn discard(&mut self, buffer: &mut ReadBuf<'_>) -> Option<io::Result<()>> {
        match self {
            Self::Memory(reader) => Some(reader.discard(buffer)),
            Self::File(_) | Self::Stream(_) => None,
        }
    }
}

impl InMemoryReader {
    fn discard(&mut self, buffer: &mut ReadBuf<'_>) -> io::Result<()> {
        let previous = self.bytes.position();
        let position = usize::try_from(previous).unwrap_or(usize::MAX);
        let read = self
            .bytes
            .get_ref()
            .len()
            .saturating_sub(position)
            .min(buffer.remaining());
        buffer.initialize_unfilled_to(read);
        buffer.advance(read);
        self.bytes
            .set_position(previous.saturating_add(read as u64));

        if read == 0 {
            Ok(())
        } else {
            self.sync_position()
        }
    }

    fn sync_position(&self) -> io::Result<()> {
        let Some(stream) = &self.stream else {
            return Ok(());
        };

        Python::attach(|py| {
            stream
                .bind(py)
                .call_method1(intern!(py, "seek"), (self.bytes.position(),))
                .map(drop)
                .map_err(python_io_error)
        })
    }
}

impl AsyncRead for InMemoryReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let position = self.bytes.position();
        match Pin::new(&mut self.bytes).poll_read(context, buffer) {
            Poll::Ready(Ok(())) if self.bytes.position() != position => {
                Poll::Ready(self.sync_position())
            }
            result => result,
        }
    }
}

fn poll_python_read(source: &mut StreamReader, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
    let remaining = buffer.remaining().min(MAX_PYTHON_STREAM_READ_BYTES);
    if remaining == 0 {
        return Poll::Ready(Ok(()));
    }

    poll_python(|py| {
        let readinto = match source.readinto {
            Some(readinto) => readinto,
            None => {
                let readinto = match source.source.bind(py).getattr(intern!(py, "readinto")) {
                    Ok(callback) => callback.is_callable(),
                    Err(error) if error.is_instance_of::<PyAttributeError>(py) => false,
                    Err(error) => return Err(error),
                };
                source.readinto = Some(readinto);
                readinto
            }
        };

        if readinto {
            let (slot, capacity) = if remaining <= BLOCK_SIZE {
                (&mut source.block, BLOCK_SIZE)
            } else {
                (&mut source.buffer, remaining)
            };
            let scratch = match slot.take() {
                Some(scratch) if scratch.bytes.bind(py).len() >= remaining => scratch,
                Some(_) | None => {
                    let bytes = PyByteArray::new_with(py, capacity, |_| Ok(()))?;
                    let export = PyBuffer::<u8>::get(bytes.as_any())?;
                    PythonReadBuffer {
                        bytes: bytes.unbind(),
                        export,
                    }
                }
            };
            let scratch = slot.insert(scratch);
            let bytes = scratch.bytes.bind(py);

            let destination = if bytes.len() == remaining {
                bytes.clone().into_any()
            } else {
                let end = isize::try_from(remaining).map_err(|_| {
                    PyOverflowError::new_err("the requested read size does not fit in memory")
                })?;
                PyMemoryView::from(bytes.as_any())?.get_item(PySlice::new(py, 0, end, 1))?
            };
            let written = source
                .source
                .bind(py)
                .call_method1(intern!(py, "readinto"), (destination,))?
                .extract()?;

            if written > remaining {
                return Err(PyValueError::new_err(
                    "a binary stream's readinto(buffer) returned more than the supplied size",
                ));
            }

            if written == scratch.export.item_count() {
                with_critical_section(bytes.as_any(), || {
                    scratch
                        .export
                        .copy_to_slice(py, buffer.initialize_unfilled_to(written))
                })?;
            } else {
                let end = isize::try_from(written).map_err(|_| {
                    PyOverflowError::new_err("the completed read size does not fit in memory")
                })?;
                let prefix =
                    PyMemoryView::from(bytes.as_any())?.get_item(PySlice::new(py, 0, end, 1))?;
                let export = PyBuffer::<u8>::get(&prefix)?;
                with_critical_section(bytes.as_any(), || {
                    export.copy_to_slice(py, buffer.initialize_unfilled_to(written))
                })?;
            }
            buffer.advance(written);
            return Ok(());
        }

        let result = source
            .source
            .bind(py)
            .call_method1(intern!(py, "read"), (remaining,))?;

        if let Ok(bytes) = result.cast::<PyBytes>() {
            return put_python_bytes(buffer, bytes.as_bytes(), remaining);
        }

        if result.is_instance_of::<PyByteArray>() || result.is_instance_of::<PyMemoryView>() {
            let source = match PyBuffer::<u8>::get(&result) {
                Ok(source) => source,
                Err(_) if result.is_instance_of::<PyMemoryView>() => {
                    let bytes = result
                        .call_method0(intern!(py, "tobytes"))?
                        .cast_into::<PyBytes>()?;
                    return put_python_bytes(buffer, bytes.as_bytes(), remaining);
                }
                Err(error) => return Err(error),
            };
            let read = source.item_count();

            if read > remaining {
                return Err(PyValueError::new_err(
                    "a binary stream's read(size) returned more than the requested size",
                ));
            }

            with_critical_section(&result, || {
                source.copy_to_slice(py, buffer.initialize_unfilled_to(read))
            })?;
            buffer.advance(read);
            return Ok(());
        }

        Err(PyTypeError::new_err(
            "a binary stream's read(size) must return bytes",
        ))
    })
}

fn put_python_bytes(buffer: &mut ReadBuf<'_>, bytes: &[u8], requested: usize) -> PyResult<()> {
    if bytes.len() > requested {
        return Err(PyValueError::new_err(
            "a binary stream's read(size) returned more than the requested size",
        ));
    }

    buffer.put_slice(bytes);
    Ok(())
}

impl AsyncWrite for Output {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::File(file) => Pin::new(file).poll_write(context, buffer),
            Self::Stream(sink) => poll_python_write(sink, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::File(file) => Pin::new(file).poll_flush(context),
            Self::Stream(writer) => poll_python_flush(writer.sink.as_ref()),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::File(file) => Pin::new(file).poll_shutdown(context),
            Self::Stream(writer) => poll_python_flush(writer.sink.as_ref()),
        }
    }
}

fn poll_python_write(writer: &PythonWriter, buffer: &[u8]) -> Poll<io::Result<usize>> {
    if buffer.is_empty() {
        return Poll::Ready(Ok(0));
    }
    let buffer = &buffer[..buffer.len().min(writer.max_write_bytes)];

    poll_python(|py| {
        let bytes = python_write_buffer(py, buffer)?;
        let written = writer
            .sink
            .bind(py)
            .call_method1(intern!(py, "write"), (bytes,))?
            .extract::<usize>()?;

        if written > buffer.len() {
            return Err(PyValueError::new_err(
                "a binary stream's write(data) returned more than the supplied size",
            ));
        }

        Ok(written)
    })
}

/// Returns a Python buffer for an archive write.
fn python_write_buffer<'py>(py: Python<'py>, buffer: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    PYTHON_WRITE_SOURCES.with(|sources| {
        let sources = sources.borrow();
        if let Some(source) = sources.last()
            && let Some(start) =
                (buffer.as_ptr() as usize).checked_sub(source.as_ref().as_ptr() as usize)
            && let Some(end) = start.checked_add(buffer.len())
            && end <= source.len()
        {
            let bytes = source.into_bound_py_any(py)?;
            if start == 0 && end == source.len() {
                return Ok(bytes);
            }
            if let Ok(start) = isize::try_from(start)
                && let Ok(end) = isize::try_from(end)
            {
                return PyMemoryView::from(&bytes)?.get_item(PySlice::new(py, start, end, 1));
            }
        }

        Ok(PyBytes::new(py, buffer).into_any())
    })
}

fn poll_python_flush(sink: &Py<PyAny>) -> Poll<io::Result<()>> {
    poll_python(|py| match sink.bind(py).getattr(intern!(py, "flush")) {
        Ok(flush) => flush.call0().map(drop),
        Err(error) if error.is_instance_of::<PyAttributeError>(py) => Ok(()),
        Err(error) => Err(error),
    })
}
