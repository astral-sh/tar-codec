//! Python bindings for tar archives.

use pyo3::{create_exception, exceptions::PyRuntimeError, prelude::*};

mod codec;
mod io;
mod runtime;

create_exception!(tar_codec, DecodeError, pyo3::exceptions::PyException);
create_exception!(tar_codec, EncodeError, pyo3::exceptions::PyException);
create_exception!(tar_codec, BuildError, pyo3::exceptions::PyException);
create_exception!(tar_codec, ExtractError, pyo3::exceptions::PyException);
create_exception!(tar_codec, InvalidatedPayloadError, PyRuntimeError);

/// Registers the `tar_codec` Python module.
#[pymodule]
fn _tar_codec(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("DecodeError", py.get_type::<DecodeError>())?;
    module.add("EncodeError", py.get_type::<EncodeError>())?;
    module.add("BuildError", py.get_type::<BuildError>())?;
    module.add("ExtractError", py.get_type::<ExtractError>())?;
    module.add(
        "InvalidatedPayloadError",
        py.get_type::<InvalidatedPayloadError>(),
    )?;
    codec::register(module)?;
    Ok(())
}
