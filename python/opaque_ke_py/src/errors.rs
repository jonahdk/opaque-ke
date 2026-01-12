use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

pub(crate) fn to_py_err<E: std::fmt::Display>(err: E) -> PyErr {
    PyErr::new::<PyRuntimeError, _>(err.to_string())
}

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "errors")?;
    parent.add_submodule(module)?;
    Ok(())
}
