use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::serialization_err;
use crate::py_utils;

#[pyfunction]
fn encode_b64(data: Vec<u8>) -> PyResult<String> {
    Ok(STANDARD.encode(data))
}

#[pyfunction]
fn decode_b64(py: Python<'_>, text: &str) -> PyResult<Py<PyBytes>> {
    let decoded = STANDARD
        .decode(text)
        .map_err(|err| serialization_err(&err.to_string()))?;
    Ok(PyBytes::new_bound(py, &decoded).into())
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "encoding")?;
    module.add_function(wrap_pyfunction!(encode_b64, &module)?)?;
    module.add_function(wrap_pyfunction!(decode_b64, &module)?)?;
    py_utils::add_submodule(py, parent, "encoding", &module)?;
    Ok(())
}
