use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::errors::serialization_err;

#[pyfunction]
fn encode_b64(data: Vec<u8>) -> PyResult<String> {
    Ok(STANDARD.encode(data))
}

#[pyfunction]
fn decode_b64(text: &str) -> PyResult<Vec<u8>> {
    STANDARD
        .decode(text)
        .map_err(|err| serialization_err(&err.to_string()))
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(py, "encoding")?;
    module.add_function(wrap_pyfunction!(encode_b64, &module)?)?;
    module.add_function(wrap_pyfunction!(decode_b64, &module)?)?;
    parent.add_submodule(&module)?;
    Ok(())
}
