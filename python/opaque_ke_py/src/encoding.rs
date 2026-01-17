use base64::Engine;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD, URL_SAFE_NO_PAD};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::serialization_err;
use crate::py_utils;

#[pyfunction]
fn encode_b64(data: Vec<u8>) -> PyResult<String> {
    Ok(URL_SAFE_NO_PAD.encode(data))
}

#[pyfunction]
fn decode_b64(py: Python<'_>, text: &str) -> PyResult<Py<PyBytes>> {
    let text = text.trim();
    let config = GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let urlsafe = GeneralPurpose::new(&alphabet::URL_SAFE, config);
    let standard = GeneralPurpose::new(&alphabet::STANDARD, config);
    let decoded = urlsafe
        .decode(text)
        .or_else(|_| standard.decode(text))
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
