use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::py_utils;
use crate::suite::SUITE_NAME;

#[pyfunction]
fn available() -> Vec<&'static str> {
    vec![SUITE_NAME]
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "ciphersuites")?;
    module.add("RISTRETTO255_SHA512", SUITE_NAME)?;
    module.add_function(wrap_pyfunction!(available, &module)?)?;
    py_utils::add_submodule(py, parent, "ciphersuites", &module)?;
    Ok(())
}
