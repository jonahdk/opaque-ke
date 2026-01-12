use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::suite::SUITE_NAME;

#[pyfunction]
fn available() -> Vec<&'static str> {
    vec![SUITE_NAME]
}

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "ciphersuites")?;
    module.add("RISTRETTO255_SHA512", SUITE_NAME)?;
    module.add_function(wrap_pyfunction!(available, module)?)?;
    parent.add_submodule(module)?;
    Ok(())
}
