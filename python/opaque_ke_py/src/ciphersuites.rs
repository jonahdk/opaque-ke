use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::py_utils;
use crate::suite::{
    ML_KEM_768_RISTRETTO255_SHA512, P256_SHA256, P384_SHA384, P521_SHA512, RISTRETTO255_SHA512,
    SuiteId,
};

#[pyfunction]
fn available() -> Vec<&'static str> {
    SuiteId::available()
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "ciphersuites")?;
    module.add("RISTRETTO255_SHA512", RISTRETTO255_SHA512)?;
    module.add("P256_SHA256", P256_SHA256)?;
    module.add("P384_SHA384", P384_SHA384)?;
    module.add("P521_SHA512", P521_SHA512)?;
    module.add(
        "ML_KEM_768_RISTRETTO255_SHA512",
        ML_KEM_768_RISTRETTO255_SHA512,
    )?;
    module.add_function(wrap_pyfunction!(available, &module)?)?;
    py_utils::add_submodule(py, parent, "ciphersuites", &module)?;
    Ok(())
}
