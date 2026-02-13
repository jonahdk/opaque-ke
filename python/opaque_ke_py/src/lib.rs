#![allow(unsafe_op_in_unsafe_fn)]

use pyo3::prelude::*;
use pyo3::types::PyList;

mod ciphersuites;
mod client;
mod encoding;
mod errors;
mod login;
mod py_utils;
mod registration;
mod server;
mod suite;
mod types;

#[pymodule]
fn opaque_ke(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Mark as a package so Python can resolve submodules like opaque_ke.client.
    m.add("__path__", PyList::empty_bound(py))?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    ciphersuites::register(py, m)?;
    registration::register(py, m)?;
    login::register(py, m)?;
    types::register(py, m)?;
    errors::register(py, m)?;
    encoding::register(py, m)?;
    client::register(py, m)?;
    server::register(py, m)?;
    Ok(())
}
