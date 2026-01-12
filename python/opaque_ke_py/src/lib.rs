use pyo3::prelude::*;

mod ciphersuites;
mod client;
mod encoding;
mod errors;
mod login;
mod registration;
mod server;
mod types;

#[pymodule]
fn opaque_ke(py: Python<'_>, m: &PyModule) -> PyResult<()> {
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
