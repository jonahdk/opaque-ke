use pyo3::prelude::*;
use pyo3::types::PyModule;

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "encoding")?;
    parent.add_submodule(module)?;
    Ok(())
}
