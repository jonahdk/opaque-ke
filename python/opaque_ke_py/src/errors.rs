use pyo3::prelude::*;

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "errors")?;
    parent.add_submodule(module)?;
    Ok(())
}
