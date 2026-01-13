use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

fn parent_name(parent: &Bound<'_, PyModule>) -> PyResult<String> {
    parent.getattr("__name__")?.extract::<String>()
}

pub fn new_submodule<'py>(
    py: Python<'py>,
    parent: &Bound<'py, PyModule>,
    name: &str,
) -> PyResult<Bound<'py, PyModule>> {
    let full_name = format!("{}.{}", parent_name(parent)?, name);
    PyModule::new_bound(py, &full_name)
}

pub fn add_submodule<'py>(
    py: Python<'py>,
    parent: &Bound<'py, PyModule>,
    name: &str,
    module: &Bound<'py, PyModule>,
) -> PyResult<()> {
    parent.add_submodule(module)?;
    parent.setattr(name, module)?;
    let parent_name = parent_name(parent)?;
    let full_name = format!("{}.{}", parent_name, name);
    let sys = py.import_bound("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item(full_name, module)?;
    if let Some(root) = parent_name.split('.').next() {
        let alias_parent = if parent_name == root {
            None
        } else {
            let root_prefix = format!("{root}.opaque_ke");
            if let Some(stripped) = parent_name.strip_prefix(&root_prefix) {
                if stripped.is_empty() {
                    Some(root.to_string())
                } else {
                    Some(format!("{root}{stripped}"))
                }
            } else {
                None
            }
        };
        if let Some(alias_parent) = alias_parent {
            let alias_full = format!("{alias_parent}.{name}");
            modules.set_item(&alias_full, module)?;
            if let Ok(alias_parent_module) = modules.get_item(&alias_parent) {
                let _ = alias_parent_module.setattr(name, module);
            }
        }
    }
    Ok(())
}

pub fn to_pybytes(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new_bound(py, data).into()
}
