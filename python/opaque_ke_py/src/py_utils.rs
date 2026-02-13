use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::invalid_state_err;
use crate::suite::SuiteId;

fn parent_name(parent: &Bound<'_, PyModule>) -> PyResult<String> {
    parent.getattr("__name__")?.extract::<String>()
}

pub fn ensure_suite(expected: SuiteId, actual: SuiteId, label: &str) -> PyResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_state_err(&format!(
            "{label} does not match requested cipher suite"
        )))
    }
}

macro_rules! per_suite_dispatch {
    (
        suite = $suite:expr,
        py = $py:expr,
        rng = $rng:expr,
        password = $password:expr,
        start = $start:ident,
        state_type = $state_ty:ident,
        state_inner = $state_inner_ty:ident,
        [ $( ($suite_id:path, $suite_ty:ty, $state_variant:ident) ),+ $(,)? ]
    ) => {
        match $suite {
            $(
                $suite_id => {
                    let result = $start::<$suite_ty>::start(&mut $rng, &$password)
                        .map_err(crate::errors::to_py_err)?;
                    let message = result.message.serialize().to_vec();
                    Ok((
                        crate::py_utils::to_pybytes($py, &message),
                        $state_ty {
                            inner: $state_inner_ty::$state_variant(Some(result.state)),
                        },
                    ))
                }
            )+
        }
    };
}

pub(crate) use per_suite_dispatch;

pub fn new_submodule<'py>(
    py: Python<'py>,
    parent: &Bound<'py, PyModule>,
    name: &str,
) -> PyResult<Bound<'py, PyModule>> {
    let full_name = format!("{}.{}", parent_name(parent)?, name);
    PyModule::new(py, &full_name)
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
    let sys = py.import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item(full_name, module)?;
    let root = parent_name.split('.').next().unwrap();
    // Propagate aliases which omit the intermediate `opaque_ke` path segment so
    // imports like `opaque_ke_py.types` resolve to modules registered under
    // `opaque_ke_py.opaque_ke.*`.
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
    Ok(())
}

pub fn to_pybytes(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, data).into()
}
