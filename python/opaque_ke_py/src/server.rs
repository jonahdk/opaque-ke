use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::to_py_err;
use crate::py_utils;
use crate::suite::{SUITE_NAME, Suite};
use crate::types::{
    ServerLoginParameters as PyServerLoginParameters, ServerLoginState,
    ServerRegistration as PyServerRegistration, ServerSetup,
};

#[pyclass(unsendable)]
pub struct OpaqueServer {
    _suite: String,
}

impl OpaqueServer {
    fn validate_suite(suite: Option<&str>) -> PyResult<String> {
        let normalized = suite.unwrap_or(SUITE_NAME).to_ascii_lowercase();
        if normalized != SUITE_NAME {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "unsupported cipher suite '{normalized}'"
            )));
        }
        Ok(normalized)
    }
}

#[pymethods]
impl OpaqueServer {
    #[new]
    fn new(suite: Option<&str>) -> PyResult<Self> {
        Ok(Self {
            _suite: Self::validate_suite(suite)?,
        })
    }

    fn start_registration(
        &self,
        py: Python<'_>,
        server_setup: PyRef<'_, ServerSetup>,
        request: Vec<u8>,
        credential_identifier: Vec<u8>,
    ) -> PyResult<Py<PyBytes>> {
        let request = RegistrationRequest::<Suite>::deserialize(&request).map_err(to_py_err)?;
        let result = ServerRegistration::<Suite>::start(
            &server_setup.inner,
            request,
            &credential_identifier,
        )
        .map_err(to_py_err)?;
        let message = result.message.serialize().to_vec();
        Ok(py_utils::to_pybytes(py, &message))
    }

    fn finish_registration(&self, upload: Vec<u8>) -> PyResult<PyServerRegistration> {
        let upload = RegistrationUpload::<Suite>::deserialize(&upload).map_err(to_py_err)?;
        Ok(PyServerRegistration {
            inner: ServerRegistration::<Suite>::finish(upload),
        })
    }

    fn start_login(
        &self,
        py: Python<'_>,
        server_setup: PyRef<'_, ServerSetup>,
        password_file: PyRef<'_, PyServerRegistration>,
        request: Vec<u8>,
        credential_identifier: Vec<u8>,
        params: Option<PyRef<'_, PyServerLoginParameters>>,
    ) -> PyResult<(Py<PyBytes>, ServerLoginState)> {
        let request = CredentialRequest::<Suite>::deserialize(&request).map_err(to_py_err)?;
        let mut rng = OsRng;
        let identifiers = params
            .as_ref()
            .and_then(|params| params.identifiers().cloned());
        let opaque_identifiers = identifiers
            .as_ref()
            .map(|ids| ids.as_opaque())
            .unwrap_or_default();
        let context = params
            .as_ref()
            .and_then(|params| params.context().map(|value| value.to_vec()));
        let parameters = if params.is_some() {
            ServerLoginParameters {
                context: context.as_deref(),
                identifiers: opaque_identifiers,
            }
        } else {
            ServerLoginParameters::default()
        };
        let result = ServerLogin::<Suite>::start(
            &mut rng,
            &server_setup.inner,
            Some(password_file.inner.clone()),
            request,
            &credential_identifier,
            parameters,
        )
        .map_err(to_py_err)?;
        let message = result.message.serialize().to_vec();
        Ok((
            py_utils::to_pybytes(py, &message),
            ServerLoginState {
                inner: Some(result.state),
            },
        ))
    }

    fn finish_login(
        &self,
        py: Python<'_>,
        mut state: PyRefMut<'_, ServerLoginState>,
        finalization: Vec<u8>,
        params: Option<PyRef<'_, PyServerLoginParameters>>,
    ) -> PyResult<Py<PyBytes>> {
        let state = state.take()?;
        let finalization =
            CredentialFinalization::<Suite>::deserialize(&finalization).map_err(to_py_err)?;
        let identifiers = params
            .as_ref()
            .and_then(|params| params.identifiers().cloned());
        let opaque_identifiers = identifiers
            .as_ref()
            .map(|ids| ids.as_opaque())
            .unwrap_or_default();
        let context = params
            .as_ref()
            .and_then(|params| params.context().map(|value| value.to_vec()));
        let parameters = if params.is_some() {
            ServerLoginParameters {
                context: context.as_deref(),
                identifiers: opaque_identifiers,
            }
        } else {
            ServerLoginParameters::default()
        };
        let result = state.finish(finalization, parameters).map_err(to_py_err)?;
        let session_key = result.session_key.to_vec();
        Ok(py_utils::to_pybytes(py, &session_key))
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "server")?;
    module.add_class::<OpaqueServer>()?;
    py_utils::add_submodule(py, parent, "server", &module)?;
    Ok(())
}
