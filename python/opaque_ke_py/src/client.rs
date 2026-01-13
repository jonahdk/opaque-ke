use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_login_err, to_py_err};
use crate::py_utils;
use crate::suite::{SUITE_NAME, Suite};
use crate::types::{
    ClientLoginFinishParameters as PyClientLoginFinishParameters, ClientLoginState,
    ClientRegistrationFinishParameters as PyClientRegistrationFinishParameters,
    ClientRegistrationState,
};

#[pyclass(unsendable)]
pub struct OpaqueClient {
    _suite: String,
}

impl OpaqueClient {
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
impl OpaqueClient {
    #[new]
    fn new(suite: Option<&str>) -> PyResult<Self> {
        Ok(Self {
            _suite: Self::validate_suite(suite)?,
        })
    }

    fn start_registration(
        &self,
        py: Python<'_>,
        password: Vec<u8>,
    ) -> PyResult<(Py<PyBytes>, ClientRegistrationState)> {
        let mut rng = OsRng;
        let result = ClientRegistration::<Suite>::start(&mut rng, &password).map_err(to_py_err)?;
        let message = result.message.serialize().to_vec();
        Ok((
            py_utils::to_pybytes(py, &message),
            ClientRegistrationState {
                inner: Some(result.state),
            },
        ))
    }

    fn finish_registration(
        &self,
        py: Python<'_>,
        mut state: PyRefMut<'_, ClientRegistrationState>,
        password: Vec<u8>,
        response: Vec<u8>,
        params: Option<PyRef<'_, PyClientRegistrationFinishParameters>>,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let state = state.take()?;
        let response = RegistrationResponse::<Suite>::deserialize(&response).map_err(to_py_err)?;
        let mut rng = OsRng;
        let identifiers = params
            .as_ref()
            .and_then(|params| params.identifiers().cloned());
        let opaque_identifiers = identifiers
            .as_ref()
            .map(|ids| ids.as_opaque())
            .unwrap_or_default();
        let ksf = params
            .as_ref()
            .and_then(|params| params.key_stretching())
            .map(|ksf| ksf.build_ksf())
            .transpose()?;
        let finish_params = if params.is_some() {
            ClientRegistrationFinishParameters::new(opaque_identifiers, ksf.as_ref())
        } else {
            ClientRegistrationFinishParameters::default()
        };
        let result = state
            .finish(&mut rng, &password, response, finish_params)
            .map_err(to_py_err)?;
        let message = result.message.serialize().to_vec();
        let export_key = result.export_key.to_vec();
        Ok((
            py_utils::to_pybytes(py, &message),
            py_utils::to_pybytes(py, &export_key),
        ))
    }

    fn start_login(
        &self,
        py: Python<'_>,
        password: Vec<u8>,
    ) -> PyResult<(Py<PyBytes>, ClientLoginState)> {
        let mut rng = OsRng;
        let result = ClientLogin::<Suite>::start(&mut rng, &password).map_err(to_py_err)?;
        let message = result.message.serialize().to_vec();
        Ok((
            py_utils::to_pybytes(py, &message),
            ClientLoginState {
                inner: Some(result.state),
            },
        ))
    }

    fn finish_login(
        &self,
        py: Python<'_>,
        mut state: PyRefMut<'_, ClientLoginState>,
        password: Vec<u8>,
        response: Vec<u8>,
        params: Option<PyRef<'_, PyClientLoginFinishParameters>>,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
        let state = state.take()?;
        let response = CredentialResponse::<Suite>::deserialize(&response).map_err(to_py_err)?;
        let mut rng = OsRng;
        let identifiers = params
            .as_ref()
            .and_then(|params| params.identifiers().cloned());
        let opaque_identifiers = identifiers
            .as_ref()
            .map(|ids| ids.as_opaque())
            .unwrap_or_default();
        let ksf = params
            .as_ref()
            .and_then(|params| params.key_stretching())
            .map(|ksf| ksf.build_ksf())
            .transpose()?;
        let context = params
            .as_ref()
            .and_then(|params| params.context().map(|value| value.to_vec()));
        let expected_server_s_pk = params
            .as_ref()
            .and_then(|params| params.server_s_pk().map(|value| value.to_vec()));
        let finish_params = if params.is_some() {
            ClientLoginFinishParameters::new(context.as_deref(), opaque_identifiers, ksf.as_ref())
        } else {
            ClientLoginFinishParameters::default()
        };
        let result = state
            .finish(&mut rng, &password, response, finish_params)
            .map_err(to_py_err)?;
        let server_s_pk = result.server_s_pk.serialize().to_vec();
        if let Some(expected) = expected_server_s_pk {
            if expected != server_s_pk {
                return Err(invalid_login_err("server public key mismatch"));
            }
        }
        let message = result.message.serialize().to_vec();
        let session_key = result.session_key.to_vec();
        let export_key = result.export_key.to_vec();
        Ok((
            py_utils::to_pybytes(py, &message),
            py_utils::to_pybytes(py, &session_key),
            py_utils::to_pybytes(py, &export_key),
            py_utils::to_pybytes(py, &server_s_pk),
        ))
    }

    #[allow(clippy::unused_self)]
    fn verify_server_public_key(&self, expected: Vec<u8>, actual: Vec<u8>) -> PyResult<()> {
        if expected == actual {
            Ok(())
        } else {
            Err(invalid_login_err("server public key mismatch"))
        }
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "client")?;
    module.add_class::<OpaqueClient>()?;
    py_utils::add_submodule(py, parent, "client", &module)?;
    Ok(())
}
