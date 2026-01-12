use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::errors::to_py_err;
use crate::suite::{SUITE_NAME, Suite};
use crate::types::{ClientLoginState, ClientRegistrationState};

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
        password: Vec<u8>,
    ) -> PyResult<(Vec<u8>, ClientRegistrationState)> {
        let mut rng = OsRng;
        let result = ClientRegistration::<Suite>::start(&mut rng, &password).map_err(to_py_err)?;
        Ok((
            result.message.serialize().to_vec(),
            ClientRegistrationState {
                inner: Some(result.state),
            },
        ))
    }

    fn finish_registration(
        &self,
        mut state: PyRefMut<'_, ClientRegistrationState>,
        password: Vec<u8>,
        response: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let state = state.take()?;
        let response = RegistrationResponse::<Suite>::deserialize(&response).map_err(to_py_err)?;
        let mut rng = OsRng;
        let result = state
            .finish(
                &mut rng,
                &password,
                response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(to_py_err)?;
        Ok((
            result.message.serialize().to_vec(),
            result.export_key.to_vec(),
        ))
    }

    fn start_login(&self, password: Vec<u8>) -> PyResult<(Vec<u8>, ClientLoginState)> {
        let mut rng = OsRng;
        let result = ClientLogin::<Suite>::start(&mut rng, &password).map_err(to_py_err)?;
        Ok((
            result.message.serialize().to_vec(),
            ClientLoginState {
                inner: Some(result.state),
            },
        ))
    }

    fn finish_login(
        &self,
        mut state: PyRefMut<'_, ClientLoginState>,
        password: Vec<u8>,
        response: Vec<u8>,
    ) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        let state = state.take()?;
        let response = CredentialResponse::<Suite>::deserialize(&response).map_err(to_py_err)?;
        let mut rng = OsRng;
        let result = state
            .finish(
                &mut rng,
                &password,
                response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(to_py_err)?;
        Ok((
            result.message.serialize().to_vec(),
            result.session_key.to_vec(),
            result.export_key.to_vec(),
            result.server_s_pk.serialize().to_vec(),
        ))
    }

    #[allow(clippy::unused_self)]
    fn verify_server_public_key(&self, expected: Vec<u8>, actual: Vec<u8>) -> PyResult<()> {
        if expected == actual {
            Ok(())
        } else {
            Err(PyErr::new::<PyValueError, _>("server public key mismatch"))
        }
    }
}

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "client")?;
    module.add_class::<OpaqueClient>()?;
    parent.add_submodule(module)?;
    Ok(())
}
