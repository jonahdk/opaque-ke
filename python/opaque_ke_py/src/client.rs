use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{ClientLogin, ClientRegistration};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_login_err, invalid_state_err};
use crate::py_utils::per_suite_dispatch;
use crate::suite::{
    MlKem768Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Ristretto255Sha512, SuiteId,
    parse_suite,
};
use crate::types::{
    ClientLoginFinishParameters as PyClientLoginFinishParameters, ClientLoginState,
    ClientLoginStateInner,
    ClientRegistrationFinishParameters as PyClientRegistrationFinishParameters,
    ClientRegistrationState, ClientRegistrationStateInner,
};
use crate::{login, py_utils, registration};

#[pyclass(unsendable)]
pub struct OpaqueClient {
    suite: SuiteId,
}

#[pymethods]
impl OpaqueClient {
    #[pyo3(signature = (suite=None))]
    #[new]
    fn new(suite: Option<String>) -> PyResult<Self> {
        Ok(Self {
            suite: parse_suite(suite.as_deref())?,
        })
    }

    fn start_registration(
        &self,
        py: Python<'_>,
        password: Vec<u8>,
    ) -> PyResult<(Py<PyBytes>, ClientRegistrationState)> {
        let mut rng = OsRng;
        per_suite_dispatch!(
            suite = self.suite,
            py = py,
            rng = rng,
            password = password,
            start = ClientRegistration,
            state_type = ClientRegistrationState,
            state_inner = ClientRegistrationStateInner,
            [
                (
                    SuiteId::Ristretto255Sha512,
                    Ristretto255Sha512,
                    Ristretto255Sha512
                ),
                (SuiteId::P256Sha256, P256Sha256, P256Sha256),
                (SuiteId::P384Sha384, P384Sha384, P384Sha384),
                (SuiteId::P521Sha512, P521Sha512, P521Sha512),
                (
                    SuiteId::MlKem768Ristretto255Sha512,
                    MlKem768Ristretto255Sha512,
                    MlKem768Ristretto255Sha512
                ),
            ]
        )
    }

    fn finish_registration(
        &self,
        py: Python<'_>,
        state: PyRefMut<'_, ClientRegistrationState>,
        password: Vec<u8>,
        response: Vec<u8>,
        params: Option<PyRef<'_, PyClientRegistrationFinishParameters>>,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let state_suite = state.suite_id();
        if state_suite != self.suite {
            return Err(invalid_state_err(
                "ClientRegistrationState does not match this client instance",
            ));
        }
        registration::client_finish_registration(py, state, password, response, params, None)
    }

    fn start_login(
        &self,
        py: Python<'_>,
        password: Vec<u8>,
    ) -> PyResult<(Py<PyBytes>, ClientLoginState)> {
        let mut rng = OsRng;
        per_suite_dispatch!(
            suite = self.suite,
            py = py,
            rng = rng,
            password = password,
            start = ClientLogin,
            state_type = ClientLoginState,
            state_inner = ClientLoginStateInner,
            [
                (
                    SuiteId::Ristretto255Sha512,
                    Ristretto255Sha512,
                    Ristretto255Sha512
                ),
                (SuiteId::P256Sha256, P256Sha256, P256Sha256),
                (SuiteId::P384Sha384, P384Sha384, P384Sha384),
                (SuiteId::P521Sha512, P521Sha512, P521Sha512),
                (
                    SuiteId::MlKem768Ristretto255Sha512,
                    MlKem768Ristretto255Sha512,
                    MlKem768Ristretto255Sha512
                ),
            ]
        )
    }

    fn finish_login(
        &self,
        py: Python<'_>,
        state: PyRefMut<'_, ClientLoginState>,
        password: Vec<u8>,
        response: Vec<u8>,
        params: Option<PyRef<'_, PyClientLoginFinishParameters>>,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>, Py<PyBytes>, Py<PyBytes>)> {
        let state_suite = state.suite_id();
        if state_suite != self.suite {
            return Err(invalid_state_err(
                "ClientLoginState does not match this client instance",
            ));
        }
        login::client_finish_login(py, state, password, response, params, None)
    }

    #[staticmethod]
    fn verify_server_public_key(expected: Vec<u8>, actual: Vec<u8>) -> PyResult<()> {
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
