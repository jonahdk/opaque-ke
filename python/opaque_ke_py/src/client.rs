use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_login_err, invalid_state_err, to_py_err};
use crate::py_utils;
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

#[pyclass(unsendable)]
pub struct OpaqueClient {
    suite: SuiteId,
}

#[pymethods]
impl OpaqueClient {
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
        mut state: PyRefMut<'_, ClientRegistrationState>,
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
        let mut rng = OsRng;
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let state = state.take_ristretto()?;
                let response = RegistrationResponse::<Ristretto255Sha512>::deserialize(&response)
                    .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientRegistrationFinishParameters::<Ristretto255Sha512>::new(
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientRegistrationFinishParameters::<Ristretto255Sha512>::default()
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
            SuiteId::P256Sha256 => {
                let state = state.take_p256()?;
                let response = RegistrationResponse::<P256Sha256>::deserialize(&response)
                    .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientRegistrationFinishParameters::<P256Sha256>::new(
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientRegistrationFinishParameters::<P256Sha256>::default()
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
            SuiteId::P384Sha384 => {
                let state = state.take_p384()?;
                let response = RegistrationResponse::<P384Sha384>::deserialize(&response)
                    .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientRegistrationFinishParameters::<P384Sha384>::new(
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientRegistrationFinishParameters::<P384Sha384>::default()
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
            SuiteId::P521Sha512 => {
                let state = state.take_p521()?;
                let response = RegistrationResponse::<P521Sha512>::deserialize(&response)
                    .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientRegistrationFinishParameters::<P521Sha512>::new(
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientRegistrationFinishParameters::<P521Sha512>::default()
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
            SuiteId::MlKem768Ristretto255Sha512 => {
                let state = state.take_kem()?;
                let response =
                    RegistrationResponse::<MlKem768Ristretto255Sha512>::deserialize(&response)
                        .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientRegistrationFinishParameters::<MlKem768Ristretto255Sha512>::new(
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientRegistrationFinishParameters::<MlKem768Ristretto255Sha512>::default()
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
        }
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
        mut state: PyRefMut<'_, ClientLoginState>,
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
        let mut rng = OsRng;
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let state = state.take_ristretto()?;
                let response = CredentialResponse::<Ristretto255Sha512>::deserialize(&response)
                    .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientLoginFinishParameters::<Ristretto255Sha512>::new(
                        context.as_deref(),
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientLoginFinishParameters::<Ristretto255Sha512>::default()
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
            SuiteId::P256Sha256 => {
                let state = state.take_p256()?;
                let response =
                    CredentialResponse::<P256Sha256>::deserialize(&response).map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientLoginFinishParameters::<P256Sha256>::new(
                        context.as_deref(),
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientLoginFinishParameters::<P256Sha256>::default()
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
            SuiteId::P384Sha384 => {
                let state = state.take_p384()?;
                let response =
                    CredentialResponse::<P384Sha384>::deserialize(&response).map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientLoginFinishParameters::<P384Sha384>::new(
                        context.as_deref(),
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientLoginFinishParameters::<P384Sha384>::default()
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
            SuiteId::P521Sha512 => {
                let state = state.take_p521()?;
                let response =
                    CredentialResponse::<P521Sha512>::deserialize(&response).map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientLoginFinishParameters::<P521Sha512>::new(
                        context.as_deref(),
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientLoginFinishParameters::<P521Sha512>::default()
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
            SuiteId::MlKem768Ristretto255Sha512 => {
                let state = state.take_kem()?;
                let response =
                    CredentialResponse::<MlKem768Ristretto255Sha512>::deserialize(&response)
                        .map_err(to_py_err)?;
                let finish_params = if params.is_some() {
                    ClientLoginFinishParameters::<MlKem768Ristretto255Sha512>::new(
                        context.as_deref(),
                        opaque_identifiers,
                        ksf.as_ref(),
                    )
                } else {
                    ClientLoginFinishParameters::<MlKem768Ristretto255Sha512>::default()
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
        }
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
