use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_login_err, invalid_state_err, to_py_err};
use crate::py_utils;
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
    fn new(suite: Option<&str>) -> PyResult<Self> {
        Ok(Self {
            suite: parse_suite(suite)?,
        })
    }

    fn start_registration(
        &self,
        py: Python<'_>,
        password: Vec<u8>,
    ) -> PyResult<(Py<PyBytes>, ClientRegistrationState)> {
        let mut rng = OsRng;
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let result = ClientRegistration::<Ristretto255Sha512>::start(&mut rng, &password)
                    .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientRegistrationState {
                        inner: ClientRegistrationStateInner::Ristretto255Sha512(Some(result.state)),
                    },
                ))
            }
            SuiteId::P256Sha256 => {
                let result = ClientRegistration::<P256Sha256>::start(&mut rng, &password)
                    .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientRegistrationState {
                        inner: ClientRegistrationStateInner::P256Sha256(Some(result.state)),
                    },
                ))
            }
            SuiteId::P384Sha384 => {
                let result = ClientRegistration::<P384Sha384>::start(&mut rng, &password)
                    .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientRegistrationState {
                        inner: ClientRegistrationStateInner::P384Sha384(Some(result.state)),
                    },
                ))
            }
            SuiteId::P521Sha512 => {
                let result = ClientRegistration::<P521Sha512>::start(&mut rng, &password)
                    .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientRegistrationState {
                        inner: ClientRegistrationStateInner::P521Sha512(Some(result.state)),
                    },
                ))
            }
            SuiteId::MlKem768Ristretto255Sha512 => {
                let result =
                    ClientRegistration::<MlKem768Ristretto255Sha512>::start(&mut rng, &password)
                        .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientRegistrationState {
                        inner: ClientRegistrationStateInner::MlKem768Ristretto255Sha512(Some(
                            result.state,
                        )),
                    },
                ))
            }
        }
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
        let finish_params = if params.is_some() {
            ClientRegistrationFinishParameters::new(opaque_identifiers, ksf.as_ref())
        } else {
            ClientRegistrationFinishParameters::default()
        };
        let mut rng = OsRng;
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let state = state.take_ristretto()?;
                let response = RegistrationResponse::<Ristretto255Sha512>::deserialize(&response)
                    .map_err(to_py_err)?;
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
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let result = ClientLogin::<Ristretto255Sha512>::start(&mut rng, &password)
                    .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientLoginState {
                        inner: ClientLoginStateInner::Ristretto255Sha512(Some(result.state)),
                    },
                ))
            }
            SuiteId::P256Sha256 => {
                let result =
                    ClientLogin::<P256Sha256>::start(&mut rng, &password).map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientLoginState {
                        inner: ClientLoginStateInner::P256Sha256(Some(result.state)),
                    },
                ))
            }
            SuiteId::P384Sha384 => {
                let result =
                    ClientLogin::<P384Sha384>::start(&mut rng, &password).map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientLoginState {
                        inner: ClientLoginStateInner::P384Sha384(Some(result.state)),
                    },
                ))
            }
            SuiteId::P521Sha512 => {
                let result =
                    ClientLogin::<P521Sha512>::start(&mut rng, &password).map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientLoginState {
                        inner: ClientLoginStateInner::P521Sha512(Some(result.state)),
                    },
                ))
            }
            SuiteId::MlKem768Ristretto255Sha512 => {
                let result = ClientLogin::<MlKem768Ristretto255Sha512>::start(&mut rng, &password)
                    .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ClientLoginState {
                        inner: ClientLoginStateInner::MlKem768Ristretto255Sha512(Some(
                            result.state,
                        )),
                    },
                ))
            }
        }
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
        let finish_params = if params.is_some() {
            ClientLoginFinishParameters::new(context.as_deref(), opaque_identifiers, ksf.as_ref())
        } else {
            ClientLoginFinishParameters::default()
        };
        let mut rng = OsRng;
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let state = state.take_ristretto()?;
                let response = CredentialResponse::<Ristretto255Sha512>::deserialize(&response)
                    .map_err(to_py_err)?;
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
