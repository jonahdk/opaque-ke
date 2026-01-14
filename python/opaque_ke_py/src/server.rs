use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_state_err, to_py_err};
use crate::py_utils;
use crate::suite::{parse_suite, Ristretto255Sha512, SuiteId};
use crate::suite::MlKem768Ristretto255Sha512;
use crate::suite::P256Sha256;
use crate::suite::P384Sha384;
use crate::suite::P521Sha512;
use crate::types::{
    ServerLoginParameters as PyServerLoginParameters, ServerLoginState, ServerLoginStateInner,
    ServerRegistration as PyServerRegistration, ServerRegistrationInner, ServerSetup,
    ServerSetupInner,
};

#[pyclass(unsendable)]
pub struct OpaqueServer {
    suite: SuiteId,
}

#[pymethods]
impl OpaqueServer {
    #[new]
    fn new(suite: Option<&str>) -> PyResult<Self> {
        Ok(Self {
            suite: parse_suite(suite)?,
        })
    }

    fn start_registration(
        &self,
        py: Python<'_>,
        server_setup: PyRef<'_, ServerSetup>,
        request: Vec<u8>,
        credential_identifier: Vec<u8>,
    ) -> PyResult<Py<PyBytes>> {
        if server_setup.suite_id() != self.suite {
            return Err(invalid_state_err(
                "ServerSetup does not match this server instance",
            ));
        }
        match &server_setup.inner {
            ServerSetupInner::Ristretto255Sha512(inner) => {
                let request =
                    RegistrationRequest::<Ristretto255Sha512>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerRegistration::<Ristretto255Sha512>::start(
                    inner,
                    request,
                    &credential_identifier,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok(py_utils::to_pybytes(py, &message))
            }
            ServerSetupInner::P256Sha256(inner) => {
                let request =
                    RegistrationRequest::<P256Sha256>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerRegistration::<P256Sha256>::start(
                    inner,
                    request,
                    &credential_identifier,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok(py_utils::to_pybytes(py, &message))
            }
            ServerSetupInner::P384Sha384(inner) => {
                let request =
                    RegistrationRequest::<P384Sha384>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerRegistration::<P384Sha384>::start(
                    inner,
                    request,
                    &credential_identifier,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok(py_utils::to_pybytes(py, &message))
            }
            ServerSetupInner::P521Sha512(inner) => {
                let request =
                    RegistrationRequest::<P521Sha512>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerRegistration::<P521Sha512>::start(
                    inner,
                    request,
                    &credential_identifier,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok(py_utils::to_pybytes(py, &message))
            }
            ServerSetupInner::MlKem768Ristretto255Sha512(inner) => {
                let request =
                    RegistrationRequest::<MlKem768Ristretto255Sha512>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerRegistration::<MlKem768Ristretto255Sha512>::start(
                    inner,
                    request,
                    &credential_identifier,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok(py_utils::to_pybytes(py, &message))
            }
        }
    }

    fn finish_registration(&self, upload: Vec<u8>) -> PyResult<PyServerRegistration> {
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let upload =
                    RegistrationUpload::<Ristretto255Sha512>::deserialize(&upload)
                        .map_err(to_py_err)?;
                Ok(PyServerRegistration {
                    inner: ServerRegistrationInner::Ristretto255Sha512(
                        ServerRegistration::<Ristretto255Sha512>::finish(upload),
                    ),
                })
            }
            SuiteId::P256Sha256 => {
                let upload =
                    RegistrationUpload::<P256Sha256>::deserialize(&upload)
                        .map_err(to_py_err)?;
                Ok(PyServerRegistration {
                    inner: ServerRegistrationInner::P256Sha256(
                        ServerRegistration::<P256Sha256>::finish(upload),
                    ),
                })
            }
            SuiteId::P384Sha384 => {
                let upload =
                    RegistrationUpload::<P384Sha384>::deserialize(&upload)
                        .map_err(to_py_err)?;
                Ok(PyServerRegistration {
                    inner: ServerRegistrationInner::P384Sha384(
                        ServerRegistration::<P384Sha384>::finish(upload),
                    ),
                })
            }
            SuiteId::P521Sha512 => {
                let upload =
                    RegistrationUpload::<P521Sha512>::deserialize(&upload)
                        .map_err(to_py_err)?;
                Ok(PyServerRegistration {
                    inner: ServerRegistrationInner::P521Sha512(
                        ServerRegistration::<P521Sha512>::finish(upload),
                    ),
                })
            }
            SuiteId::MlKem768Ristretto255Sha512 => {
                let upload =
                    RegistrationUpload::<MlKem768Ristretto255Sha512>::deserialize(&upload)
                        .map_err(to_py_err)?;
                Ok(PyServerRegistration {
                    inner: ServerRegistrationInner::MlKem768Ristretto255Sha512(
                        ServerRegistration::<MlKem768Ristretto255Sha512>::finish(upload),
                    ),
                })
            }
        }
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
        if server_setup.suite_id() != self.suite {
            return Err(invalid_state_err(
                "ServerSetup does not match this server instance",
            ));
        }
        if password_file.suite_id() != self.suite {
            return Err(invalid_state_err(
                "ServerRegistration does not match this server instance",
            ));
        }
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
        match (&server_setup.inner, &password_file.inner) {
            (ServerSetupInner::Ristretto255Sha512(setup), ServerRegistrationInner::Ristretto255Sha512(reg)) => {
                let request =
                    CredentialRequest::<Ristretto255Sha512>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerLogin::<Ristretto255Sha512>::start(
                    &mut rng,
                    setup,
                    Some(reg.clone()),
                    request,
                    &credential_identifier,
                    parameters,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ServerLoginState {
                        inner: ServerLoginStateInner::Ristretto255Sha512(Some(result.state)),
                    },
                ))
            }
            (ServerSetupInner::P256Sha256(setup), ServerRegistrationInner::P256Sha256(reg)) => {
                let request =
                    CredentialRequest::<P256Sha256>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerLogin::<P256Sha256>::start(
                    &mut rng,
                    setup,
                    Some(reg.clone()),
                    request,
                    &credential_identifier,
                    parameters,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ServerLoginState {
                        inner: ServerLoginStateInner::P256Sha256(Some(result.state)),
                    },
                ))
            }
            (ServerSetupInner::P384Sha384(setup), ServerRegistrationInner::P384Sha384(reg)) => {
                let request =
                    CredentialRequest::<P384Sha384>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerLogin::<P384Sha384>::start(
                    &mut rng,
                    setup,
                    Some(reg.clone()),
                    request,
                    &credential_identifier,
                    parameters,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ServerLoginState {
                        inner: ServerLoginStateInner::P384Sha384(Some(result.state)),
                    },
                ))
            }
            (ServerSetupInner::P521Sha512(setup), ServerRegistrationInner::P521Sha512(reg)) => {
                let request =
                    CredentialRequest::<P521Sha512>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerLogin::<P521Sha512>::start(
                    &mut rng,
                    setup,
                    Some(reg.clone()),
                    request,
                    &credential_identifier,
                    parameters,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ServerLoginState {
                        inner: ServerLoginStateInner::P521Sha512(Some(result.state)),
                    },
                ))
            }
            (ServerSetupInner::MlKem768Ristretto255Sha512(setup), ServerRegistrationInner::MlKem768Ristretto255Sha512(reg)) => {
                let request =
                    CredentialRequest::<MlKem768Ristretto255Sha512>::deserialize(&request)
                        .map_err(to_py_err)?;
                let result = ServerLogin::<MlKem768Ristretto255Sha512>::start(
                    &mut rng,
                    setup,
                    Some(reg.clone()),
                    request,
                    &credential_identifier,
                    parameters,
                )
                .map_err(to_py_err)?;
                let message = result.message.serialize().to_vec();
                Ok((
                    py_utils::to_pybytes(py, &message),
                    ServerLoginState {
                        inner: ServerLoginStateInner::MlKem768Ristretto255Sha512(Some(result.state)),
                    },
                ))
            }
            _ => Err(invalid_state_err(
                "ServerSetup and ServerRegistration use different cipher suites",
            )),
        }
    }

    fn finish_login(
        &self,
        py: Python<'_>,
        mut state: PyRefMut<'_, ServerLoginState>,
        finalization: Vec<u8>,
        params: Option<PyRef<'_, PyServerLoginParameters>>,
    ) -> PyResult<Py<PyBytes>> {
        if state.suite_id() != self.suite {
            return Err(invalid_state_err(
                "ServerLoginState does not match this server instance",
            ));
        }
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
        match self.suite {
            SuiteId::Ristretto255Sha512 => {
                let state = state.take_ristretto()?;
                let finalization =
                    CredentialFinalization::<Ristretto255Sha512>::deserialize(&finalization)
                        .map_err(to_py_err)?;
                let result = state.finish(finalization, parameters).map_err(to_py_err)?;
                let session_key = result.session_key.to_vec();
                Ok(py_utils::to_pybytes(py, &session_key))
            }
            SuiteId::P256Sha256 => {
                let state = state.take_p256()?;
                let finalization =
                    CredentialFinalization::<P256Sha256>::deserialize(&finalization)
                        .map_err(to_py_err)?;
                let result = state.finish(finalization, parameters).map_err(to_py_err)?;
                let session_key = result.session_key.to_vec();
                Ok(py_utils::to_pybytes(py, &session_key))
            }
            SuiteId::P384Sha384 => {
                let state = state.take_p384()?;
                let finalization =
                    CredentialFinalization::<P384Sha384>::deserialize(&finalization)
                        .map_err(to_py_err)?;
                let result = state.finish(finalization, parameters).map_err(to_py_err)?;
                let session_key = result.session_key.to_vec();
                Ok(py_utils::to_pybytes(py, &session_key))
            }
            SuiteId::P521Sha512 => {
                let state = state.take_p521()?;
                let finalization =
                    CredentialFinalization::<P521Sha512>::deserialize(&finalization)
                        .map_err(to_py_err)?;
                let result = state.finish(finalization, parameters).map_err(to_py_err)?;
                let session_key = result.session_key.to_vec();
                Ok(py_utils::to_pybytes(py, &session_key))
            }
            SuiteId::MlKem768Ristretto255Sha512 => {
                let state = state.take_kem()?;
                let finalization =
                    CredentialFinalization::<MlKem768Ristretto255Sha512>::deserialize(&finalization)
                        .map_err(to_py_err)?;
                let result = state.finish(finalization, parameters).map_err(to_py_err)?;
                let session_key = result.session_key.to_vec();
                Ok(py_utils::to_pybytes(py, &session_key))
            }
        }
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "server")?;
    module.add_class::<OpaqueServer>()?;
    py_utils::add_submodule(py, parent, "server", &module)?;
    Ok(())
}
