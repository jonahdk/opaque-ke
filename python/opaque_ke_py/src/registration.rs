use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerRegistration,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_state_err, to_py_err};
use crate::py_utils;
use crate::suite::{
    MlKem768Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512, Ristretto255Sha512, SuiteId,
    parse_suite,
};
use crate::types::{
    ClientRegistrationFinishParameters as PyClientRegistrationFinishParameters,
    ClientRegistrationState, ClientRegistrationStateInner,
    ServerRegistration as PyServerRegistration, ServerRegistrationInner, ServerSetup,
    ServerSetupInner,
};

fn ensure_suite(expected: SuiteId, actual: SuiteId, label: &str) -> PyResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_state_err(&format!(
            "{label} does not match requested cipher suite"
        )))
    }
}

#[pyfunction(name = "start_registration")]
#[pyo3(signature = (password, suite=None))]
fn client_start_registration(
    py: Python<'_>,
    password: Vec<u8>,
    suite: Option<&str>,
) -> PyResult<(Py<PyBytes>, ClientRegistrationState)> {
    let suite = parse_suite(suite)?;
    let mut rng = OsRng;
    match suite {
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
            let result =
                ClientRegistration::<P256Sha256>::start(&mut rng, &password).map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ClientRegistrationState {
                    inner: ClientRegistrationStateInner::P256Sha256(Some(result.state)),
                },
            ))
        }
        SuiteId::P384Sha384 => {
            let result =
                ClientRegistration::<P384Sha384>::start(&mut rng, &password).map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok((
                py_utils::to_pybytes(py, &message),
                ClientRegistrationState {
                    inner: ClientRegistrationStateInner::P384Sha384(Some(result.state)),
                },
            ))
        }
        SuiteId::P521Sha512 => {
            let result =
                ClientRegistration::<P521Sha512>::start(&mut rng, &password).map_err(to_py_err)?;
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

#[pyfunction(name = "finish_registration")]
#[pyo3(signature = (state, password, response, params=None, suite=None))]
fn client_finish_registration(
    py: Python<'_>,
    mut state: PyRefMut<'_, ClientRegistrationState>,
    password: Vec<u8>,
    response: Vec<u8>,
    params: Option<PyRef<'_, PyClientRegistrationFinishParameters>>,
    suite: Option<&str>,
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let state_suite = state.suite_id();
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested))?;
        ensure_suite(requested, state_suite, "ClientRegistrationState")?;
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
    match state_suite {
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
            let response =
                RegistrationResponse::<P256Sha256>::deserialize(&response).map_err(to_py_err)?;
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
            let response =
                RegistrationResponse::<P384Sha384>::deserialize(&response).map_err(to_py_err)?;
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
            let response =
                RegistrationResponse::<P521Sha512>::deserialize(&response).map_err(to_py_err)?;
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

#[pyfunction(name = "start_registration")]
#[pyo3(signature = (server_setup, request, credential_identifier, suite=None))]
fn server_start_registration(
    py: Python<'_>,
    server_setup: PyRef<'_, ServerSetup>,
    request: Vec<u8>,
    credential_identifier: Vec<u8>,
    suite: Option<&str>,
) -> PyResult<Py<PyBytes>> {
    let setup_suite = server_setup.suite_id();
    if let Some(requested) = suite {
        let requested = parse_suite(Some(requested))?;
        ensure_suite(requested, setup_suite, "ServerSetup")?;
    }
    match &server_setup.inner {
        ServerSetupInner::Ristretto255Sha512(inner) => {
            let request = RegistrationRequest::<Ristretto255Sha512>::deserialize(&request)
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
                RegistrationRequest::<P256Sha256>::deserialize(&request).map_err(to_py_err)?;
            let result =
                ServerRegistration::<P256Sha256>::start(inner, request, &credential_identifier)
                    .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::P384Sha384(inner) => {
            let request =
                RegistrationRequest::<P384Sha384>::deserialize(&request).map_err(to_py_err)?;
            let result =
                ServerRegistration::<P384Sha384>::start(inner, request, &credential_identifier)
                    .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::P521Sha512(inner) => {
            let request =
                RegistrationRequest::<P521Sha512>::deserialize(&request).map_err(to_py_err)?;
            let result =
                ServerRegistration::<P521Sha512>::start(inner, request, &credential_identifier)
                    .map_err(to_py_err)?;
            let message = result.message.serialize().to_vec();
            Ok(py_utils::to_pybytes(py, &message))
        }
        ServerSetupInner::MlKem768Ristretto255Sha512(inner) => {
            let request = RegistrationRequest::<MlKem768Ristretto255Sha512>::deserialize(&request)
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

#[pyfunction(name = "finish_registration")]
#[pyo3(signature = (upload, suite=None))]
fn server_finish_registration(
    upload: Vec<u8>,
    suite: Option<&str>,
) -> PyResult<PyServerRegistration> {
    let suite = parse_suite(suite)?;
    match suite {
        SuiteId::Ristretto255Sha512 => {
            let upload = RegistrationUpload::<Ristretto255Sha512>::deserialize(&upload)
                .map_err(to_py_err)?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::Ristretto255Sha512(ServerRegistration::<
                    Ristretto255Sha512,
                >::finish(
                    upload
                )),
            })
        }
        SuiteId::P256Sha256 => {
            let upload =
                RegistrationUpload::<P256Sha256>::deserialize(&upload).map_err(to_py_err)?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::P256Sha256(
                    ServerRegistration::<P256Sha256>::finish(upload),
                ),
            })
        }
        SuiteId::P384Sha384 => {
            let upload =
                RegistrationUpload::<P384Sha384>::deserialize(&upload).map_err(to_py_err)?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::P384Sha384(
                    ServerRegistration::<P384Sha384>::finish(upload),
                ),
            })
        }
        SuiteId::P521Sha512 => {
            let upload =
                RegistrationUpload::<P521Sha512>::deserialize(&upload).map_err(to_py_err)?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::P521Sha512(
                    ServerRegistration::<P521Sha512>::finish(upload),
                ),
            })
        }
        SuiteId::MlKem768Ristretto255Sha512 => {
            let upload = RegistrationUpload::<MlKem768Ristretto255Sha512>::deserialize(&upload)
                .map_err(to_py_err)?;
            Ok(PyServerRegistration {
                inner: ServerRegistrationInner::MlKem768Ristretto255Sha512(ServerRegistration::<
                    MlKem768Ristretto255Sha512,
                >::finish(
                    upload
                )),
            })
        }
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "registration")?;

    let client = py_utils::new_submodule(py, &module, "client")?;
    client.add_function(wrap_pyfunction!(client_start_registration, &client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_registration, &client)?)?;
    py_utils::add_submodule(py, &module, "client", &client)?;

    let server = py_utils::new_submodule(py, &module, "server")?;
    server.add_function(wrap_pyfunction!(server_start_registration, &server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_registration, &server)?)?;
    py_utils::add_submodule(py, &module, "server", &server)?;

    py_utils::add_submodule(py, parent, "registration", &module)?;
    Ok(())
}
