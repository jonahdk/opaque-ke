use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, ServerLogin, ServerLoginParameters,
};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_login_err, to_py_err};
use crate::py_utils;
use crate::suite::Suite;
use crate::types::{
    ClientLoginFinishParameters as PyClientLoginFinishParameters, ClientLoginState,
    ServerLoginParameters as PyServerLoginParameters, ServerLoginState, ServerRegistration,
    ServerSetup,
};

#[pyfunction(name = "start_login")]
fn client_start_login(
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

#[pyfunction(name = "finish_login")]
fn client_finish_login(
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

#[pyfunction(name = "start_login")]
fn server_start_login(
    py: Python<'_>,
    server_setup: PyRef<'_, ServerSetup>,
    password_file: PyRef<'_, ServerRegistration>,
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

#[pyfunction(name = "finish_login")]
fn server_finish_login(
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

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "login")?;

    let client = py_utils::new_submodule(py, &module, "client")?;
    client.add_function(wrap_pyfunction!(client_start_login, &client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_login, &client)?)?;
    py_utils::add_submodule(py, &module, "client", &client)?;

    let server = py_utils::new_submodule(py, &module, "server")?;
    server.add_function(wrap_pyfunction!(server_start_login, &server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_login, &server)?)?;
    py_utils::add_submodule(py, &module, "server", &server)?;

    py_utils::add_submodule(py, parent, "login", &module)?;
    Ok(())
}
