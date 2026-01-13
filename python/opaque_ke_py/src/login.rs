use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, ServerLogin, ServerLoginParameters,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::errors::{invalid_login_err, to_py_err};
use crate::suite::Suite;
use crate::types::{
    ClientLoginFinishParameters as PyClientLoginFinishParameters, ClientLoginState,
    ServerLoginParameters as PyServerLoginParameters, ServerLoginState, ServerRegistration,
    ServerSetup,
};

#[pyfunction(name = "start_login")]
fn client_start_login(password: Vec<u8>) -> PyResult<(Vec<u8>, ClientLoginState)> {
    let mut rng = OsRng;
    let result = ClientLogin::<Suite>::start(&mut rng, &password).map_err(to_py_err)?;
    Ok((
        result.message.serialize().to_vec(),
        ClientLoginState {
            inner: Some(result.state),
        },
    ))
}

#[pyfunction(name = "finish_login")]
fn client_finish_login(
    mut state: PyRefMut<'_, ClientLoginState>,
    password: Vec<u8>,
    response: Vec<u8>,
    params: Option<PyRef<'_, PyClientLoginFinishParameters>>,
) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
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
    Ok((
        result.message.serialize().to_vec(),
        result.session_key.to_vec(),
        result.export_key.to_vec(),
        server_s_pk,
    ))
}

#[pyfunction(name = "start_login")]
fn server_start_login(
    server_setup: PyRef<'_, ServerSetup>,
    password_file: PyRef<'_, ServerRegistration>,
    request: Vec<u8>,
    credential_identifier: Vec<u8>,
    params: Option<PyRef<'_, PyServerLoginParameters>>,
) -> PyResult<(Vec<u8>, ServerLoginState)> {
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
    Ok((
        result.message.serialize().to_vec(),
        ServerLoginState {
            inner: Some(result.state),
        },
    ))
}

#[pyfunction(name = "finish_login")]
fn server_finish_login(
    mut state: PyRefMut<'_, ServerLoginState>,
    finalization: Vec<u8>,
    params: Option<PyRef<'_, PyServerLoginParameters>>,
) -> PyResult<Vec<u8>> {
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
    Ok(result.session_key.to_vec())
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new_bound(py, "login")?;

    let client = PyModule::new_bound(py, "client")?;
    client.add_function(wrap_pyfunction!(client_start_login, &client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_login, &client)?)?;
    module.add_submodule(&client)?;

    let server = PyModule::new_bound(py, "server")?;
    server.add_function(wrap_pyfunction!(server_start_login, &server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_login, &server)?)?;
    module.add_submodule(&server)?;

    parent.add_submodule(&module)?;
    Ok(())
}
