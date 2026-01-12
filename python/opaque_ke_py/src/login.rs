use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, ServerLogin, ServerLoginParameters,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::errors::to_py_err;
use crate::suite::Suite;
use crate::types::{ClientLoginState, ServerLoginState, ServerRegistration, ServerSetup};

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

#[pyfunction(name = "start_login")]
fn server_start_login(
    server_setup: PyRef<'_, ServerSetup>,
    password_file: PyRef<'_, ServerRegistration>,
    request: Vec<u8>,
    credential_identifier: Vec<u8>,
) -> PyResult<(Vec<u8>, ServerLoginState)> {
    let request = CredentialRequest::<Suite>::deserialize(&request).map_err(to_py_err)?;
    let mut rng = OsRng;
    let result = ServerLogin::<Suite>::start(
        &mut rng,
        &server_setup.inner,
        Some(password_file.inner.clone()),
        request,
        &credential_identifier,
        ServerLoginParameters::default(),
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
) -> PyResult<Vec<u8>> {
    let state = state.take()?;
    let finalization =
        CredentialFinalization::<Suite>::deserialize(&finalization).map_err(to_py_err)?;
    let result = state
        .finish(finalization, ServerLoginParameters::default())
        .map_err(to_py_err)?;
    Ok(result.session_key.to_vec())
}

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "login")?;

    let client = PyModule::new(py, "client")?;
    client.add_function(wrap_pyfunction!(client_start_login, client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_login, client)?)?;
    module.add_submodule(client)?;

    let server = PyModule::new(py, "server")?;
    server.add_function(wrap_pyfunction!(server_start_login, server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_login, server)?)?;
    module.add_submodule(server)?;

    parent.add_submodule(module)?;
    Ok(())
}
