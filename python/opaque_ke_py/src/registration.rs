use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, RegistrationRequest,
    RegistrationResponse, RegistrationUpload, ServerRegistration,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::errors::to_py_err;
use crate::suite::Suite;
use crate::types::{
    ClientRegistrationState, ServerRegistration as PyServerRegistration, ServerSetup,
};

#[pyfunction(name = "start_registration")]
fn client_start_registration(password: Vec<u8>) -> PyResult<(Vec<u8>, ClientRegistrationState)> {
    let mut rng = OsRng;
    let result = ClientRegistration::<Suite>::start(&mut rng, &password).map_err(to_py_err)?;
    Ok((
        result.message.serialize().to_vec(),
        ClientRegistrationState {
            inner: Some(result.state),
        },
    ))
}

#[pyfunction(name = "finish_registration")]
fn client_finish_registration(
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

#[pyfunction(name = "start_registration")]
fn server_start_registration(
    server_setup: PyRef<'_, ServerSetup>,
    request: Vec<u8>,
    credential_identifier: Vec<u8>,
) -> PyResult<Vec<u8>> {
    let request = RegistrationRequest::<Suite>::deserialize(&request).map_err(to_py_err)?;
    let result =
        ServerRegistration::<Suite>::start(&server_setup.inner, request, &credential_identifier)
            .map_err(to_py_err)?;
    Ok(result.message.serialize().to_vec())
}

#[pyfunction(name = "finish_registration")]
fn server_finish_registration(upload: Vec<u8>) -> PyResult<PyServerRegistration> {
    let upload = RegistrationUpload::<Suite>::deserialize(&upload).map_err(to_py_err)?;
    Ok(PyServerRegistration {
        inner: ServerRegistration::<Suite>::finish(upload),
    })
}

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "registration")?;

    let client = PyModule::new(py, "client")?;
    client.add_function(wrap_pyfunction!(client_start_registration, client)?)?;
    client.add_function(wrap_pyfunction!(client_finish_registration, client)?)?;
    module.add_submodule(client)?;

    let server = PyModule::new(py, "server")?;
    server.add_function(wrap_pyfunction!(server_start_registration, server)?)?;
    server.add_function(wrap_pyfunction!(server_finish_registration, server)?)?;
    module.add_submodule(server)?;

    parent.add_submodule(module)?;
    Ok(())
}
