use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::invalid_state_err;
use crate::suite::{SuiteId, parse_suite};
use crate::types::{
    ServerLoginParameters as PyServerLoginParameters, ServerLoginState,
    ServerRegistration as PyServerRegistration, ServerSetup,
};
use crate::{login, py_utils, registration};

#[pyclass(unsendable)]
pub struct OpaqueServer {
    suite: SuiteId,
}

#[pymethods]
impl OpaqueServer {
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
        server_setup: PyRef<'_, ServerSetup>,
        request: Vec<u8>,
        credential_identifier: Vec<u8>,
    ) -> PyResult<Py<PyBytes>> {
        if server_setup.suite_id() != self.suite {
            return Err(invalid_state_err(
                "ServerSetup does not match this server instance",
            ));
        }
        registration::server_start_registration(
            py,
            server_setup,
            request,
            credential_identifier,
            None,
        )
    }

    fn finish_registration(&self, upload: Vec<u8>) -> PyResult<PyServerRegistration> {
        registration::server_finish_registration_with_suite(upload, self.suite)
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
        login::server_start_login(
            py,
            server_setup,
            password_file,
            request,
            credential_identifier,
            params,
            None,
        )
    }

    fn finish_login(
        &self,
        py: Python<'_>,
        state: PyRefMut<'_, ServerLoginState>,
        finalization: Vec<u8>,
        params: Option<PyRef<'_, PyServerLoginParameters>>,
    ) -> PyResult<Py<PyBytes>> {
        if state.suite_id() != self.suite {
            return Err(invalid_state_err(
                "ServerLoginState does not match this server instance",
            ));
        }
        login::server_finish_login(py, state, finalization, params, None)
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "server")?;
    module.add_class::<OpaqueServer>()?;
    py_utils::add_submodule(py, parent, "server", &module)?;
    Ok(())
}
