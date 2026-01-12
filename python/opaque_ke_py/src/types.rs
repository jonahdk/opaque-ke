use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientRegistration, ServerLogin, ServerRegistration as OpaqueServerRegistration,
    ServerSetup as OpaqueServerSetup,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::errors::to_py_err;
use crate::suite::Suite;

#[pyclass(unsendable)]
pub struct ServerSetup {
    pub(crate) inner: OpaqueServerSetup<Suite>,
}

#[pymethods]
impl ServerSetup {
    #[new]
    fn new() -> PyResult<Self> {
        let mut rng = OsRng;
        Ok(Self {
            inner: OpaqueServerSetup::<Suite>::new(&mut rng),
        })
    }

    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = OpaqueServerSetup::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn serialize(&self) -> Vec<u8> {
        self.inner.serialize().to_vec()
    }
}

#[pyclass(unsendable)]
pub struct ServerRegistration {
    pub(crate) inner: OpaqueServerRegistration<Suite>,
}

#[pymethods]
impl ServerRegistration {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = OpaqueServerRegistration::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    fn serialize(&self) -> PyResult<Vec<u8>> {
        Ok(self.inner.serialize().to_vec())
    }
}

#[pyclass(unsendable)]
pub struct ClientRegistrationState {
    pub(crate) inner: Option<ClientRegistration<Suite>>,
}

impl ClientRegistrationState {
    pub(crate) fn take(&mut self) -> PyResult<ClientRegistration<Suite>> {
        self.inner.take().ok_or_else(|| {
            PyErr::new::<PyValueError, _>("ClientRegistrationState has already been used")
        })
    }
}

#[pymethods]
impl ClientRegistrationState {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = ClientRegistration::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn serialize(&self) -> PyResult<Vec<u8>> {
        let inner = self.inner.as_ref().ok_or_else(|| {
            PyErr::new::<PyValueError, _>("ClientRegistrationState has already been used")
        })?;
        Ok(inner.serialize().to_vec())
    }
}

#[pyclass(unsendable)]
pub struct ClientLoginState {
    pub(crate) inner: Option<ClientLogin<Suite>>,
}

impl ClientLoginState {
    pub(crate) fn take(&mut self) -> PyResult<ClientLogin<Suite>> {
        self.inner
            .take()
            .ok_or_else(|| PyErr::new::<PyValueError, _>("ClientLoginState has already been used"))
    }
}

#[pymethods]
impl ClientLoginState {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = ClientLogin::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn serialize(&self) -> PyResult<Vec<u8>> {
        let inner = self.inner.as_ref().ok_or_else(|| {
            PyErr::new::<PyValueError, _>("ClientLoginState has already been used")
        })?;
        Ok(inner.serialize().to_vec())
    }
}

#[pyclass(unsendable)]
pub struct ServerLoginState {
    pub(crate) inner: Option<ServerLogin<Suite>>,
}

impl ServerLoginState {
    pub(crate) fn take(&mut self) -> PyResult<ServerLogin<Suite>> {
        self.inner
            .take()
            .ok_or_else(|| PyErr::new::<PyValueError, _>("ServerLoginState has already been used"))
    }
}

#[pymethods]
impl ServerLoginState {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = ServerLogin::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn serialize(&self) -> PyResult<Vec<u8>> {
        let inner = self.inner.as_ref().ok_or_else(|| {
            PyErr::new::<PyValueError, _>("ServerLoginState has already been used")
        })?;
        Ok(inner.serialize().to_vec())
    }
}

pub fn register(py: Python<'_>, parent: &PyModule) -> PyResult<()> {
    let module = PyModule::new(py, "types")?;
    module.add_class::<ServerSetup>()?;
    module.add_class::<ServerRegistration>()?;
    module.add_class::<ClientRegistrationState>()?;
    module.add_class::<ClientLoginState>()?;
    module.add_class::<ServerLoginState>()?;
    parent.add_submodule(module)?;
    Ok(())
}
