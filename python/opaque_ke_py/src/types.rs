use opaque_ke::argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    ClientLogin, ClientRegistration, Identifiers as OpaqueIdentifiers, ServerLogin,
    ServerRegistration as OpaqueServerRegistration, ServerSetup as OpaqueServerSetup,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::errors::{invalid_state_err, to_py_err};
use crate::py_utils;
use crate::suite::Suite;

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct Identifiers {
    #[pyo3(get)]
    client: Option<Vec<u8>>,
    #[pyo3(get)]
    server: Option<Vec<u8>>,
}

impl Identifiers {
    pub(crate) fn as_opaque(&self) -> OpaqueIdentifiers<'_> {
        OpaqueIdentifiers {
            client: self.client.as_deref(),
            server: self.server.as_deref(),
        }
    }
}

#[pymethods]
impl Identifiers {
    #[new]
    fn new(client: Option<Vec<u8>>, server: Option<Vec<u8>>) -> Self {
        Self { client, server }
    }
}

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct Argon2Params {
    #[pyo3(get)]
    memory_cost_kib: u32,
    #[pyo3(get)]
    time_cost: u32,
    #[pyo3(get)]
    parallelism: u32,
    #[pyo3(get)]
    output_length: Option<usize>,
}

impl Argon2Params {
    pub(crate) fn to_params(&self) -> PyResult<Params> {
        Params::new(
            self.memory_cost_kib,
            self.time_cost,
            self.parallelism,
            self.output_length,
        )
        .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string()))
    }
}

#[pymethods]
impl Argon2Params {
    #[new]
    fn new(
        memory_cost_kib: u32,
        time_cost: u32,
        parallelism: u32,
        output_length: Option<usize>,
    ) -> Self {
        Self {
            memory_cost_kib,
            time_cost,
            parallelism,
            output_length,
        }
    }
}

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct KeyStretching {
    #[pyo3(get)]
    variant: String,
    params: Option<Argon2Params>,
}

impl KeyStretching {
    pub(crate) fn build_ksf(&self) -> PyResult<Argon2<'static>> {
        let params = if let Some(params) = self.params.as_ref() {
            params.to_params()?
        } else {
            match self.variant.as_str() {
                "memory_constrained" => Params::new(1 << 16, 3, 4, None)
                    .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string()))?,
                "rfc_recommended" => Params::new((1 << 21) - 1, 1, 4, None)
                    .map_err(|err| PyErr::new::<PyValueError, _>(err.to_string()))?,
                _ => Params::DEFAULT,
            }
        };
        let algorithm = Algorithm::Argon2id;
        let version = Version::V0x13;
        Ok(Argon2::new(algorithm, version, params))
    }
}

#[pymethods]
impl KeyStretching {
    #[new]
    fn new(variant: &str, params: Option<PyRef<'_, Argon2Params>>) -> PyResult<Self> {
        let normalized = variant.to_ascii_lowercase();
        if normalized != "memory_constrained" && normalized != "rfc_recommended" {
            return Err(PyErr::new::<PyValueError, _>(format!(
                "unsupported key stretching variant '{normalized}'"
            )));
        }
        Ok(Self {
            variant: normalized,
            params: params.map(|value| value.clone()),
        })
    }
}

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct ClientRegistrationFinishParameters {
    identifiers: Option<Identifiers>,
    key_stretching: Option<KeyStretching>,
}

impl ClientRegistrationFinishParameters {
    pub(crate) fn identifiers(&self) -> Option<&Identifiers> {
        self.identifiers.as_ref()
    }

    pub(crate) fn key_stretching(&self) -> Option<&KeyStretching> {
        self.key_stretching.as_ref()
    }
}

#[pymethods]
impl ClientRegistrationFinishParameters {
    #[new]
    fn new(
        identifiers: Option<PyRef<'_, Identifiers>>,
        key_stretching: Option<PyRef<'_, KeyStretching>>,
    ) -> Self {
        Self {
            identifiers: identifiers.map(|value| value.clone()),
            key_stretching: key_stretching.map(|value| value.clone()),
        }
    }
}

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct ServerLoginParameters {
    context: Option<Vec<u8>>,
    identifiers: Option<Identifiers>,
}

impl ServerLoginParameters {
    pub(crate) fn context(&self) -> Option<&[u8]> {
        self.context.as_deref()
    }

    pub(crate) fn identifiers(&self) -> Option<&Identifiers> {
        self.identifiers.as_ref()
    }
}

#[pymethods]
impl ServerLoginParameters {
    #[new]
    fn new(context: Option<Vec<u8>>, identifiers: Option<PyRef<'_, Identifiers>>) -> Self {
        Self {
            context,
            identifiers: identifiers.map(|value| value.clone()),
        }
    }
}

#[pyclass(unsendable)]
#[derive(Clone)]
pub struct ClientLoginFinishParameters {
    context: Option<Vec<u8>>,
    identifiers: Option<Identifiers>,
    key_stretching: Option<KeyStretching>,
    server_s_pk: Option<Vec<u8>>,
}

impl ClientLoginFinishParameters {
    pub(crate) fn context(&self) -> Option<&[u8]> {
        self.context.as_deref()
    }

    pub(crate) fn identifiers(&self) -> Option<&Identifiers> {
        self.identifiers.as_ref()
    }

    pub(crate) fn key_stretching(&self) -> Option<&KeyStretching> {
        self.key_stretching.as_ref()
    }

    pub(crate) fn server_s_pk(&self) -> Option<&[u8]> {
        self.server_s_pk.as_deref()
    }
}

#[pymethods]
impl ClientLoginFinishParameters {
    #[new]
    fn new(
        context: Option<Vec<u8>>,
        identifiers: Option<PyRef<'_, Identifiers>>,
        key_stretching: Option<PyRef<'_, KeyStretching>>,
        server_s_pk: Option<Vec<u8>>,
    ) -> Self {
        Self {
            context,
            identifiers: identifiers.map(|value| value.clone()),
            key_stretching: key_stretching.map(|value| value.clone()),
            server_s_pk,
        }
    }
}

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

    fn serialize(&self, py: Python<'_>) -> Py<PyBytes> {
        let serialized = self.inner.serialize().to_vec();
        py_utils::to_pybytes(py, &serialized)
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

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let serialized = self.inner.serialize().to_vec();
        Ok(py_utils::to_pybytes(py, &serialized))
    }
}

#[pyclass(unsendable)]
pub struct ClientRegistrationState {
    pub(crate) inner: Option<ClientRegistration<Suite>>,
}

impl ClientRegistrationState {
    pub(crate) fn take(&mut self) -> PyResult<ClientRegistration<Suite>> {
        self.inner
            .take()
            .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))
    }
}

#[pymethods]
impl ClientRegistrationState {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = ClientRegistration::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| invalid_state_err("ClientRegistrationState has already been used"))?;
        let serialized = inner.serialize().to_vec();
        Ok(py_utils::to_pybytes(py, &serialized))
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
            .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))
    }
}

#[pymethods]
impl ClientLoginState {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = ClientLogin::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| invalid_state_err("ClientLoginState has already been used"))?;
        let serialized = inner.serialize().to_vec();
        Ok(py_utils::to_pybytes(py, &serialized))
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
            .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))
    }
}

#[pymethods]
impl ServerLoginState {
    #[staticmethod]
    fn deserialize(data: Vec<u8>) -> PyResult<Self> {
        let inner = ServerLogin::<Suite>::deserialize(&data).map_err(to_py_err)?;
        Ok(Self { inner: Some(inner) })
    }

    fn serialize(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| invalid_state_err("ServerLoginState has already been used"))?;
        let serialized = inner.serialize().to_vec();
        Ok(py_utils::to_pybytes(py, &serialized))
    }
}

pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = py_utils::new_submodule(py, parent, "types")?;
    module.add_class::<Identifiers>()?;
    module.add_class::<Argon2Params>()?;
    module.add_class::<KeyStretching>()?;
    module.add_class::<ClientRegistrationFinishParameters>()?;
    module.add_class::<ServerLoginParameters>()?;
    module.add_class::<ClientLoginFinishParameters>()?;
    module.add_class::<ServerSetup>()?;
    module.add_class::<ServerRegistration>()?;
    module.add_class::<ClientRegistrationState>()?;
    module.add_class::<ClientLoginState>()?;
    module.add_class::<ServerLoginState>()?;
    py_utils::add_submodule(py, parent, "types", &module)?;
    Ok(())
}
