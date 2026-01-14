use opaque_ke::argon2::Argon2;
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use opaque_ke::{ml_kem::MlKem768, TripleDhKem};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;

pub(crate) const RISTRETTO255_SHA512: &str = "ristretto255_sha512";
pub(crate) const P256_SHA256: &str = "p256_sha256";
pub(crate) const P384_SHA384: &str = "p384_sha384";
pub(crate) const P521_SHA512: &str = "p521_sha512";
pub(crate) const ML_KEM_768_RISTRETTO255_SHA512: &str = "ml_kem_768_ristretto255_sha512";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SuiteId {
    Ristretto255Sha512,
    P256Sha256,
    P384Sha384,
    P521Sha512,
    MlKem768Ristretto255Sha512,
}

impl SuiteId {
    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            RISTRETTO255_SHA512 => Some(SuiteId::Ristretto255Sha512),
            P256_SHA256 => Some(SuiteId::P256Sha256),
            P384_SHA384 => Some(SuiteId::P384Sha384),
            P521_SHA512 => Some(SuiteId::P521Sha512),
            ML_KEM_768_RISTRETTO255_SHA512 => Some(SuiteId::MlKem768Ristretto255Sha512),
            _ => None,
        }
    }

    pub(crate) fn available() -> Vec<&'static str> {
        let mut suites = vec![RISTRETTO255_SHA512];
        suites.push(P256_SHA256);
        suites.push(P384_SHA384);
        suites.push(P521_SHA512);
        suites.push(ML_KEM_768_RISTRETTO255_SHA512);
        suites
    }
}

pub(crate) fn parse_suite(suite: Option<&str>) -> PyResult<SuiteId> {
    let raw = suite.unwrap_or(RISTRETTO255_SHA512);
    let normalized = raw.to_ascii_lowercase();
    SuiteId::from_str(normalized.as_str()).ok_or_else(|| {
        let available = SuiteId::available().join(", ");
        PyErr::new::<PyValueError, _>(format!(
            "unsupported cipher suite '{normalized}' (available: {available})"
        ))
    })
}

pub(crate) struct Ristretto255Sha512;

impl CipherSuite for Ristretto255Sha512 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct P256Sha256;

impl CipherSuite for P256Sha256 {
    type OprfCs = p256::NistP256;
    type KeyExchange = TripleDh<p256::NistP256, Sha256>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct P384Sha384;

impl CipherSuite for P384Sha384 {
    type OprfCs = p384::NistP384;
    type KeyExchange = TripleDh<p384::NistP384, Sha384>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct P521Sha512;

impl CipherSuite for P521Sha512 {
    type OprfCs = p521::NistP521;
    type KeyExchange = TripleDh<p521::NistP521, Sha512>;
    type Ksf = Argon2<'static>;
}

pub(crate) struct MlKem768Ristretto255Sha512;

impl CipherSuite for MlKem768Ristretto255Sha512 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDhKem<Ristretto255, Sha512, MlKem768>;
    type Ksf = Argon2<'static>;
}
