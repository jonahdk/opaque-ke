use opaque_ke::argon2::Argon2;
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use sha2::Sha512;

pub(crate) struct Ristretto255Sha512;

impl CipherSuite for Ristretto255Sha512 {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

pub(crate) const SUITE_NAME: &str = "ristretto255_sha512";

pub(crate) type Suite = Ristretto255Sha512;
