#[cfg(feature = "ring")]
use ring::{hkdf, hmac};

#[derive(Default, Clone, Debug)]
pub enum Algorithm {
    SHA1,
    #[default]
    SHA256,
    SHA384,
    SHA512,
}

impl Algorithm {
    #[inline]
    pub fn output_length(&self) -> usize {
        match self {
            Algorithm::SHA1 => 20,
            Algorithm::SHA256 => 32,
            Algorithm::SHA384 => 48,
            Algorithm::SHA512 => 64,
        }
    }

    #[cfg(feature = "ring")]
    pub fn to_hmac(&self) -> hmac::Algorithm {
        match self {
            Algorithm::SHA1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::SHA256 => hmac::HMAC_SHA256,
            Algorithm::SHA384 => hmac::HMAC_SHA384,
            Algorithm::SHA512 => hmac::HMAC_SHA512,
        }
    }

    #[cfg(feature = "ring")]
    pub fn to_hkdf(&self) -> hkdf::Algorithm {
        match self {
            Algorithm::SHA1 => hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::SHA256 => hkdf::HKDF_SHA256,
            Algorithm::SHA384 => hkdf::HKDF_SHA384,
            Algorithm::SHA512 => hkdf::HKDF_SHA512,
        }
    }
}
