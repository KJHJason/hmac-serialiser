use crate::algorithm::Algorithm;

#[cfg(not(feature = "ring"))]
use hkdf::Hkdf;

#[cfg(feature = "ring")]
use ring::hkdf;

pub struct HkdfWrapper {
    algo: Algorithm,
}

#[cfg(not(feature = "ring"))]
macro_rules! hkdf_expand {
    ($self:ident, $ikm:ident, $salt:ident, $info:ident, $D:ty) => {{
        let hk = Hkdf::<$D>::new(Some($salt), $ikm);
        let mut okm = vec![0u8; $self.algo.output_length()];
        hk.expand($info, &mut okm)
            .expect("could not expand key due to possibly invalid length");
        okm
    }};
}

impl HkdfWrapper {
    pub fn new(algo: Algorithm) -> Self {
        Self { algo }
    }

    #[cfg(not(feature = "ring"))]
    pub fn expand(&self, ikm: &[u8], salt: &[u8], info: &[u8]) -> Vec<u8> {
        match self.algo {
            Algorithm::SHA1 => hkdf_expand!(self, ikm, salt, info, sha1::Sha1),
            Algorithm::SHA256 => hkdf_expand!(self, ikm, salt, info, sha2::Sha256),
            Algorithm::SHA384 => hkdf_expand!(self, ikm, salt, info, sha2::Sha384),
            Algorithm::SHA512 => hkdf_expand!(self, ikm, salt, info, sha2::Sha512),
        }
    }

    #[cfg(feature = "ring")]
    pub fn expand(&self, ikm: &[u8], salt: &[u8], info: &[u8]) -> Vec<u8> {
        let hkdf_algo = self.algo.to_hkdf();
        let prk = hkdf::Salt::new(hkdf_algo, salt).extract(ikm);

        let mut okm = vec![0u8; self.algo.output_length()];
        let okm_slice = &mut okm[..];
        prk.expand(&[info], self.algo.to_hmac())
            .expect("could not expand key due to possibly invalid length")
            .fill(okm_slice)
            .expect("could not fill key due to possibly invalid length");
        okm
    }
}
