use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

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
            Algorithm::SHA1 => Sha1::output_size(),
            Algorithm::SHA256 => Sha256::output_size(),
            Algorithm::SHA384 => Sha384::output_size(),
            Algorithm::SHA512 => Sha512::output_size(),
        }
    }
}
