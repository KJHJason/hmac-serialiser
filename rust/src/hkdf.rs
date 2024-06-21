use crate::algorithm::Algorithm;
use hkdf::Hkdf;

pub struct HkdfWrapper {
    algo: Algorithm,
}

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

    pub fn expand(&self, ikm: &[u8], salt: &[u8], info: &[u8]) -> Vec<u8> {
        match self.algo {
            Algorithm::SHA1 => hkdf_expand!(self, ikm, salt, info, sha1::Sha1),
            Algorithm::SHA256 => hkdf_expand!(self, ikm, salt, info, sha2::Sha256),
            Algorithm::SHA384 => hkdf_expand!(self, ikm, salt, info, sha2::Sha384),
            Algorithm::SHA512 => hkdf_expand!(self, ikm, salt, info, sha2::Sha512),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::Algorithm;
    use rand;
    use rand::Rng as _;

    pub fn get_random_bytes(length: usize) -> Vec<u8> {
        let mut random_bytes = vec![0u8; length];
        rand::thread_rng().fill(&mut random_bytes[..]);
        random_bytes
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn test_empty_key_hkdf_expand() {
        let salt = b"";
        let ikm = b"";
        let info = b"";
        let algo = Algorithm::SHA1;
        let algo_output_length = algo.output_length();
        let hkdf = HkdfWrapper::new(algo);
        let okm = hkdf.expand(ikm, salt, info);

        println!("sha1 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), algo_output_length);
    }

    #[test]
    fn test_hdkf_expand_with_salt() {
        let salt = get_random_bytes(32);
        let ikm = b"";
        let info = b"";
        let algo = Algorithm::SHA256;
        let algo_output_length = algo.output_length();
        let hkdf = HkdfWrapper::new(algo);
        let okm = hkdf.expand(ikm, &salt, info);

        println!("sha256 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), algo_output_length);
    }

    #[test]
    fn test_hdkf_expand_with_ikm() {
        let salt = b"";
        let ikm = b"kjhjason";
        let info = b"";
        let algo = Algorithm::SHA384;
        let algo_output_length = algo.output_length();
        let hkdf = HkdfWrapper::new(algo);
        let okm = hkdf.expand(ikm.as_ref(), salt, info);

        println!("sha384 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), algo_output_length);
    }

    #[test]
    fn test_hdkf_expand_with_info() {
        let salt = b"";
        let ikm = b"";
        let info = b"kjhjason";
        let algo = Algorithm::SHA512;
        let algo_output_length = algo.output_length();
        let hkdf = HkdfWrapper::new(algo);
        let okm = hkdf.expand(ikm, salt, info);

        println!("sha512 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), algo_output_length);
    }

    #[test]
    fn test_hdkf_expand_with_all() {
        let salt = b"kjhjason.com";
        let ikm = b"jason";
        let info = b"kjhjason";
        let algo = Algorithm::SHA256;
        let algo_output_length = algo.output_length();
        let hkdf = HkdfWrapper::new(algo);
        let okm = hkdf.expand(ikm, salt, info);

        println!("sha256 okm: {}", bytes_to_hex(&okm));
        assert_eq!(okm.len(), algo_output_length);
    }
}
