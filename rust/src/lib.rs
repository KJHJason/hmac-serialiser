//! # HMAC Signer
//!
//! `hmac-serialiser` is a Rust library for generating and verifying HMAC signatures for secure data transmission.
//!
//! Regarding the cryptographic implementations, the underlying [SHA1](https://crates.io/crates/sha1),
//! [SHA2](https://crates.io/crates/sha2), [HMAC](https://crates.io/crates/hmac),
//! and [HKDF](https://crates.io/crates/hkdf) implementations are by [RustCrypto](https://github.com/RustCrypto).
//!
//! Additionally, the data serialisation and deserialisation uses the [serde](https://crates.io/crates/serde) crate and
//! the signed data is then encoded or decoded using the [base64](https://crates.io/crates/base64) crate.
//!
//! ## License
//!
//! This library is licensed under the MIT license.
//!
//! ## Features
//!
//! - Supports various encoding schemes for signatures.
//! - Flexible HMAC signer logic for custom data types.
//! - Provides a convenient interface for signing and verifying data.
//!
//! ## Example
//!
//! ```rust
//! use hmac_serialiser::{Encoder, HmacSigner, KeyInfo, Payload, Algorithm};
//! use serde::{Serialize, Deserialize};
//! 
//! #[derive(Serialize, Deserialize, Debug)]
//! struct UserData {
//!     // Add your data fields here
//!     username: String,
//!     email: String,
//! }
//! 
//! impl Payload for UserData {
//!     fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
//!         // Add logic to retrieve expiration time if needed
//!         None
//!     }
//! }
//! 
//! fn main() {
//!     // Define your secret key, salt, and optional info
//!     let key_info = KeyInfo {
//!         key: b"your_secret_key".to_vec(),
//!         salt: b"your_salt".to_vec(),
//!         info: vec![], // empty info
//!     };
//! 
//!     // Initialize the HMAC signer
//!     let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafeNoPadding);
//! 
//!     // Serialize your data
//!     let user_data = UserData {
//!         username: "user123".to_string(),
//!         email: "user123@example.com".to_string(),
//!     };
//! 
//!     // Sign the data (safe to use by clients)
//!     let token = signer.sign(&user_data);
//!     println!("Token: {}", token);
//!     
//!     // Verify the token given by the client
//!     let verified_data: UserData = signer.unsign(&token)
//!         .expect("Failed to verify token");
//!     println!("Verified data: {:?}", verified_data);
//! }
//! ```
//!
//! ## Supported Encoders
//!
//! - `Standard`: Standard base64 encoding.
//! - `UrlSafe`: URL-safe base64 encoding.
//! - `StandardNoPadding`: Standard base64 encoding without padding.
//! - `UrlSafeNoPadding`: URL-safe base64 encoding without padding. (Default)
//!
//! ## Supported HMAC Algorithms
//!
//! - `SHA1`
//! - `SHA256` (Default)
//! - `SHA384`
//! - `SHA512`
//!
//! Note: Although SHA1 is cryptographically broken, HMAC-SHA1 is not used for integrity checks like file hash checks.
//! Therefore, it is still considered secure to use HMAC-SHA1 to verify the authenticity of a given payload.
//! However, it is still recommended to choose a stronger hash function like SHA256 or even SHA512.
//!
//! ## Traits
//!
//! - `Payload`: A trait for data structures that can be signed and verified.
//!
//! ## Errors
//!
//! Errors are represented by the `Error` enum, which includes:
//!
//! - `InvalidInput`: Invalid input payload.
//! - `InvalidSignature`: Invalid signature provided.
//! - `InvalidPayload`: Invalid payload structure when de-serialising valid payload
//! - `InvalidToken`: Invalid token provided.
//! - `HkdfExpandError`: Error during key expansion.
//! - `HkdfFillError`: Error during key filling.
//! - `TokenExpired`: Token has expired.
//!
//! ## Contributing
//!
//! Contributions are welcome! Feel free to open issues and pull requests on [GitHub](https://github.com/KJHJason/hmac-serialiser-rs).
//!
//! ```

pub mod algorithm;
pub mod errors;
mod hkdf;

use algorithm::Algorithm;
use base64::{engine::general_purpose, Engine as _};
use errors::Error;
use hmac::Mac;
use serde::{Deserialize, Serialize};

const DELIM: char = '.';

/// An enum for defining the encoding scheme for the payload and the signature.
///
/// Usually, you should use the encoder with no padding to shorten the token length by a few characters.
///
/// Whether to use URL-safe or Standard encoding depends on the application's requirements.
///
/// For example, if you are developing a password reset route
/// in a web application like /password-reset?token=...., you would want
/// to use the UrlSafe encoding so that the token can be safely used in the URL.
#[derive(Default, Debug, Clone)]
pub enum Encoder {
    // Standard base64 encoding
    Standard,

    // URL-safe base64 encoding
    UrlSafe,

    // Standard base64 encoding without padding
    StandardNoPadding,

    #[default]
    // URL-safe base64 encoding without padding
    UrlSafeNoPadding,
}

impl Encoder {
    #[inline]
    fn get_encoder(&self) -> general_purpose::GeneralPurpose {
        match self {
            Encoder::Standard => general_purpose::STANDARD,
            Encoder::UrlSafe => general_purpose::URL_SAFE,
            Encoder::StandardNoPadding => general_purpose::STANDARD_NO_PAD,
            Encoder::UrlSafeNoPadding => general_purpose::URL_SAFE_NO_PAD,
        }
    }
}

/// A trait for custom payload types that can be signed and verified.
///
/// This trait defines methods for retrieving expiration time and is used in conjunction with
/// signing and verifying operations.
///
/// If your payload type does not require an expiration time, you can implement the trait as follows:
/// ```rust
/// use hmac_serialiser::Payload;
/// use chrono::{DateTime, Utc};
///
/// struct CustomData {
///    data: String,
/// }
///
/// impl Payload for CustomData {
///    fn get_exp(&self) -> Option<DateTime<Utc>> {
///       None
///   }
/// }
///```
pub trait Payload {
    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>>;
}

/// A struct that holds the key information required for key expansion.
///
/// The key expansion process is used to derive a new key from the main secret key. Its main purpose is to expand
/// the key to the HMAC algorithm's block size to avoid padding which can reduce the effort required for a brute force attack.
///
/// The `KeyInfo` struct contains the main secret key, salt for key expansion, and optional application-specific info.
/// - `key` field is the main secret key used for signing and verifying the payload.
/// - `salt` field is used for key expansion.
/// - `info` field is optional and can be used to provide application-specific information.
///
/// The `salt` and the `info` fields can help to prevent key reuse and provide additional security.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    // Main secret key
    pub key: Vec<u8>,

    // Salt for the key expansion (Optional)
    pub salt: Vec<u8>,

    // Application specific info (Optional)
    pub info: Vec<u8>,
}

impl Default for KeyInfo {
    fn default() -> Self {
        Self {
            key: vec![],
            salt: vec![],
            info: vec![],
        }
    }
}

/// A struct that holds the HMAC signer logic.
///
/// The `HmacSigner` struct is used for signing and verifying the payload using HMAC signatures.
#[derive(Debug, Clone)]
pub struct HmacSigner {
    expanded_key: Vec<u8>,
    algo: Algorithm,
    encoder: general_purpose::GeneralPurpose,
}

macro_rules! get_hmac {
    ($self:ident, $D:ty) => {
        hmac::Hmac::<$D>::new_from_slice(&$self.expanded_key)
            .expect("HMAC can take key of any size")
    };
}

macro_rules! hmac_sign {
    ($self:ident, $payload:ident, $D:ty) => {{
        let mut mac = get_hmac!($self, $D);
        mac.update($payload);
        mac.finalize().into_bytes().to_vec()
    }};
}

macro_rules! hmac_verify {
    ($self:ident, $payload:ident, $signature:ident, $D:ty) => {{
        let mut mac = get_hmac!($self, $D);
        mac.update($payload);
        mac.verify_slice($signature).is_ok()
    }};
}

impl HmacSigner {
    pub fn new(key_info: KeyInfo, algo: Algorithm, encoder: Encoder) -> Self {
        if key_info.key.is_empty() {
            panic!("Key cannot be empty"); // panic if key is empty as it is usually due to developer error
        }

        let expanded_key = hkdf::HkdfWrapper::new(algo.clone()).expand(
            &key_info.key,
            &key_info.salt,
            &key_info.info,
        );
        Self {
            expanded_key,
            algo,
            encoder: encoder.get_encoder(),
        }
    }
    #[inline]
    fn sign_payload(&self, payload: &[u8]) -> Vec<u8> {
        match self.algo {
            Algorithm::SHA1 => hmac_sign!(self, payload, sha1::Sha1),
            Algorithm::SHA256 => hmac_sign!(self, payload, sha2::Sha256),
            Algorithm::SHA384 => hmac_sign!(self, payload, sha2::Sha384),
            Algorithm::SHA512 => hmac_sign!(self, payload, sha2::Sha512),
        }
    }

    #[inline]
    fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        match self.algo {
            Algorithm::SHA1 => hmac_verify!(self, payload, signature, sha1::Sha1),
            Algorithm::SHA256 => hmac_verify!(self, payload, signature, sha2::Sha256),
            Algorithm::SHA384 => hmac_verify!(self, payload, signature, sha2::Sha384),
            Algorithm::SHA512 => hmac_verify!(self, payload, signature, sha2::Sha512),
        }
    }
}

impl HmacSigner {
    /// Verifies the token and returns the deserialised payload.
    ///
    /// Before verifying the payload, the input token is split into two parts: the encoded payload and the signature.
    /// If the token does not contain two parts, an `InvalidInput` error is returned.
    ///
    /// Afterwards, if the encoded payload is empty, an `InvalidToken` error is returned even if the signature is valid.
    ///
    /// The signature is then decoded using the provided encoder. If the decoding fails, an `InvalidSignature` error is returned.
    ///
    /// The encoded payload and the signature are then verified via HMAC. If the verification fails, an `InvalidToken` error is returned.
    ///
    /// If the encoded payload is valid, the payload is decoded and deserialised using serde.
    /// If the payload's expiration time is not provided, the deserialized payload is returned.
    /// Otherwise, the expiration time is checked against the current time. If the expiration time is earlier than the current time, a `TokenExpired` error is returned.
    ///
    /// Sample Usage:
    /// ```rust
    /// use hmac_serialiser::{HmacSigner, KeyInfo, Encoder, algorithm::Algorithm, errors::Error, Payload};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Serialize, Deserialize, Debug)]
    /// struct UserData {
    ///     username: String,
    /// }
    /// impl Payload for UserData {
    ///    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
    ///         None
    ///     }
    /// }
    ///
    /// let key_info = KeyInfo {
    ///    key: b"your_secret_key".to_vec(),
    ///    salt: b"your_salt".to_vec(),
    ///    info: vec![], // empty info
    /// };
    ///
    /// // Initialize the HMAC signer
    /// let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafe);
    /// let result: Result<UserData, Error> = signer.unsign(&"token.signature");
    /// // or
    /// let result = signer.unsign::<UserData>(&"token.signature");
    /// ```
    pub fn unsign<T: for<'de> Deserialize<'de> + Payload>(&self, token: &str) -> Result<T, Error> {
        let parts: Vec<&str> = token.split(DELIM).collect();
        if parts.len() != 2 {
            return Err(Error::InvalidInput(token.to_string()));
        }

        let encoded_payload = parts[0];
        if encoded_payload.is_empty() {
            return Err(Error::InvalidToken);
        }

        let signature = self
            .encoder
            .decode(parts[1])
            .map_err(|_| Error::InvalidSignature)?;
        let encoded_payload = parts[0].as_bytes();
        if !self.verify(&encoded_payload, &signature) {
            return Err(Error::InvalidToken);
        }

        // at this pt, the token is valid and hence we can safely unwrap
        let decoded_payload = self
            .encoder
            .decode(encoded_payload)
            .expect("payload should be valid base64");
        let payload = String::from_utf8(decoded_payload).expect("payload should be valid utf-8");

        // usually de-serialisation errors are
        // caused when the developer was expecting the
        // wrong payload type or has recently changed the payload type
        let deserialised_payload: T =
            serde_json::from_str(&payload).map_err(|_| Error::InvalidPayload)?;

        if let Some(expiry) = deserialised_payload.get_exp() {
            if expiry < chrono::Utc::now() {
                return Err(Error::TokenExpired);
            }
        }
        Ok(deserialised_payload)
    }

    /// Signs the payload and returns the token which can be sent to the client.
    ///
    /// Sample Usage:
    /// ```rust
    /// use hmac_serialiser::{HmacSigner, KeyInfo, Encoder, algorithm::Algorithm, errors::Error, Payload};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Serialize, Deserialize, Debug)]
    /// struct UserData {
    ///     username: String,
    /// }
    /// impl Payload for UserData {
    ///    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
    ///         None
    ///     }
    /// }
    ///
    /// let key_info = KeyInfo {
    ///    key: b"your_secret_key".to_vec(),
    ///    salt: b"your_salt".to_vec(),
    ///    info: b"auth-context".to_vec(),
    /// };
    ///
    /// // Initialize the HMAC signer
    /// let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafe);
    /// let user = UserData { username: "user123".to_string() };
    /// let result: String = signer.sign(&user);
    /// ```
    pub fn sign<T: Serialize + Payload>(&self, payload: &T) -> String {
        let token = serde_json::to_string(payload).unwrap();
        let token = self.encoder.encode(token.as_bytes());
        let signature = self.sign_payload(token.as_bytes());
        let signature = self.encoder.encode(&signature);
        format!("{}{}{}", token, DELIM, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[derive(Serialize, Deserialize, Debug)]
    struct TestClaim {
        #[serde(with = "chrono::serde::ts_seconds")]
        exp: chrono::DateTime<Utc>,
        data: String,
    }

    impl Payload for TestClaim {
        fn get_exp(&self) -> Option<chrono::DateTime<Utc>> {
            Some(self.exp)
        }
    }

    fn setup(salt: Vec<u8>, info: Vec<u8>, algo: Algorithm, encoder: Encoder) -> HmacSigner {
        let key_info = KeyInfo {
            key: b"test_secret_key".to_vec(),
            salt,
            info,
        };
        HmacSigner::new(key_info, algo, encoder)
    }

    #[test]
    fn test_sign_and_unsign_valid_token() {
        let signer = setup(vec![], vec![], Algorithm::SHA256, Encoder::UrlSafeNoPadding);
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let verified_claim: TestClaim = signer.unsign(&token).unwrap();
        println!("Token: {}", token);
        println!("Verified claim: {:?}", verified_claim);
        assert_eq!(verified_claim.data, claim.data);
    }

    #[test]
    fn test_invalid_token() {
        let data = "tttttttttttttttttttttttttttttttttttttttttt";
        let expected_error = Error::InvalidInput(data.to_string());
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        match signer.unsign::<TestClaim>(&data) {
            Ok(_) => panic!("Expected error"),
            Err(e) => assert_eq!(e, expected_error),
        };
    }

    #[test]
    fn test_invalid_token_with_valid_signature() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let valid_signature = token.split('.').collect::<Vec<&str>>()[1];
        let invalid_token = format!("{}.{}", "bad_data", valid_signature);
        println!("Invalid token: {}", invalid_token);
        println!("Valid token: {}", token);

        let result: Result<TestClaim, Error> = signer.unsign(&invalid_token);
        assert!(matches!(result, Err(Error::InvalidToken)));
    }

    #[test]
    fn test_unsign_expired_token() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() - Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let result: Result<TestClaim, Error> = signer.unsign(&token);

        assert!(matches!(result, Err(Error::TokenExpired)));
    }

    #[test]
    fn test_unsign_invalid_signature() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let mut invalid_token = token.clone();
        invalid_token.push_str("invalid");

        let result: Result<TestClaim, Error> = signer.unsign(&invalid_token);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_unsign_malformed_token() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );

        let malformed_token = "malformed.token";

        let result: Result<TestClaim, Error> = signer.unsign(malformed_token);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }

    #[test]
    fn test_unsign_invalid_base64_signature() {
        let signer = setup(
            vec![1, 2, 3],
            vec![4, 5, 6],
            Algorithm::SHA256,
            Encoder::UrlSafe,
        );
        let claim = TestClaim {
            exp: Utc::now() + Duration::hours(1),
            data: "test_data".to_string(),
        };

        let token = signer.sign(&claim);
        let parts: Vec<&str> = token.split(DELIM).collect();
        let invalid_token = format!("{}.{}", parts[0], "invalid_base64");

        let result: Result<TestClaim, Error> = signer.unsign(&invalid_token);

        assert!(matches!(result, Err(Error::InvalidSignature)));
    }
}
