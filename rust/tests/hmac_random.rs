#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use hmac_serialiser::{Algorithm, Encoder, Error, HmacSigner, KeyInfo, Payload, DELIM};
    use serde::{Deserialize, Serialize};

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
