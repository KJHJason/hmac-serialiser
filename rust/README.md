# hmac-serialiser

[![Crates.io version shield](https://img.shields.io/crates/v/hmac-serialiser.svg)](https://crates.io/crates/hmac-serialiser)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

HMAC Serialisers to cryptographically sign data like Python's ItsDangerous library but in rust.

This is mainly for developers who wants a shorter signed data compared to JSON Web Tokens (JWT) where the data might be too long for their use case.

This HMAC Serialiser is inspired by Python's ItsDangerous library and produces an output structure of `<payload>.<signature>` unlike JWT where it produces `<header>.<payload>.<signature>`.

Why is the header omitted? The header usually contains information like the algorithm used when the data was signed.
This responsibility is instead placed on the developer's hands. Hence, removing the need to store the header information about the algorithm used when verifying the signed data.

Additionally, the key used in the HMAC algorithm is expanded using HKDF to address key reuse issues by deriving the key from the original key, salt, and an optional info supplied.
Moreover, the expanded key is expanded to the length of the hash function's output size that is used in the HMAC algorithm to avoid key padding which can reduce the efforts needed to brute-force.

Regarding the cryptographic implementations, you can choose which implementations to use from via the `features` flag in the `Cargo.toml` file:
- `rust_crypto`
  - the underlying [SHA1](https://crates.io/crates/sha1), [SHA2](https://crates.io/crates/sha2), [HMAC](https://crates.io/crates/hmac), and [HKDF](https://crates.io/crates/hkdf) implementations are by [RustCrypto](https://github.com/RustCrypto).
- `ring`
  - The underlying SHA1, SHA2, HMAC, and HKDF implementations are from the [ring](https://crates.io/crates/ring) crate.

Additionally, the data serialisation and deserialisation uses the [serde](https://crates.io/crates/serde) crate and the signed data is then encoded or decoded using the [base64](https://crates.io/crates/base64) crate.

## Sample Usage

Add this to your `Cargo.toml`:
```toml
[dependencies]
hmac-serialiser = { version = "0.3.0", features = ["rust_crypto"] }
```

```rust
use hmac_serialiser::{Encoder, HmacSigner, KeyInfo, Payload, Algorithm};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct UserData {
    // Add your data fields here
    username: String,
    email: String,
}

impl Payload for UserData {
    fn get_exp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        // Add logic to retrieve expiration time if needed
        None
    }
}

fn main() {
    // Define your secret key, salt, and optional info
    let key_info = KeyInfo {
        key: b"your_secret_key".to_vec(),
        salt: b"your_salt".to_vec(),
        info: vec![], // empty info
    };

    // Initialize the HMAC signer
    let signer = HmacSigner::new(key_info, Algorithm::SHA256, Encoder::UrlSafeNoPadding);

    // Serialize your data
    let user_data = UserData {
        username: "user123".to_string(),
        email: "user123@example.com".to_string(),
    };

    // Sign the data (safe to use by clients)
    let token = signer.sign(&user_data);
    println!("Token: {}", token);
    
    // Verify the token given by the client
    let verified_data: UserData = signer.unsign(&token)
        .expect("Failed to verify token");
    println!("Verified data: {:?}", verified_data);
}
```
