use sha2::{Digest, Sha256};
use std::fmt::Write;

pub fn salt_password(password: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    let mut result = String::new();
    hasher.update(password);
    hasher.update(salt);

    for byte in hasher.finalize() {
        write!(&mut result, "{:02x}", byte).unwrap();
    }

    result
}
