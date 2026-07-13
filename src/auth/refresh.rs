use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn generate_refresh_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    
    let raw = hex::encode(bytes);
    let hashed = hash_token(&raw);
    
    (raw, hashed)
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
