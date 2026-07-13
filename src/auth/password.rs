use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use crate::config::Config;
use crate::errors::AppError;

pub fn hash_password(password: &str, config: &Config) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    
    let params = Params::new(
        config.argon_memory,
        config.argon_iterations,
        config.argon_parallelism,
        Some(32),
    )
    .map_err(|e| AppError::Internal(format!("Failed to build Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Failed to parse password hash: {}", e)))?;

    let argon2 = Argon2::default();
    
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}
