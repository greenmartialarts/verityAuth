use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::config::Config;
use crate::errors::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub iat: i64,
    pub exp: i64,
}

pub fn generate_jwt(user_id: Uuid, email: &str, config: &Config) -> Result<(String, i64), AppError> {
    let iat = Utc::now();
    let duration = Duration::seconds(config.jwt_access_expiration);
    let exp = iat + duration;
    
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        iat: iat.timestamp(),
        exp: exp.timestamp(),
    };

    let encoding_key = EncodingKey::from_ed_pem(config.jwt_private_key.as_bytes())
        .map_err(|e| AppError::Internal(format!("Invalid Ed25519 private key: {}", e)))?;

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("2026-01".to_string());
    let token = encode(&header, &claims, &encoding_key)
        .map_err(|e| AppError::Internal(format!("Failed to sign JWT: {}", e)))?;

    Ok((token, duration.num_seconds()))
}

pub fn verify_jwt(token: &str, config: &Config) -> Result<Claims, AppError> {
    let decoding_key = DecodingKey::from_ed_pem(config.jwt_public_key.as_bytes())
        .map_err(|e| AppError::Internal(format!("Invalid Ed25519 public key: {}", e)))?;

    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|_| AppError::AuthError("Invalid credentials.".to_string()))?;

    Ok(token_data.claims)
}
