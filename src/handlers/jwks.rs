use axum::{extract::State, Json};
use base64::prelude::*;
use serde::Serialize;
use crate::errors::AppError;
use crate::AppState;

#[derive(Serialize)]
struct Jwk {
    kty: String,
    crv: String,
    kid: String,
    alg: String,
    r#use: String,
    x: String,
}

#[derive(Serialize)]
pub struct JwksResponse {
    keys: Vec<Jwk>,
}

pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<JwksResponse>, AppError> {
    // Parse raw public key bytes from the configured PEM
    let pem = &state.config.jwt_public_key;
    
    // Extract base64 content between BEGIN/END markers
    let b64_content = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat()
        .replace(" ", "")
        .replace("\r", "")
        .replace("\n", "");

    let der_bytes = BASE64_STANDARD
        .decode(&b64_content)
        .map_err(|e| AppError::Internal(format!("Failed to base64 decode public key: {}", e)))?;

    // Extract the raw 32-byte public key from SPKI DER structure (offset 12)
    let raw_key_bytes = if der_bytes.len() == 44 {
        &der_bytes[12..]
    } else if der_bytes.len() == 32 {
        &der_bytes[..]
    } else {
        return Err(AppError::Internal("Unexpected Ed25519 public key format/length".to_string()));
    };

    let x = BASE64_URL_SAFE_NO_PAD.encode(raw_key_bytes);

    let keys = vec![Jwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        kid: "2026-01".to_string(),
        alg: "EdDSA".to_string(),
        r#use: "sig".to_string(),
        x,
    }];

    Ok(Json(JwksResponse { keys }))
}
