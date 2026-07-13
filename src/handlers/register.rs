use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::auth::jwt::generate_jwt;
use crate::auth::password::hash_password;
use crate::auth::refresh::generate_refresh_token;
use crate::errors::AppError;
use crate::utils::validation::{validate_email, validate_password};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let email = payload.email.trim().to_lowercase();
    let password = payload.password;

    if !validate_email(&email) {
        return Err(AppError::ValidationError("Invalid email format.".to_string()));
    }

    if !validate_password(&password) {
        return Err(AppError::ValidationError(
            "Password must be 12-256 characters long and include uppercase, lowercase, number, and special character."
                .to_string(),
        ));
    }

    // Check if user already exists
    let user_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)"
    )
    .bind(&email)
    .fetch_one(&state.db)
    .await?;

    if user_exists {
        return Err(AppError::ValidationError("Email is already registered.".to_string()));
    }

    // Hash password
    let password_hash = hash_password(&password, &state.config)?;

    // Store user
    let user_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id"
    )
    .bind(&email)
    .bind(&password_hash)
    .fetch_one(&state.db)
    .await?;

    // Generate tokens
    let (access_token, expires_in) = generate_jwt(user_id, &email, &state.config)?;
    let (raw_refresh_token, hashed_refresh_token) = generate_refresh_token();

    let expires_at = Utc::now() + chrono::Duration::seconds(state.config.jwt_refresh_expiration);

    // Store refresh token
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)"
    )
    .bind(user_id)
    .bind(hashed_refresh_token)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    Ok(Json(AuthResponse {
        success: true,
        access_token,
        refresh_token: raw_refresh_token,
        expires_in,
    }))
}
