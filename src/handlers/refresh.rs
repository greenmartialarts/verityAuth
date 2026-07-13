use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;
use crate::auth::jwt::generate_jwt;
use crate::auth::refresh::{generate_refresh_token, hash_token};
use crate::errors::AppError;
use crate::handlers::register::AuthResponse;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(sqlx::FromRow)]
struct TokenRecord {
    user_id: Uuid,
    expires_at: DateTime<Utc>,
}

pub async fn handler(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let hashed_payload_token = hash_token(&payload.refresh_token);

    // Find token in database
    let token_record = sqlx::query_as::<_, TokenRecord>(
        "SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = $1"
    )
    .bind(&hashed_payload_token)
    .fetch_optional(&state.db)
    .await?;

    let record = match token_record {
        Some(r) => r,
        None => return Err(AppError::AuthError("Invalid credentials.".to_string())),
    };

    // Verify expiration
    if record.expires_at < Utc::now() {
        // Delete expired token
        sqlx::query(
            "DELETE FROM refresh_tokens WHERE token_hash = $1"
        )
        .bind(&hashed_payload_token)
        .execute(&state.db)
        .await?;
        
        return Err(AppError::AuthError("Invalid credentials.".to_string()));
    }

    // Get user details for JWT generation
    let user_email: String = sqlx::query_scalar(
        "SELECT email FROM users WHERE id = $1"
    )
    .bind(record.user_id)
    .fetch_one(&state.db)
    .await?;

    // Rotate refresh token: delete old, insert new
    sqlx::query(
        "DELETE FROM refresh_tokens WHERE token_hash = $1"
    )
    .bind(&hashed_payload_token)
    .execute(&state.db)
    .await?;

    let (new_raw, new_hashed) = generate_refresh_token();
    let expires_at = Utc::now() + chrono::Duration::seconds(state.config.jwt_refresh_expiration);

    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)"
    )
    .bind(record.user_id)
    .bind(&new_hashed)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    // Generate new access token
    let (access_token, expires_in) = generate_jwt(record.user_id, &user_email, &state.config)?;

    Ok(Json(AuthResponse {
        success: true,
        access_token,
        refresh_token: new_raw,
        expires_in,
    }))
}
