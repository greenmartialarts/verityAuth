use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::time::sleep;
use uuid::Uuid;
use crate::auth::jwt::generate_jwt;
use crate::auth::password::verify_password;
use crate::auth::rate_limit::get_failed_delay;
use crate::auth::refresh::generate_refresh_token;
use crate::errors::AppError;
use crate::handlers::register::AuthResponse;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(sqlx::FromRow)]
struct LoginUserRecord {
    id: Uuid,
    password_hash: String,
    failed_attempts: i32,
    locked_until: Option<DateTime<Utc>>,
}

pub async fn handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let ip = addr.ip();

    // 1. IP rate limiting
    if !state.ip_rate_limiter.check_rate_limit(ip) {
        return Err(AppError::RateLimitError("Rate limit exceeded.".to_string()));
    }

    let email = payload.email.trim().to_lowercase();
    let password = payload.password;

    // 2. Find user by email
    let user_opt = sqlx::query_as::<_, LoginUserRecord>(
        "SELECT id, password_hash, failed_attempts, locked_until FROM users WHERE email = $1"
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    let user = match user_opt {
        Some(u) => u,
        None => {
            // User does not exist. Apply a generic delay to prevent timing analysis
            sleep(get_failed_delay(1)).await;
            return Err(AppError::AuthError("Invalid credentials.".to_string()));
        }
    };

    // 3. Check lock status
    let now = Utc::now();
    if let Some(locked_until) = user.locked_until {
        if locked_until > now {
            // Apply delay even if locked
            sleep(get_failed_delay(user.failed_attempts)).await;
            return Err(AppError::AuthError("Invalid credentials.".to_string()));
        }
    }

    // 4. Verify password
    let is_valid = verify_password(&password, &user.password_hash)?;

    if is_valid {
        // Success: Reset failed login counter
        sqlx::query(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = $1"
        )
        .bind(user.id)
        .execute(&state.db)
        .await?;

        // Generate tokens
        let (access_token, expires_in) = generate_jwt(user.id, &email, &state.config)?;
        let (raw_refresh_token, hashed_refresh_token) = generate_refresh_token();

        let expires_at = Utc::now() + chrono::Duration::seconds(state.config.jwt_refresh_expiration);

        // Delete old refresh tokens and insert the new one
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
            .bind(user.id)
            .execute(&state.db)
            .await?;

        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)"
        )
        .bind(user.id)
        .bind(&hashed_refresh_token)
        .bind(expires_at)
        .execute(&state.db)
        .await?;

        Ok(Json(AuthResponse {
            success: true,
            access_token,
            refresh_token: raw_refresh_token,
            expires_in,
        }))
    } else {
        // Unsuccessful: Increment failed attempts
        let new_failures = user.failed_attempts + 1;
        let lock_duration = if new_failures >= 15 {
            // Lock account for 15 minutes
            Some(now + chrono::Duration::minutes(15))
        } else {
            None
        };

        sqlx::query(
            "UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3"
        )
        .bind(new_failures)
        .bind(lock_duration)
        .bind(user.id)
        .execute(&state.db)
        .await?;

        // Apply exponential delay
        let delay = get_failed_delay(new_failures);
        sleep(delay).await;

        Err(AppError::AuthError("Invalid credentials.".to_string()))
    }
}
