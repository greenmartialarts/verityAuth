use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use crate::auth::password::{hash_password, verify_password};
use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;
use crate::utils::validation::validate_password;
use crate::AppState;

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

pub async fn handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>, AppError> {
    // Fetch user's current password hash
    let password_hash: String = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE id = $1"
    )
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    // Verify current password
    let is_valid = verify_password(&payload.current_password, &password_hash)?;
    if !is_valid {
        return Err(AppError::AuthError("Invalid credentials.".to_string()));
    }

    // Validate new password
    if !validate_password(&payload.new_password) {
        return Err(AppError::ValidationError(
            "New password does not meet security requirements.".to_string(),
        ));
    }

    // Hash and save new password
    let new_hash = hash_password(&payload.new_password, &state.config)?;

    sqlx::query(
        "UPDATE users SET password_hash = $1, failed_attempts = 0, locked_until = NULL, updated_at = NOW() WHERE id = $2"
    )
    .bind(&new_hash)
    .bind(user.id)
    .execute(&state.db)
    .await?;

    // Revoke refresh tokens on password change
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await?;

    Ok(Json(ChangePasswordResponse { success: true }))
}
