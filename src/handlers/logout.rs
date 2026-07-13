use axum::{extract::State, Json};
use serde::Serialize;
use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;
use crate::AppState;

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

pub async fn handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<LogoutResponse>, AppError> {
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await?;

    Ok(Json(LogoutResponse { success: true }))
}
