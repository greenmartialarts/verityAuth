use axum::{extract::State, Json};
use serde::Serialize;
use crate::errors::AppError;
use crate::AppState;

#[derive(Serialize)]
pub struct HealthResponse {
    pub success: bool,
    pub status: String,
}

pub async fn handler(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, AppError> {
    // Check database responsiveness
    let _: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(HealthResponse {
        success: true,
        status: "healthy".to_string(),
    }))
}
