use axum::Json;
use serde::Serialize;
use uuid::Uuid;
use crate::errors::AppError;
use crate::middleware::AuthenticatedUser;

#[derive(Serialize)]
pub struct MeResponse {
    pub success: bool,
    pub id: Uuid,
    pub email: String,
}

pub async fn handler(
    user: AuthenticatedUser,
) -> Result<Json<MeResponse>, AppError> {
    Ok(Json(MeResponse {
        success: true,
        id: user.id,
        email: user.email,
    }))
}
