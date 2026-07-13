use axum::{
    extract::{FromRequestParts, FromRef},
    http::header::AUTHORIZATION,
    http::request::Parts,
};
use axum::async_trait;
use uuid::Uuid;
use crate::auth::jwt::verify_jwt;
use crate::errors::AppError;

pub struct AuthenticatedUser {
    pub id: Uuid,
    pub email: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    crate::AppState: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| AppError::AuthError("Invalid credentials.".to_string()))?;

        if !auth_header.starts_with("Bearer ") {
            return Err(AppError::AuthError("Invalid credentials.".to_string()));
        }

        let token = auth_header[7..].to_string();

        // Extract State using FromRef
        let app_state = crate::AppState::from_ref(state);

        let claims = verify_jwt(&token, &app_state.config)?;

        let id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::AuthError("Invalid credentials.".to_string()))?;

        Ok(Self {
            id,
            email: claims.email,
        })
    }
}
