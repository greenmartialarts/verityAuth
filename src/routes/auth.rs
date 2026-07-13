use axum::{routing::{get, post}, Router};
use crate::handlers::{login, register, refresh, jwks, health};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/register", post(register::handler))
        .route("/login", post(login::handler))
        .route("/refresh", post(refresh::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .route("/health", get(health::handler))
}
