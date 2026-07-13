use axum::{routing::{get, post}, Router};
use crate::handlers::{change_password, logout, me};
use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/me", get(me::handler))
        .route("/change-password", post(change_password::handler))
        .route("/logout", post(logout::handler))
}
