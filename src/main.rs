use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    Router,
};
use axum::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod auth;
mod config;
mod database;
mod errors;
mod handlers;
mod middleware;
mod models;
mod routes;
mod utils;

use crate::auth::rate_limit::IpRateLimiter;
use crate::config::Config;
use crate::database::DbPool;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Config,
    pub ip_rate_limiter: Arc<IpRateLimiter>,
}

#[async_trait]
impl<S> FromRequestParts<S> for AppState
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_ref(state))
    }
}



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env();

    // Connect to database and run migrations
    let db = database::connect(&config.database_url).await?;

    let state = AppState {
        db,
        config: config.clone(),
        ip_rate_limiter: Arc::new(IpRateLimiter::new()),
    };

    // Configure CORS
    let cors = if config.allowed_origins == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let mut origins = Vec::new();
        for origin in config.allowed_origins.split(',') {
            if let Ok(value) = origin.trim().parse() {
                origins.push(value);
            }
        }
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(Any)
            .allow_headers(Any)
    };

    // Combine routes
    let app = Router::new()
        .nest("/", routes::auth::router())
        .nest("/", routes::me::router())
        .layer(cors)
        .with_state(state);

    // Run axum server
    // Render (and most PaaS platforms) inject a PORT env var — bind to it.
    // Fall back to 8080 for local development.
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
