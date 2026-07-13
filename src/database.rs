use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use std::time::Duration;
use tracing::info;

pub type DbPool = Pool<Postgres>;

pub async fn connect(database_url: &str) -> Result<DbPool, sqlx::Error> {
    info!("Connecting to PostgreSQL database...");
    
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await?;
        
    info!("Successfully connected to the database. Running migrations...");
    
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await?;
        
    info!("Migrations applied successfully.");
    
    Ok(pool)
}
