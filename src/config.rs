use std::env;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub jwt_private_key: String,
    pub jwt_public_key: String,
    pub jwt_access_expiration: i64,
    pub jwt_refresh_expiration: i64,
    pub argon_memory: u32,
    pub argon_iterations: u32,
    pub argon_parallelism: u32,
    pub allowed_origins: String,
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL environment variable must be set");

        let jwt_private_key_raw = env::var("JWT_PRIVATE_KEY")
            .expect("JWT_PRIVATE_KEY environment variable must be set");
        let jwt_private_key = Self::resolve_key_content(&jwt_private_key_raw);

        let jwt_public_key_raw = env::var("JWT_PUBLIC_KEY")
            .expect("JWT_PUBLIC_KEY environment variable must be set");
        let jwt_public_key = Self::resolve_key_content(&jwt_public_key_raw);

        let jwt_access_expiration = env::var("JWT_ACCESS_EXPIRATION")
            .unwrap_or_else(|_| "600".to_string())
            .parse::<i64>()
            .expect("JWT_ACCESS_EXPIRATION must be a valid integer");

        let jwt_refresh_expiration = env::var("JWT_REFRESH_EXPIRATION")
            .unwrap_or_else(|_| "2592000".to_string())
            .parse::<i64>()
            .expect("JWT_REFRESH_EXPIRATION must be a valid integer");

        let argon_memory = env::var("ARGON_MEMORY")
            .unwrap_or_else(|_| "65536".to_string())
            .parse::<u32>()
            .expect("ARGON_MEMORY must be a valid integer");

        let argon_iterations = env::var("ARGON_ITERATIONS")
            .unwrap_or_else(|_| "3".to_string())
            .parse::<u32>()
            .expect("ARGON_ITERATIONS must be a valid integer");

        let argon_parallelism = env::var("ARGON_PARALLELISM")
            .unwrap_or_else(|_| "2".to_string())
            .parse::<u32>()
            .expect("ARGON_PARALLELISM must be a valid integer");

        let allowed_origins = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "*".to_string());

        Self {
            database_url,
            jwt_private_key,
            jwt_public_key,
            jwt_access_expiration,
            jwt_refresh_expiration,
            argon_memory,
            argon_iterations,
            argon_parallelism,
            allowed_origins,
        }
    }

    fn resolve_key_content(val: &str) -> String {
        // If it starts with a common file path pattern, try to read the file
        if val.starts_ok_path() || Path::new(val).exists() {
            fs::read_to_string(val)
                .unwrap_or_else(|_| panic!("Failed to read key file from path: {}", val))
        } else {
            // Replace literal \n sequences with actual newlines
            val.replace("\\n", "\n")
        }
    }
}

trait PathCheck {
    fn starts_ok_path(&self) -> bool;
}

impl PathCheck for str {
    fn starts_ok_path(&self) -> bool {
        self.starts_with("./") || self.starts_with("/") || self.starts_with("../")
    }
}
