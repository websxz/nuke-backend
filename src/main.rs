use axum::routing::{get, post};
use axum::Router;
use dotenv::dotenv;
use sea_orm::Database;
use websxz_accounts_backend::handler::oauth::{exchange_token, oauth};
use std::env;
use std::sync::Arc;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use websxz_accounts_backend::handler::login::{login, refresh_token};
use websxz_accounts_backend::AppState;
use websxz_accounts_backend::handler::register::{register, verify};

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::registry().with(fmt::layer()).init();
    let db_url = env::var("DB_URL").expect("DB_URL must be set");
    let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");

    let redis_client = redis::Client::open(redis_url).expect("failed to connect redis");
    let db = Database::connect(db_url)
        .await
        .expect("database connect failed");

    let v0 = Router::new()
        .route("/login", post(login))
        .route("/refresh", get(refresh_token))
        .route("/register", post(register))
        .route("/verify", get(verify))
        .route("/oauth", get(oauth))
        .route("/oauth/token", get(exchange_token))
        .with_state(Arc::new(AppState {
            db,
            redis: redis_client,
        }));

    let app = Router::new().nest("/v0", v0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();

    tracing::info!("Server started.");
    axum::serve(listener, app).await.unwrap();
}
