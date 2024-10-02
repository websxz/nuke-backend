use sea_orm::DatabaseConnection;

pub mod data;
pub mod entity;
pub mod handler;
pub mod middleware;
pub mod utils;

pub struct AppState {
    pub db: DatabaseConnection,
    pub redis: redis::Client,
}
