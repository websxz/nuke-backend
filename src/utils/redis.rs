use crate::data::error::Error;
use rand::distributions::Alphanumeric;
use rand::Rng;
use redis::Commands;

pub fn get_connection(redis: &redis::Client) -> Result<redis::Connection, Error> {
    redis.get_connection().map_err(|e| {
        tracing::warn!("failed to get redis connection: {}", e);
        Error::InternalServerError
    })
}

pub trait InsertRefreshToken {
    fn insert_refresh_token(&mut self, token: &str, id: u32) -> Result<(), Error>;
}

impl InsertRefreshToken for redis::Connection {
    fn insert_refresh_token(&mut self, token: &str, id: u32) -> Result<(), Error> {
        let _: () = self
            .set_ex(format!("refresh:{}", token), id, 3 * 30 * 24 * 60 * 60)
            .map_err(|e| {
                tracing::warn!("failed to set refresh token: {}", e);
                Error::InternalServerError
            })?;

        Ok(())
    }
}

pub fn generate_refresh_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}
