use crate::data::error::Error;
use lazy_static::lazy_static;
use lettre::transport::smtp::PoolConfig;
use lettre::{Message, SmtpTransport, Transport};
use std::env;

lazy_static! {
    static ref SENDER: SmtpTransport =
        SmtpTransport::from_url(&env::var("SMTP_URL").expect("SMTP_URL must be set"))
            .expect("failed to parse smtp url")
            .pool_config(PoolConfig::new().max_size(20))
            .build();
}

pub fn send(message: &Message) -> Result<(), Error> {
    if cfg!(debug_assertions) {
        tracing::debug!("{}", String::from_utf8(message.formatted()).unwrap());
        return Ok(());
    }

    let _ = SENDER.send(message).map_err(|e| {
        tracing::warn!("failed to send email: {}", e);
        Error::InternalServerError
    });
    Ok(())
}
