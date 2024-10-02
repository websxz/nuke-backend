use crate::data::error::Error;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fmt::Debug;
use std::ops::Deref;

lazy_static! {
    static ref TURNSTILE_URL: &'static str =
        "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    static ref TURNSTILE_SECRET_KEY: &'static str = env::var("TURNSTILE_SECRET_KEY")
        .expect("TURNSTILE_SECRET_KEY env not found")
        .leak();
    static ref REQUEST_CLIENT: reqwest::Client = reqwest::Client::new();
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", content = "content")]
pub enum Captcha {
    #[serde(rename = "turnstile")]
    Turnstile(String),
}

pub async fn verify_captcha(captcha: Captcha, remote_ip: Option<&str>) -> Result<(), Error> {
    if cfg!(debug_assertions) {
        return Ok(())
    }

    match captcha {
        Captcha::Turnstile(token) => verify_turnstile(token.as_str(), remote_ip).await,
    }
}

async fn verify_turnstile(token: &str, remote_ip: Option<&str>) -> Result<(), Error> {
    let resp = REQUEST_CLIENT
        .post(*TURNSTILE_URL)
        .body(
            json!({
                "secret": *TURNSTILE_URL,
                "response": token,
                "remoteip": remote_ip,
            })
            .to_string(),
        )
        .send()
        .await
        .map_err(|e| {
            tracing::debug!("encounter an when verifying turnstile: {}", e);
            Error::InternalServerError
        })?;

    let body_data = resp.bytes().await.map_err(|e| {
        tracing::debug!("failed to read response's body: {}", e);
        Error::InternalServerError
    })?;

    let resp_data: TurnstileVerificationResponse = serde_json::from_slice(body_data.deref())
        .map_err(|e| {
            tracing::debug!("failed to parse json: {}", e);
            Error::InternalServerError
        })?;

    if resp_data.success {
        Ok(())
    } else {
        for c in resp_data.error_codes {
            return Err(match c.as_str() {
                "missing-input-response" => Error::MissingCaptchaToken,
                "invalid-input-response" => Error::InvalidCaptcha,
                "bad-request" => Error::BadRequest,
                "timeout-or-duplicate" => Error::TimeOutOrDuplicateCaptcha,
                "internal-error" => Error::InternalServerError,
                e => {
                    tracing::warn!(
                        "encountered an error code cannot be triggered by user: {}",
                        e
                    );
                    Error::InternalServerError
                }
            });
        }
        Err(Error::InternalServerError)
    }
}

#[derive(Deserialize)]
struct TurnstileVerificationResponse {
    success: bool,
    #[serde(rename = "error-codes")]
    error_codes: Vec<String>,
}
