use crate::data::error::Error;
use crate::entity::user;
use crate::utils::captcha::{verify_captcha, Captcha};
use crate::utils::encryption::salt_password;
use crate::utils::redis::{generate_refresh_token, get_connection};
use crate::AppState;
use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use lazy_static::lazy_static;
use lettre::message::{header, Mailbox, SinglePart};
use lettre::Message;
use rand::distributions::Alphanumeric;
use rand::Rng;
use sea_orm::{ActiveValue, ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use redis::Commands;
use validator::Validate;
use crate::utils::email::send;

lazy_static! {
    static ref FROM: Mailbox = env::var("FROM_MAILBOX")
        .expect("FROM_MAILBOX must be set")
        .parse()
        .expect("parse from mailbox failed");
}

#[derive(Template)]
#[template(path = "email_verification.html")]
struct EmailVerificationTemplate<'a> {
    verification_link: &'a str,
}

pub async fn register(
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterPayload>,
) -> Result<(), impl IntoResponse> {
    payload.validate().map_err(|_e| Error::BadRequest)?;

    let remote_ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());

    verify_captcha(payload.captcha, remote_ip).await?;

    if user::Entity::find()
        .filter(user::Column::Email.eq(&payload.email))
        .one(&state.db)
        .await
        .map_err(map_database_error)?
        .is_some()
    {
        return Err(Error::RegisteredEmail);
    }

    let email = Message::builder()
        .subject("验证你的电子邮件")
        .from(FROM.clone())
        .to(payload.email.parse().map_err(|e| {
            tracing::debug!("email illegal: {}", e);
            Error::BadRequest
        })?);

    let mut conn = get_connection(&state.redis)?;
    let token = generate_refresh_token();

    let key = format!("email_verify:{}", &token);

    let _: () = redis::pipe()
        .atomic()
        .hset_multiple(
            &key,
            &[
                ("email", &payload.email),
                ("hashed_password", &payload.hashed_password),
            ],
        )
        .ignore()
        .expire(&key, 24 * 60 * 60)
        .ignore()
        .query(&mut conn)
        .map_err(|e| {
            tracing::warn!("redis error when record email verification token: {}", e);
            Error::InternalServerError
        })?;

    let email = email.singlepart(
        SinglePart::builder()
            .header(header::ContentType::TEXT_HTML)
            .body(
                EmailVerificationTemplate {
                    verification_link: &format!("https://nuke.websxz.org/verify?code={}", &token),
                }
                .render()
                .map_err(|e| {
                    tracing::warn!("email template render failed: {}", e);
                    Error::InternalServerError
                })?,
            ),
    ).map_err(|e| {
        tracing::warn!("failed to build email: {}",e);
        Error::InternalServerError
    })?;

    let _ = send(&email)?;

    Ok(())
}

#[derive(Deserialize)]
pub struct TokenQuery {
    token: String,
}


pub async fn verify(
    state: State<Arc<AppState>>,
    Query(params): Query<TokenQuery>,
) -> Result<(), impl IntoResponse> {
    let TokenQuery { token } = params;

    let mut conn = get_connection(&state.redis)?;
    let key = format!("email_verify:{}", &token);
    let v: (Option<String>, Option<String>) = conn.hget(&key, &["email", "hashed_password"]).map_err(map_database_error)?;

    if let (Some(email), Some(hashed_password)) = v {
        let _: () = conn.del(&key).map_err(map_database_error)?;

        let salt: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(16)
            .map(char::from)
            .collect();

        let salted_password = salt_password(&hashed_password, &salt);
        let name = email[..email.find('@').unwrap()].to_string();
        user::Entity::insert(user::ActiveModel {
            id: ActiveValue::NotSet,
            name: ActiveValue::Set(name),
            email: ActiveValue::Set(email.clone()),
            avatar: ActiveValue::Set(None),
            salted_password: ActiveValue::Set(salted_password),
            salt: ActiveValue::Set(salt),
            created_at: ActiveValue::NotSet,
            updated_at: ActiveValue::NotSet,
        })
            .exec(&state.db)
            .await
            .map_err(map_database_error)?;

        return Ok(());
    }

    Err(Error::NotFound)
}

fn map_database_error(e: impl std::error::Error) -> Error {
    tracing::warn!("database error: {}", e);
    Error::InternalServerError
}

#[derive(Deserialize, Debug, Validate)]
pub struct RegisterPayload {
    #[validate(email)]
    email: String,
    hashed_password: String,
    captcha: Captcha,
}
