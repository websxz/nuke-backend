use std::sync::Arc;

use crate::data::credential::generate_token;
use crate::data::error::Error;
use crate::entity::user;
use crate::utils::captcha::{verify_captcha, Captcha};
use crate::utils::encryption::salt_password;
use crate::utils::redis::{generate_refresh_token, get_connection, InsertRefreshToken};
use crate::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::Authorization;
use axum_extra::TypedHeader;
use redis::Commands;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

pub async fn login(
    state: State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<LoginBody>,
) -> Result<Json<Token>, impl IntoResponse> {
    let remote_ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok());

    verify_captcha(data.captcha, remote_ip)
        .await
        .map_err(Into::into)?;

    if let Some(user) = user::Entity::find()
        .filter(user::Column::Email.eq(data.email))
        .one(&state.db)
        .await
        .map_err(|e| {
            tracing::warn!("database error: {}", e);
            Error::InternalServerError
        })?
    {
        if user.salted_password != salt_password(&data.hashed_password, &user.salt) {
            return Err(Error::IncorrectEmailOrPassword);
        }

        let mut conn = get_connection(&state.redis)?;
        let refresh_token = generate_refresh_token();
        conn.insert_refresh_token(&refresh_token, user.id)?;

        return Ok(Json(Token {
            token: generate_token(user.id)?,
            refresh_token,
        }));
    }
    Err(Error::IncorrectEmailOrPassword)
}

pub async fn refresh_token(
    state: State<Arc<AppState>>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<Token>, impl IntoResponse> {
    let key = format!("refresh:{}", bearer.token());
    let mut conn = get_connection(&state.redis)?;

    let exist: bool = conn.exists(&key).map_err(|e| {
        tracing::warn!("failed to judge existence of refresh token: {}", e);
        Error::InternalServerError
    })?;

    if exist {
        let id = conn.get(&key).map_err(|e| {
            tracing::warn!("failed to get value: {}", e);
            Error::InternalServerError
        })?;

        let _: () = conn.del(&key).map_err(|e| {
            tracing::warn!("failed to delete key: {}", e);
            Error::InternalServerError
        })?;

        let r = generate_refresh_token();
        let _: () = conn.insert_refresh_token(&r, id)?;

        return Ok(Json(Token {
            token: generate_token(id)?,
            refresh_token: r,
        }));
    }

    Err(Error::Unauthorized)
}

#[derive(Serialize, Debug)]
pub struct Token {
    token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    email: String,
    hashed_password: String,
    captcha: Captcha,
}
