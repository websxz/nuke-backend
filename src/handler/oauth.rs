use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};
use redis::Commands;
use sea_orm::EntityTrait;
use serde::Deserialize;

use crate::{
    data::{
        credential::{generate_oauth_token, Claims, Scope},
        error::Error,
    },
    entity::oauth_client,
    utils::{
        db::StanderizeError,
        redis::{generate_refresh_token, get_connection},
    },
    AppState,
};

#[derive(Deserialize, Debug)]
pub struct OAuthParams {
    scopes: String,
    redirect_uri: String,
    client_id: u32,
    state: String,
    response_type: ResponseType,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub enum ResponseType {
    #[serde(rename = "code")]
    Code,
}

pub async fn oauth(
    state: State<Arc<AppState>>,
    Query(params): Query<OAuthParams>,
    claims: Claims,
) -> Result<Json<String>, Error> {
    let OAuthParams {
        scopes,
        redirect_uri,
        client_id,
        state: req_state,
        response_type,
    } = params;

    if response_type != ResponseType::Code {
        return Err(Error::BadRequest);
    }

    let mut conn = get_connection(&state.redis)?;

    let code = generate_refresh_token();
    let key = format!("oauth:{}", &code);

    let _: () = redis::pipe()
        .atomic()
        .hset_multiple(
            &key,
            &[
                ("client_id", client_id.to_string()),
                ("scopes", scopes),
                ("uid", claims.uid.to_string()),
            ],
        )
        .ignore()
        .expire(&key, 5 * 60)
        .ignore()
        .query(&mut conn)
        .map_err(|e| {
            tracing::warn!("redis error: {}", e);
            Error::InternalServerError
        })?;

    Ok(Json(
        redirect_uri + &format!("?state={}&code={}", req_state, code),
    ))
}

#[derive(Deserialize, Debug)]
pub struct ExchangeTokenParams {
    code: String,
    client_secret: String,
}

pub async fn exchange_token(
    state: State<Arc<AppState>>,
    Query(params): Query<ExchangeTokenParams>,
) -> Result<Json<String>, Error> {
    let ExchangeTokenParams {
        code,
        client_secret,
    } = params;

    let key = format!("oauth:{}", &code);
    let mut conn = get_connection(&state.redis)?;
    let v: (Option<String>, Option<String>, Option<String>) = conn
        .hget(&key, &["client_id", "scopes", "uid"])
        .warn_err()?;

    if let (Some(client_id), Some(scopes), Some(uid)) = v {
        let client = oauth_client::Entity::find_by_id(client_id.parse::<u32>().debug_err()?)
            .one(&state.db)
            .await
            .warn_err()?;
        if let Some(client) = client {
            if client.client_secret != client_secret {
                return Err(Error::Unauthorized);
            }

            let scopes: Vec<Scope> = scopes
                .split(' ')
                .filter_map(|selection| serde_json::from_str(selection).ok())
                .collect();

            let token = generate_oauth_token(uid.parse::<u32>().debug_err()?, scopes)?;

            let _: () = conn.del(&key).warn_err()?;

            return Ok(Json(token));
        }

        return Err(Error::BadRequest);
    }

    Err(Error::NotFound)
}
