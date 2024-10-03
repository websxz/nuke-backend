#![allow(long_running_const_eval)]

use crate::data::error::Error;
use crate::utils::db::StanderizeError;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::{async_trait, RequestPartsExt};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use chrono::Utc;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref TOKEN_KEYS: Keys = {
        let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        Keys::new(secret.as_bytes())
    };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<const S: u16> {
    pub exp: usize,
    pub uid: u32,
    pub scopes: Option<Vec<Scope>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Scope {
    #[serde(rename = "profile.read")]
    ProfileRead,
    #[serde(rename = "profile.write")]
    ProfileWrite,
}

#[async_trait]
impl<T, const S: u16> FromRequestParts<T> for Claims<S>
where
    T: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &T) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| {
                tracing::debug!("{}", e);
                Error::InvalidToken
            })?;
        // Decode the user data
        let token_data =
            decode::<Claims<S>>(bearer.token(), &TOKEN_KEYS.decoding, &Validation::default())
                .map_err(|e| {
                    tracing::debug!("{}", e);
                    match e.kind() {
                        ErrorKind::ExpiredSignature => Error::ExpiredToken,
                        _ => Error::InvalidToken,
                    }
                })?;

        if let Some(s) = &token_data.claims.scopes {
            if S != S & scopes(s.as_slice()) {
                return Err(Error::MissingScope);
            }
        }

        Ok(token_data.claims)
    }
}

pub const fn scopes(s: &[Scope]) -> u16 {
    let mut result = 0;
    let mut i = 0;

    while i < s.len() {
        result |= 1 << (s[i] as u16);

        i += 1;
    }

    result
}

pub fn generate_token(uid: u32) -> Result<String, Error> {
    Ok(encode(
        &Header::default(),
        &Claims::<0> {
            uid,
            exp: Utc::now().timestamp() as usize + 30 * 60,
            scopes: None,
        },
        &TOKEN_KEYS.encoding,
    )
    .map_err(|_| {
        tracing::warn!("failed to generate a token for id: {}", uid);
        Error::InternalServerError
    })?)
}

pub fn generate_oauth_token(uid: u32, s: Vec<Scope>) -> Result<String, Error> {
    Ok(
        encode(&Header::default(), &Claims::<0>{
            uid,
            exp: Utc::now().timestamp() as usize + 30 * 60,
            scopes: Some(s),
        }, &TOKEN_KEYS.encoding)
        .warn_err()?
    )
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}
