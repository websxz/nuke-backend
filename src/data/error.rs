use axum::http::StatusCode;
use axum::{
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::json;

#[derive(Serialize, Debug)]
pub enum Error {
    TimeOutOrDuplicateCaptcha,
    InvalidCaptcha,
    InternalServerError,
    BadRequest,
    NotFound,
    MissingCaptchaToken,
    IncorrectEmailOrPassword,
    Unauthorized,
    RegisteredEmail,
    InvalidToken,
    ExpiredToken,
    MissingScope,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = match &self {
            Error::TimeOutOrDuplicateCaptcha => StatusCode::BAD_REQUEST,
            Error::InvalidCaptcha => StatusCode::BAD_REQUEST,
            Error::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Error::BadRequest => StatusCode::BAD_REQUEST,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::MissingCaptchaToken => StatusCode::BAD_REQUEST,
            Error::IncorrectEmailOrPassword => StatusCode::UNAUTHORIZED,
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::RegisteredEmail => StatusCode::CONFLICT,
            Error::InvalidToken => StatusCode::BAD_REQUEST,
            Error::ExpiredToken => StatusCode::UNAUTHORIZED,
            Error::MissingScope => StatusCode::FORBIDDEN,
        };

        (
            status_code,
            Json(json!({
                "error": self
            })),
        )
            .into_response()
    }
}
