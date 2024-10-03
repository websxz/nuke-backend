use std::sync::Arc;

use axum::{extract::State, Json};
use chrono::NaiveDateTime;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    data::{
        credential::{scopes, Claims, Scope},
        error::Error,
    },
    entity::user,
    utils::db::StanderizeError,
    AppState,
};

pub async fn me(
    state: State<Arc<AppState>>,
    claims: Claims<{ scopes(&[Scope::ProfileRead]) }>,
) -> Result<Json<MyProfile>, Error> {
    let user = user::Entity::find_by_id(claims.uid)
        .one(&state.db)
        .await
        .warn_err()?
        .ok_or(Error::NotFound)?;

    Ok(Json(MyProfile {
        email: user.email,
        name: user.name,
        id: user.id,
        avatar: user.avatar,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

pub async fn edit(
    state: State<Arc<AppState>>,
    claims: Claims<{ scopes(&[Scope::ProfileWrite]) }>,
    Json(params): Json<ProfileEdit>,
) -> Result<(), Error> {
    params.validate().map_err(|_e| Error::BadRequest)?;

    let user = user::Entity::find_by_id(claims.uid)
        .one(&state.db)
        .await
        .warn_err()?
        .ok_or(Error::NotFound)?;
    let mut user: user::ActiveModel = user.into();

    if let Some(changed_name) = params.name {
        user.name = Set(changed_name);
    }

    user.update(&state.db).await.warn_err()?;

    Ok(())
}

#[derive(Serialize, Debug, Validate, Deserialize)]
pub struct ProfileEdit {
    #[validate(length(min = 3, max = 25))]
    name: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct MyProfile {
    email: String,
    name: String,
    id: u32,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    avatar: Option<String>,
}
