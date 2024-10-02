use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "oauth_client")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub client_id: u32,
    pub official: bool,
    pub client_secret: String,
    #[sea_orm(created_at)]
    pub created_at: Option<NaiveDateTime>,
    #[sea_orm(updated_at)]
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}