use chrono::NaiveDateTime;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: u32,
    pub name: String,
    #[sea_orm(indexed)]
    pub email: String,
    pub avatar: Option<String>,
    pub salted_password: String,
    pub salt: String,
    #[sea_orm(created_at)]
    pub created_at: NaiveDateTime,
    #[sea_orm(updated_at)]
    pub updated_at: NaiveDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}