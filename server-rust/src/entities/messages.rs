//! Table `messages` : le serveur ne stocke QUE du chiffré (`ciphertext` = jeton
//! Brocolis illisible sans la clé). `seq` est un compteur durable (BIGSERIAL).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize)]
#[sea_orm(table_name = "messages")]
pub struct Model {
    #[sea_orm(primary_key)]
    #[serde(skip_deserializing)]
    pub seq: i64,
    pub msg_id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub ciphertext: String,
    pub sent_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
