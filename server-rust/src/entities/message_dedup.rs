//! Table `message_dedup` : garantit l'idempotence `(conversation_id, msg_id)`
//! même en cas de POST concurrents, INDÉPENDAMMENT du partitionnement de
//! `messages`. Nécessaire car, une fois `messages` partitionnée par temps, une
//! contrainte d'unicité sur elle devrait contenir `sent_at` (la clé de
//! partition) — ce qui ne dédoublonnerait plus par `msg_id` seul.
//!
//! `sent_at` sert uniquement à purger cette table comme les messages.
//! On n'y stocke que des identifiants — aucun contenu, aucun secret.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "message_dedup")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub conversation_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub msg_id: String,
    pub sent_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
