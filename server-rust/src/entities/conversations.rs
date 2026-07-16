//! Table `conversations`. `participants` est un JSON ('[]' = conversation
//! « scellée » : l'accès est cryptographique, pas par liste de membres).
//!
//! Entité prête pour les endpoints conversations à porter (create/list) ; pas
//! encore requêtée, d'où l'`allow(dead_code)`.
#![allow(dead_code)]

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "conversations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub participants: String,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
