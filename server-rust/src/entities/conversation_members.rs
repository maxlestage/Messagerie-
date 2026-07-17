//! Table `conversation_members` : index d'appartenance (un couple
//! (conversation, utilisateur) par ligne). Permet de lister les conversations
//! d'un utilisateur en O(ses conversations) via un index sur `user_id`, au lieu
//! de balayer TOUTE la table `conversations` à chaque requête.
//!
//! Le serveur ne stocke ici que des identifiants — aucun contenu, aucun secret.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "conversation_members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub conversation_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
