//! Table `read_cursors` : jusqu'où chaque utilisateur a lu une conversation
//! (`up_to` = dernier `seq` lu). Sert aux accusés « Distribué / Lu ».

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "read_cursors")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub conversation_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: String,
    pub up_to: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
