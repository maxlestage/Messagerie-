//! Les données du serveur, en mémoire avec [Memoire](https://maxlestage.github.io/Memoire/) :
//! plus de Postgres ni de Redis.
//!
//! Le serveur ne garde que du chiffré (jetons Brocolis illisibles sans la clé),
//! une semaine au plus (`MESSAGE_RETENTION_DAYS`) et dans un budget de mémoire
//! (`MEMORY_BUDGET_MB`) : au-delà, les plus vieux messages partent les premiers.
//!
//! Par défaut tout vit en RAM et disparaît au redémarrage. Avec `MEMOIRE_PATH`,
//! Memoire écrit aussi chaque changement dans un fichier, relu au démarrage
//! suivant (utile sur un disque qui dure ; sur Heroku, le disque d'un dyno est
//! effacé à chaque redémarrage).

use memoire_orm::prelude::*;
use memoire_orm::{Error, Result};

/// Un message chiffré. `seq` est le curseur des clients : il ne fait que monter,
/// même d'un démarrage à l'autre (voir [`first_seq`]).
#[derive(Model, Debug, Clone, PartialEq)]
#[memoire(table = "messages", unique(conversation_id, msg_id))]
pub struct Message {
    #[memoire(primary_key)]
    pub seq: i64,
    /// L'identifiant choisi par l'expéditeur : un renvoi ne duplique rien.
    pub msg_id: String,
    #[memoire(index)]
    pub conversation_id: String,
    pub sender_id: String,
    pub ciphertext: String,
    /// ISO 8601 en UTC (`…Z`) : l'ordre alphabétique est l'ordre chronologique.
    pub sent_at: String,
    /// Taille du chiffré en octets, pour le budget de mémoire.
    pub size: i64,
}

/// Une conversation à participants explicites. Les autres (« scellées ») n'ont
/// pas de ligne : leur id est une empreinte de la clé partagée.
#[derive(Model, Debug, Clone, PartialEq)]
#[memoire(table = "conversations")]
pub struct Conversation {
    #[memoire(primary_key)]
    pub id: String,
    /// Les participants, en JSON (`[{id, displayName}]`).
    pub participants: String,
    pub created_at: String,
}

/// Index d'appartenance : « les conversations de cet utilisateur ».
#[derive(Model, Debug, Clone, PartialEq)]
#[memoire(table = "conversation_members", unique(conversation_id, user_id))]
pub struct Member {
    #[memoire(primary_key, auto_increment)]
    pub id: i64,
    pub conversation_id: String,
    #[memoire(index)]
    pub user_id: String,
}

/// Jusqu'où un utilisateur a lu une conversation (« Distribué / Lu »).
#[derive(Model, Debug, Clone, PartialEq)]
#[memoire(table = "read_cursors")]
pub struct ReadCursor {
    /// `conversation_id` + `\n` + `user_id`.
    #[memoire(primary_key)]
    pub key: String,
    #[memoire(index)]
    pub conversation_id: String,
    pub user_id: String,
    pub up_to: i64,
}

/// Accès Pro offert : l'e-mail Apple vérifié rattaché à un appareil.
#[derive(Model, Debug, Clone, PartialEq)]
#[memoire(table = "plan_grants")]
pub struct PlanGrant {
    #[memoire(primary_key)]
    pub user_id: String,
    pub email: String,
    pub linked_at: String,
}

/// Horodatage ISO 8601 en UTC avec `Z` (même forme que `Date.toISOString()`).
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Le premier `seq` d'un démarrage : l'heure en millisecondes × 1000. Un client
/// qui a gardé son curseur d'avant un redémarrage (`after=…`) voit donc encore
/// les nouveaux messages, qui ont toujours un `seq` plus grand. (Il faudrait
/// plus de mille messages par milliseconde, en moyenne, pour le rattraper.)
pub fn first_seq(now_ms: i64) -> i64 {
    now_ms.max(1).saturating_mul(1000)
}

fn read_key(conv: &str, user: &str) -> String {
    format!("{conv}\n{user}")
}

/// Les chiffres publics du serveur (page Serveur du site) : des totaux, aucun
/// identifiant.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct Totals {
    pub messages: u64,
    pub conversations: u64,
    pub bytes: i64,
}

pub struct Store {
    db: MemoryDb,
    /// Le prochain `seq`. Le verrou couvre aussi l'insertion : l'ordre des
    /// `seq` est exactement celui des écritures, un client qui rattrape avec
    /// `after=` ne saute jamais un message.
    next_seq: tokio::sync::Mutex<i64>,
    /// Budget du chiffré gardé en mémoire, en octets.
    budget: i64,
}

impl Store {
    /// Une base vide, en mémoire seulement.
    pub async fn in_memory(budget_bytes: i64) -> Result<Store> {
        Store::with_db(MemoryDb::new(), budget_bytes).await
    }

    /// Une base gardée aussi dans `path` (créé s'il n'existe pas).
    pub async fn open(path: &str, budget_bytes: i64) -> Result<Store> {
        Store::with_db(MemoryDb::open(path)?, budget_bytes).await
    }

    async fn with_db(db: MemoryDb, budget: i64) -> Result<Store> {
        db.create_table_if_not_exists::<Message>().await?;
        db.create_table_if_not_exists::<Conversation>().await?;
        db.create_table_if_not_exists::<Member>().await?;
        db.create_table_if_not_exists::<ReadCursor>().await?;
        db.create_table_if_not_exists::<PlanGrant>().await?;
        let last = Message::query().max(Message::SEQ, &db).await?.unwrap_or(0);
        let next = first_seq(chrono::Utc::now().timestamp_millis()).max(last + 1);
        Ok(Store {
            db,
            next_seq: tokio::sync::Mutex::new(next),
            budget: budget.max(1),
        })
    }

    /// La base elle-même (tests, inspection).
    pub fn db(&self) -> &MemoryDb {
        &self.db
    }

    // ── Messages ────────────────────────────────────────────────────────────

    /// Stocke un message chiffré. Idempotent sur `(conversation, id)` : un
    /// renvoi rend le message déjà connu, avec `false`.
    pub async fn post_message(
        &self,
        conv: &str,
        id: &str,
        sender: &str,
        ciphertext: &str,
    ) -> Result<(Message, bool)> {
        let mut next = self.next_seq.lock().await;
        if let Some(existing) = self.find_message(conv, id).await? {
            return Ok((existing, false));
        }
        let mut message = Message {
            seq: *next,
            msg_id: id.to_owned(),
            conversation_id: conv.to_owned(),
            sender_id: sender.to_owned(),
            ciphertext: ciphertext.to_owned(),
            sent_at: now_iso(),
            size: ciphertext.len() as i64,
        };
        match message.insert(&self.db).await {
            Ok(_) => {}
            // Impossible sous le verrou, mais sans danger : on rend l'existant.
            Err(e) if e.is_unique_violation() => {
                drop(next);
                let existing = self.find_message(conv, id).await?.ok_or(e)?;
                return Ok((existing, false));
            }
            Err(e) => return Err(e),
        }
        *next += 1;
        drop(next);
        self.enforce_budget().await?;
        Ok((message, true))
    }

    async fn find_message(&self, conv: &str, id: &str) -> Result<Option<Message>> {
        Message::query()
            .filter(Message::CONVERSATION_ID.eq(conv) & Message::MSG_ID.eq(id))
            .first(&self.db)
            .await
    }

    /// Les messages après `after`, `limit` au plus, et s'il en reste.
    pub async fn messages(
        &self,
        conv: &str,
        after: i64,
        limit: u64,
    ) -> Result<(Vec<Message>, bool)> {
        let mut rows = Message::query()
            .filter(Message::CONVERSATION_ID.eq(conv) & Message::SEQ.gt(after))
            .order_by(Message::SEQ.asc())
            .limit(limit + 1)
            .all(&self.db)
            .await?;
        let has_more = rows.len() as u64 > limit;
        rows.truncate(limit as usize);
        Ok((rows, has_more))
    }

    /// Supprime les messages envoyés avant `cutoff` (ISO 8601).
    pub async fn purge_before(&self, cutoff: &str) -> Result<u64> {
        Message::delete_many()
            .filter(Message::SENT_AT.lt(cutoff))
            .execute(&self.db)
            .await
    }

    /// Garde le chiffré sous le budget : au-delà, les plus vieux messages
    /// partent jusqu'à revenir à 90 % du budget. Renvoie le nombre supprimé.
    pub async fn enforce_budget(&self) -> Result<u64> {
        let total = Message::query()
            .sum(Message::SIZE, &self.db)
            .await?
            .unwrap_or(0);
        if total <= self.budget {
            return Ok(0);
        }
        let target = total - self.budget / 10 * 9;
        let sizes = Message::query()
            .order_by(Message::SEQ.asc())
            .columns((Message::SEQ, Message::SIZE))
            .all(&self.db)
            .await?;
        let mut freed = 0;
        let mut last = None;
        for (seq, size) in sizes {
            freed += size;
            last = Some(seq);
            if freed >= target {
                break;
            }
        }
        match last {
            Some(seq) => {
                Message::delete_many()
                    .filter(Message::SEQ.le(seq))
                    .execute(&self.db)
                    .await
            }
            None => Ok(0),
        }
    }

    // ── Accusés de lecture ──────────────────────────────────────────────────

    /// `{ userId: dernierSeqLu }` d'une conversation.
    pub async fn readers(&self, conv: &str) -> Result<Vec<ReadCursor>> {
        ReadCursor::query()
            .filter(ReadCursor::CONVERSATION_ID.eq(conv))
            .all(&self.db)
            .await
    }

    /// Avance le curseur de lecture, sans jamais le faire reculer. Renvoie la
    /// valeur retenue.
    pub async fn mark_read(&self, conv: &str, user: &str, up_to: i64) -> Result<i64> {
        let key = read_key(conv, user);
        // Transaction : deux accusés simultanés ne peuvent pas faire reculer le
        // curseur (le second échoue en conflit et recommence).
        loop {
            let tx = self.db.begin().await?;
            let current = ReadCursor::find(&tx, key.clone())
                .await?
                .map_or(0, |c| c.up_to);
            let up_to = up_to.max(0).max(current);
            let cursor = ReadCursor {
                key: key.clone(),
                conversation_id: conv.to_owned(),
                user_id: user.to_owned(),
                up_to,
            };
            cursor.upsert(&tx).await?;
            match tx.commit().await {
                Ok(()) => return Ok(up_to),
                Err(e) if e.is_conflict() => continue,
                Err(e) => return Err(e),
            }
        }
    }

    // ── Conversations ───────────────────────────────────────────────────────

    pub async fn conversation(&self, id: &str) -> Result<Option<Conversation>> {
        Conversation::find(&self.db, id.to_owned()).await
    }

    /// Crée une conversation et son index d'appartenance (un membre par id).
    pub async fn create_conversation(
        &self,
        participants_json: String,
        members: &[String],
    ) -> Result<Conversation> {
        let mut conv = Conversation {
            id: uuid::Uuid::new_v4().to_string(),
            participants: participants_json,
            created_at: now_iso(),
        };
        let tx = self.db.begin().await?;
        conv.insert(&tx).await?;
        let mut seen = std::collections::HashSet::new();
        let rows: Vec<Member> = members
            .iter()
            .filter(|m| !m.is_empty() && seen.insert(m.as_str()))
            .map(|m| Member {
                id: 0,
                conversation_id: conv.id.clone(),
                user_id: m.clone(),
            })
            .collect();
        if !rows.is_empty() {
            Member::insert_many(&tx, &rows).await?;
        }
        tx.commit().await?;
        Ok(conv)
    }

    /// Les conversations dont `user` est membre.
    pub async fn conversations_of(&self, user: &str) -> Result<Vec<Conversation>> {
        let ids: Vec<String> = Member::query()
            .filter(Member::USER_ID.eq(user))
            .columns(Member::CONVERSATION_ID)
            .all(&self.db)
            .await?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        Conversation::query()
            .filter(Conversation::ID.is_in(ids))
            .order_by(Conversation::CREATED_AT.asc())
            .all(&self.db)
            .await
    }

    // ── Accès offerts ───────────────────────────────────────────────────────

    pub async fn linked_email(&self, user: &str) -> Result<Option<String>> {
        Ok(PlanGrant::find(&self.db, user.to_owned())
            .await?
            .map(|g| g.email))
    }

    pub async fn link_email(&self, user: &str, email: &str) -> Result<()> {
        let grant = PlanGrant {
            user_id: user.to_owned(),
            email: email.to_owned(),
            linked_at: now_iso(),
        };
        grant.upsert(&self.db).await.map(|_| ())
    }

    pub async fn unlink_email(&self, user: &str) -> Result<bool> {
        PlanGrant::delete_by_key(&self.db, user.to_owned()).await
    }

    // ── Chiffres ────────────────────────────────────────────────────────────

    pub async fn totals(&self) -> Result<Totals> {
        Ok(Totals {
            messages: Message::count(&self.db).await?,
            conversations: Message::query()
                .columns(Message::CONVERSATION_ID)
                .distinct()
                .count(&self.db)
                .await?,
            bytes: Message::query()
                .sum(Message::SIZE, &self.db)
                .await?
                .unwrap_or(0),
        })
    }
}

/// Une erreur de stockage, pour les journaux.
pub fn describe(e: &Error) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run<F: std::future::Future<Output = Result<()>>>(f: F) {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
            .unwrap();
    }

    #[test]
    fn seq_starts_after_the_clock_and_keeps_climbing() {
        assert_eq!(first_seq(1_760_000_000_000), 1_760_000_000_000_000);
        // Toujours sous 2^53 : exact en JavaScript comme en Swift/Kotlin.
        assert!(first_seq(4_000_000_000_000) < 1 << 53);
        run(async {
            let store = Store::in_memory(1 << 30).await?;
            let (a, created) = store.post_message("c", "m1", "alice", "AAA").await?;
            assert!(created);
            let (b, _) = store.post_message("c", "m2", "bob", "BBB").await?;
            assert!(a.seq >= first_seq(chrono::Utc::now().timestamp_millis() - 60_000));
            assert_eq!(b.seq, a.seq + 1);
            Ok(())
        });
    }

    #[test]
    fn a_resent_message_is_not_duplicated() {
        run(async {
            let store = Store::in_memory(1 << 30).await?;
            let (a, created) = store.post_message("c", "m1", "alice", "AAA").await?;
            let (again, created_again) = store.post_message("c", "m1", "alice", "AAA").await?;
            assert!(created && !created_again);
            assert_eq!(a, again);
            // Le même id dans une autre conversation est un autre message.
            let (other, created_other) = store.post_message("d", "m1", "alice", "AAA").await?;
            assert!(created_other);
            assert_ne!(other.seq, a.seq);
            assert_eq!(store.totals().await?.messages, 2);
            Ok(())
        });
    }

    #[test]
    fn retention_drops_old_messages_only() {
        run(async {
            let store = Store::in_memory(1 << 30).await?;
            store.post_message("c", "old", "a", "X").await?;
            // Vieillit le premier message à la main.
            Message::update_many()
                .set(Message::SENT_AT, "2000-01-01T00:00:00.000Z".to_string())
                .filter(Message::MSG_ID.eq("old"))
                .execute(store.db())
                .await?;
            store.post_message("c", "new", "a", "Y").await?;
            assert_eq!(store.purge_before("2020-01-01T00:00:00.000Z").await?, 1);
            let (left, _) = store.messages("c", 0, 10).await?;
            assert_eq!(left.len(), 1);
            assert_eq!(left[0].msg_id, "new");
            Ok(())
        });
    }

    #[test]
    fn the_budget_evicts_the_oldest_messages() {
        run(async {
            // 100 octets de budget, des messages de 30 octets.
            let store = Store::in_memory(100).await?;
            let body = "x".repeat(30);
            for i in 0..3 {
                store
                    .post_message("c", &format!("m{i}"), "a", &body)
                    .await?;
            }
            assert_eq!(store.totals().await?.bytes, 90);
            // Le quatrième dépasse : on redescend sous 90 % du budget.
            store.post_message("c", "m3", "a", &body).await?;
            let totals = store.totals().await?;
            assert!(totals.bytes <= 90, "{totals:?}");
            let (left, _) = store.messages("c", 0, 10).await?;
            assert_eq!(left.last().unwrap().msg_id, "m3", "le plus récent reste");
            assert!(left.iter().all(|m| m.msg_id != "m0"), "le plus vieux part");
            Ok(())
        });
    }

    #[test]
    fn read_cursors_never_go_back() {
        run(async {
            let store = Store::in_memory(1 << 30).await?;
            assert_eq!(store.mark_read("c", "alice", 5).await?, 5);
            assert_eq!(store.mark_read("c", "alice", 3).await?, 5);
            assert_eq!(store.mark_read("c", "alice", -1).await?, 5);
            assert_eq!(store.mark_read("c", "bob", 2).await?, 2);
            let readers = store.readers("c").await?;
            assert_eq!(readers.len(), 2);
            Ok(())
        });
    }

    #[test]
    fn the_file_keeps_messages_and_their_order() {
        let dir = std::env::temp_dir().join(format!("brocolis-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.memoire");
        let path = path.to_str().unwrap().to_owned();
        let first = std::sync::Mutex::new(0);
        run(async {
            let store = Store::open(&path, 1 << 30).await?;
            let (m, _) = store.post_message("c", "m1", "a", "X").await?;
            *first.lock().unwrap() = m.seq;
            Ok(())
        });
        run(async {
            let store = Store::open(&path, 1 << 30).await?;
            let (old, _) = store.messages("c", 0, 10).await?;
            assert_eq!(old.len(), 1, "relu depuis le fichier");
            let (m, _) = store.post_message("c", "m2", "a", "Y").await?;
            assert!(m.seq > *first.lock().unwrap());
            Ok(())
        });
        let _ = std::fs::remove_dir_all(dir);
    }
}
