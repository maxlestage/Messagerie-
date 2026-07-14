//! Stockage en mémoire, protégé par un `RwLock`, avec diffusion temps réel.
//!
//! Volontairement simple et **sans dépendance à une base** : idéal pour démarrer
//! et pour les tests. Toute la logique passe par [`Store`], donc remplacer ce
//! backend par Postgres/SQLite (via `sqlx`) ne change que ce fichier — les
//! handlers restent identiques.
//!
//! Temps réel : chaque conversation possède un canal `tokio::broadcast`. Quand un
//! message arrive, il est poussé à tous les abonnés SSE de cette conversation.

use std::collections::HashMap;
use std::sync::RwLock;

use time::OffsetDateTime;
use tokio::sync::broadcast;

use crate::models::{Conversation, Participant, StoredMessage};

/// Combien de messages récents le canal temps réel garde en tampon par
/// conversation (au-delà, un abonné très lent « rate » des messages et devra
/// re-synchroniser via `GET /messages?after=`).
const BROADCAST_CAPACITY: usize = 256;

pub struct Store {
    inner: RwLock<Inner>,
}

struct Inner {
    conversations: HashMap<String, Conversation>,
    /// conversationId -> messages (ordre d'insertion == ordre `seq`).
    messages: HashMap<String, Vec<StoredMessage>>,
    /// conversationId -> émetteur temps réel.
    channels: HashMap<String, broadcast::Sender<StoredMessage>>,
    /// Compteur de séquence global, monotone.
    seq: u64,
}

impl Store {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Inner {
                conversations: HashMap::new(),
                messages: HashMap::new(),
                channels: HashMap::new(),
                seq: 0,
            }),
        }
    }

    /// Crée une conversation et renvoie son enregistrement.
    pub fn create_conversation(
        &self,
        id: String,
        participants: Vec<Participant>,
        created_at: OffsetDateTime,
    ) -> Conversation {
        let convo = Conversation {
            id: id.clone(),
            participants,
            created_at,
        };
        let mut inner = self.inner.write().unwrap();
        inner.conversations.insert(id.clone(), convo.clone());
        inner.messages.entry(id).or_default();
        convo
    }

    pub fn conversation(&self, id: &str) -> Option<Conversation> {
        self.inner.read().unwrap().conversations.get(id).cloned()
    }

    /// Conversations auxquelles participe `user_id`, les plus récemment actives
    /// d'abord (dernier message, sinon date de création).
    pub fn conversations_for(&self, user_id: &str) -> Vec<Conversation> {
        let inner = self.inner.read().unwrap();
        let mut list: Vec<Conversation> = inner
            .conversations
            .values()
            .filter(|c| c.participants.iter().any(|p| p.id == user_id))
            .cloned()
            .collect();
        list.sort_by_key(|c| {
            let last = inner
                .messages
                .get(&c.id)
                .and_then(|m| m.last())
                .map(|m| m.sent_at)
                .unwrap_or(c.created_at);
            std::cmp::Reverse(last)
        });
        list
    }

    /// Enregistre un message chiffré, lui attribue un `seq`, et le diffuse en
    /// temps réel. Idempotent sur `id` : renvoyer deux fois le même id ne crée
    /// qu'une entrée (utile pour les renvois réseau).
    pub fn append_message(
        &self,
        id: String,
        conversation_id: String,
        sender_id: String,
        ciphertext: String,
        sent_at: OffsetDateTime,
    ) -> StoredMessage {
        let mut inner = self.inner.write().unwrap();

        // Idempotence : si l'id existe déjà dans cette conversation, on le renvoie.
        if let Some(existing) = inner
            .messages
            .get(&conversation_id)
            .and_then(|msgs| msgs.iter().find(|m| m.id == id))
            .cloned()
        {
            return existing;
        }

        inner.seq += 1;
        let msg = StoredMessage {
            id,
            conversation_id: conversation_id.clone(),
            sender_id,
            ciphertext,
            sent_at,
            seq: inner.seq,
        };
        inner
            .messages
            .entry(conversation_id.clone())
            .or_default()
            .push(msg.clone());

        // Diffusion temps réel (ignorer l'erreur = simplement aucun abonné).
        if let Some(tx) = inner.channels.get(&conversation_id) {
            let _ = tx.send(msg.clone());
        }
        msg
    }

    /// Messages d'une conversation dont `seq > after`, par ordre chronologique.
    /// `after = 0` renvoie tout l'historique.
    pub fn messages_after(&self, conversation_id: &str, after: u64) -> Vec<StoredMessage> {
        self.inner
            .read()
            .unwrap()
            .messages
            .get(conversation_id)
            .map(|msgs| msgs.iter().filter(|m| m.seq > after).cloned().collect())
            .unwrap_or_default()
    }

    /// S'abonne au flux temps réel d'une conversation (crée le canal au besoin).
    pub fn subscribe(&self, conversation_id: &str) -> broadcast::Receiver<StoredMessage> {
        let mut inner = self.inner.write().unwrap();
        inner
            .channels
            .entry(conversation_id.to_string())
            .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0)
            .subscribe()
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}
