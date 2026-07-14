//! Modèles de données de l'API de messagerie.
//!
//! Principe de confidentialité : **le serveur ne voit jamais de texte en clair.**
//! Un message ne transporte qu'un `ciphertext` (base64 de `nonce||ct||tag`,
//! AES-256-GCM). Le déchiffrement se fait uniquement sur les appareils, avec une
//! clé que le serveur ne possède pas. Côté serveur, on ne fait que router et
//! stocker du charabia.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Un participant connu du serveur (identité opaque + nom d'affichage).
/// Le nom n'est PAS secret ; si tu veux le cacher au serveur, chiffre-le aussi
/// côté client et mets un placeholder ici.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Une conversation (un « match ») : la liste de ses participants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Conversation {
    pub id: String,
    /// Identifiants des participants (2 pour un 1-à-1, plus pour un groupe).
    pub participants: Vec<Participant>,
    #[serde(rename = "createdAt", with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Message tel qu'il est stocké / transmis : chiffré.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "senderId")]
    pub sender_id: String,
    /// base64 de `nonce || ciphertext || tag`. Illisible sans la clé.
    pub ciphertext: String,
    #[serde(rename = "sentAt", with = "time::serde::rfc3339")]
    pub sent_at: OffsetDateTime,
    /// Compteur monotone attribué par le serveur : sert de curseur pour la
    /// pagination et le rattrapage (`?after=`). Ordre de livraison stable même
    /// si deux messages ont la même seconde.
    pub seq: u64,
}

// ── Corps de requêtes ────────────────────────────────────────────────────────

/// Création d'une conversation.
#[derive(Debug, Deserialize)]
pub struct CreateConversationBody {
    pub participants: Vec<Participant>,
}

/// Envoi d'un message. Le client fournit un `id` (idempotence) — s'il est absent,
/// le serveur en génère un.
#[derive(Debug, Deserialize)]
pub struct SendMessageBody {
    pub id: Option<String>,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    /// Doit correspondre à l'utilisateur authentifié (en-tête `X-User-Id`).
    #[serde(rename = "senderId")]
    pub sender_id: String,
    pub ciphertext: String,
}

// ── Réponses ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct MessagesPage {
    pub messages: Vec<StoredMessage>,
    /// Curseur à repasser dans `?after=` pour ne récupérer que la suite.
    pub cursor: u64,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}
