//! Handlers HTTP (Actix-web).
//!
//! Toutes les routes « métier » exigent un en-tête `X-User-Id` : c'est l'identité
//! de l'appelant. Pour un vrai déploiement, remplace [`auth_user`] par une
//! vérification de jeton (JWT signé, session…) — le reste ne change pas.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use futures_util::StreamExt;
use time::OffsetDateTime;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::models::{
    ApiError, Conversation, CreateConversationBody, MessagesPage, SendMessageBody,
};
use crate::store::Store;

/// Identité authentifiée. Ici : la valeur brute de `X-User-Id`. À durcir en prod.
fn auth_user(req: &HttpRequest) -> Result<String, HttpResponse> {
    match req.headers().get("X-User-Id").and_then(|v| v.to_str().ok()) {
        Some(id) if !id.trim().is_empty() => Ok(id.trim().to_string()),
        _ => Err(HttpResponse::Unauthorized()
            .json(ApiError::new("en-tête X-User-Id requis"))),
    }
}

/// Un utilisateur a accès à une conversation si :
///  - elle est « scellée » (aucun participant listé) → l'accès est
///    cryptographique (l'id est dérivé d'une clé partagée ; sans la clé on ne
///    peut rien lire même en connaissant l'id) ;
///  - ou il figure explicitement dans la liste des participants.
fn can_access(convo: &Conversation, user: &str) -> bool {
    convo.participants.is_empty() || convo.participants.iter().any(|p| p.id == user)
}

pub async fn health() -> impl Responder {
    HttpResponse::Ok().body("ok")
}

/// POST /v1/conversations — crée une conversation. L'appelant doit être l'un des
/// participants.
pub async fn create_conversation(
    req: HttpRequest,
    store: web::Data<Store>,
    body: web::Json<CreateConversationBody>,
) -> impl Responder {
    let user = match auth_user(&req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let body = body.into_inner();
    if body.participants.len() < 2 {
        return HttpResponse::BadRequest()
            .json(ApiError::new("il faut au moins 2 participants"));
    }
    if !body.participants.iter().any(|p| p.id == user) {
        return HttpResponse::Forbidden()
            .json(ApiError::new("tu dois faire partie de la conversation"));
    }
    let convo = store.create_conversation(
        Uuid::new_v4().to_string(),
        body.participants,
        OffsetDateTime::now_utc(),
    );
    HttpResponse::Created().json(convo)
}

/// GET /v1/conversations — conversations de l'appelant.
pub async fn list_conversations(
    req: HttpRequest,
    store: web::Data<Store>,
) -> impl Responder {
    let user = match auth_user(&req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    HttpResponse::Ok().json(store.conversations_for(&user))
}

#[derive(serde::Deserialize)]
pub struct MessagesQuery {
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(default)]
    pub after: u64,
}

/// GET /v1/messages?conversationId=..&after=.. — historique / rattrapage.
pub async fn list_messages(
    req: HttpRequest,
    store: web::Data<Store>,
    query: web::Query<MessagesQuery>,
) -> impl Responder {
    let user = match auth_user(&req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match store.conversation(&query.conversation_id) {
        Some(c) if can_access(&c, &user) => {}
        Some(_) => {
            return HttpResponse::Forbidden()
                .json(ApiError::new("accès refusé à cette conversation"))
        }
        None => {
            return HttpResponse::NotFound().json(ApiError::new("conversation inconnue"))
        }
    }
    let messages = store.messages_after(&query.conversation_id, query.after);
    let cursor = messages.last().map(|m| m.seq).unwrap_or(query.after);
    HttpResponse::Ok().json(MessagesPage { messages, cursor })
}

/// POST /v1/messages — envoie un message chiffré.
pub async fn send_message(
    req: HttpRequest,
    store: web::Data<Store>,
    body: web::Json<SendMessageBody>,
) -> impl Responder {
    let user = match auth_user(&req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let body = body.into_inner();
    if body.sender_id != user {
        return HttpResponse::Forbidden()
            .json(ApiError::new("senderId doit être l'utilisateur authentifié"));
    }
    if body.ciphertext.trim().is_empty() {
        return HttpResponse::BadRequest().json(ApiError::new("ciphertext vide"));
    }
    match store.conversation(&body.conversation_id) {
        Some(c) if can_access(&c, &user) => {}
        Some(_) => {
            return HttpResponse::Forbidden()
                .json(ApiError::new("accès refusé à cette conversation"))
        }
        // Conversation inconnue → on la crée « scellée » : l'id opaque (dérivé
        // d'une clé partagée) suffit, l'accès reste cryptographique.
        None => store.ensure_sealed(&body.conversation_id, OffsetDateTime::now_utc()),
    }
    let msg = store.append_message(
        body.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        body.conversation_id,
        body.sender_id,
        body.ciphertext,
        OffsetDateTime::now_utc(),
    );
    HttpResponse::Created().json(msg)
}

/// GET /v1/stream?conversationId=.. — flux temps réel (Server-Sent Events).
///
/// Chaque nouveau message chiffré arrive en `data: {json}\n\n`. Le client garde
/// la connexion ouverte et affiche au fil de l'eau. Un `:keep-alive` initial
/// ouvre le flux tout de suite.
pub async fn stream_messages(
    req: HttpRequest,
    store: web::Data<Store>,
    query: web::Query<MessagesQuery>,
) -> impl Responder {
    let user = match auth_user(&req) {
        Ok(u) => u,
        Err(r) => return r,
    };
    match store.conversation(&query.conversation_id) {
        Some(c) if can_access(&c, &user) => {}
        Some(_) => {
            return HttpResponse::Forbidden()
                .json(ApiError::new("accès refusé à cette conversation"))
        }
        // Permet d'ouvrir le flux d'une conversation scellée avant tout message.
        None => store.ensure_sealed(&query.conversation_id, OffsetDateTime::now_utc()),
    }

    let rx = store.subscribe(&query.conversation_id);
    // Commentaire SSE initial : force l'ouverture immédiate du flux côté client.
    let hello = futures_util::stream::once(async {
        Ok::<web::Bytes, actix_web::Error>(web::Bytes::from_static(b":ok\n\n"))
    });
    let events = BroadcastStream::new(rx).filter_map(|item| async move {
        match item {
            Ok(msg) => match serde_json::to_string(&msg) {
                Ok(json) => Some(Ok(web::Bytes::from(format!("data: {json}\n\n")))),
                Err(_) => None,
            },
            // L'abonné a pris du retard et a raté des messages : on ignore (il
            // rattrapera via GET /messages?after=).
            Err(_) => None,
        }
    });

    HttpResponse::Ok()
        .insert_header(("content-type", "text/event-stream"))
        .insert_header(("cache-control", "no-cache"))
        .insert_header(("connection", "keep-alive"))
        .streaming(hello.chain(events))
}
