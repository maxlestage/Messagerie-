//! API messagerie Brocolis 🥦 en Rust (Actix-web + SeaORM).
//!
//! Portage EN PARALLÈLE du serveur Node (`server/`). Ce service couvre le cœur
//! messagerie sur Postgres ; il ne stocke QUE du chiffré (jetons Brocolis).
//! À porter ensuite : rendez-vous X25519, flux SSE, push APNs, Redis.
//!
//! Persistance DURABLE native : Postgres est la source de vérité (plus de
//! snapshot SQLite comme côté Node). `seq` = BIGSERIAL, stable et monotone.

mod apns;
mod entities;
mod realtime;
mod rendezvous;

use actix_files::Files;
use apns::Apns;
use realtime::Realtime;
use actix_web::web::Bytes;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use async_stream::stream;
use chrono::SecondsFormat;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter, QueryOrder, Set,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::broadcast;

use entities::{conversations, messages, read_cursors};
use rendezvous::Rendezvous;

/// Diffusion temps réel intra-process : un canal `broadcast` par conversation.
/// Chaque flux SSE s'abonne ; `POST /v1/messages` et `/v1/read` publient.
/// (Le temps réel INTER-dynos via Redis, comme côté Node, reste à porter.)
#[derive(Default)]
struct Broadcaster {
    channels: Mutex<HashMap<String, broadcast::Sender<String>>>,
}

impl Broadcaster {
    fn subscribe(&self, conv: &str) -> broadcast::Receiver<String> {
        let mut map = self.channels.lock().unwrap();
        map.entry(conv.to_string())
            .or_insert_with(|| broadcast::channel(64).0)
            .subscribe()
    }

    fn publish(&self, conv: &str, line: String) {
        let map = self.channels.lock().unwrap();
        if let Some(tx) = map.get(conv) {
            let _ = tx.send(line); // aucun abonné : sans importance
        }
    }
}

/// Fenêtre de rétention : une semaine (réglable via MESSAGE_RETENTION_DAYS).
fn retention_days() -> i64 {
    std::env::var("MESSAGE_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(7)
}

/// Horodatage ISO 8601 en UTC avec 'Z' (même forme que `Date.toISOString()`),
/// pour que la comparaison lexicographique = comparaison chronologique.
fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn user_id(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Contrôle d'accès à une conversation (parité avec le serveur Node).
/// - conversation inconnue ⇒ autorisée (traitée comme scellée : rien de lisible
///   sans la clé de toute façon, le serveur ne relaie que du chiffré) ;
/// - conversation sans participants explicites (scellée) ⇒ autorisée ;
/// - conversation à participants ⇒ l'appelant doit en faire partie.
/// Défense en profondeur : le vrai secret reste le chiffrement de bout en bout.
async fn can_access(db: &DatabaseConnection, conv: &str, user: &str) -> bool {
    match conversations::Entity::find_by_id(conv.to_string()).one(db).await {
        Ok(Some(c)) => {
            let participants: Vec<Participant> =
                serde_json::from_str(&c.participants).unwrap_or_default();
            participants.is_empty() || participants.iter().any(|p| p.id == user)
        }
        // Inconnue ou erreur de lecture : on n'ajoute pas de blocage (comme Node).
        _ => true,
    }
}

/// Sortie JSON d'un message, au MÊME format que le serveur Node.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct MessageOut {
    id: String,
    conversation_id: String,
    sender_id: String,
    ciphertext: String,
    sent_at: String,
    seq: i64,
}

impl From<messages::Model> for MessageOut {
    fn from(m: messages::Model) -> Self {
        MessageOut {
            id: m.msg_id,
            conversation_id: m.conversation_id,
            sender_id: m.sender_id,
            ciphertext: m.ciphertext,
            sent_at: m.sent_at,
            seq: m.seq,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendBody {
    conversation_id: String,
    id: String,
    ciphertext: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadBody {
    conversation_id: String,
    up_to: i64,
}

#[derive(serde::Deserialize)]
struct MessagesQuery {
    #[serde(rename = "conversationId")]
    conversation_id: String,
    #[serde(default)]
    after: i64,
}

async fn health() -> impl Responder {
    HttpResponse::Ok().content_type("text/plain").body("ok")
}

/// POST /v1/messages — stocke un message chiffré (idempotent sur (conv, id)).
async fn post_message(
    req: HttpRequest,
    db: web::Data<DatabaseConnection>,
    bc: web::Data<Broadcaster>,
    rt: web::Data<Realtime>,
    body: web::Json<SendBody>,
) -> impl Responder {
    let Some(sender) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let conv = body.conversation_id.trim();
    let ciphertext = body.ciphertext.trim();
    if conv.is_empty() || ciphertext.is_empty() {
        return HttpResponse::BadRequest().body("conversationId et ciphertext requis");
    }
    let db = db.get_ref();

    if !can_access(db, conv, &sender).await {
        return HttpResponse::Forbidden().body("accès refusé à cette conversation");
    }

    // Déjà présent ? (idempotence : le client peut renvoyer le même id.)
    if let Ok(Some(existing)) = messages::Entity::find()
        .filter(messages::Column::ConversationId.eq(conv))
        .filter(messages::Column::MsgId.eq(&body.id))
        .one(db)
        .await
    {
        return HttpResponse::Ok().json(MessageOut::from(existing));
    }

    let active = messages::ActiveModel {
        seq: sea_orm::ActiveValue::NotSet,
        msg_id: Set(body.id.clone()),
        conversation_id: Set(conv.to_string()),
        sender_id: Set(sender),
        ciphertext: Set(ciphertext.to_string()),
        sent_at: Set(now_iso()),
    };
    match active.insert(db).await {
        Ok(saved) => {
            let out = MessageOut::from(saved);
            // Diffusion temps réel : abonnés SSE locaux, puis (si Redis) les
            // autres dynos. Les clients dédoublonnent par id.
            if let Ok(json) = serde_json::to_string(&out) {
                let line = format!("data: {json}\n\n");
                bc.publish(&out.conversation_id, line.clone());
                rt.publish(&out.conversation_id, &line);
            }
            HttpResponse::Created().json(out)
        }
        Err(e) => {
            eprintln!("insert message: {e}");
            HttpResponse::InternalServerError().body("stockage impossible")
        }
    }
}

/// GET /v1/messages?conversationId=&after= — suite des messages + accusés.
async fn get_messages(
    req: HttpRequest,
    db: web::Data<DatabaseConnection>,
    q: web::Query<MessagesQuery>,
) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let db = db.get_ref();
    if !can_access(db, &q.conversation_id, &user).await {
        return HttpResponse::Forbidden().body("accès refusé à cette conversation");
    }
    let rows = messages::Entity::find()
        .filter(messages::Column::ConversationId.eq(&q.conversation_id))
        .filter(messages::Column::Seq.gt(q.after))
        .order_by_asc(messages::Column::Seq)
        .all(db)
        .await
        .unwrap_or_default();

    let cursor = rows.last().map(|m| m.seq).unwrap_or(q.after);
    let out: Vec<MessageOut> = rows.into_iter().map(MessageOut::from).collect();

    // Accusés de lecture { userId: dernierSeqLu }.
    let readers_rows = read_cursors::Entity::find()
        .filter(read_cursors::Column::ConversationId.eq(&q.conversation_id))
        .all(db)
        .await
        .unwrap_or_default();
    let mut readers = serde_json::Map::new();
    for r in readers_rows {
        readers.insert(r.user_id, serde_json::json!(r.up_to));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "messages": out,
        "cursor": cursor,
        "readers": readers,
    }))
}

/// POST /v1/read — avance le curseur de lecture (max monotone).
async fn post_read(
    req: HttpRequest,
    db: web::Data<DatabaseConnection>,
    bc: web::Data<Broadcaster>,
    body: web::Json<ReadBody>,
) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let conv = body.conversation_id.trim();
    if conv.is_empty() {
        return HttpResponse::BadRequest().body("conversationId requis");
    }
    let db = db.get_ref();

    if !can_access(db, conv, &user).await {
        return HttpResponse::Forbidden().body("accès refusé à cette conversation");
    }

    // Curseur MONOTONE : on ne recule jamais (max avec la valeur existante).
    let existing = read_cursors::Entity::find_by_id((conv.to_string(), user.clone()))
        .one(db)
        .await
        .ok()
        .flatten()
        .map(|m| m.up_to)
        .unwrap_or(0);
    let up_to = body.up_to.max(0).max(existing);

    let active = read_cursors::ActiveModel {
        conversation_id: Set(conv.to_string()),
        user_id: Set(user.clone()),
        up_to: Set(up_to),
    };
    let res = read_cursors::Entity::insert(active)
        .on_conflict(
            OnConflict::columns([
                read_cursors::Column::ConversationId,
                read_cursors::Column::UserId,
            ])
            .update_column(read_cursors::Column::UpTo)
            .to_owned(),
        )
        .exec(db)
        .await;
    match res {
        Ok(_) => {
            // Accusé de lecture en temps réel (l'expéditeur verra « Lu »).
            let line = serde_json::json!({ "type": "read", "reader": user, "upTo": up_to });
            bc.publish(conv, format!("data: {line}\n\n"));
            HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
        }
        Err(e) => {
            eprintln!("read cursor: {e}");
            HttpResponse::InternalServerError().body("curseur impossible")
        }
    }
}

#[derive(serde::Deserialize)]
struct StreamQuery {
    #[serde(rename = "conversationId")]
    conversation_id: String,
}

/// GET /v1/stream?conversationId=.. — flux temps réel (Server-Sent Events).
/// Émet `data: {message}\n\n` à chaque nouveau message et
/// `data: {"type":"read",...}\n\n` à chaque accusé, plus un keep-alive.
async fn stream(
    req: HttpRequest,
    db: web::Data<DatabaseConnection>,
    bc: web::Data<Broadcaster>,
    q: web::Query<StreamQuery>,
) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let conv = q.conversation_id.trim().to_string();
    if conv.is_empty() {
        return HttpResponse::BadRequest().body("conversationId requis");
    }
    if !can_access(db.get_ref(), &conv, &user).await {
        return HttpResponse::Forbidden().body("accès refusé à cette conversation");
    }

    let mut rx = bc.subscribe(&conv);
    let body = stream! {
        // Amorce + désactive le tampon d'un éventuel proxy.
        yield Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b":ok\n\n"));
        // Heroku coupe une connexion inactive après ~55 s : ping toutes les 25 s.
        let mut ka = tokio::time::interval(Duration::from_secs(25));
        ka.tick().await; // consomme le tick immédiat
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Ok(line) => yield Ok(Bytes::from(line)),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = ka.tick() => {
                    yield Ok(Bytes::from_static(b":keep-alive\n\n"));
                }
            }
        }
    };

    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("cache-control", "no-cache"))
        .insert_header(("x-accel-buffering", "no"))
        .streaming(body)
}

// ── Rendez-vous X25519 (relais de clés publiques, éphémère) ───────────────────

#[derive(serde::Deserialize)]
struct PairQuery {
    code: String,
    #[serde(default, rename = "peerId")]
    peer_id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairBody {
    code: String,
    peer_id: String,
    #[serde(rename = "pub")]
    pub_key: String,
}

async fn pair_get(rdv: web::Data<Rendezvous>, q: web::Query<PairQuery>) -> impl Responder {
    let code = q.code.trim();
    if code.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "code requis" }));
    }
    HttpResponse::Ok().json(rdv.peers_excluding(code, q.peer_id.trim()))
}

async fn pair_post(rdv: web::Data<Rendezvous>, body: web::Json<PairBody>) -> impl Responder {
    let (code, peer_id, pub_key) =
        (body.code.trim(), body.peer_id.trim(), body.pub_key.trim());
    if code.is_empty() || peer_id.is_empty() || pub_key.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "code, peerId et pub requis" }));
    }
    match rdv.add_peer(code, peer_id, pub_key) {
        Ok(peers) => HttpResponse::Ok().json(peers),
        Err(()) => HttpResponse::Conflict()
            .json(serde_json::json!({ "error": "ce code a déjà atteint le maximum de participants" })),
    }
}

#[derive(serde::Deserialize)]
struct WrapQuery {
    code: String,
    #[serde(rename = "peerId")]
    peer_id: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapItem {
    to_peer_id: String,
    blob: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapBody {
    code: String,
    from_peer_id: String,
    from_pub: String,
    items: Vec<WrapItem>,
}

async fn wrap_get(rdv: web::Data<Rendezvous>, q: web::Query<WrapQuery>) -> impl Responder {
    let (code, peer_id) = (q.code.trim(), q.peer_id.trim());
    if code.is_empty() || peer_id.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "code et peerId requis" }));
    }
    HttpResponse::Ok().json(rdv.get_wrap(code, peer_id))
}

async fn wrap_post(rdv: web::Data<Rendezvous>, body: web::Json<WrapBody>) -> impl Responder {
    let (code, from, from_pub) =
        (body.code.trim(), body.from_peer_id.trim(), body.from_pub.trim());
    if code.is_empty() || from.is_empty() || from_pub.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "code, fromPeerId, fromPub et items requis" }));
    }
    let items: Vec<(String, String)> = body
        .items
        .iter()
        .map(|it| (it.to_peer_id.trim().to_string(), it.blob.trim().to_string()))
        .collect();
    let count = rdv.put_wraps(code, from, from_pub, &items);
    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "count": count }))
}

// ── Push Live Activity : enregistrement du token (envoi APNs à venir) ─────────

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveTokenBody {
    code: String,
    peer_id: String,
    token: String,
}

async fn live_token_post(rdv: web::Data<Rendezvous>, body: web::Json<LiveTokenBody>) -> impl Responder {
    let (code, peer_id, token) = (body.code.trim(), body.peer_id.trim(), body.token.trim());
    if code.is_empty() || peer_id.is_empty() || token.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "code, peerId et token requis" }));
    }
    rdv.put_live_token(code, peer_id, token);
    HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}

// ── Push Live Activity : envoi APNs (update / end) ────────────────────────────

fn default_event() -> String {
    "update".to_string()
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveUpdateBody {
    code: String,
    peer_id: String,
    #[serde(default = "default_event")]
    event: String,
    content_state: serde_json::Value,
    #[serde(default)]
    dismissal_date: Option<i64>,
}

async fn live_update_post(
    rdv: web::Data<Rendezvous>,
    apns: web::Data<Option<Apns>>,
    body: web::Json<LiveUpdateBody>,
) -> impl Responder {
    let (code, peer_id, event) = (body.code.trim(), body.peer_id.trim(), body.event.trim());
    if code.is_empty() || peer_id.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "code et peerId requis" }));
    }
    if event != "update" && event != "end" {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "event doit valoir \"update\" ou \"end\"" }));
    }
    if !body.content_state.is_object() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "contentState (objet) requis" }));
    }
    let Some(token) = rdv.live_token(code, peer_id) else {
        return HttpResponse::NotFound()
            .json(serde_json::json!({ "error": "aucun token de Live Activity pour ce peerId" }));
    };
    let Some(sender) = apns.get_ref().as_ref() else {
        return HttpResponse::ServiceUnavailable()
            .json(serde_json::json!({ "error": "push non configuré côté serveur" }));
    };
    match sender
        .send_live_activity(&token, event, &body.content_state, body.dismissal_date)
        .await
    {
        Ok(status) => HttpResponse::Ok().json(serde_json::json!({ "ok": true, "apns": status })),
        Err(e) => {
            HttpResponse::BadGateway().json(serde_json::json!({ "error": "échec APNs", "detail": e }))
        }
    }
}

// ── Conversations à participants explicites ──────────────────────────────────

#[derive(serde::Deserialize, serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Participant {
    id: String,
    #[serde(default)]
    display_name: String,
}

#[derive(serde::Deserialize)]
struct CreateConversation {
    participants: Vec<Participant>,
}

async fn conversations_post(
    req: HttpRequest,
    db: web::Data<DatabaseConnection>,
    body: web::Json<CreateConversation>,
) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "X-User-Id requis" }));
    };
    if body.participants.len() < 2 {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "au moins 2 participants requis" }));
    }
    if !body.participants.iter().any(|p| p.id == user) {
        return HttpResponse::Forbidden()
            .json(serde_json::json!({ "error": "tu dois faire partie de la conversation" }));
    }
    let clean: Vec<Participant> = body
        .participants
        .iter()
        .map(|p| Participant { id: p.id.clone(), display_name: p.display_name.clone() })
        .collect();
    let id = uuid::Uuid::new_v4().to_string();
    let created_at = now_iso();
    let participants_json = serde_json::to_string(&clean).unwrap_or_else(|_| "[]".into());

    let active = conversations::ActiveModel {
        id: Set(id.clone()),
        participants: Set(participants_json),
        created_at: Set(created_at.clone()),
    };
    if let Err(e) = active.insert(db.get_ref()).await {
        eprintln!("insert conversation: {e}");
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "création impossible" }));
    }
    HttpResponse::Created().json(serde_json::json!({
        "id": id, "participants": clean, "createdAt": created_at
    }))
}

async fn conversations_get(
    req: HttpRequest,
    db: web::Data<DatabaseConnection>,
) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": "X-User-Id requis" }));
    };
    let rows = conversations::Entity::find()
        .all(db.get_ref())
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for r in rows {
        let participants: Vec<Participant> =
            serde_json::from_str(&r.participants).unwrap_or_default();
        if !participants.is_empty() && participants.iter().any(|p| p.id == user) {
            out.push(serde_json::json!({
                "id": r.id, "participants": participants, "createdAt": r.created_at
            }));
        }
    }
    HttpResponse::Ok().json(out)
}

// ── Vitrine ──────────────────────────────────────────────────────────────────

const HOME_HTML: &str = r#"<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Brocolis 🥦 — serveur</title>
<style>body{font-family:system-ui;background:#e9f6ec;color:#15321f;display:grid;
place-items:center;min-height:100vh;margin:0}main{max-width:34rem;padding:2rem;
text-align:center}h1{font-size:2rem}code{background:#f1f8f3;padding:.15rem .4rem;
border-radius:.4rem}</style></head><body><main>
<h1>Brocolis 🥦</h1>
<p>Serveur de messagerie chiffrée (Rust · Actix). Il ne relaie que du chiffré.</p>
<p>API : <code>/health</code>, <code>/pair</code>, <code>/wrap</code>,
<code>/v1/messages</code>, <code>/v1/stream</code>.</p>
</main></body></html>"#;

async fn home() -> impl Responder {
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(HOME_HTML)
}

/// Crée les tables si besoin (idempotent). Postgres via SeaORM.
async fn ensure_schema(db: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS conversations (
            id           TEXT PRIMARY KEY,
            participants TEXT NOT NULL DEFAULT '[]',
            created_at   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            seq             BIGSERIAL PRIMARY KEY,
            msg_id          TEXT NOT NULL,
            conversation_id TEXT NOT NULL,
            sender_id       TEXT NOT NULL,
            ciphertext      TEXT NOT NULL,
            sent_at         TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_unique ON messages(conversation_id, msg_id);
        CREATE INDEX IF NOT EXISTS idx_msg_conv_seq ON messages(conversation_id, seq);
        CREATE INDEX IF NOT EXISTS idx_msg_sent_at ON messages(sent_at);
        CREATE TABLE IF NOT EXISTS read_cursors (
            conversation_id TEXT NOT NULL,
            user_id         TEXT NOT NULL,
            up_to           BIGINT NOT NULL,
            PRIMARY KEY (conversation_id, user_id)
        );
        "#,
    )
    .await
    .map(|_| ())
}

/// Purge périodique des messages plus vieux que la fenêtre de rétention.
async fn retention_loop(db: DatabaseConnection) {
    let days = retention_days();
    loop {
        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        if let Err(e) = messages::Entity::delete_many()
            .filter(messages::Column::SentAt.lt(&cutoff))
            .exec(&db)
            .await
        {
            eprintln!("purge rétention: {e}");
        }
    }
}

/// Force `sslmode=require` sur une URL Postgres distante (Heroku impose TLS avec
/// un certificat auto-signé ; `require` chiffre sans vérifier la chaîne, comme
/// le `rejectUnauthorized:false` du serveur Node). Local/déjà réglé : inchangé.
fn normalize_db_url(url: String) -> String {
    let is_pg = url.starts_with("postgres://") || url.starts_with("postgresql://");
    let is_local = url.contains("@localhost") || url.contains("@127.0.0.1");
    if is_pg && !is_local && !url.contains("sslmode=") {
        let sep = if url.contains('?') { '&' } else { '?' };
        format!("{url}{sep}sslmode=require")
    } else {
        url
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8788);
    let database_url = normalize_db_url(
        std::env::var("DATABASE_URL")
            .expect("DATABASE_URL requis (Heroku Postgres) pour le service Rust"),
    );

    let db = Database::connect(&database_url)
        .await
        .expect("connexion Postgres impossible");
    ensure_schema(&db).await.expect("création du schéma impossible");

    // Rétention en tâche de fond.
    tokio::spawn(retention_loop(db.clone()));

    let max_peers: usize = std::env::var("MAX_PEERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    let rdv = web::Data::new(Rendezvous::new(max_peers));
    // Purge des relais éphémères (pair/wrap/tokens) toutes les minutes.
    {
        let rdv = rdv.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                rdv.prune();
            }
        });
    }

    // Vitrine statique optionnelle (répertoire PUBLIC_DIR, défaut "public").
    let public_dir = std::env::var("PUBLIC_DIR").unwrap_or_else(|_| "public".to_string());

    // Push APNs (Live Activity) : None si config incomplète → route 503.
    let apns = web::Data::new(Apns::from_env());
    if apns.get_ref().is_some() {
        println!("APNs configuré : mises à jour de Live Activity actives.");
    }

    let data = web::Data::new(db);
    let broadcaster = web::Data::new(Broadcaster::default());

    // Temps réel inter-dynos (Redis, optionnel) : rediffuse aux abonnés locaux.
    let bc_for_redis = broadcaster.clone().into_inner();
    let realtime = web::Data::new(
        Realtime::connect(std::env::var("REDIS_URL").ok(), move |conv, line| {
            bc_for_redis.publish(&conv, line);
        })
        .await,
    );

    println!("Messagerie Brocolis 🥦 (Rust/Actix) à l'écoute sur le port {port}");

    HttpServer::new(move || {
        let mut app = App::new()
            .app_data(data.clone())
            .app_data(broadcaster.clone())
            .app_data(rdv.clone())
            .app_data(apns.clone())
            .app_data(realtime.clone())
            .app_data(web::JsonConfig::default().limit(8 * 1024 * 1024)) // médias chiffrés
            .route("/health", web::get().to(health))
            // Rendez-vous X25519
            .route("/pair", web::get().to(pair_get))
            .route("/pair", web::post().to(pair_post))
            .route("/wrap", web::get().to(wrap_get))
            .route("/wrap", web::post().to(wrap_post))
            .route("/push/live-activity/token", web::post().to(live_token_post))
            .route("/push/live-activity/update", web::post().to(live_update_post))
            // Messagerie
            .route("/v1/conversations", web::post().to(conversations_post))
            .route("/v1/conversations", web::get().to(conversations_get))
            .route("/v1/messages", web::post().to(post_message))
            .route("/v1/messages", web::get().to(get_messages))
            .route("/v1/read", web::post().to(post_read))
            .route("/v1/stream", web::get().to(stream));
        // Vitrine React (Vite/HashRouter) : servie À LA RACINE quand le bundle
        // est présent (image Docker → PUBLIC_DIR), et aussi sur /site/ (rétro-
        // compat). L'utilisateur qui ouvre l'URL du serveur voit donc le vrai
        // site (accueil, doc, Salon, navigation) et pas seulement l'API.
        // `Files` en dernier : les routes d'API ci-dessus gardent la priorité.
        if std::path::Path::new(&public_dir).is_dir() {
            app = app
                .service(Files::new("/site", &public_dir).index_file("index.html"))
                .service(Files::new("/", &public_dir).index_file("index.html"));
        } else {
            // Pas de bundle (dev local) : page d'accueil minimale de l'API.
            app = app.route("/", web::get().to(home));
        }
        // CORS ouvert : le serveur ne relaie que du public/chiffré (clés
        // publiques, jetons). Permet au site (Salon des rendez-vous) de lire
        // l'état d'un code depuis un autre domaine.
        app.wrap(
            actix_web::middleware::DefaultHeaders::new()
                .add(("Access-Control-Allow-Origin", "*")),
        )
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_forces_sslmode_on_remote_postgres() {
        let out = normalize_db_url("postgres://u:p@ec2.example.com:5432/db".into());
        assert!(out.ends_with("?sslmode=require"), "got: {out}");
    }

    #[test]
    fn normalize_appends_with_ampersand_when_query_exists() {
        let out = normalize_db_url("postgres://u:p@host/db?connect_timeout=5".into());
        assert!(out.contains("connect_timeout=5"));
        assert!(out.ends_with("&sslmode=require"), "got: {out}");
    }

    #[test]
    fn normalize_leaves_local_and_preset_urls_untouched() {
        // Local : pas de TLS imposé.
        let local = "postgres://brocolis:brocolis@localhost/brocolis".to_string();
        assert_eq!(normalize_db_url(local.clone()), local);
        let loop_ip = "postgresql://u@127.0.0.1:5432/db".to_string();
        assert_eq!(normalize_db_url(loop_ip.clone()), loop_ip);
        // sslmode déjà présent : on n'y touche pas.
        let preset = "postgres://u@host/db?sslmode=disable".to_string();
        assert_eq!(normalize_db_url(preset.clone()), preset);
        // Non-postgres : inchangé.
        let other = "mysql://u@host/db".to_string();
        assert_eq!(normalize_db_url(other.clone()), other);
    }

    #[test]
    fn message_out_serializes_in_camel_case() {
        let m = messages::Model {
            seq: 7,
            msg_id: "m1".into(),
            conversation_id: "c1".into(),
            sender_id: "alice".into(),
            ciphertext: "ZZ".into(),
            sent_at: "2026-01-01T00:00:00.000Z".into(),
        };
        let v = serde_json::to_value(MessageOut::from(m)).unwrap();
        // Format de fil identique au serveur Node (clés camelCase).
        assert_eq!(v["id"], "m1");
        assert_eq!(v["conversationId"], "c1");
        assert_eq!(v["senderId"], "alice");
        assert_eq!(v["ciphertext"], "ZZ");
        assert_eq!(v["sentAt"], "2026-01-01T00:00:00.000Z");
        assert_eq!(v["seq"], 7);
    }
}
