//! API messagerie Brocolis 🥦 en Rust (Actix-web + SeaORM).
//!
//! Portage EN PARALLÈLE du serveur Node (`server/`). Ce service couvre le cœur
//! messagerie sur Postgres ; il ne stocke QUE du chiffré (jetons Brocolis).
//! À porter ensuite : rendez-vous X25519, flux SSE, push APNs, Redis.
//!
//! Persistance DURABLE native : Postgres est la source de vérité (plus de
//! snapshot SQLite comme côté Node). `seq` = BIGSERIAL, stable et monotone.

mod entities;

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

use entities::{messages, read_cursors};

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
            // Diffusion temps réel aux abonnés SSE (clients dédoublonnent par id).
            if let Ok(json) = serde_json::to_string(&out) {
                bc.publish(&out.conversation_id, format!("data: {json}\n\n"));
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
    db: web::Data<DatabaseConnection>,
    q: web::Query<MessagesQuery>,
) -> impl Responder {
    let db = db.get_ref();
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
    bc: web::Data<Broadcaster>,
    q: web::Query<StreamQuery>,
) -> impl Responder {
    if user_id(&req).is_none() {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    }
    let conv = q.conversation_id.trim().to_string();
    if conv.is_empty() {
        return HttpResponse::BadRequest().body("conversationId requis");
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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8788);
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL requis (Heroku Postgres) pour le service Rust");

    let db = Database::connect(&database_url)
        .await
        .expect("connexion Postgres impossible");
    ensure_schema(&db).await.expect("création du schéma impossible");

    // Rétention en tâche de fond.
    tokio::spawn(retention_loop(db.clone()));

    let data = web::Data::new(db);
    let broadcaster = web::Data::new(Broadcaster::default());
    println!("Messagerie Brocolis 🥦 (Rust/Actix) à l'écoute sur le port {port}");

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .app_data(broadcaster.clone())
            .app_data(web::JsonConfig::default().limit(8 * 1024 * 1024)) // médias chiffrés
            .route("/health", web::get().to(health))
            .route("/v1/messages", web::post().to(post_message))
            .route("/v1/messages", web::get().to(get_messages))
            .route("/v1/read", web::post().to(post_read))
            .route("/v1/stream", web::get().to(stream))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
