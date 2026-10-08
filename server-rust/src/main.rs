//! API messagerie Brocolis 🥦 en Rust (Actix-web + SeaORM).
//!
//! Portage EN PARALLÈLE du serveur Node (`server/`). Ce service couvre le cœur
//! messagerie sur Postgres ; il ne stocke QUE du chiffré (jetons Brocolis).
//! À porter ensuite : rendez-vous X25519, flux SSE, push APNs, Redis.
//!
//! Persistance DURABLE native : Postgres est la source de vérité (plus de
//! snapshot SQLite comme côté Node). `seq` = BIGSERIAL, stable et monotone.

mod apns;
mod apple_signin;
mod entities;
mod realtime;
mod rendezvous;

use actix_files::Files;
use apns::Apns;
use apple_signin::{AppleKeys, VerifyError};
use realtime::Realtime;
use actix_web::web::Bytes;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use async_stream::stream;
use chrono::SecondsFormat;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    DbBackend, DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set, Statement,
};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::broadcast;

use entities::{conversation_members, conversations, message_dedup, messages, read_cursors};
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

/// Accès offerts : les identifiants d'appareil listés dans `BROCOLIS_PRO_IDS`
/// (séparés par des virgules) obtiennent Brocolis Pro sans passer par l'App
/// Store. Sert aux comptes de l'auteur et de ses proches, pas à vendre.
///
/// Pure, donc testable sans serveur ni variable d'environnement.
fn granted_tier_from_list(raw: &str, user: &str) -> &'static str {
    let user = user.trim();
    if user.is_empty() {
        return "free";
    }
    // Comparaison exacte après nettoyage : une entrée vide (« a,,b ») ou de
    // simples espaces ne doivent ouvrir aucun accès.
    for entry in raw.split(',') {
        let entry = entry.trim();
        if !entry.is_empty() && entry == user {
            return "pro";
        }
    }
    "free"
}

/// E-mail rattaché à cet appareil par « Se connecter avec Apple », s'il y en a un.
async fn linked_email(db: &DatabaseConnection, user: &str) -> Option<String> {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT email FROM plan_grants WHERE user_id = $1",
            [user.into()],
        ))
        .await
        .ok()??;
    row.try_get::<String>("", "email").ok()
}

/// Palier offert à un appareil : par son identifiant (`BROCOLIS_PRO_IDS`) ou
/// par l'e-mail Apple qui lui est rattaché (`BROCOLIS_PRO_EMAILS`). Les listes
/// sont relues à chaque appel : retirer une entrée retire l'accès.
async fn granted_tier(db: &DatabaseConnection, user: &str) -> (&'static str, Option<String>) {
    let ids = std::env::var("BROCOLIS_PRO_IDS").unwrap_or_default();
    let email = linked_email(db, user).await;
    if granted_tier_from_list(&ids, user) == "pro" {
        return ("pro", email);
    }
    let emails = std::env::var("BROCOLIS_PRO_EMAILS").unwrap_or_default();
    match &email {
        Some(e) if apple_signin::email_in_list(&emails, e) => ("pro", email),
        _ => ("free", email),
    }
}

/// GET /v1/plan — le palier offert à l'appelant (voir `granted_tier`).
/// Ne dit RIEN des abonnements App Store : ceux-là, seul l'appareil les
/// connaît, via StoreKit. L'app prend le plus ouvert des deux.
async fn get_plan(db: web::Data<DatabaseConnection>, req: HttpRequest) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let (tier, email) = granted_tier(&db, &user).await;
    HttpResponse::Ok().json(serde_json::json!({ "tier": tier, "email": email }))
}

#[derive(serde::Deserialize)]
struct AppleLinkBody {
    #[serde(rename = "identityToken")]
    identity_token: String,
}

/// POST /v1/plan/apple — « Se connecter avec Apple ». Vérifie le jeton
/// d'identité d'Apple ; si son e-mail figure dans `BROCOLIS_PRO_EMAILS`, le
/// rattache à cet appareil (Pro offert). Sinon rien n'est conservé.
async fn post_plan_apple(
    db: web::Data<DatabaseConnection>,
    apple: web::Data<AppleKeys>,
    req: HttpRequest,
    body: web::Json<AppleLinkBody>,
) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let email = match apple.verify(&body.identity_token, &apple_signin::expected_audience()).await {
        Ok(email) => email,
        Err(None) => {
            return HttpResponse::ServiceUnavailable()
                .json(serde_json::json!({ "error": "Apple injoignable, réessaie" }))
        }
        Err(Some(VerifyError::NoVerifiedEmail)) => {
            return HttpResponse::UnprocessableEntity()
                .json(serde_json::json!({ "error": "aucun e-mail vérifié dans le jeton Apple" }))
        }
        Err(Some(e)) => {
            eprintln!("[plan/apple] jeton refusé : {e:?}");
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "jeton Apple invalide" }));
        }
    };
    let emails = std::env::var("BROCOLIS_PRO_EMAILS").unwrap_or_default();
    if !apple_signin::email_in_list(&emails, &email) {
        return HttpResponse::Ok().json(serde_json::json!({ "tier": "free", "email": email }));
    }
    let saved = db
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO plan_grants (user_id, email) VALUES ($1, $2) \
             ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, linked_at = now()",
            [user.clone().into(), email.clone().into()],
        ))
        .await;
    if let Err(e) = saved {
        eprintln!("[plan/apple] enregistrement impossible : {e}");
        return HttpResponse::InternalServerError().finish();
    }
    HttpResponse::Ok().json(serde_json::json!({ "tier": "pro", "email": email }))
}

/// DELETE /v1/plan/apple — détache l'e-mail de cet appareil.
async fn delete_plan_apple(db: web::Data<DatabaseConnection>, req: HttpRequest) -> impl Responder {
    let Some(user) = user_id(&req) else {
        return HttpResponse::Unauthorized().body("x-user-id requis");
    };
    let _ = db
        .execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM plan_grants WHERE user_id = $1",
            [user.clone().into()],
        ))
        .await;
    let (tier, _) = granted_tier(&db, &user).await;
    HttpResponse::Ok().json(serde_json::json!({ "tier": tier, "email": null }))
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
    /// Taille de page demandée (optionnelle). Bornée par `MAX_MESSAGES_PAGE`.
    #[serde(default)]
    limit: Option<i64>,
}

/// Pagination de `GET /v1/messages` : on ne renvoie jamais tout un historique
/// d'un coup (une longue conversation pourrait peser des Mo de médias chiffrés).
/// Le client avance page par page avec `after=<cursor>` tant que `hasMore`.
const DEFAULT_MESSAGES_PAGE: u64 = 200;
const MAX_MESSAGES_PAGE: u64 = 500;

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

    let sent = now_iso();

    // Idempotence RACE-SAFE : on « réserve » (conversation_id, msg_id) dans la
    // table de dédup. `messages` étant partitionnée par temps, elle ne peut plus
    // porter cette unicité (il faudrait y inclure sent_at) — d'où la table dédiée.
    let reserve = message_dedup::Entity::insert(message_dedup::ActiveModel {
        conversation_id: Set(conv.to_string()),
        msg_id: Set(body.id.clone()),
        sent_at: Set(sent.clone()),
    })
    .on_conflict(
        OnConflict::columns([
            message_dedup::Column::ConversationId,
            message_dedup::Column::MsgId,
        ])
        .do_nothing()
        .to_owned(),
    )
    .exec(db)
    .await;

    match reserve {
        // Déjà connu : on renvoie le message existant (idempotent).
        Err(DbErr::RecordNotInserted) => {
            if let Ok(Some(existing)) = messages::Entity::find()
                .filter(messages::Column::ConversationId.eq(conv))
                .filter(messages::Column::MsgId.eq(&body.id))
                .one(db)
                .await
            {
                return HttpResponse::Ok().json(MessageOut::from(existing));
            }
            // Réservation présente mais message absent (tentative précédente
            // interrompue) : on ré-insère ci-dessous pour se rétablir.
        }
        Err(e) => {
            eprintln!("réservation dedup: {e}");
            return HttpResponse::InternalServerError().body("stockage impossible");
        }
        Ok(_) => {}
    }

    let active = messages::ActiveModel {
        seq: sea_orm::ActiveValue::NotSet,
        msg_id: Set(body.id.clone()),
        conversation_id: Set(conv.to_string()),
        sender_id: Set(sender),
        ciphertext: Set(ciphertext.to_string()),
        sent_at: Set(sent),
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
    // Taille de page effective : défaut 200, plafonnée à 500, jamais illimitée.
    let page = q
        .limit
        .filter(|n| *n > 0)
        .map(|n| (n as u64).min(MAX_MESSAGES_PAGE))
        .unwrap_or(DEFAULT_MESSAGES_PAGE);

    // Les deux lectures sont INDÉPENDANTES : on les lance en parallèle (deux
    // connexions du pool) → un seul aller-retour de latence au lieu de deux.
    // On demande UNE ligne de plus que la page pour savoir s'il en reste sans
    // requête supplémentaire : si on obtient page+1, il y a une page suivante.
    let messages_fut = messages::Entity::find()
        .filter(messages::Column::ConversationId.eq(&q.conversation_id))
        .filter(messages::Column::Seq.gt(q.after))
        .order_by_asc(messages::Column::Seq)
        .limit(page + 1)
        .all(db);
    let readers_fut = read_cursors::Entity::find()
        .filter(read_cursors::Column::ConversationId.eq(&q.conversation_id))
        .all(db);
    let (rows_res, readers_res) = tokio::join!(messages_fut, readers_fut);

    let mut rows = rows_res.unwrap_or_default();
    let has_more = rows.len() as u64 > page;
    if has_more {
        rows.truncate(page as usize); // on ne renvoie que la page demandée
    }

    let cursor = rows.last().map(|m| m.seq).unwrap_or(q.after);
    let out: Vec<MessageOut> = rows.into_iter().map(MessageOut::from).collect();

    // Accusés de lecture { userId: dernierSeqLu }.
    let readers_rows = readers_res.unwrap_or_default();
    let mut readers = serde_json::Map::new();
    for r in readers_rows {
        readers.insert(r.user_id, serde_json::json!(r.up_to));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "messages": out,
        "cursor": cursor,
        "readers": readers,
        // Champs additifs (les anciens clients les ignorent) : pour paginer,
        // rappeler avec `after=cursor` tant que `hasMore` est vrai.
        "hasMore": has_more,
        "limit": page,
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

    // Index d'appartenance : une ligne (conversation, membre) par participant,
    // pour lister les conversations d'un utilisateur sans balayer toute la table.
    let mut seen = std::collections::HashSet::new();
    let members: Vec<conversation_members::ActiveModel> = clean
        .iter()
        .filter(|p| !p.id.is_empty() && seen.insert(p.id.clone()))
        .map(|p| conversation_members::ActiveModel {
            conversation_id: Set(id.clone()),
            user_id: Set(p.id.clone()),
        })
        .collect();
    if !members.is_empty() {
        let res = conversation_members::Entity::insert_many(members)
            .on_conflict(
                OnConflict::columns([
                    conversation_members::Column::ConversationId,
                    conversation_members::Column::UserId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec(db.get_ref())
            .await;
        if let Err(e) = res {
            // Non bloquant : la conversation existe ; l'index se recréera au besoin.
            eprintln!("insert conversation_members: {e}");
        }
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
    let db = db.get_ref();

    // 1) Les ids des conversations de CET utilisateur, via l'index (idx_members_user)
    //    — O(ses conversations), et non plus un balayage de toute la table.
    let ids: Vec<String> = conversation_members::Entity::find()
        .filter(conversation_members::Column::UserId.eq(&user))
        .all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.conversation_id)
        .collect();
    if ids.is_empty() {
        return HttpResponse::Ok().json(serde_json::json!([]));
    }

    // 2) On ne charge que ces conversations-là (par clé primaire).
    let rows = conversations::Entity::find()
        .filter(conversations::Column::Id.is_in(ids))
        .all(db)
        .await
        .unwrap_or_default();
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let participants: Vec<Participant> =
                serde_json::from_str(&r.participants).unwrap_or_default();
            serde_json::json!({
                "id": r.id, "participants": participants, "createdAt": r.created_at
            })
        })
        .collect();
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
        -- Table `messages` PARTITIONNÉE EN COMPOSITE :
        --   niveau 1 : HASH(conversation_id), 16 partitions (localité par
        --              conversation + socle de sharding Citus) ;
        --   niveau 2 : RANGE(sent_at) par JOUR + une partition DEFAULT de
        --              sécurité. Objectif : la rétention devient un DROP de
        --              partition (quasi gratuit, pas de DELETE ligne à ligne ni
        --              de bloat), et le DEFAULT garantit que l'INSERT ne rate
        --              JAMAIS, même si le cron d'entretien a du retard.
        -- La clé primaire doit contenir les DEUX clés de partition :
        --   (conversation_id, sent_at, seq).
        -- Conséquence : l'unicité (conversation_id, msg_id) ne peut plus être un
        -- index sur `messages` (il devrait contenir sent_at) → l'idempotence
        -- passe par la table `message_dedup` ci-dessous.
        -- Migration idempotente et ATOMIQUE depuis toute forme antérieure (table
        -- simple, ou hash-simple de l'étape précédente) sans perte de données.
        DO $mig$
        DECLARE
          tbl_exists   bool;
          is_composite bool;
          i            int;
          d            date;
          r            record;
        BEGIN
          SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname='messages' AND relkind IN ('r','p'))
            INTO tbl_exists;
          -- « composite » = la partition de hachage messages_p0 est elle-même partitionnée.
          SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname='messages_p0' AND relkind='p')
            INTO is_composite;

          IF NOT is_composite THEN
            IF tbl_exists THEN
              ALTER TABLE messages RENAME TO messages_legacy;
              -- Ancien schéma hash-only (étape précédente) : les partitions
              -- messages_pN gardent leur nom en suivant le parent renommé et
              -- entreraient en COLLISION avec les nouvelles (« relation
              -- messages_p0 already exists »). On libère ces noms en les
              -- préfixant ; les données restent lisibles via messages_legacy.
              FOR r IN
                SELECT c.relname AS n FROM pg_class c
                WHERE c.relname ~ '^messages_p[0-9]' AND c.relkind IN ('r','p')
              LOOP
                EXECUTE format('ALTER TABLE %I RENAME TO %I', r.n, 'legacy_' || r.n);
              END LOOP;
            END IF;

            CREATE TABLE messages (
              seq             BIGSERIAL,
              msg_id          TEXT NOT NULL,
              conversation_id TEXT NOT NULL,
              sender_id       TEXT NOT NULL,
              ciphertext      TEXT NOT NULL,
              sent_at         TEXT NOT NULL,
              PRIMARY KEY (conversation_id, sent_at, seq)
            ) PARTITION BY HASH (conversation_id);

            -- 16 partitions de hachage, chacune sous-partitionnée par jour + DEFAULT.
            FOR i IN 0..15 LOOP
              EXECUTE format(
                'CREATE TABLE messages_p%s PARTITION OF messages '
                || 'FOR VALUES WITH (MODULUS 16, REMAINDER %s) PARTITION BY RANGE (sent_at)', i, i);
              EXECUTE format(
                'CREATE TABLE messages_p%s_def PARTITION OF messages_p%s DEFAULT', i, i);
            END LOOP;

            -- Partitions quotidiennes sur [today-8 .. today+2], créées AVANT toute
            -- recopie pour que les données récentes y atterrissent (le DEFAULT ne
            -- récupère que ce qui est hors fenêtre).
            FOR i IN 0..15 LOOP
              FOR d IN
                SELECT generate_series(current_date - 8, current_date + 2, interval '1 day')::date
              LOOP
                EXECUTE format(
                  'CREATE TABLE IF NOT EXISTS messages_p%s_d%s PARTITION OF messages_p%s '
                  || 'FOR VALUES FROM (%L) TO (%L)',
                  i, to_char(d,'YYYYMMDD'), i, to_char(d,'YYYY-MM-DD'), to_char(d + 1,'YYYY-MM-DD'));
              END LOOP;
            END LOOP;

            IF tbl_exists THEN
              INSERT INTO messages (seq, msg_id, conversation_id, sender_id, ciphertext, sent_at)
                SELECT seq, msg_id, conversation_id, sender_id, ciphertext, sent_at
                FROM messages_legacy;
              -- Réaligne la séquence sur le max recopié (sinon collisions de PK).
              PERFORM setval(
                pg_get_serial_sequence('messages','seq'),
                GREATEST((SELECT COALESCE(MAX(seq),0) FROM messages), 1));
            END IF;
          END IF;

          -- Idempotence (conversation_id, msg_id), race-safe, hors partitionnement.
          CREATE TABLE IF NOT EXISTS message_dedup (
            conversation_id TEXT NOT NULL,
            msg_id          TEXT NOT NULL,
            sent_at         TEXT NOT NULL,
            PRIMARY KEY (conversation_id, msg_id)
          );
          IF tbl_exists AND NOT is_composite THEN
            INSERT INTO message_dedup (conversation_id, msg_id, sent_at)
              SELECT conversation_id, msg_id, MIN(sent_at)
              FROM messages GROUP BY conversation_id, msg_id
              ON CONFLICT DO NOTHING;
            DROP TABLE IF EXISTS messages_legacy;
          END IF;
        END
        $mig$;
        CREATE INDEX IF NOT EXISTS idx_dedup_sent_at ON message_dedup(sent_at);
        -- Accès historique (conversation_id, seq) : index NON unique (pas besoin de
        -- contenir la clé de partition), cascade sur toutes les partitions.
        CREATE INDEX IF NOT EXISTS idx_msg_conv_seq ON messages(conversation_id, seq);
        CREATE INDEX IF NOT EXISTS idx_msg_sent_at ON messages(sent_at);
        CREATE TABLE IF NOT EXISTS read_cursors (
            conversation_id TEXT NOT NULL,
            user_id         TEXT NOT NULL,
            up_to           BIGINT NOT NULL,
            PRIMARY KEY (conversation_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id TEXT NOT NULL,
            user_id         TEXT NOT NULL,
            PRIMARY KEY (conversation_id, user_id)
        );
        -- Index clé : « les conversations de cet utilisateur » sans balayer la
        -- table entière. Indispensable dès que le nombre de conversations grandit.
        CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);
        -- Accès offerts par e-mail : appareil → e-mail Apple vérifié. Une
        -- ligne n'existe que si l'e-mail figurait dans BROCOLIS_PRO_EMAILS.
        CREATE TABLE IF NOT EXISTS plan_grants (
            user_id   TEXT PRIMARY KEY,
            email     TEXT NOT NULL,
            linked_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
        "#,
    )
    .await
    .map(|_| ())
}

/// Crée (idempotent, best-effort) les partitions quotidiennes autour
/// d'aujourd'hui pour les 16 partitions de hachage, afin que les nouveaux
/// messages atterrissent dans une partition DATÉE (et non dans le DEFAULT, qui
/// n'est qu'un filet). Tolère l'échec d'un CREATE (ex. si le DEFAULT contient
/// déjà des lignes de la plage) : les données restent lisibles et purgeables.
async fn ensure_time_partitions(db: &DatabaseConnection) {
    let today = chrono::Utc::now().date_naive();
    for off in -1..=2 {
        let d = today + chrono::Duration::days(off);
        let lo = d.format("%Y-%m-%d");
        let hi = (d + chrono::Duration::days(1)).format("%Y-%m-%d");
        let tag = d.format("%Y%m%d");
        for i in 0..16 {
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS messages_p{i}_d{tag} PARTITION OF messages_p{i} \
                 FOR VALUES FROM ('{lo}') TO ('{hi}')"
            );
            let _ = db.execute_unprepared(&sql).await;
        }
    }
}

/// Rétention par DROP : supprime les partitions quotidiennes plus vieilles que
/// la fenêtre — quasi gratuit (pas de DELETE ligne à ligne ni de bloat). Les
/// partitions DEFAULT (`messages_pN_def`) ne sont jamais touchées.
async fn drop_old_partitions(db: &DatabaseConnection, days: i64) {
    let cutoff_tag = (chrono::Utc::now().date_naive() - chrono::Duration::days(days))
        .format("%Y%m%d")
        .to_string();
    let sql = format!(
        r#"DO $drop$
        DECLARE r record;
        BEGIN
          FOR r IN SELECT relname FROM pg_class
                   WHERE relname ~ '^messages_p[0-9]+_d[0-9]{{8}}$' LOOP
            IF substring(r.relname from '_d([0-9]{{8}})$') < '{cutoff_tag}' THEN
              EXECUTE format('DROP TABLE IF EXISTS %I', r.relname);
            END IF;
          END LOOP;
        END $drop$;"#
    );
    let _ = db.execute_unprepared(&sql).await;
}

/// Boucle d'entretien (horaire) : crée les partitions à venir, DROP les
/// anciennes (rétention), puis passe un filet — purge des éventuels restes en
/// partition DEFAULT et de la table de dédup — sous la fenêtre de rétention.
async fn maintenance_loop(db: DatabaseConnection) {
    let days = retention_days();
    loop {
        ensure_time_partitions(&db).await;
        drop_old_partitions(&db, days).await;

        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        if let Err(e) = messages::Entity::delete_many()
            .filter(messages::Column::SentAt.lt(&cutoff))
            .exec(&db)
            .await
        {
            eprintln!("purge rétention (filet DEFAULT): {e}");
        }
        if let Err(e) = message_dedup::Entity::delete_many()
            .filter(message_dedup::Column::SentAt.lt(&cutoff))
            .exec(&db)
            .await
        {
            eprintln!("purge dédup: {e}");
        }
        tokio::time::sleep(Duration::from_secs(60 * 60)).await;
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

/// Enregistre TOUTES les routes de l'API (hors vitrine statique). Partagé entre
/// le serveur de production et les tests d'intégration : les tests exercent donc
/// exactement le même câblage que la prod (pas de dérive possible).
fn configure_api(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health))
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
        .route("/v1/plan", web::get().to(get_plan))
        .route("/v1/plan/apple", web::post().to(post_plan_apple))
        .route("/v1/plan/apple", web::delete().to(delete_plan_apple))
        .route("/v1/stream", web::get().to(stream));
}

/// Connexion Postgres avec réessais + backoff. Ne panique qu'après plusieurs
/// échecs consécutifs (vraie panne), pas au premier hoquet transitoire.
async fn connect_db_with_retry(opt: ConnectOptions) -> DatabaseConnection {
    let mut delay = 1u64;
    for attempt in 1..=6 {
        match Database::connect(opt.clone()).await {
            Ok(db) => return db,
            Err(e) => {
                eprintln!("[boot] connexion Postgres échouée (essai {attempt}/6) : {e}");
                if attempt == 6 {
                    panic!("connexion Postgres impossible après réessais : {e}");
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(15);
            }
        }
    }
    unreachable!()
}

/// Application du schéma avec réessais (Postgres peut être momentanément
/// indisponible au démarrage).
async fn ensure_schema_with_retry(db: &DatabaseConnection) {
    let mut delay = 1u64;
    for attempt in 1..=6 {
        match ensure_schema(db).await {
            Ok(()) => return,
            Err(e) => {
                eprintln!("[boot] ensure_schema échoué (essai {attempt}/6) : {e}");
                if attempt == 6 {
                    panic!("création du schéma impossible après réessais : {e}");
                }
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(15);
            }
        }
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

    // Pool de connexions BORNÉ : chaque dyno garde son pool sous le plafond de
    // connexions de Postgres (Heroku : ~20 sur les petits plans). Sans borne, un
    // pic — ou plusieurs dynos — épuiserait le cap et ferait tomber la base.
    // `DB_MAX_CONNECTIONS` permet de l'ajuster selon le plan/PgBouncer.
    let max_conns: u32 = std::env::var("DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let mut opt = ConnectOptions::new(database_url);
    opt.max_connections(max_conns)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(30 * 60))
        .sqlx_logging(false);
    // Connexion + schéma avec RÉESSAIS. Heroku coupe brièvement Postgres
    // (maintenance, rotation d'identifiants, redémarrage de dyno) : sans réessai,
    // `Database::connect(...).expect(...)` paniquait au boot → « H10 App crashed ».
    let db = connect_db_with_retry(opt).await;
    ensure_schema_with_retry(&db).await;
    // Partitions temporelles du jour prêtes avant de servir (utile au redémarrage
    // d'une base déjà migrée, si l'entretien n'a pas tourné depuis un moment).
    ensure_time_partitions(&db).await;

    // Entretien des partitions + rétention par DROP, en tâche de fond.
    tokio::spawn(maintenance_loop(db.clone()));

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
    let apple_keys = web::Data::new(AppleKeys::default());
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
            .app_data(apple_keys.clone())
            .app_data(web::JsonConfig::default().limit(8 * 1024 * 1024)) // médias chiffrés
            .configure(configure_api);
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
    // TCP_NODELAY : envoie les petits paquets (messages, événements SSE)
    // immédiatement, sans attendre l'algorithme de Nagle. Latence temps réel.
    .tcp_nodelay(true)
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Accès offerts (BROCOLIS_PRO_IDS) ---

    #[test]
    fn granted_tier_opens_pro_for_a_listed_id() {
        assert_eq!(granted_tier_from_list("AAA,BBB", "BBB"), "pro");
        // Les espaces autour des entrées sont tolérés : une liste se colle
        // souvent à la main dans l'interface Heroku.
        assert_eq!(granted_tier_from_list(" AAA , BBB ", "AAA"), "pro");
    }

    #[test]
    fn granted_tier_stays_free_for_everyone_else() {
        assert_eq!(granted_tier_from_list("AAA,BBB", "CCC"), "free");
        assert_eq!(granted_tier_from_list("", "AAA"), "free");
    }

    /// Le piège : une liste vide, ou avec des virgules en trop, ne doit pas
    /// ouvrir Pro à un appelant sans identifiant. Sans ce garde-fou,
    /// `"".split(',')` renvoie une entrée vide qui matcherait un `user` vide.
    #[test]
    fn granted_tier_never_opens_on_an_empty_identity() {
        assert_eq!(granted_tier_from_list("", ""), "free");
        assert_eq!(granted_tier_from_list(",,", ""), "free");
        assert_eq!(granted_tier_from_list("AAA,,BBB", ""), "free");
        assert_eq!(granted_tier_from_list("AAA,,BBB", "   "), "free");
    }

    /// Un identifiant qui n'est qu'un préfixe d'une entrée listée n'ouvre
    /// rien : la comparaison est exacte, pas « commence par ».
    #[test]
    fn granted_tier_requires_an_exact_match() {
        assert_eq!(granted_tier_from_list("AAABBB", "AAA"), "free");
        assert_eq!(granted_tier_from_list("AAA", "AAABBB"), "free");
    }

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

/// Tests d'INTÉGRATION bout-en-bout des handlers `/v1/*` contre un vrai Postgres
/// (équivalent de `messaging.test.js` / `messages-store.test.js` côté Node).
/// SAUTÉS proprement si aucune base n'est configurée (`TEST_DATABASE_URL` ou
/// `DATABASE_URL`) : `cargo test` reste vert sans Postgres ; la CI en fournit un.
#[cfg(test)]
mod integration {
    use super::*;
    use actix_web::test;
    use serde_json::json;

    async fn test_db() -> Option<DatabaseConnection> {
        let url = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .ok()?;
        let db = Database::connect(normalize_db_url(url)).await.ok()?;
        ensure_schema(&db).await.ok()?;
        Some(db)
    }

    // Récupère la base ou saute le test (retour anticipé) si aucune n'est là.
    macro_rules! db_or_skip {
        () => {
            match test_db().await {
                Some(db) => db,
                None => {
                    eprintln!("[skip] aucune base : définir TEST_DATABASE_URL ou DATABASE_URL");
                    return;
                }
            }
        };
    }

    // Construit l'app de test avec le MÊME câblage de routes que la prod.
    macro_rules! make_app {
        ($db:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($db.clone()))
                    .app_data(web::Data::new(Broadcaster::default()))
                    .app_data(web::Data::new(Rendezvous::new(16)))
                    .app_data(web::Data::new(Option::<Apns>::None))
                    .app_data(web::Data::new(Realtime::disabled()))
                    .app_data(web::Data::new(AppleKeys::default()))
                    .app_data(web::JsonConfig::default().limit(8 * 1024 * 1024))
                    .configure(configure_api),
            )
            .await
        };
    }

    // Crée une conversation et renvoie son id (String). Macro pour éviter de
    // devoir nommer le type opaque du service de test.
    macro_rules! create_conv {
        ($app:expr, $owner:expr, $participants:expr) => {{
            let req = test::TestRequest::post()
                .uri("/v1/conversations")
                .insert_header(("X-User-Id", $owner))
                .set_json(json!({ "participants": $participants }))
                .to_request();
            let resp = test::call_service(&$app, req).await;
            assert_eq!(resp.status(), 201, "création conversation");
            let body: serde_json::Value = test::read_body_json(resp).await;
            body["id"].as_str().unwrap().to_string()
        }};
    }

    // Envoie un message et renvoie son `seq`.
    macro_rules! post_msg {
        ($app:expr, $sender:expr, $conv:expr, $id:expr, $ct:expr) => {{
            let req = test::TestRequest::post()
                .uri("/v1/messages")
                .insert_header(("X-User-Id", $sender))
                .set_json(json!({ "conversationId": $conv, "id": $id, "ciphertext": $ct }))
                .to_request();
            let resp = test::call_service(&$app, req).await;
            assert_eq!(resp.status(), 201, "envoi message");
            let body: serde_json::Value = test::read_body_json(resp).await;
            body["seq"].as_i64().unwrap()
        }};
    }

    /// Accès offert par e-mail : un appareil rattaché à un e-mail Apple listé
    /// dans `BROCOLIS_PRO_EMAILS` obtient Pro ; retirer l'e-mail de la liste ou
    /// détacher l'appareil le retire. (La vérification du jeton Apple elle-même
    /// est couverte par les tests de `apple_signin`.)
    #[actix_web::test]
    async fn plan_follows_the_linked_apple_email() {
        let db = db_or_skip!();
        let app = make_app!(db);
        let user = format!("grant-{}", uuid::Uuid::new_v4());
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO plan_grants (user_id, email) VALUES ($1, 'max@icloud.com')",
            [user.clone().into()],
        ))
        .await
        .unwrap();

        macro_rules! plan {
            () => {{
                let req = test::TestRequest::get()
                    .uri("/v1/plan")
                    .insert_header(("X-User-Id", user.as_str()))
                    .to_request();
                let v: serde_json::Value = test::call_and_read_body_json(&app, req).await;
                v
            }};
        }

        // Seul ce test lit ou écrit BROCOLIS_PRO_EMAILS.
        std::env::set_var("BROCOLIS_PRO_EMAILS", "ami@exemple.fr, Max@iCloud.com");
        let v = plan!();
        assert_eq!(v["tier"], "pro");
        assert_eq!(v["email"], "max@icloud.com");

        std::env::set_var("BROCOLIS_PRO_EMAILS", "ami@exemple.fr");
        assert_eq!(plan!()["tier"], "free", "retiré de la liste = plus de Pro");

        std::env::set_var("BROCOLIS_PRO_EMAILS", "max@icloud.com");
        let req = test::TestRequest::delete()
            .uri("/v1/plan/apple")
            .insert_header(("X-User-Id", user.as_str()))
            .to_request();
        let v: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(v["tier"], "free", "appareil détaché");
        assert_eq!(plan!()["email"], serde_json::Value::Null);
        std::env::remove_var("BROCOLIS_PRO_EMAILS");
    }

    /// Un jeton Apple illisible est refusé (401) sans rien enregistrer.
    #[actix_web::test]
    async fn plan_apple_rejects_a_bogus_token() {
        let db = db_or_skip!();
        let app = make_app!(db);
        let req = test::TestRequest::post()
            .uri("/v1/plan/apple")
            .insert_header(("X-User-Id", "bogus-token-user"))
            .set_json(json!({ "identityToken": "pas-un-jeton" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn messages_are_paginated() {
        let db = db_or_skip!();
        let app = make_app!(db);
        let conv = create_conv!(app, "alice", json!([{ "id": "alice" }, { "id": "bob" }]));

        // Cinq messages dans l'ordre.
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = uuid::Uuid::new_v4().to_string();
            post_msg!(app, "bob", conv, id, format!("c{i}"));
            ids.push(id);
        }

        // Une page depuis `after`, taille `limit`. Macro pour éviter de nommer
        // le type opaque du service de test.
        macro_rules! page {
            ($after:expr, $limit:expr) => {{
                let req = test::TestRequest::get()
                    .uri(&format!(
                        "/v1/messages?conversationId={}&after={}&limit={}",
                        conv, $after, $limit
                    ))
                    .insert_header(("X-User-Id", "alice"))
                    .to_request();
                let v: serde_json::Value = test::call_and_read_body_json(&app, req).await;
                v
            }};
        }

        // Page 1 : 2 messages, il en reste.
        let p1 = page!(0, 2);
        assert_eq!(p1["messages"].as_array().unwrap().len(), 2);
        assert_eq!(p1["hasMore"], true);
        assert_eq!(p1["limit"], 2);
        assert_eq!(p1["messages"][0]["id"], ids[0]);
        assert_eq!(p1["messages"][1]["id"], ids[1]);
        let c1 = p1["cursor"].as_i64().unwrap();

        // Page 2 : 2 messages de plus.
        let p2 = page!(c1, 2);
        assert_eq!(p2["messages"].as_array().unwrap().len(), 2);
        assert_eq!(p2["hasMore"], true);
        assert_eq!(p2["messages"][0]["id"], ids[2]);
        assert_eq!(p2["messages"][1]["id"], ids[3]);
        let c2 = p2["cursor"].as_i64().unwrap();

        // Page 3 : le dernier, plus rien après.
        let p3 = page!(c2, 2);
        assert_eq!(p3["messages"].as_array().unwrap().len(), 1);
        assert_eq!(p3["hasMore"], false);
        assert_eq!(p3["messages"][0]["id"], ids[4]);

        // `limit` hors bornes est ramené au plafond (jamais illimité).
        let capped = page!(0, 100_000);
        assert_eq!(capped["limit"], MAX_MESSAGES_PAGE);
    }

    #[actix_web::test]
    async fn messages_table_is_hash_partitioned() {
        let db = db_or_skip!();
        use sea_orm::{DbBackend, Statement};

        // `messages` doit être une table PARTITIONNÉE (relkind='p')…
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT relkind::text FROM pg_class WHERE relname='messages'".to_owned(),
            ))
            .await
            .unwrap()
            .expect("table messages introuvable");
        let relkind: String = row.try_get_by_index(0).unwrap();
        assert_eq!(relkind, "p", "messages doit rester partitionnée");

        // …avec ses 16 partitions.
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT count(*)::bigint FROM pg_inherits i \
                 JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname='messages'"
                    .to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        let n: i64 = row.try_get_by_index(0).unwrap();
        assert_eq!(n, 16, "16 partitions de hachage attendues");

        // …composite : la partition de hachage messages_p0 est elle-même
        // partitionnée (par temps).
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT relkind::text FROM pg_class WHERE relname='messages_p0'".to_owned(),
            ))
            .await
            .unwrap()
            .expect("messages_p0 introuvable");
        let sub: String = row.try_get_by_index(0).unwrap();
        assert_eq!(sub, "p", "messages_p0 doit être sous-partitionnée par temps");

        // La table de dédup (idempotence) doit exister.
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT count(*)::bigint FROM pg_class WHERE relname='message_dedup'".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        let dedup: i64 = row.try_get_by_index(0).unwrap();
        assert_eq!(dedup, 1, "table message_dedup attendue");
    }

    #[actix_web::test]
    async fn partition_maintenance_creates_today_and_drops_old() {
        let db = db_or_skip!();
        use sea_orm::{DbBackend, Statement};

        // Entretien : crée les partitions du jour, DROP les trop vieilles.
        ensure_time_partitions(&db).await;
        drop_old_partitions(&db, retention_days()).await;

        // La partition quotidienne d'aujourd'hui existe sur les 16 hash.
        let today = chrono::Utc::now().date_naive().format("%Y%m%d").to_string();
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT count(*)::bigint FROM pg_class \
                     WHERE relname ~ '^messages_p[0-9]+_d{today}$'"
                ),
            ))
            .await
            .unwrap()
            .unwrap();
        let n: i64 = row.try_get_by_index(0).unwrap();
        assert_eq!(n, 16, "16 partitions quotidiennes du jour attendues");

        // Aucune partition quotidienne plus vieille que la fenêtre ne subsiste.
        let cutoff = (chrono::Utc::now().date_naive()
            - chrono::Duration::days(retention_days()))
        .format("%Y%m%d")
        .to_string();
        let row = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "SELECT count(*)::bigint FROM pg_class \
                     WHERE relname ~ '^messages_p[0-9]+_d[0-9]{{8}}$' \
                     AND substring(relname from '_d([0-9]{{8}})$') < '{cutoff}'"
                ),
            ))
            .await
            .unwrap()
            .unwrap();
        let stale: i64 = row.try_get_by_index(0).unwrap();
        assert_eq!(stale, 0, "aucune partition périmée ne doit subsister");
    }

    #[actix_web::test]
    async fn message_lifecycle_end_to_end() {
        let db = db_or_skip!();
        let app = make_app!(db);

        let conv = create_conv!(
            app,
            "alice",
            json!([{ "id": "alice", "displayName": "Alice" },
                   { "id": "bob", "displayName": "Bob" }])
        );

        // Bob envoie un message.
        let mid = uuid::Uuid::new_v4().to_string();
        let req = test::TestRequest::post()
            .uri("/v1/messages")
            .insert_header(("X-User-Id", "bob"))
            .set_json(json!({ "conversationId": conv, "id": mid, "ciphertext": "SECRET" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 201);
        let posted: serde_json::Value = test::read_body_json(resp).await;
        let seq = posted["seq"].as_i64().unwrap();
        assert_eq!(posted["senderId"], "bob");
        assert_eq!(posted["ciphertext"], "SECRET");

        // Ré-envoi du MÊME id : idempotent (200, même seq, pas de doublon).
        let req = test::TestRequest::post()
            .uri("/v1/messages")
            .insert_header(("X-User-Id", "bob"))
            .set_json(json!({ "conversationId": conv, "id": mid, "ciphertext": "SECRET" }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        let again: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(again["seq"].as_i64().unwrap(), seq);

        // Alice lit l'historique : un seul message, curseur = seq, aucun lecteur.
        let req = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={conv}"))
            .insert_header(("X-User-Id", "alice"))
            .to_request();
        let got: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(got["messages"].as_array().unwrap().len(), 1);
        assert_eq!(got["cursor"].as_i64().unwrap(), seq);
        assert!(got["readers"].as_object().unwrap().is_empty());

        // Alice pose un accusé de lecture jusqu'à seq.
        let req = test::TestRequest::post()
            .uri("/v1/read")
            .insert_header(("X-User-Id", "alice"))
            .set_json(json!({ "conversationId": conv, "upTo": seq }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 200);

        // Bob voit maintenant qu'Alice a lu jusqu'à seq.
        let req = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={conv}"))
            .insert_header(("X-User-Id", "bob"))
            .to_request();
        let got: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(got["readers"]["alice"].as_i64().unwrap(), seq);

        // Rattrapage `after=seq` : plus rien de neuf.
        let req = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={conv}&after={seq}"))
            .insert_header(("X-User-Id", "alice"))
            .to_request();
        let got: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert!(got["messages"].as_array().unwrap().is_empty());
        assert_eq!(got["cursor"].as_i64().unwrap(), seq);
    }

    #[actix_web::test]
    async fn access_control_end_to_end() {
        let db = db_or_skip!();
        let app = make_app!(db);

        let conv = create_conv!(
            app,
            "alice",
            json!([{ "id": "alice", "displayName": "Alice" },
                   { "id": "bob", "displayName": "Bob" }])
        );

        // GET messages sans X-User-Id → 401.
        let req = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={conv}"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 401);

        // GET messages en non-participant (carol) → 403.
        let req = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={conv}"))
            .insert_header(("X-User-Id", "carol"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 403);

        // POST message en non-participant → 403.
        let req = test::TestRequest::post()
            .uri("/v1/messages")
            .insert_header(("X-User-Id", "carol"))
            .set_json(json!({ "conversationId": conv, "id": "x", "ciphertext": "y" }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 403);

        // POST read en non-participant → 403.
        let req = test::TestRequest::post()
            .uri("/v1/read")
            .insert_header(("X-User-Id", "carol"))
            .set_json(json!({ "conversationId": conv, "upTo": 1 }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 403);

        // GET stream en non-participant → 403 (le handler refuse avant de diffuser).
        let req = test::TestRequest::get()
            .uri(&format!("/v1/stream?conversationId={conv}"))
            .insert_header(("X-User-Id", "carol"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 403);

        // Conversation INCONNUE (scellée) → autorisée (200), rien de lisible sans clé.
        let unknown = uuid::Uuid::new_v4().to_string();
        let req = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={unknown}"))
            .insert_header(("X-User-Id", "zoe"))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 200);
    }

    #[actix_web::test]
    async fn conversation_membership_rules() {
        let db = db_or_skip!();
        let app = make_app!(db);

        // Moins de 2 participants → 400.
        let req = test::TestRequest::post()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "alice"))
            .set_json(json!({ "participants": [{ "id": "alice" }] }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 400);

        // Créateur absent de la liste → 403.
        let req = test::TestRequest::post()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "alice"))
            .set_json(json!({ "participants": [{ "id": "bob" }, { "id": "carol" }] }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status(), 403);

        // Conversation valide, puis elle apparaît dans la liste d'Alice.
        let conv = create_conv!(app, "alice", json!([{ "id": "alice" }, { "id": "bob" }]));
        let req = test::TestRequest::get()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "alice"))
            .to_request();
        let list: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert!(list.as_array().unwrap().iter().any(|c| c["id"] == conv));

        // Carol (non-membre) ne la voit pas.
        let req = test::TestRequest::get()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "carol"))
            .to_request();
        let list: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert!(!list.as_array().unwrap().iter().any(|c| c["id"] == conv));
    }
}
