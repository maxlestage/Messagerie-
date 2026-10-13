//! Les routes de l'API, avec Vitesse. Même protocole qu'avant (mêmes chemins,
//! mêmes corps JSON, mêmes codes) : les apps iOS, Android et montre n'ont rien
//! à changer.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use vitesse::prelude::*;
use vitesse::sse::{Event, KeepAlive};

use crate::apns::Apns;
use crate::apple_signin::{self, AppleKeys, VerifyError};
use crate::broadcast::Broadcaster;
use crate::limits::{Kind, Limits};
use crate::live::{content_state, LiveSubscriptions};
use crate::rendezvous::Rendezvous;
use crate::store::{describe, Message, Store};

/// Pagination de `GET /v1/messages` : jamais tout un historique d'un coup (une
/// longue conversation peut peser des Mo de médias chiffrés). Le client avance
/// page par page avec `after=<cursor>` tant que `hasMore`.
pub const DEFAULT_MESSAGES_PAGE: u64 = 200;
pub const MAX_MESSAGES_PAGE: u64 = 500;

/// L'expéditeur APNs, s'il est configuré (sinon la route d'envoi répond 503).
pub struct Push(pub Option<Apns>);

/// L'heure de démarrage, pour `/stats`.
pub struct Started(pub Instant);

fn store(req: &Request) -> &Store {
    req.state::<Arc<Store>>()
}

fn rdv(req: &Request) -> &Rendezvous {
    req.state::<Arc<Rendezvous>>()
}

fn bc(req: &Request) -> &Broadcaster {
    req.state::<Arc<Broadcaster>>()
}

fn live(req: &Request) -> &'static Arc<LiveSubscriptions> {
    req.state::<Arc<LiveSubscriptions>>()
}

fn user_id(req: &Request) -> Option<String> {
    req.header("x-user-id")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        // Le navigateur (discussion du site) ouvre le flux temps réel avec
        // EventSource, qui ne sait pas envoyer d'en-tête : `?userId=`.
        .or_else(|| {
            req.query_as::<UserIdQuery>()
                .ok()
                .and_then(|q| q.user_id)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

#[derive(Deserialize)]
struct UserIdQuery {
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

/// Taille maximale d'un message chiffré (photo, vocal d'une minute compris).
const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;

/// `429` si l'appelant dépasse le plafond de `kind` (par adresse, et par
/// appareil quand `device` est connu).
fn too_many(req: &Request, kind: Kind, device: Option<&str>) -> Option<Response> {
    let limits = req.state::<Arc<Limits>>();
    let ip = req.ip().map_or_else(|| "?".to_owned(), |ip| ip.to_string());
    // Par adresse : plafond ×10 (plusieurs appareils derrière une même box).
    let by_ip = limits.allow(kind, &format!("ip:{ip}"));
    let by_device = device.is_none_or(|d| limits.allow(kind, &format!("dev:{d}")));
    if by_ip && by_device {
        None
    } else {
        Some(json_error(429, "trop de requêtes : réessaie dans une minute"))
    }
}

fn text(status: u16, body: &'static str) -> Response {
    res::status(status).text(body)
}

fn json_error(status: u16, message: impl Into<String>) -> Response {
    res::status(status).json(json!({ "error": message.into() }))
}

fn storage_error(context: &str, e: &memoire_orm::Error) -> Response {
    eprintln!("[{context}] {}", describe(e));
    text(500, "stockage impossible")
}

/// Ajoute toutes les routes de l'API.
pub fn routes(app: &mut App) {
    app.get("/health", |_| async { "ok" });
    app.get("/stats", stats);
    // Rendez-vous X25519
    app.get("/pair", pair_get);
    app.post("/pair", pair_post);
    app.get("/wrap", wrap_get);
    app.post("/wrap", wrap_post);
    app.post("/push/live-activity/token", live_token_post);
    app.post("/push/live-activity/update", live_update_post);
    // Messagerie
    app.post("/v1/conversations", conversations_post);
    app.get("/v1/conversations", conversations_get);
    app.post("/v1/messages", post_message);
    app.get("/v1/messages", get_messages);
    app.post("/v1/read", post_read);
    app.get("/v1/stream", stream);
    app.post("/v1/live", live_subscribe);
    // Accès offerts
    app.get("/v1/plan", get_plan);
    app.post("/v1/plan/apple", post_plan_apple);
    app.delete("/v1/plan/apple", delete_plan_apple);
    // Une adresse inconnue sous l'API répond en JSON (et non avec la page 404
    // du site, dont les routes `/:lang/:page` attraperaient `/v1/…`).
    app.all("/v1/*rest", unknown);
    app.all("/push/*rest", unknown);
}

/// 404 en JSON, comme le reste de l'API.
pub async fn unknown(req: Request) -> Response {
    json_error(404, format!("Cannot {} {}", req.method(), req.path()))
}

/// Les chemins de l'API : une adresse inconnue sous l'un d'eux répond en JSON,
/// pas avec la page 404 du site.
pub fn is_api_path(path: &str) -> bool {
    ["/v1/", "/pair", "/wrap", "/push/", "/health", "/stats"]
        .iter()
        .any(|p| path.starts_with(p))
}

// ── État public ──────────────────────────────────────────────────────────────

/// GET /stats — des totaux pour la page Serveur du site (aucun identifiant).
async fn stats(req: Request) -> Response {
    let totals = match store(&req).totals().await {
        Ok(t) => t,
        Err(e) => return storage_error("stats", &e),
    };
    res::json(json!({
        "messages": totals.messages,
        "conversations": totals.conversations,
        "bytes": totals.bytes,
        "rooms": rdv(&req).room_count(),
        "listeners": bc(&req).listeners(),
        "uptime": req.state::<Started>().0.elapsed().as_secs(),
        "retentionDays": retention_days(),
        "storage": "memoire",
    }))
    .header("cache-control", "no-store")
}

// ── Accès offerts ────────────────────────────────────────────────────────────

/// Fenêtre de rétention : une semaine (réglable via MESSAGE_RETENTION_DAYS).
pub fn retention_days() -> i64 {
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
pub fn granted_tier_from_list(raw: &str, user: &str) -> &'static str {
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

/// Palier offert à un appareil : par son identifiant (`BROCOLIS_PRO_IDS`) ou
/// par l'e-mail Apple qui lui est rattaché (`BROCOLIS_PRO_EMAILS`). Les listes
/// sont relues à chaque appel : retirer une entrée retire l'accès.
async fn granted_tier(
    store: &Store,
    user: &str,
    ticket: Option<&str>,
) -> (&'static str, Option<String>) {
    let ids = std::env::var("BROCOLIS_PRO_IDS").unwrap_or_default();
    let mut email = store.linked_email(user).await.ok().flatten();
    // Après un redémarrage, la mémoire est vide : le ticket signé que l'app
    // renvoie rétablit le lien appareil → e-mail.
    if email.is_none() {
        if let Some(from_ticket) = ticket.and_then(|t| apple_signin::ticket_email(t, user)) {
            let _ = store.link_email(user, &from_ticket).await;
            email = Some(from_ticket);
        }
    }
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
async fn get_plan(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let ticket = req.header("x-brocolis-grant").map(str::to_owned);
    let (tier, email) = granted_tier(store(&req), &user, ticket.as_deref()).await;
    res::json(json!({ "tier": tier, "email": email }))
}

#[derive(Deserialize)]
struct AppleLinkBody {
    #[serde(rename = "identityToken")]
    identity_token: String,
}

/// POST /v1/plan/apple — « Se connecter avec Apple ». Vérifie le jeton
/// d'identité d'Apple ; si son e-mail figure dans `BROCOLIS_PRO_EMAILS`, le
/// rattache à cet appareil (Pro offert). Sinon rien n'est conservé.
async fn post_plan_apple(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::AppleLink, None) {
        return r;
    }
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let body: AppleLinkBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let apple = req.state::<AppleKeys>();
    let email = match apple
        .verify(&body.identity_token, &apple_signin::expected_audience())
        .await
    {
        Ok(email) => email,
        Err(None) => return json_error(503, "Apple injoignable, réessaie"),
        Err(Some(VerifyError::NoVerifiedEmail)) => {
            return json_error(422, "aucun e-mail vérifié dans le jeton Apple")
        }
        Err(Some(e)) => {
            eprintln!("[plan/apple] jeton refusé : {e:?}");
            return json_error(401, "jeton Apple invalide");
        }
    };
    let emails = std::env::var("BROCOLIS_PRO_EMAILS").unwrap_or_default();
    if !apple_signin::email_in_list(&emails, &email) {
        return res::json(json!({ "tier": "free", "email": email }));
    }
    if let Err(e) = store(&req).link_email(&user, &email).await {
        eprintln!("[plan/apple] enregistrement impossible : {}", describe(&e));
        return res::send_status(500);
    }
    // Le ticket permet à l'app de rétablir l'accès après un redémarrage.
    let ticket = apple_signin::issue_ticket(&user, &email);
    res::json(json!({ "tier": "pro", "email": email, "ticket": ticket }))
}

/// DELETE /v1/plan/apple — détache l'e-mail de cet appareil.
async fn delete_plan_apple(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let _ = store(&req).unlink_email(&user).await;
    let (tier, _) = granted_tier(store(&req), &user, None).await;
    res::json(json!({ "tier": tier, "email": null }))
}

// ── Messagerie ───────────────────────────────────────────────────────────────

#[derive(Deserialize, serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Participant {
    pub id: String,
    #[serde(default)]
    pub display_name: String,
}

/// Contrôle d'accès à une conversation :
/// - conversation inconnue ⇒ autorisée (traitée comme scellée : rien de lisible
///   sans la clé de toute façon, le serveur ne relaie que du chiffré) ;
/// - conversation sans participants explicites (scellée) ⇒ autorisée ;
/// - conversation à participants ⇒ l'appelant doit en faire partie.
///
/// Défense en profondeur : le vrai secret reste le chiffrement de bout en bout.
async fn can_access(store: &Store, conv: &str, user: &str) -> bool {
    match store.conversation(conv).await {
        Ok(Some(c)) => {
            let participants: Vec<Participant> =
                serde_json::from_str(&c.participants).unwrap_or_default();
            participants.is_empty() || participants.iter().any(|p| p.id == user)
        }
        _ => true,
    }
}

/// Sortie JSON d'un message, au même format qu'avant (clés camelCase).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageOut {
    pub id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub ciphertext: String,
    pub sent_at: String,
    pub seq: i64,
}

impl From<Message> for MessageOut {
    fn from(m: Message) -> Self {
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendBody {
    conversation_id: String,
    #[serde(default)]
    id: String,
    ciphertext: String,
}

/// POST /v1/messages — stocke un message chiffré (idempotent sur (conv, id)).
async fn post_message(req: Request) -> Response {
    let Some(sender) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let body: SendBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let conv = body.conversation_id.trim();
    let ciphertext = body.ciphertext.trim();
    if conv.is_empty() || ciphertext.is_empty() {
        return text(400, "conversationId et ciphertext requis");
    }
    if ciphertext.len() > MAX_CIPHERTEXT {
        return json_error(413, "message trop lourd");
    }
    if let Some(r) = too_many(&req, Kind::Send, Some(&sender)) {
        return r;
    }
    let store = store(&req);
    if !can_access(store, conv, &sender).await {
        return text(403, "accès refusé à cette conversation");
    }
    // Sans id, le message en reçoit un (mais un renvoi le dupliquera).
    let id = match body.id.trim() {
        "" => uuid::Uuid::new_v4().to_string(),
        id => id.to_string(),
    };
    match store.post_message(conv, &id, &sender, ciphertext).await {
        Ok((message, created)) => {
            let out = MessageOut::from(message);
            if !created {
                return res::json(&out);
            }
            // Temps réel : les abonnés SSE de la conversation. Les clients
            // dédoublonnent par id.
            if let Ok(json) = serde_json::to_string(&out) {
                bc(&req).publish(conv, json);
            }
            // Live Activity des correspondants : compteur de non-lus, même app
            // fermée.
            let followers = live(&req).followers(conv, &sender);
            if !followers.is_empty() {
                let (store, live, push) = (req.state::<Arc<Store>>(), live(&req), req.state::<Push>());
                tokio::spawn(async move {
                    for (user, _) in followers {
                        refresh_live_activity(store, live, push, &user).await;
                    }
                });
            }
            res::status(201).json(&out)
        }
        Err(e) => storage_error("insert message", &e),
    }
}

#[derive(Deserialize)]
struct MessagesQuery {
    #[serde(rename = "conversationId")]
    conversation_id: String,
    #[serde(default)]
    after: i64,
    /// Taille de page demandée (optionnelle). Bornée par `MAX_MESSAGES_PAGE`.
    #[serde(default)]
    limit: Option<i64>,
}

/// GET /v1/messages?conversationId=&after= — suite des messages + accusés.
async fn get_messages(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let q: MessagesQuery = match req.query_as() {
        Ok(q) => q,
        Err(e) => return e.into_response(),
    };
    let store = store(&req);
    if !can_access(store, &q.conversation_id, &user).await {
        return text(403, "accès refusé à cette conversation");
    }
    // Taille de page effective : défaut 200, plafonnée à 500, jamais illimitée.
    let page = q
        .limit
        .filter(|n| *n > 0)
        .map(|n| (n as u64).min(MAX_MESSAGES_PAGE))
        .unwrap_or(DEFAULT_MESSAGES_PAGE);
    let (rows, has_more) = match store.messages(&q.conversation_id, q.after, page).await {
        Ok(r) => r,
        Err(e) => return storage_error("messages", &e),
    };
    let cursor = rows.last().map_or(q.after, |m| m.seq);
    let messages: Vec<MessageOut> = rows.into_iter().map(MessageOut::from).collect();

    // Accusés de lecture { userId: dernierSeqLu }.
    let mut readers = serde_json::Map::new();
    for r in store.readers(&q.conversation_id).await.unwrap_or_default() {
        readers.insert(r.user_id, json!(r.up_to));
    }

    res::json(json!({
        "messages": messages,
        "cursor": cursor,
        "readers": readers,
        // Pour paginer, rappeler avec `after=cursor` tant que `hasMore` est vrai.
        "hasMore": has_more,
        "limit": page,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadBody {
    conversation_id: String,
    up_to: i64,
}

/// POST /v1/read — avance le curseur de lecture (max monotone).
async fn post_read(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let body: ReadBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let conv = body.conversation_id.trim();
    if conv.is_empty() {
        return text(400, "conversationId requis");
    }
    let store = store(&req);
    if !can_access(store, conv, &user).await {
        return text(403, "accès refusé à cette conversation");
    }
    match store.mark_read(conv, &user, body.up_to).await {
        Ok(up_to) => {
            // Accusé de lecture en temps réel (l'expéditeur verra « Lu »).
            let event = json!({ "type": "read", "reader": user, "upTo": up_to });
            bc(&req).publish(conv, event.to_string());
            // Lu ici (ou sur un autre appareil) : le compteur de la Live
            // Activity de ce lecteur retombe.
            if live(&req).of(&user).is_some() {
                let (store, live, push) = (req.state::<Arc<Store>>(), live(&req), req.state::<Push>());
                let user = user.clone();
                tokio::spawn(async move { refresh_live_activity(store, live, push, &user).await });
            }
            res::json(json!({ "ok": true }))
        }
        Err(e) => {
            eprintln!("[read cursor] {}", describe(&e));
            text(500, "curseur impossible")
        }
    }
}

#[derive(Deserialize)]
struct StreamQuery {
    #[serde(rename = "conversationId")]
    conversation_id: String,
}

/// GET /v1/stream?conversationId=.. — flux temps réel (Server-Sent Events).
/// Émet `data: {message}` à chaque nouveau message et
/// `data: {"type":"read",...}` à chaque accusé, plus un commentaire toutes les
/// 25 s (Heroku coupe une connexion muette au bout de 55 s).
async fn stream(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let q: StreamQuery = match req.query_as() {
        Ok(q) => q,
        Err(e) => return e.into_response(),
    };
    let conv = q.conversation_id.trim().to_string();
    if conv.is_empty() {
        return text(400, "conversationId requis");
    }
    if !can_access(store(&req), &conv, &user).await {
        return text(403, "accès refusé à cette conversation");
    }

    let mut rx = bc(&req).subscribe(&conv);
    let (tx, events) = vitesse::sse::channel(64);
    tokio::spawn(async move {
        // Amorce : les en-têtes partent tout de suite, même à travers un proxy.
        if tx.send(Event::new().comment("ok")).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                msg = rx.recv() => match msg {
                    Ok(json) => {
                        if tx.send(Event::new().data(json)).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                _ = tx.closed() => break,
            }
        }
    });
    events
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(25))
                .text("keep-alive"),
        )
        .into_response()
        .header("x-accel-buffering", "no")
}

#[derive(Deserialize)]
struct CreateConversation {
    participants: Vec<Participant>,
}

/// POST /v1/conversations — conversation à participants explicites.
async fn conversations_post(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return json_error(401, "X-User-Id requis");
    };
    let body: CreateConversation = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    if body.participants.len() < 2 {
        return json_error(400, "au moins 2 participants requis");
    }
    if !body.participants.iter().any(|p| p.id == user) {
        return json_error(403, "tu dois faire partie de la conversation");
    }
    let participants_json =
        serde_json::to_string(&body.participants).unwrap_or_else(|_| "[]".into());
    let members: Vec<String> = body.participants.iter().map(|p| p.id.clone()).collect();
    match store(&req)
        .create_conversation(participants_json, &members)
        .await
    {
        Ok(conv) => res::status(201).json(json!({
            "id": conv.id, "participants": body.participants, "createdAt": conv.created_at
        })),
        Err(e) => {
            eprintln!("[conversation] {}", describe(&e));
            json_error(500, "création impossible")
        }
    }
}

/// GET /v1/conversations — les conversations de l'appelant.
async fn conversations_get(req: Request) -> Response {
    let Some(user) = user_id(&req) else {
        return json_error(401, "X-User-Id requis");
    };
    let rows = store(&req)
        .conversations_of(&user)
        .await
        .unwrap_or_default();
    let out: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            let participants: Vec<Participant> =
                serde_json::from_str(&r.participants).unwrap_or_default();
            json!({ "id": r.id, "participants": participants, "createdAt": r.created_at })
        })
        .collect();
    res::json(out)
}

// ── Live Activity tenue à jour par le serveur ────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveBody {
    token: String,
    conversation_ids: Vec<String>,
    #[serde(default)]
    since: Option<i64>,
}

/// POST /v1/live — abonne la Live Activity de l'appelant (push token APNs) à
/// ses conversations : le serveur la met à jour à chaque message reçu ou lu.
async fn live_subscribe(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::Push, None) {
        return r;
    }
    let Some(user) = user_id(&req) else {
        return text(401, "x-user-id requis");
    };
    let body: LiveBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let token = body.token.trim();
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_hexdigit()) || token.len() > 400 {
        return json_error(400, "token (hexadécimal) requis");
    }
    // Seulement les conversations auxquelles l'appelant a droit.
    let store = store(&req);
    let mut conversations = Vec::new();
    for conv in body.conversation_ids.iter().map(|c| c.trim()).filter(|c| !c.is_empty()).take(200) {
        if can_access(store, conv, &user).await {
            conversations.push(conv.to_string());
        }
    }
    let since = body.since.unwrap_or_else(|| chrono::Utc::now().timestamp());
    let count = conversations.len();
    live(&req).subscribe(&user, token, since, conversations);
    res::json(json!({ "ok": true, "conversations": count, "push": req.state::<Push>().0.is_some() }))
}

/// Recalcule les non-lus de `user` sur toutes ses conversations suivies et
/// pousse le nouvel état à sa Live Activity. Sans APNs configuré : rien.
pub async fn refresh_live_activity(store: &Store, live: &LiveSubscriptions, push: &Push, user: &str) {
    let (Some(apns), Some(reg)) = (push.0.as_ref(), live.of(user)) else {
        return;
    };
    let mut unread = 0;
    let mut last: Option<String> = None;
    for conv in &reg.conversations {
        if let Ok((n, at)) = store.unread(conv, user).await {
            unread += n;
            last = last.max(at);
        }
    }
    let last_at = last
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(&at).ok())
        .map(|at| at.timestamp());
    let state = content_state(reg.since, unread, last_at);
    match apns.send_live_activity(&reg.token, "update", &state, None).await {
        // Token périmé : la Live Activity est finie, on l'oublie.
        Ok(400) | Ok(410) => live.forget(user, &reg.token),
        Ok(_) => {}
        Err(e) => eprintln!("[live] APNs : {e}"),
    }
}

// ── Rendez-vous X25519 (relais de clés publiques, éphémère) ───────────────────

#[derive(Deserialize)]
struct PairQuery {
    code: String,
    #[serde(default, rename = "peerId")]
    peer_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PairBody {
    code: String,
    peer_id: String,
    #[serde(rename = "pub")]
    pub_key: String,
    /// C'est l'invitant : lui seul pourra remettre la clé de groupe.
    #[serde(default)]
    host: bool,
}

/// Un code de salon : 4 à 16 caractères A–Z / 0–9 (ceux de l'app et du site).
fn valid_code(code: &str) -> bool {
    (4..=16).contains(&code.len()) && code.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Un identifiant de participant : court et imprimable.
fn valid_peer_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Une clé publique X25519 : 32 octets en base64.
fn valid_public_key(b64: &str) -> bool {
    b64.len() <= 64 && brocolis_site::crypto::unb64(b64).is_some_and(|raw| raw.len() == 32)
}

/// Une clé de groupe emballée (nonce 12 + 32 + tag 16 = 60 octets, base64).
fn valid_blob(b64: &str) -> bool {
    b64.len() <= 128 && brocolis_site::crypto::unb64(b64).is_some_and(|raw| raw.len() == 60)
}

async fn pair_get(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::PairRead, None) {
        return r;
    }
    let q: PairQuery = match req.query_as() {
        Ok(q) => q,
        Err(e) => return e.into_response(),
    };
    let code = q.code.trim();
    if !valid_code(code) {
        return json_error(400, "code invalide");
    }
    res::json(rdv(&req).peers_excluding(code, q.peer_id.trim()))
}

async fn pair_post(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::PairPublish, None) {
        return r;
    }
    let body: PairBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let (code, peer_id, pub_key) = (body.code.trim(), body.peer_id.trim(), body.pub_key.trim());
    if !valid_code(code) || !valid_peer_id(peer_id) || !valid_public_key(pub_key) {
        return json_error(400, "code, peerId ou pub invalide");
    }
    match rdv(&req).add_peer_as(code, peer_id, pub_key, body.host) {
        Ok(peers) => res::json(peers),
        Err(crate::rendezvous::PairError::Full) => {
            json_error(409, "ce code a déjà atteint le maximum de participants")
        }
        Err(crate::rendezvous::PairError::KeyMismatch) => {
            json_error(409, "ce participant est déjà inscrit avec une autre clé")
        }
    }
}

#[derive(Deserialize)]
struct WrapQuery {
    code: String,
    #[serde(rename = "peerId")]
    peer_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapItem {
    to_peer_id: String,
    blob: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WrapBody {
    code: String,
    from_peer_id: String,
    from_pub: String,
    items: Vec<WrapItem>,
}

async fn wrap_get(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::PairRead, None) {
        return r;
    }
    let q: WrapQuery = match req.query_as() {
        Ok(q) => q,
        Err(e) => return e.into_response(),
    };
    let (code, peer_id) = (q.code.trim(), q.peer_id.trim());
    if !valid_code(code) || !valid_peer_id(peer_id) {
        return json_error(400, "code ou peerId invalide");
    }
    res::json(rdv(&req).get_wrap(code, peer_id))
}

async fn wrap_post(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::Wrap, None) {
        return r;
    }
    let body: WrapBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let (code, from, from_pub) = (
        body.code.trim(),
        body.from_peer_id.trim(),
        body.from_pub.trim(),
    );
    if !valid_code(code) || !valid_peer_id(from) || !valid_public_key(from_pub) || body.items.len() > 64 {
        return json_error(400, "code, fromPeerId, fromPub ou items invalide");
    }
    let items: Vec<(String, String)> = body
        .items
        .iter()
        .map(|it| (it.to_peer_id.trim().to_string(), it.blob.trim().to_string()))
        .filter(|(to, blob)| valid_peer_id(to) && valid_blob(blob))
        .collect();
    match rdv(&req).put_wraps(code, from, from_pub, &items) {
        Some(count) => res::json(json!({ "ok": true, "count": count })),
        None => json_error(403, "seul l'invitant de ce code peut remettre la clé"),
    }
}

// ── Push Live Activity ───────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LiveTokenBody {
    code: String,
    peer_id: String,
    token: String,
}

async fn live_token_post(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::Push, None) {
        return r;
    }
    let body: LiveTokenBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let (code, peer_id, token) = (body.code.trim(), body.peer_id.trim(), body.token.trim());
    if code.is_empty() || peer_id.is_empty() || token.is_empty() {
        return json_error(400, "code, peerId et token requis");
    }
    rdv(&req).put_live_token(code, peer_id, token);
    res::json(json!({ "ok": true }))
}

fn default_event() -> String {
    "update".to_string()
}

#[derive(Deserialize)]
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

/// Ne laisse passer vers APNs que l'état attendu par la Live Activity
/// (`since`, `unread`, `lastAt`, des nombres bornés) : pas de texte arbitraire
/// poussé sur l'écran verrouillé de quelqu'un d'autre.
fn clean_state(state: &serde_json::Value) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (key, max) in [("since", 1e11), ("unread", 9_999.0), ("lastAt", 1e11)] {
        if let Some(n) = state.get(key).and_then(|v| v.as_f64()).filter(|n| (0.0..=max).contains(n)) {
            out.insert(key.to_owned(), json!(n.round() as i64));
        }
    }
    serde_json::Value::Object(out)
}

async fn live_update_post(req: Request) -> Response {
    if let Some(r) = too_many(&req, Kind::Push, None) {
        return r;
    }
    let body: LiveUpdateBody = match req.json().await {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let (code, peer_id, event) = (body.code.trim(), body.peer_id.trim(), body.event.trim());
    if code.is_empty() || peer_id.is_empty() {
        return json_error(400, "code et peerId requis");
    }
    if event != "update" && event != "end" {
        return json_error(400, "event doit valoir \"update\" ou \"end\"");
    }
    if !body.content_state.is_object() {
        return json_error(400, "contentState (objet) requis");
    }
    let Some(token) = rdv(&req).live_token(code, peer_id) else {
        return json_error(404, "aucun token de Live Activity pour ce peerId");
    };
    let Some(sender) = req.state::<Push>().0.as_ref() else {
        return json_error(503, "push non configuré côté serveur");
    };
    match sender
        .send_live_activity(&token, event, &clean_state(&body.content_state), body.dismissal_date)
        .await
    {
        Ok(status) => res::json(json!({ "ok": true, "apns": status })),
        Err(e) => res::status(502).json(json!({ "error": "échec APNs", "detail": e })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn message_out_serializes_in_camel_case() {
        let m = Message {
            seq: 7,
            msg_id: "m1".into(),
            conversation_id: "c1".into(),
            sender_id: "alice".into(),
            ciphertext: "ZZ".into(),
            sent_at: "2026-01-01T00:00:00.000Z".into(),
            size: 2,
        };
        let v = serde_json::to_value(MessageOut::from(m)).unwrap();
        assert_eq!(v["id"], "m1");
        assert_eq!(v["conversationId"], "c1");
        assert_eq!(v["senderId"], "alice");
        assert_eq!(v["ciphertext"], "ZZ");
        assert_eq!(v["sentAt"], "2026-01-01T00:00:00.000Z");
        assert_eq!(v["seq"], 7);
        // Le budget mémoire reste une affaire de serveur.
        assert!(v.get("size").is_none());
    }

    #[test]
    fn api_paths_are_recognised() {
        assert!(is_api_path("/v1/nope"));
        assert!(is_api_path("/pair"));
        assert!(!is_api_path("/fr/"));
        assert!(!is_api_path("/"));
    }
}
