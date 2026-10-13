//! La discussion en ligne du navigateur : même appairage que l'app (salon
//! `/pair`, clé de groupe emballée `/wrap`) et même messagerie (`/v1/messages`,
//! flux `/v1/stream`). Tout est chiffré ici, dans la page ; le serveur ne voit
//! que des clés publiques et des jetons `[[BROCOLIS:v1:…]]`.
//!
//! Gardés dans le navigateur (localStorage) : l'identité X25519, l'identifiant
//! d'appareil et la clé de la discussion en cours (pour la retrouver en
//! rechargeant la page). « Quitter » efface la clé.

use std::cell::{Cell, RefCell};

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, spawn_local};

use super::live::sleep;
use super::window;
use crate::crypto::{self, Identity};
use crate::islands::{ChatMsg, ChatPhase, ChatStates, chat_body};

const IDENTITY: &str = "brocolis.web.identity";
const DEVICE: &str = "brocolis.web.device";
const CHAT_KEY: &str = "brocolis.web.chatKey";

thread_local! {
    /// Chaque nouvelle action arrête les boucles de la précédente.
    static RUN: Cell<u32> = const { Cell::new(0) };
    static KEY: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
    static STREAM: RefCell<Option<web_sys::EventSource>> = const { RefCell::new(None) };
}

fn next_run() -> u32 {
    RUN.with(|r| {
        r.set(r.get().wrapping_add(1));
        r.get()
    })
}

fn still(run: u32) -> bool {
    RUN.with(Cell::get) == run
}

fn storage() -> Option<web_sys::Storage> {
    window().local_storage().ok().flatten()
}

fn stored(name: &str) -> Option<String> {
    storage()?.get_item(name).ok().flatten().filter(|s| !s.is_empty())
}

fn store(name: &str, value: &str) {
    if let Some(s) = storage() {
        let _ = s.set_item(name, value);
    }
}

fn identity() -> Identity {
    if let Some(id) = stored(IDENTITY).and_then(|s| Identity::from_b64(&s)) {
        return id;
    }
    let id = Identity::generate();
    store(IDENTITY, &id.secret_b64());
    id
}

fn device_id() -> String {
    stored(DEVICE).unwrap_or_else(|| {
        let id = crypto::uuid();
        store(DEVICE, &id);
        id
    })
}

fn encode(s: &str) -> String {
    js_sys::encode_uri_component(s).as_string().unwrap_or_default()
}

fn field(obj: &JsValue, key: &str) -> JsValue {
    js_sys::Reflect::get(obj, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

fn text_field(obj: &JsValue, key: &str) -> String {
    field(obj, key).as_string().unwrap_or_default()
}

/// Une requête JSON vers le serveur (même origine), avec `X-User-Id`.
async fn call(method: &str, url: &str, body: Option<String>) -> Option<JsValue> {
    let init = web_sys::RequestInit::new();
    init.set_method(method);
    let headers = web_sys::Headers::new().ok()?;
    headers.set("X-User-Id", &device_id()).ok()?;
    if let Some(body) = body {
        headers.set("Content-Type", "application/json").ok()?;
        init.set_body(&JsValue::from_str(&body));
    }
    init.set_headers(&headers);
    let res: web_sys::Response = JsFuture::from(window().fetch_with_str_and_init(url, &init))
        .await
        .ok()?
        .dyn_into()
        .ok()?;
    if !res.ok() {
        return None;
    }
    JsFuture::from(res.json().ok()?).await.ok()
}

fn json(pairs: &[(&str, &str)]) -> String {
    let obj = js_sys::Object::new();
    for (k, v) in pairs {
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str(k), &JsValue::from_str(v));
    }
    js_sys::JSON::stringify(&obj).ok().and_then(|s| s.as_string()).unwrap_or_default()
}

/// Les autres participants du salon `code` : (peerId, pub).
async fn peers(code: &str, peer_id: &str) -> Vec<(String, String)> {
    let Some(body) = call("GET", &format!("/pair?code={}&peerId={}", encode(code), encode(peer_id)), None).await
    else {
        return Vec::new();
    };
    let Ok(list) = field(&body, "peers").dyn_into::<js_sys::Array>() else {
        return Vec::new();
    };
    list.iter()
        .map(|p| (text_field(&p, "peerId"), text_field(&p, "pub")))
        .filter(|(id, pk)| !id.is_empty() && !pk.is_empty())
        .collect()
}

async fn publish(code: &str, peer_id: &str, public: &str) -> bool {
    call("POST", "/pair", Some(json(&[("code", code), ("peerId", peer_id), ("pub", public)])))
        .await
        .is_some()
}

// ── J'invite ─────────────────────────────────────────────────────────────────

/// Crée une invitation (code, QR, lien) et remet la clé à chaque arrivant,
/// tant que la page reste ouverte (10 min).
pub fn invite(s: ChatStates) {
    let lang = s.lang;
    let run = next_run();
    let me = identity();
    let public = me.public_b64();
    let peer_id = crypto::uuid();
    let code = crypto::pairing_code();
    let origin = window().location().origin().unwrap_or_default();
    let link = format!("{origin}/{}/salon/?code={code}", lang.code());
    let qr = crypto::qr_svg(&link)
        .map(|svg| format!("data:image/svg+xml;utf8,{}", encode(&svg)))
        .unwrap_or_default();
    s.phase.set(ChatPhase::Inviting { code: code.clone(), link, qr });
    s.status.set(String::new());
    s.joined.set(0);
    let group_key = crypto::random_bytes::<32>();

    spawn_local(async move {
        if !publish(&code, &peer_id, &public).await {
            s.status.set(lang.t("chat.offline").to_owned());
            return;
        }
        let mut served: Vec<String> = Vec::new();
        for _ in 0..300 {
            if !still(run) {
                return;
            }
            let fresh: Vec<(String, String)> = peers(&code, &peer_id)
                .await
                .into_iter()
                .filter(|(id, pk)| *pk != public && !served.contains(id))
                .collect();
            if !fresh.is_empty() {
                let items = js_sys::Array::new();
                for (id, pk) in &fresh {
                    if let Some(blob) = me.wrap_group_key(&group_key, pk) {
                        let item = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(&item, &"toPeerId".into(), &JsValue::from_str(id));
                        let _ = js_sys::Reflect::set(&item, &"blob".into(), &JsValue::from_str(&blob));
                        items.push(&item);
                    }
                }
                let body = js_sys::Object::new();
                let _ = js_sys::Reflect::set(&body, &"code".into(), &JsValue::from_str(&code));
                let _ = js_sys::Reflect::set(&body, &"fromPeerId".into(), &JsValue::from_str(&peer_id));
                let _ = js_sys::Reflect::set(&body, &"fromPub".into(), &JsValue::from_str(&public));
                let _ = js_sys::Reflect::set(&body, &"items".into(), &items);
                let body = js_sys::JSON::stringify(&body).ok().and_then(|s| s.as_string()).unwrap_or_default();
                if call("POST", "/wrap", Some(body)).await.is_some() {
                    let first = served.is_empty();
                    served.extend(fresh.into_iter().map(|(id, _)| id));
                    if first {
                        enter(group_key, s, run);
                    } else {
                        s.joined.set(served.len() as u32 - 1);
                        s.status.set(lang.t("chat.someoneJoined").to_owned());
                    }
                }
            }
            sleep(2000).await;
        }
    });
}

/// Copie le lien d'invitation.
pub fn copy_link(s: ChatStates) {
    let lang = s.lang;
    let link = s.phase.with(|p| match p {
        ChatPhase::Inviting { link, .. } => link.clone(),
        _ => String::new(),
    });
    let clipboard = window().navigator().clipboard();
    spawn_local(async move {
        let ok = JsFuture::from(clipboard.write_text(&link)).await.is_ok();
        s.status.set(if ok { lang.t("chat.copied") } else { lang.t("chat.copyFailed") }.to_owned());
    });
}

// ── Je rejoins ───────────────────────────────────────────────────────────────

/// Rejoint l'invitation `code` et attend la clé (10 min au plus).
pub fn join(code: String, s: ChatStates) {
    let run = next_run();
    let me = identity();
    let public = me.public_b64();
    let peer_id = crypto::uuid();
    s.phase.set(ChatPhase::Joining(code.clone()));
    s.status.set(String::new());

    spawn_local(async move {
        if !publish(&code, &peer_id, &public).await {
            s.phase.set(ChatPhase::Setup);
            s.status.set(s.lang.t("chat.offline").to_owned());
            return;
        }
        for _ in 0..300 {
            if !still(run) {
                return;
            }
            let url = format!("/wrap?code={}&peerId={}", encode(&code), encode(&peer_id));
            if let Some(body) = call("GET", &url, None).await {
                let wrap = field(&body, "wrap");
                if wrap.is_object() {
                    let key = me.unwrap_group_key(&text_field(&wrap, "blob"), &text_field(&wrap, "fromPub"));
                    if let Some(key) = key {
                        enter(key, s, run);
                        return;
                    }
                }
            }
            sleep(2000).await;
        }
        if still(run) {
            s.phase.set(ChatPhase::Setup);
        }
    });
}

// ── La discussion ────────────────────────────────────────────────────────────

/// Reprend la discussion gardée par ce navigateur, s'il y en a une.
pub fn resume(s: ChatStates) {
    let key = stored(CHAT_KEY)
        .and_then(|k| crypto::unb64(&k))
        .and_then(|k| <[u8; 32]>::try_from(k).ok());
    if let Some(key) = key {
        enter(key, s, next_run());
    }
}

fn enter(key: [u8; 32], s: ChatStates, run: u32) {
    store(CHAT_KEY, &crypto::b64(&key));
    KEY.with(|k| *k.borrow_mut() = Some(key));
    s.fingerprint.set(crypto::fingerprint(&key));
    s.messages.set(Vec::new());
    s.phase.set(ChatPhase::Chat);
    let conv = crypto::conversation_id(&key);
    let me = device_id();

    spawn_local(async move {
        // L'historique encore sur le serveur (7 jours au plus), page par page.
        let mut after: u64 = 0;
        loop {
            let url = format!("/v1/messages?conversationId={}&after={after}", encode(&conv));
            let Some(page) = call("GET", &url, None).await else { break };
            let Ok(list) = field(&page, "messages").dyn_into::<js_sys::Array>() else { break };
            for m in list.iter() {
                add(&m, &key, &me, s);
            }
            after = field(&page, "cursor").as_f64().unwrap_or(0.0) as u64;
            if field(&page, "hasMore").as_bool() != Some(true) || !still(run) {
                break;
            }
        }
        if still(run) {
            listen(&conv, key, me, s);
        }
    });
}

/// Le flux temps réel (SSE) de la conversation.
fn listen(conv: &str, key: [u8; 32], me: String, s: ChatStates) {
    close_stream();
    let url = format!("/v1/stream?conversationId={}&userId={}", encode(conv), encode(&me));
    let Ok(source) = web_sys::EventSource::new(&url) else { return };
    let on_message = Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        let Some(text) = e.data().as_string() else { return };
        let Ok(value) = js_sys::JSON::parse(&text) else { return };
        // Un accusé de lecture n'a pas de `ciphertext` : ignoré.
        if field(&value, "ciphertext").is_string() {
            add(&value, &key, &me, s);
        }
    });
    source.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    on_message.forget();
    STREAM.with(|st| *st.borrow_mut() = Some(source));
}

fn close_stream() {
    STREAM.with(|st| {
        if let Some(old) = st.borrow_mut().take() {
            old.close();
        }
    });
}

/// Ajoute un message reçu (sans doublon), dans l'ordre.
fn add(m: &JsValue, key: &[u8; 32], me: &str, s: ChatStates) {
    let id = text_field(m, "id");
    if id.is_empty() || s.messages.with(|list| list.iter().any(|x| x.id == id)) {
        return;
    }
    let msg = ChatMsg {
        seq: field(m, "seq").as_f64().unwrap_or(0.0) as u64,
        mine: text_field(m, "senderId") == me,
        body: chat_body(crypto::open_tokens(key, &text_field(m, "ciphertext"))),
        id,
    };
    s.messages.update(|list| {
        list.push(msg);
        list.sort_by_key(|x| x.seq);
    });
    scroll_to_end();
}

fn scroll_to_end() {
    if let Ok(Some(log)) = super::document().query_selector(".chat-log") {
        log.set_scroll_top(log.scroll_height());
    }
}

/// Chiffre et envoie un message.
pub fn send(text: String, s: ChatStates) {
    let Some(key) = KEY.with(|k| *k.borrow()) else { return };
    let Some(token) = crypto::seal_token(&key, &text) else { return };
    let conv = crypto::conversation_id(&key);
    let me = device_id();
    let body = json(&[("id", &crypto::uuid()), ("conversationId", &conv), ("senderId", &me), ("ciphertext", &token)]);
    spawn_local(async move {
        if let Some(m) = call("POST", "/v1/messages", Some(body)).await {
            add(&m, &key, &me, s);
        } else {
            s.status.set(s.lang.t("chat.offline").to_owned());
        }
    });
}

/// Quitte la discussion : la clé est oubliée par ce navigateur.
pub fn leave(s: ChatStates) {
    next_run();
    close_stream();
    KEY.with(|k| *k.borrow_mut() = None);
    if let Some(st) = storage() {
        let _ = st.remove_item(CHAT_KEY);
    }
    s.messages.set(Vec::new());
    s.fingerprint.set(String::new());
    s.joined.set(0);
    s.status.set(String::new());
    s.phase.set(ChatPhase::Setup);
}
