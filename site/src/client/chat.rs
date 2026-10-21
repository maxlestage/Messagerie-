//! La discussion en ligne du navigateur : même appairage que l'app (salon
//! `/pair`, clé de groupe emballée `/wrap`) et même messagerie (`/v1/messages`,
//! flux `/v1/stream`). Tout est chiffré ici, dans la page ; le serveur ne voit
//! que des clés publiques, des paquets de clés publiques et des jetons.
//!
//! **Protocole v3** (`docs/SECURITE.md` §8, logique dans [`crate::v3`]) : ce
//! navigateur a un appareil v3 ; il publie son paquet de clés dans le salon.
//! Appairés à deux avec un appareil qui en publie un aussi, les messages
//! partent en jetons v3 (double cliquet, hybride X25519 + ML-KEM-768) et
//! l'empreinte couvre les deux identités ; sinon (ancien iPhone, groupe),
//! l'ancien format, exactement comme avant.
//!
//! Gardés dans le navigateur (localStorage, chiffrés par le coffre
//! `coffre.rs` : clé WebCrypto non exportable) : l'identité X25519,
//! l'appareil v3, l'état v3 (sessions et messages ouverts), le contact et la
//! clé de la discussion en cours (pour la retrouver en rechargeant la page) ;
//! en clair : l'identifiant d'appareil. « Quitter » efface la clé, le contact
//! et l'état v3 (l'appareil reste). Plusieurs onglets ne touchent jamais à
//! l'état v3 en même temps (verrou `navigator.locks`, §8.3).

use std::cell::{Cell, RefCell};

use brocolis_proto::KeyBundle;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{JsFuture, spawn_local};

use super::coffre;
use super::live::sleep;
use super::window;
use crate::crypto::{self, Identity};
use crate::islands::{ChatMsg, ChatPhase, ChatStates, chat_body};
use crate::v3::{self, Engine, KeyInfo, Opened};

const IDENTITY: &str = "brocolis.web.identity";
const DEVICE: &str = "brocolis.web.device";
const CHAT_KEY: &str = "brocolis.web.chatKey";
const CHAT_PEER: &str = "brocolis.web.chatPeer";
const V3_DEVICE: &str = "brocolis.web.v3.device";
const V3_STATE: &str = "brocolis.web.v3.state";
/// Celui qui rejoint relit le salon pendant 8 jours : s'il y voit plus d'une
/// autre personne, la clé est une clé de groupe (§8.4).
const GROUP_WATCH: u64 = 8 * 24 * 3600;

/// Le correspondant v3 de la discussion (données publiques, gardées au
/// coffre avec la clé).
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Contact {
    /// Son paquet de clés (base64), reçu dans le salon.
    bundle: String,
    /// Sa capacité v4 signée (base64, §9.6), reçue avec le paquet.
    caps: String,
    /// Quand (secondes Unix).
    at: u64,
    /// Devenue une clé de groupe : plus de v3.
    group: bool,
    /// Le salon et mon peerId, pour y vérifier qu'on reste à deux.
    code: String,
    peer_id: String,
    /// Jusqu'à quand le vérifier.
    until: u64,
}

thread_local! {
    /// Chaque nouvelle action arrête les boucles de la précédente.
    static RUN: Cell<u32> = const { Cell::new(0) };
    static KEY: RefCell<Option<[u8; 32]>> = const { RefCell::new(None) };
    static CONTACT: RefCell<Option<Contact>> = const { RefCell::new(None) };
    static STREAM: RefCell<Option<web_sys::EventSource>> = const { RefCell::new(None) };
    /// Une transaction v3 en cours dans CET onglet (verrou local, en plus de
    /// `navigator.locks` qui peut manquer).
    static BUSY: Cell<bool> = const { Cell::new(false) };
    /// Les jetons v3 déjà affichés : un même jeton republié par le serveur
    /// sous un autre identifiant est ignoré (§1 : un rejeu est ignoré).
    static SEEN_TOKENS: RefCell<std::collections::HashSet<String>> = RefCell::new(std::collections::HashSet::new());
    /// L'identité X25519 une fois sortie du coffre (base64 du secret).
    static ME: RefCell<Option<String>> = const { RefCell::new(None) };
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

fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

/// L'identité X25519 de ce navigateur : sortie du coffre, ou créée (puis
/// rangée au coffre) la première fois.
async fn identity() -> Identity {
    if let Some(id) = ME.with(|m| m.borrow().clone()).and_then(|s| Identity::from_b64(&s)) {
        return id;
    }
    let id = match coffre::load(IDENTITY).await.and_then(|s| Identity::from_b64(&s)) {
        Some(id) => id,
        None => {
            let id = Identity::generate();
            coffre::save(IDENTITY, &id.secret_b64(), || true).await;
            id
        }
    };
    ME.with(|m| *m.borrow_mut() = Some(id.secret_b64()));
    id
}

fn device_id() -> String {
    stored(DEVICE).unwrap_or_else(|| {
        let id = crypto::uuid();
        store(DEVICE, &id);
        id
    })
}

// ── Le v3 : une transaction à la fois (§8.3) ─────────────────────────────────

/// Le verrou `navigator.locks` tenu pendant une transaction : relâché quand
/// il est lâché (`Drop`).
struct WebLock(js_sys::Function);

impl Drop for WebLock {
    fn drop(&mut self) {
        let _ = self.0.call0(&JsValue::NULL);
    }
}

/// Prend le verrou v3 de l'origine (plusieurs onglets) ; `None` si le
/// navigateur n'a pas `navigator.locks` (on continue sans).
async fn web_lock() -> Option<WebLock> {
    let locks = js_sys::Reflect::get(&window().navigator(), &"locks".into()).ok()?;
    if !locks.is_object() {
        return None;
    }
    let request: js_sys::Function = js_sys::Reflect::get(&locks, &"request".into()).ok()?.dyn_into().ok()?;
    let mut release = None;
    let held = js_sys::Promise::new(&mut |resolve, _| release = Some(resolve));
    let mut granted = None;
    let acquired = js_sys::Promise::new(&mut |resolve, _| granted = Some(resolve));
    let granted = granted?;
    let on_grant = Closure::once_into_js(move |_lock: JsValue| -> JsValue {
        let _ = granted.call0(&JsValue::NULL);
        held.into()
    });
    request.call2(&locks, &"brocolis-v3".into(), &on_grant).ok()?;
    JsFuture::from(acquired).await.ok()?;
    Some(WebLock(release?))
}

/// Le verrou local de l'onglet : relâché quand il est lâché.
struct LocalLock;

impl Drop for LocalLock {
    fn drop(&mut self) {
        BUSY.with(|b| b.set(false));
    }
}

/// Attend son tour dans l'onglet : sans lui, deux tâches (un envoi et un
/// message reçu) pourraient lire le même état et servir deux fois la même
/// clé de message. Pas d'`await` entre le test et la prise : c'est atomique.
async fn local_lock() -> LocalLock {
    while BUSY.with(Cell::get) {
        sleep(5).await;
    }
    BUSY.with(|b| b.set(true));
    LocalLock
}

/// Une transaction v3 : verrous, appareil et état sortis du coffre, `f`, puis
/// l'appareil et l'état réécrits (l'appareil d'abord) avant de rendre la main.
async fn with_engine<T>(f: impl FnOnce(&mut Engine, u64) -> T) -> T {
    let _local = local_lock().await;
    let _lock = web_lock().await;
    let device = coffre::load(V3_DEVICE).await;
    let state = coffre::load(V3_STATE).await;
    let t = now();
    let mut engine = Engine::load(device.as_deref(), state.as_deref(), t);
    let out = f(&mut engine, t);
    let dirty = engine.take_dirty();
    if let Some(d) = dirty.device {
        coffre::save(V3_DEVICE, &d, || true).await;
    }
    if let Some(s) = dirty.state {
        coffre::save(V3_STATE, &s, || true).await;
    }
    out
}

fn contact() -> Option<Contact> {
    CONTACT.with(|c| c.borrow().clone())
}

async fn save_contact(c: Option<Contact>) {
    CONTACT.with(|x| *x.borrow_mut() = c.clone());
    match c.and_then(|c| serde_json::to_string(&c).ok()) {
        Some(json) => coffre::save(CHAT_PEER, &json, || true).await,
        None => {
            if let Some(s) = storage() {
                let _ = s.remove_item(CHAT_PEER);
            }
        }
    }
}

/// Le paquet du contact, s'il est encore « à deux ».
fn contact_bundle(c: &Option<Contact>) -> Option<KeyBundle> {
    c.as_ref()
        .filter(|c| !c.group)
        .and_then(|c| KeyBundle::from_base64(&c.bundle).ok())
}

/// Sa capacité v4 (le moteur la vérifie contre le paquet).
fn contact_caps(c: &Option<Contact>) -> Option<[u8; 64]> {
    c.as_ref()
        .filter(|c| !c.group)
        .and_then(|c| crypto::unb64(&c.caps))
        .and_then(|raw| raw.try_into().ok())
}

/// La clé de la discussion, vue par le moteur v3.
fn key_info<'a>(
    key: [u8; 32],
    c: &Option<Contact>,
    bundle: Option<&'a KeyBundle>,
    caps: Option<&'a [u8; 64]>,
    id: &'a str,
) -> KeyInfo<'a> {
    KeyInfo {
        id,
        key,
        bundle,
        caps,
        bundle_at: c.as_ref().map_or(0, |c| c.at),
        group: c.as_ref().is_some_and(|c| c.group),
        psk: false,
    }
}

/// Recalcule le libellé de protection (§8.8).
fn show_protection(engine: &Engine, key: [u8; 32], t: u64, s: ChatStates) {
    let c = contact();
    let bundle = contact_bundle(&c);
    let caps = contact_caps(&c);
    let conv = crypto::conversation_id(&key);
    let k = key_info(key, &c, bundle.as_ref(), caps.as_ref(), &conv);
    s.protection.set(s.lang.t(engine.protection(&k, t).i18n_key()).to_owned());
}

// ── Réseau ───────────────────────────────────────────────────────────────────

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

/// Un participant du salon : peerId, clé publique, paquet v3 et capacité v4
/// éventuels.
struct RoomPeer {
    id: String,
    public: String,
    bundle: Option<String>,
    caps: Option<String>,
}

/// Les autres participants du salon `code`.
async fn peers(code: &str, peer_id: &str) -> Vec<RoomPeer> {
    let Some(body) = call("GET", &format!("/pair?code={}&peerId={}", encode(code), encode(peer_id)), None).await
    else {
        return Vec::new();
    };
    let Ok(list) = field(&body, "peers").dyn_into::<js_sys::Array>() else {
        return Vec::new();
    };
    list.iter()
        .map(|p| RoomPeer {
            id: text_field(&p, "peerId"),
            public: text_field(&p, "pub"),
            bundle: field(&p, "bundle").as_string().filter(|b| !b.is_empty()),
            caps: field(&p, "caps").as_string().filter(|c| !c.is_empty()),
        })
        .filter(|p| !p.id.is_empty() && !p.public.is_empty())
        .collect()
}

/// S'inscrit au salon ; `host` : c'est l'invitant (lui seul remettra la clé).
/// `mine` : le paquet de clés v3 (§8.4) et la capacité v4 (§9.6).
async fn publish(code: &str, peer_id: &str, public: &str, host: bool, mine: &Mine) -> bool {
    let body = js_sys::Object::new();
    for (k, v) in [("code", code), ("peerId", peer_id), ("pub", public)] {
        let _ = js_sys::Reflect::set(&body, &JsValue::from_str(k), &JsValue::from_str(v));
    }
    let _ = js_sys::Reflect::set(&body, &"host".into(), &JsValue::from_bool(host));
    if let Some(b) = &mine.bundle {
        let _ = js_sys::Reflect::set(&body, &"bundle".into(), &JsValue::from_str(b));
        if let Some(c) = &mine.caps {
            let _ = js_sys::Reflect::set(&body, &"caps".into(), &JsValue::from_str(c));
        }
    }
    let body = js_sys::JSON::stringify(&body).ok().and_then(|s| s.as_string()).unwrap_or_default();
    call("POST", "/pair", Some(body)).await.is_some()
}

/// Ce que je publie au salon : paquet v3 et capacité v4.
struct Mine {
    bundle: Option<String>,
    caps: Option<String>,
}

async fn my_bundle() -> Mine {
    with_engine(|e, _| Mine {
        bundle: e.bundle_b64(),
        caps: e.caps_b64(),
    })
    .await
}

/// Un contact « à deux » si ce correspondant a publié un paquet.
fn new_contact(peer: &RoomPeer, code: &str, peer_id: &str, until: u64) -> Option<Contact> {
    let bundle = peer.bundle.clone()?;
    KeyBundle::from_base64(&bundle).ok()?;
    let caps = peer.caps.clone().unwrap_or_default();
    Some(Contact { bundle, caps, at: now(), group: false, code: code.to_owned(), peer_id: peer_id.to_owned(), until })
}

// ── J'invite ─────────────────────────────────────────────────────────────────

/// Crée une invitation (code, QR, lien) et remet la clé à chaque arrivant,
/// tant que la page reste ouverte (10 min).
pub fn invite(s: ChatStates) {
    let lang = s.lang;
    let run = next_run();
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
        let me = identity().await;
        let public = me.public_b64();
        let bundle = my_bundle().await;
        if !still(run) {
            return;
        }
        if !publish(&code, &peer_id, &public, true, &bundle).await {
            s.status.set(lang.t("chat.offline").to_owned());
            return;
        }
        let mut served: Vec<String> = Vec::new();
        for _ in 0..300 {
            if !still(run) {
                return;
            }
            let fresh: Vec<RoomPeer> = peers(&code, &peer_id)
                .await
                .into_iter()
                .filter(|p| p.public != public && !served.contains(&p.id))
                .collect();
            if !fresh.is_empty() {
                let items = js_sys::Array::new();
                for p in &fresh {
                    if let Some(blob) = me.wrap_group_key(&group_key, &p.public) {
                        let item = js_sys::Object::new();
                        let _ = js_sys::Reflect::set(&item, &"toPeerId".into(), &JsValue::from_str(&p.id));
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
                    // À deux tant qu'une seule personne a la clé (§8.4).
                    let duo = first && fresh.len() == 1;
                    let peer = duo.then(|| new_contact(&fresh[0], &code, &peer_id, 0)).flatten();
                    served.extend(fresh.into_iter().map(|p| p.id));
                    if first {
                        enter(group_key, peer, s, run, true);
                    } else {
                        // Une deuxième personne : la clé devient une clé de groupe.
                        if let Some(mut c) = contact().filter(|c| !c.group) {
                            c.group = true;
                            save_contact(Some(c)).await;
                            with_engine(|e, t| show_protection(e, group_key, t, s)).await;
                        }
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
    let peer_id = crypto::uuid();
    s.phase.set(ChatPhase::Joining(code.clone()));
    s.status.set(String::new());

    spawn_local(async move {
        let me = identity().await;
        let public = me.public_b64();
        let bundle = my_bundle().await;
        if !still(run) {
            return;
        }
        if !publish(&code, &peer_id, &public, false, &bundle).await {
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
                    let (from, from_pub) = (text_field(&wrap, "from"), text_field(&wrap, "fromPub"));
                    if let Some(key) = me.unwrap_group_key(&text_field(&wrap, "blob"), &from_pub) {
                        // Le paquet de l'invitant, et sommes-nous à deux ?
                        let room = peers(&code, &peer_id).await;
                        let duo = room.len() == 1;
                        let peer = room
                            .iter()
                            .find(|p| p.id == from && p.public == from_pub)
                            .filter(|_| duo)
                            .and_then(|p| new_contact(p, &code, &peer_id, now() + GROUP_WATCH));
                        enter(key, peer, s, run, false);
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
    let run = next_run();
    spawn_local(async move {
        let key = coffre::load(CHAT_KEY)
            .await
            .and_then(|k| crypto::unb64(&k))
            .and_then(|k| <[u8; 32]>::try_from(k).ok());
        let peer = coffre::load(CHAT_PEER).await.and_then(|j| serde_json::from_str::<Contact>(&j).ok());
        // Une autre action (J'invite, Je rejoins) a pu partir pendant la lecture.
        if let Some(key) = key
            && still(run)
        {
            enter(key, peer, s, run, false);
        }
    });
}

/// Celui qui a rejoint vérifie, 8 jours durant, qu'on est toujours à deux
/// (§8.4) : plus d'un autre participant dans le salon = clé de groupe.
async fn watch_group(key: [u8; 32], s: ChatStates) {
    let Some(mut c) = contact().filter(|c| !c.group && c.until > now() && !c.code.is_empty()) else {
        return;
    };
    if peers(&c.code, &c.peer_id).await.len() > 1 {
        c.group = true;
        save_contact(Some(c)).await;
        with_engine(|e, t| show_protection(e, key, t, s)).await;
    }
}

fn enter(key: [u8; 32], peer: Option<Contact>, s: ChatStates, run: u32, initiator: bool) {
    let saved = crypto::b64(&key);
    KEY.with(|k| *k.borrow_mut() = Some(key));
    CONTACT.with(|c| *c.borrow_mut() = peer.clone());
    SEEN_TOKENS.with(|seen| seen.borrow_mut().clear());
    s.messages.set(Vec::new());
    s.phase.set(ChatPhase::Chat);
    let conv = crypto::conversation_id(&key);
    let me = device_id();

    spawn_local(async move {
        // Rangées au coffre, sauf si l'on a quitté pendant le chiffrement.
        coffre::save(CHAT_KEY, &saved, move || still(run)).await;
        if still(run) {
            save_contact(peer.clone()).await;
        }
        // L'empreinte : les deux identités v3 si l'on est à deux avec un
        // appareil v3, sinon celle d'avant ; l'invitant ouvre la session.
        let bundle = contact_bundle(&peer);
        let caps = contact_caps(&peer);
        let fp = with_engine(|e, t| {
            let k = key_info(key, &peer, bundle.as_ref(), caps.as_ref(), &conv);
            if initiator {
                e.open_session(&k, t);
            }
            show_protection(e, key, t, s);
            e.fingerprint(&k)
        })
        .await;
        s.fingerprint.set(fp.unwrap_or_else(|| crypto::fingerprint(&key)));
        // L'historique encore sur le serveur (7 jours au plus), page par page.
        let mut after: u64 = 0;
        loop {
            let url = format!("/v1/messages?conversationId={}&after={after}", encode(&conv));
            let Some(page) = call("GET", &url, None).await else { break };
            let Ok(list) = field(&page, "messages").dyn_into::<js_sys::Array>() else { break };
            ingest(list.iter().collect(), key, &me, s).await;
            after = field(&page, "cursor").as_f64().unwrap_or(0.0) as u64;
            if field(&page, "hasMore").as_bool() != Some(true) || !still(run) {
                break;
            }
        }
        if still(run) {
            listen(&conv, key, me, s);
            watch_group(key, s).await;
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
            let me = me.clone();
            spawn_local(async move { ingest(vec![value], key, &me, s).await });
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

/// Ajoute des messages reçus (sans doublon), dans l'ordre : les jetons v3 en
/// une seule transaction (§8.6), les autres en v1.
async fn ingest(list: Vec<JsValue>, key: [u8; 32], me: &str, s: ChatStates) {
    let fresh: Vec<(String, u64, bool, String)> = list
        .iter()
        .map(|m| {
            (
                text_field(m, "id"),
                field(m, "seq").as_f64().unwrap_or(0.0) as u64,
                text_field(m, "senderId") == me,
                text_field(m, "ciphertext"),
            )
        })
        .filter(|(id, ..)| !id.is_empty() && !s.messages.with(|l| l.iter().any(|x| &x.id == id)))
        .filter(|(.., ct)| match v3::find_tokens(ct).first() {
            Some(&(a, b)) => SEEN_TOKENS.with(|seen| seen.borrow_mut().insert(v3::token_hash(&ct[a..b]))),
            None => true,
        })
        .collect();
    if fresh.is_empty() {
        return;
    }
    let c = contact();
    let bundle = contact_bundle(&c);
    let caps = contact_caps(&c);
    let conv = crypto::conversation_id(&key);
    let lang = s.lang;
    let has_v3 = fresh.iter().any(|(.., ct)| !v3::find_tokens(ct).is_empty());
    let opened: Vec<Option<Option<String>>> = if has_v3 {
        with_engine(|e, t| {
            let k = key_info(key, &c, bundle.as_ref(), caps.as_ref(), &conv);
            let out = fresh
                .iter()
                .map(|(_, _, mine, ct)| {
                    v3::open_message(e, ct, &[k], &k, *mine, t).map(|o| match o {
                        Opened::Text(text) => Some(text),
                        Opened::Replay if *mine => Some(lang.t("chat.v3sent").to_owned()),
                        _ => None,
                    })
                })
                .collect();
            show_protection(e, key, t, s);
            out
        })
        .await
    } else {
        vec![None; fresh.len()]
    };
    let msgs: Vec<ChatMsg> = fresh
        .into_iter()
        .zip(opened)
        .map(|((id, seq, mine, ct), v3)| ChatMsg {
            id,
            seq,
            mine,
            body: chat_body(v3.unwrap_or_else(|| crypto::open_tokens(&key, &ct))),
        })
        .collect();
    s.messages.update(|list| {
        for m in msgs {
            if !list.iter().any(|x| x.id == m.id) {
                list.push(m);
            }
        }
        list.sort_by_key(|x| x.seq);
    });
    scroll_to_end();
}

fn scroll_to_end() {
    if let Ok(Some(log)) = super::document().query_selector(".chat-log") {
        log.set_scroll_top(log.scroll_height());
    }
}

/// Chiffre et envoie un message : en v3 si la discussion le permet (§8.5),
/// sinon en v1.
pub fn send(text: String, s: ChatStates) {
    let Some(key) = KEY.with(|k| *k.borrow()) else { return };
    let conv = crypto::conversation_id(&key);
    let me = device_id();
    spawn_local(async move {
        let c = contact();
        let bundle = contact_bundle(&c);
        let caps = contact_caps(&c);
        let sealed = with_engine(|e, t| {
            let k = key_info(key, &c, bundle.as_ref(), caps.as_ref(), &conv);
            let out = v3::seal_message(e, &k, &text, t);
            show_protection(e, key, t, s);
            out
        })
        .await;
        let Some(token) = sealed.or_else(|| crypto::seal_token(&key, &text)) else { return };
        let body = json(&[("id", &crypto::uuid()), ("conversationId", &conv), ("senderId", &me), ("ciphertext", &token)]);
        if let Some(m) = call("POST", "/v1/messages", Some(body)).await {
            ingest(vec![m], key, &me, s).await;
        } else {
            s.status.set(s.lang.t("chat.offline").to_owned());
        }
    });
}

/// Quitte la discussion : la clé, le contact et l'état v3 sont oubliés par
/// ce navigateur (l'appareil v3 reste).
pub fn leave(s: ChatStates) {
    next_run();
    close_stream();
    KEY.with(|k| *k.borrow_mut() = None);
    CONTACT.with(|c| *c.borrow_mut() = None);
    if let Some(st) = storage() {
        for name in [CHAT_KEY, CHAT_PEER, V3_STATE] {
            let _ = st.remove_item(name);
        }
    }
    s.messages.set(Vec::new());
    s.fingerprint.set(String::new());
    s.protection.set(String::new());
    s.joined.set(0);
    s.status.set(String::new());
    s.phase.set(ChatPhase::Setup);
}

// ── Photos et vocaux ─────────────────────────────────────────────────────────
//
// Même format que l'app : le texte chiffré commence par `BRCM1:img:` (JPEG en
// base64) ou `BRCM1:aud:` (audio en base64). L'iPhone lit l'audio avec
// AVAudioPlayer, qui ne connaît pas le WebM des navigateurs : on enregistre
// donc en WAV (PCM 16 kHz mono), lisible partout.

/// Taille maximale d'une photo, comme l'app (côté le plus long).
const PHOTO_MAX_SIDE: f64 = 1280.0;
/// Durée maximale d'un vocal : une minute, comme dans l'app.
pub const VOICE_MAX_SECONDS: f64 = 60.0;
const VOICE_RATE: u32 = 16_000;

/// La photo choisie dans `<input type=file>` : réduite, compressée en JPEG,
/// puis envoyée chiffrée.
pub fn send_photo(input: web_sys::HtmlInputElement, s: ChatStates) {
    let Some(file) = input.files().and_then(|f| f.get(0)) else { return };
    input.set_value("");
    let Ok(url) = web_sys::Url::create_object_url_with_blob(&file) else { return };
    let Ok(img) = web_sys::HtmlImageElement::new() else { return };
    s.status.set(s.lang.t("chat.sendingPhoto").to_owned());
    let img2 = img.clone();
    let url2 = url.clone();
    let onload = Closure::once_into_js(move || {
        let _ = web_sys::Url::revoke_object_url(&url2);
        let (w, h) = (img2.natural_width() as f64, img2.natural_height() as f64);
        if w == 0.0 || h == 0.0 {
            return;
        }
        let scale = (PHOTO_MAX_SIDE / w.max(h)).min(1.0);
        let (cw, ch) = ((w * scale).round(), (h * scale).round());
        let Ok(canvas) = super::document().create_element("canvas") else { return };
        let canvas: web_sys::HtmlCanvasElement = canvas.unchecked_into();
        canvas.set_width(cw as u32);
        canvas.set_height(ch as u32);
        let Some(ctx) = canvas
            .get_context("2d")
            .ok()
            .flatten()
            .and_then(|c| c.dyn_into::<web_sys::CanvasRenderingContext2d>().ok())
        else {
            return;
        };
        let _ = ctx.draw_image_with_html_image_element_and_dw_and_dh(&img2, 0.0, 0.0, cw, ch);
        let Ok(data_url) = canvas.to_data_url_with_type_and_encoder_options("image/jpeg", &JsValue::from_f64(0.6))
        else {
            return;
        };
        if let Some((_, b64)) = data_url.split_once(',') {
            send(format!("BRCM1:img:{b64}"), s);
            s.status.set(String::new());
        }
    });
    img.set_onload(Some(onload.unchecked_ref()));
    img.set_src(&url);
}

/// L'enregistrement en cours.
struct Recording {
    context: web_sys::AudioContext,
    stream: web_sys::MediaStream,
    // Gardés en vie tant qu'on enregistre.
    _source: web_sys::MediaStreamAudioSourceNode,
    _processor: web_sys::ScriptProcessorNode,
    samples: std::rc::Rc<RefCell<Vec<f32>>>,
    rate: f32,
}

thread_local! {
    static RECORDING: RefCell<Option<Recording>> = const { RefCell::new(None) };
}

/// Démarre (ou arrête et envoie) un vocal. `recording` suit l'état du bouton.
pub fn toggle_voice(s: ChatStates, recording: active::State<bool>) {
    if RECORDING.with(|r| r.borrow().is_some()) {
        stop_voice(s, recording, true);
        return;
    }
    let Ok(devices) = window().navigator().media_devices() else {
        s.status.set(s.lang.t("chat.micDenied").to_owned());
        return;
    };
    let constraints = web_sys::MediaStreamConstraints::new();
    constraints.set_audio(&JsValue::TRUE);
    let Ok(promise) = devices.get_user_media_with_constraints(&constraints) else { return };
    spawn_local(async move {
        let Ok(stream) = JsFuture::from(promise).await else {
            s.status.set(s.lang.t("chat.micDenied").to_owned());
            return;
        };
        let stream: web_sys::MediaStream = stream.unchecked_into();
        let Ok(context) = web_sys::AudioContext::new() else { return };
        let Ok(source) = context.create_media_stream_source(&stream) else { return };
        let Ok(processor) = context.create_script_processor_with_buffer_size_and_number_of_input_channels_and_number_of_output_channels(4096, 1, 1)
        else {
            return;
        };
        let samples = std::rc::Rc::new(RefCell::new(Vec::<f32>::new()));
        let rate = context.sample_rate();
        let sink = samples.clone();
        let limit = (rate as f64 * VOICE_MAX_SECONDS) as usize;
        let lang = s.lang;
        let shown = std::rc::Rc::new(Cell::new(u32::MAX));
        let on_audio = Closure::<dyn FnMut(web_sys::AudioProcessingEvent)>::new(move |e: web_sys::AudioProcessingEvent| {
            if let Ok(data) = e.input_buffer().and_then(|b| b.get_channel_data(0)) {
                let mut all = sink.borrow_mut();
                all.extend_from_slice(&data);
                // Le compteur « 0:12 / 1:00 », mis à jour chaque seconde.
                let secs = (all.len() as f32 / rate) as u32;
                if secs != shown.get() {
                    shown.set(secs);
                    s.status.set(format!("🔴 {} {}:{:02} / 1:00", lang.t("chat.recording"), secs / 60, secs % 60));
                }
                if all.len() >= limit {
                    all.truncate(limit);
                    drop(all);
                    // Durée maximale atteinte : on envoie.
                    stop_voice(s, recording, true);
                }
            }
        });
        processor.set_onaudioprocess(Some(on_audio.as_ref().unchecked_ref()));
        on_audio.forget();
        let _ = source.connect_with_audio_node(&processor);
        let _ = processor.connect_with_audio_node(&context.destination());
        RECORDING.with(|r| {
            *r.borrow_mut() = Some(Recording { context, stream, _source: source, _processor: processor, samples, rate })
        });
        recording.set(true);
    });
}

/// Arrête l'enregistrement ; l'envoie si `deliver`.
pub fn stop_voice(s: ChatStates, recording: active::State<bool>, deliver: bool) {
    let Some(rec) = RECORDING.with(|r| r.borrow_mut().take()) else { return };
    rec._processor.set_onaudioprocess(None);
    let _ = rec._source.disconnect();
    let _ = rec._processor.disconnect();
    let _ = rec.context.close();
    for track in rec.stream.get_tracks().iter() {
        track.unchecked_into::<web_sys::MediaStreamTrack>().stop();
    }
    recording.set(false);
    s.status.set(String::new());
    let samples = rec.samples.borrow();
    // Moins d'un tiers de seconde : un appui par erreur.
    if !deliver || samples.len() < (rec.rate as usize) / 3 {
        return;
    }
    let wav = crate::crypto::wav_16k(&samples, rec.rate, VOICE_RATE);
    send(format!("BRCM1:aud:{}", crypto::b64(&wav)), s);
}
