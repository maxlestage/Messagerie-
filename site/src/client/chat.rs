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
