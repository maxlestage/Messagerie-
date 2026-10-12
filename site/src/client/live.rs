//! Ce qui parle au serveur : le salon en direct (`/pair`), la latence
//! (`/health`) et les chiffres publics (`/stats`). Toujours la même origine :
//! la page est servie par le serveur qu'elle observe.

use std::cell::Cell;

use active::State;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};

use super::{every, later, now, request_frame, window};
use crate::islands::{BARS, Peer, Room, Stats, Status};

thread_local! {
    /// Le salon observé : un nouveau code arrête la surveillance du précédent.
    static ROOM: Cell<u32> = const { Cell::new(0) };
    /// Une animation des chiffres est en cours.
    static TWEENING: Cell<bool> = const { Cell::new(false) };
}

/// Attend `ms` millisecondes.
pub async fn sleep(ms: i32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let _ = window().set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms);
    });
    let _ = JsFuture::from(promise).await;
}

/// `GET url`, abandonné au bout de `timeout_ms`.
async fn fetch(url: &str, timeout_ms: i32) -> Option<web_sys::Response> {
    let controller = web_sys::AbortController::new().ok()?;
    let init = web_sys::RequestInit::new();
    init.set_signal(Some(&controller.signal()));
    let promise = window().fetch_with_str_and_init(url, &init);
    later(timeout_ms, move || controller.abort());
    JsFuture::from(promise).await.ok()?.dyn_into().ok()
}

async fn fetch_json(url: &str) -> Option<JsValue> {
    let res = fetch(url, 8000).await?;
    if !res.ok() {
        return None;
    }
    JsFuture::from(res.json().ok()?).await.ok()
}

fn field(obj: &JsValue, key: &str) -> JsValue {
    js_sys::Reflect::get(obj, &JsValue::from_str(key)).unwrap_or(JsValue::UNDEFINED)
}

fn number(obj: &JsValue, key: &str) -> f64 {
    field(obj, key).as_f64().unwrap_or(0.0)
}

fn encode(s: &str) -> String {
    js_sys::encode_uri_component(s)
        .as_string()
        .unwrap_or_default()
}

// ── Salon ────────────────────────────────────────────────────────────────────

async fn peers(code: &str) -> Option<Vec<Peer>> {
    let body = fetch_json(&format!("/pair?code={}", encode(code))).await?;
    let list: js_sys::Array = field(&body, "peers").dyn_into().ok()?;
    Some(
        list.iter()
            .map(|p| Peer {
                id: field(&p, "peerId").as_string().unwrap_or_default(),
                public_key: field(&p, "pub").as_string().unwrap_or_default(),
            })
            .filter(|p| !p.id.is_empty())
            .collect(),
    )
}

/// Surveille le salon `code` : les participants sont relus toutes les quatre
/// secondes, jusqu'à ce qu'un autre code soit demandé.
pub fn watch_room(code: String, room: State<Room>, refreshing: State<bool>) {
    let run = ROOM.with(|r| {
        r.set(r.get().wrapping_add(1));
        r.get()
    });
    // L'adresse garde le code : on peut la partager.
    if let Ok(history) = window().history() {
        let url = format!("?code={}", encode(&code));
        let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(&url));
    }
    spawn_local(async move {
        while ROOM.with(Cell::get) == run && room.is_alive() {
            refreshing.set(true);
            let started = now();
            let next = match peers(&code).await {
                Some(p) => Room::Peers(p),
                None => Room::Unreachable,
            };
            if ROOM.with(Cell::get) != run {
                break;
            }
            if room.with(|r| *r != next) {
                room.set(next);
            }
            // Le témoin « en direct » clignote au moins un instant.
            let spent = (now() - started) as i32;
            sleep((450 - spent).max(0)).await;
            refreshing.set(false);
            sleep(3550).await;
        }
    });
}

// ── Serveur ──────────────────────────────────────────────────────────────────

/// Mesure la latence de `/health` et l'ajoute au graphique.
pub fn probe(status: State<Status>, history: State<Vec<u32>>) {
    status.set(Status::Checking);
    spawn_local(async move {
        let started = now();
        let ok = fetch(&format!("/health?t={}", js_sys::Date::now() as u64), 8000)
            .await
            .is_some_and(|r| r.ok());
        let ms = (now() - started).round().max(1.0) as u32;
        // La vérification se voit, même quand le serveur répond très vite.
        sleep((350 - (now() - started) as i32).max(0)).await;
        if ok {
            status.set(Status::Online(ms));
            history.update(|h| {
                h.push(ms);
                if h.len() > BARS {
                    h.remove(0);
                }
            });
        } else {
            status.set(Status::Offline);
        }
    });
}

async fn stats() -> Option<Stats> {
    let body = fetch_json(&format!("/stats?t={}", js_sys::Date::now() as u64)).await?;
    Some(Stats {
        messages: number(&body, "messages"),
        conversations: number(&body, "conversations"),
        rooms: number(&body, "rooms"),
        listeners: number(&body, "listeners"),
        bytes: number(&body, "bytes"),
        uptime: number(&body, "uptime"),
    })
}

/// Les chiffres affichés rattrapent les chiffres reçus, en ralentissant.
fn tween(target: State<Stats>, shown: State<Stats>) {
    if TWEENING.with(Cell::get) {
        return;
    }
    TWEENING.with(|t| t.set(true));
    let mut last = now();
    request_frame(move |time| {
        let dt = ((time - last) / 1000.0).clamp(0.0, 0.1);
        last = time;
        let goal = target.get();
        let current = shown.get();
        let k = 1.0 - (-7.0 * dt).exp();
        let step = |a: f64, b: f64| {
            if (b - a).abs() < 0.5 {
                b
            } else {
                a + (b - a) * k
            }
        };
        let next = Stats {
            messages: step(current.messages, goal.messages),
            conversations: step(current.conversations, goal.conversations),
            rooms: step(current.rooms, goal.rooms),
            listeners: step(current.listeners, goal.listeners),
            bytes: step(current.bytes, goal.bytes),
            // L'horloge ne ralentit pas : elle suit la seconde.
            uptime: if current.uptime == 0.0 {
                step(0.0, goal.uptime)
            } else {
                goal.uptime
            },
        };
        shown.set(next);
        let done = next == goal;
        if done {
            TWEENING.with(|t| t.set(false));
        }
        !done
    });
}

/// Démarre la page Serveur : adresse, latence toutes les cinq secondes,
/// chiffres publics, et l'horloge « en ligne depuis » qui tourne.
pub fn start_status(
    status: State<Status>,
    history: State<Vec<u32>>,
    target: State<Stats>,
    shown: State<Stats>,
    origin: State<String>,
) {
    if let Ok(o) = window().location().origin() {
        origin.set(o);
    }
    probe(status, history);
    every(5000, move || {
        if status.get() != Status::Checking {
            probe(status, history);
        }
    });
    let refresh = move || {
        spawn_local(async move {
            if let Some(s) = stats().await {
                target.set(s);
                tween(target, shown);
            }
        });
    };
    refresh();
    every(5000, refresh);
    every(1000, move || {
        if target.with(|t| t.uptime > 0.0) {
            target.update(|t| t.uptime += 1.0);
            tween(target, shown);
        }
    });
}
