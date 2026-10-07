//! Salon des rendez-vous : explique l'appairage et laisse VOIR, en direct, qui
//! est présent sous un code (données publiques : clés publiques uniquement).

use gloo::net::http::Request;
use gloo::timers::callback::Interval;
use serde::Deserialize;
use web_sys::{AbortSignal, HtmlInputElement};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::config::server_base;
use crate::prefs::use_prefs;

const REFRESH_MS: u32 = 4000;

#[derive(Clone, PartialEq, Deserialize)]
struct Peer {
    #[serde(rename = "peerId")]
    peer_id: String,
    #[serde(rename = "pub")]
    public_key: String,
}

#[derive(Deserialize)]
struct PairResponse {
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Clone, PartialEq)]
enum Room {
    Loading,
    Peers(Vec<Peer>),
    Unreachable,
}

async fn fetch_peers(base: &str, code: &str) -> Option<Vec<Peer>> {
    let signal = AbortSignal::timeout_with_u32(8000);
    let res = Request::get(&format!("{base}/pair"))
        .query([("code", code)])
        .abort_signal(Some(&signal))
        .send()
        .await
        .ok()?;
    res.json::<PairResponse>().await.ok().map(|r| r.peers)
}

fn short_key(key: &str) -> String {
    let head: String = key.chars().take(14).collect();
    if head.len() < key.len() {
        format!("{head}…")
    } else {
        head
    }
}

#[function_component(SalonPage)]
pub fn salon_page() -> Html {
    let prefs = use_prefs();
    let base = use_memo((), |_| server_base());
    let code = use_state(String::new);
    let active = use_state_eq(|| None::<String>);
    let room = use_state_eq(|| Room::Loading);
    let refreshing = use_state_eq(|| false);

    // Rafraîchit toutes les 4 s tant qu'un salon est ouvert.
    {
        let room = room.clone();
        let refreshing = refreshing.clone();
        let base = base.clone();
        use_effect_with((*active).clone(), move |active| {
            let interval = active.clone().map(|c| {
                let load = move || {
                    let room = room.clone();
                    let refreshing = refreshing.clone();
                    let base = base.clone();
                    let c = c.clone();
                    refreshing.set(true);
                    wasm_bindgen_futures::spawn_local(async move {
                        room.set(match fetch_peers(&base, &c).await {
                            Some(peers) => Room::Peers(peers),
                            None => Room::Unreachable,
                        });
                        refreshing.set(false);
                    });
                };
                load();
                Interval::new(REFRESH_MS, load)
            });
            move || drop(interval)
        });
    }

    let oninput = {
        let code = code.clone();
        Callback::from(move |e: InputEvent| {
            code.set(e.target_unchecked_into::<HtmlInputElement>().value())
        })
    };
    let onsubmit = {
        let code = code.clone();
        let active = active.clone();
        let room = room.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            let c = code.trim().to_string();
            if !c.is_empty() {
                if active.as_deref() != Some(c.as_str()) {
                    room.set(Room::Loading);
                }
                active.set(Some(c));
            }
        })
    };

    let steps = ["salon.step1", "salon.step2", "salon.step3", "salon.step4"];

    html! {
        <section class="legal salon-page">
            <h1>{ prefs.t("salon.title") }{ " 🤝" }</h1>
            <p class="lead">{ prefs.t("salon.intro") }</p>

            <h2>{ prefs.t("salon.howTitle") }</h2>
            <ol class="steps">
                { for steps.iter().map(|s| html! { <li>{ prefs.t(s) }</li> }) }
            </ol>
            <p class="callout">{ "🔑 " }{ prefs.t("salon.fingerprint") }</p>

            <h2>{ prefs.t("salon.roomTitle") }</h2>
            <p class="legal-note">{ prefs.t("salon.roomNote") }</p>

            <form class="salon-form" {onsubmit}>
                <label for="salon-code">{ prefs.t("salon.codeLabel") }</label>
                <div class="salon-row">
                    <input
                        id="salon-code"
                        class="input"
                        inputmode="text"
                        autocomplete="off"
                        placeholder={prefs.t("salon.codePlaceholder")}
                        value={(*code).clone()}
                        {oninput}
                    />
                    <button type="submit" class="btn primary" disabled={code.trim().is_empty()}>
                        { prefs.t("salon.view") }
                    </button>
                </div>
            </form>

            if let Some(c) = (*active).clone() {
                <div class="panel salon-room" aria-live="polite">
                    <p class="salon-room-head">
                        <strong>{ prefs.t("salon.peers") }</strong>
                        <code class="code-badge">{ c }</code>
                        if *refreshing {
                            <em class="salon-refreshing">{ prefs.t("salon.refreshing") }</em>
                        }
                    </p>
                    {
                        match &*room {
                            Room::Loading => html! {},
                            Room::Unreachable => html! {
                                <div class="salon-error">
                                    <strong>{ prefs.t("salon.errorTitle") }</strong>
                                    <p>{ prefs.t("salon.errorCors") }</p>
                                </div>
                            },
                            Room::Peers(peers) if peers.is_empty() => html! {
                                <p class="salon-empty">{ prefs.t("salon.empty") }</p>
                            },
                            Room::Peers(peers) => html! {
                                <ul class="salon-peers">
                                    { for peers.iter().map(|p| html! {
                                        <li key={p.peer_id.clone()}>
                                            <span class="salon-peer-id">{ "🥦 " }{ &p.peer_id }</span>
                                            <code class="salon-peer-pub" title={p.public_key.clone()}>
                                                { format!("{}: {}", prefs.t("salon.pub"), short_key(&p.public_key)) }
                                            </code>
                                        </li>
                                    }) }
                                </ul>
                            },
                        }
                    }
                </div>
            }

            <p class="legal-note">{ prefs.t("salon.privacy") }</p>
            <p><Link<Route> to={Route::Home} classes="back">{ prefs.t("back") }</Link<Route>></p>
        </section>
    }
}
