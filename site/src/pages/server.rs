//! État du serveur de rendez-vous, en direct.

use gloo::net::http::Request;
use web_sys::{AbortSignal, RequestMode};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::Route;
use crate::config::server_base;
use crate::prefs::use_prefs;

const ENDPOINTS: [(&str, &str, &str); 3] = [
    ("POST / GET", "/pair", "server.api.pair"),
    ("POST / GET", "/wrap", "server.api.wrap"),
    ("GET", "/health", "server.api.health"),
];

const TIMEOUT_MS: u32 = 8000;

#[derive(Clone, Copy, PartialEq)]
enum Status {
    Checking,
    Online(u32),
    Offline,
}

async fn probe(base: &str) -> Status {
    let url = format!("{base}/health");
    let started = js_sys::Date::now();
    let elapsed = || (js_sys::Date::now() - started).round() as u32;

    let signal = AbortSignal::timeout_with_u32(TIMEOUT_MS);
    match Request::get(&url).abort_signal(Some(&signal)).send().await {
        Ok(res) if res.ok() => Status::Online(elapsed()),
        Ok(_) => Status::Offline,
        Err(_) => {
            // Hors du serveur (autre hébergement, dev local), pas d'en-têtes CORS :
            // une requête opaque qui aboutit suffit à dire qu'il est joignable.
            let signal = AbortSignal::timeout_with_u32(TIMEOUT_MS);
            match Request::get(&url)
                .mode(RequestMode::NoCors)
                .abort_signal(Some(&signal))
                .send()
                .await
            {
                Ok(_) => Status::Online(elapsed()),
                Err(_) => Status::Offline,
            }
        }
    }
}

#[function_component(ServerPage)]
pub fn server_page() -> Html {
    let prefs = use_prefs();
    let base = use_memo((), |_| server_base());
    let status = use_state_eq(|| Status::Checking);

    let check = {
        let status = status.clone();
        let base = base.clone();
        Callback::from(move |_: ()| {
            status.set(Status::Checking);
            let status = status.clone();
            let base = base.clone();
            wasm_bindgen_futures::spawn_local(async move {
                status.set(probe(&base).await);
            });
        })
    };

    {
        let check = check.clone();
        use_effect_with((), move |_| check.emit(()));
    }

    let (class, label) = match *status {
        Status::Checking => ("checking", prefs.t("server.checking")),
        Status::Online(_) => ("online", prefs.t("server.online")),
        Status::Offline => ("offline", prefs.t("server.offline")),
    };

    html! {
        <section class="legal server-page">
            <h1>{ prefs.t("server.title") }{ " 🛰️" }</h1>
            <p class="lead">{ prefs.t("server.note") }</p>

            <div class="panel server-card">
                <div class="server-row">
                    <strong>{ prefs.t("server.status") }</strong>
                    <span class={classes!("server-status", class)} role="status" aria-live="polite">
                        <span class="server-dot" aria-hidden="true" />
                        { label }
                        if let Status::Online(ms) = *status {
                            <em>{ format!(" — {} {ms} ms", prefs.t("server.latency")) }</em>
                        }
                    </span>
                </div>
                <div class="server-row">
                    <strong>{ prefs.t("server.address") }</strong>
                    <code class="server-url">{ (*base).clone() }</code>
                </div>
                <div class="cta">
                    <a class="btn primary" href={(*base).clone()} target="_blank" rel="noopener noreferrer">
                        { prefs.t("server.open") }
                    </a>
                    <button type="button" class="btn" disabled={*status == Status::Checking}
                            onclick={check.reform(|_: MouseEvent| ())}>
                        { prefs.t("server.recheck") }
                    </button>
                </div>
            </div>

            <h2>{ prefs.t("server.api") }</h2>
            <ul class="endpoints">
                { for ENDPOINTS.iter().map(|(method, path, key)| html! {
                    <li>
                        <code class="method">{ *method }</code>
                        <code class="path">{ *path }</code>
                        <span>{ prefs.t(key) }</span>
                    </li>
                }) }
            </ul>
            <p class="legal-note">{ prefs.t("server.privacy") }</p>

            <p><Link<Route> to={Route::Home} classes="back">{ prefs.t("back") }</Link<Route>></p>
        </section>
    }
}
