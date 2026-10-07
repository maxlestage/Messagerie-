//! Accueil : héros, fonctionnalités, formules et README du dépôt.

use gloo::net::http::Request;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::app::{Route, scroll_to_section};
use crate::config::{BROCOLIS_URL, REPO_URL};
use crate::markdown;
use crate::prefs::use_prefs;

const FEATURES: [(&str, &str, &str); 7] = [
    ("🧩", "feat.graft.t", "feat.graft.d"),
    ("🔒", "feat.crypto.t", "feat.crypto.d"),
    ("🤝", "feat.pair.t", "feat.pair.d"),
    ("👥", "feat.group.t", "feat.group.d"),
    ("⏳", "feat.rotate.t", "feat.rotate.d"),
    ("⌚️", "feat.watch.t", "feat.watch.d"),
    ("🥦", "feat.interop.t", "feat.interop.d"),
];

const STATS: [(&str, &str); 3] = [
    ("stat.cipher", "stat.cipher.d"),
    ("stat.kex", "stat.kex.d"),
    ("stat.server", "stat.server.d"),
];

/// (préfixe de clé, emoji, mis en avant)
const PLANS: [(&str, &str, bool); 3] = [
    ("plan.free", "🌱", false),
    ("plan.plus", "🥦", false),
    ("plan.pro", "🚀", true),
];

#[function_component(HomePage)]
pub fn home_page() -> Html {
    html! {
        <>
            <Hero />
            <Features />
            <Pricing />
            <Readme />
        </>
    }
}

#[function_component(Hero)]
fn hero() -> Html {
    let prefs = use_prefs();
    let to_pricing = Callback::from(|e: MouseEvent| {
        e.prevent_default();
        scroll_to_section("pricing");
    });

    html! {
        <header class="hero" id="top">
            <div class="hero-glow" aria-hidden="true" />
            <div class="hero-inner">
                <img class="logo-img" src="photo.png" alt={prefs.t("hero.alt")} width="148" height="148" />
                <p class="badge">{ prefs.t("hero.badge") }</p>
                <h1>
                    { prefs.t("hero.title") }<br />
                    <span class="accent">{ prefs.t("hero.titleAccent") }</span>
                </h1>
                <p class="tagline">{ Html::from_html_unchecked(prefs.t("hero.tagline").into()) }</p>
                <div class="cta">
                    <a class="btn primary" href="#/pricing" onclick={to_pricing}>{ prefs.t("cta.pricing") }</a>
                    <Link<Route> to={Route::Salon} classes="btn">{ prefs.t("cta.salon") }</Link<Route>>
                    <Link<Route> to={Route::Server} classes="btn">{ prefs.t("cta.server") }</Link<Route>>
                    <a class="btn ghost" href={REPO_URL} target="_blank" rel="noopener noreferrer">{ prefs.t("cta.repo") }</a>
                    <a class="btn ghost" href={BROCOLIS_URL} target="_blank" rel="noopener noreferrer">{ prefs.t("cta.brocolis") }</a>
                </div>
                <dl class="stats">
                    { for STATS.iter().map(|(v, d)| html! {
                        <div class="stat">
                            <dt>{ prefs.t(v) }</dt>
                            <dd>{ prefs.t(d) }</dd>
                        </div>
                    }) }
                </dl>
            </div>
        </header>
    }
}

#[function_component(Features)]
fn features() -> Html {
    let prefs = use_prefs();
    html! {
        <section class="section" id="features" aria-labelledby="features-title">
            <div class="section-head">
                <h2 id="features-title">{ prefs.t("features.title") }</h2>
                <p>{ prefs.t("features.note") }</p>
            </div>
            <div class="features">
                { for FEATURES.iter().map(|(icon, title, text)| html! {
                    <article class="card">
                        <div class="card-icon" aria-hidden="true">{ *icon }</div>
                        <h3>{ prefs.t(title) }</h3>
                        <p>{ prefs.t(text) }</p>
                    </article>
                }) }
            </div>
        </section>
    }
}

#[function_component(Pricing)]
fn pricing() -> Html {
    let prefs = use_prefs();
    let plans = PLANS.iter().map(|(prefix, icon, featured)| {
        let k = |suffix: &str| prefs.t(&format!("{prefix}.{suffix}"));
        let paid = *prefix != "plan.free";
        html! {
            <article class={classes!("plan", featured.then_some("featured"))}>
                if *featured {
                    <span class="plan-flag">{ prefs.t("pricing.popular") }</span>
                }
                <h3><span aria-hidden="true">{ *icon }</span>{ " " }{ k("name") }</h3>
                <p class="plan-price">
                    <strong>{ k("price") }</strong>
                    if paid { <span>{ prefs.t("pricing.month") }</span> }
                </p>
                <ul>
                    { for ["f1", "f2", "f3"].iter().map(|f| html! { <li>{ k(f) }</li> }) }
                </ul>
            </article>
        }
    });

    html! {
        <section class="section" id="pricing" aria-labelledby="pricing-title">
            <div class="section-head">
                <h2 id="pricing-title">{ prefs.t("pricing.title") }</h2>
                <p>{ prefs.t("pricing.note") }</p>
            </div>
            <div class="plans">{ for plans }</div>
            <p class="plans-foot">{ prefs.t("pricing.foot") }</p>
        </section>
    }
}

#[derive(Clone, PartialEq)]
enum Doc {
    Loading,
    Ready(AttrValue),
    Unavailable,
}

async fn fetch_readme() -> Option<String> {
    let res = Request::get("README.md").send().await.ok()?;
    if !res.ok() {
        return None;
    }
    res.text().await.ok()
}

#[function_component(Readme)]
fn readme() -> Html {
    let prefs = use_prefs();
    let doc = use_state(|| Doc::Loading);

    {
        let doc = doc.clone();
        use_effect_with((), move |_| {
            wasm_bindgen_futures::spawn_local(async move {
                doc.set(match fetch_readme().await {
                    Some(md) if !md.trim().is_empty() => Doc::Ready(markdown::render(&md).into()),
                    _ => Doc::Unavailable,
                });
            });
        });
    }

    html! {
        <section class="section readme" id="doc" aria-labelledby="doc-title">
            <div class="section-head">
                <h2 id="doc-title">{ prefs.t("doc.title") }</h2>
                <p>{ prefs.t("doc.note") }</p>
            </div>
            {
                match &*doc {
                    Doc::Loading => html! {
                        <div class="skeleton" aria-busy="true">
                            <p class="loading">{ prefs.t("doc.loading") }</p>
                            <span /><span /><span />
                        </div>
                    },
                    Doc::Unavailable => html! {
                        <p class="loading">
                            { prefs.t("doc.unavailable") }{ " " }
                            <a href={REPO_URL} target="_blank" rel="noopener noreferrer">{ "GitHub" }</a>
                        </p>
                    },
                    Doc::Ready(html) => html! {
                        <article class="markdown">{ Html::from_html_unchecked(html.clone()) }</article>
                    },
                }
            }
        </section>
    }
}
