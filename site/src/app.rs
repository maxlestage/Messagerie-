//! Coquille du site : routes, barre de navigation, pied de page.

use gloo::events::EventListener;
use gloo::timers::callback::Timeout;
use wasm_bindgen::JsCast;
use web_sys::{ScrollBehavior, ScrollIntoViewOptions};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::config::{BROCOLIS_URL, REPO_URL};
use crate::i18n::Lang;
use crate::pages::{home::HomePage, license::LicensePage, salon::SalonPage, server::ServerPage};
use crate::prefs::{Prefs, PrefsAction, Theme, apply_to_document, use_prefs};

#[derive(Clone, Routable, PartialEq, Debug)]
pub enum Route {
    #[at("/")]
    Home,
    #[at("/salon")]
    Salon,
    #[at("/serveur")]
    Server,
    #[at("/license")]
    License,
    #[not_found]
    #[at("/404")]
    NotFound,
}

fn switch(route: Route) -> Html {
    match route {
        Route::Home | Route::NotFound => html! { <HomePage /> },
        Route::Salon => html! { <SalonPage /> },
        Route::Server => html! { <ServerPage /> },
        Route::License => html! { <LicensePage /> },
    }
}

/// Défile en douceur jusqu'à une section de l'accueil (après le rendu).
pub fn scroll_to_section(id: &'static str) {
    Timeout::new(60, move || {
        if let Some(el) = gloo::utils::document().get_element_by_id(id) {
            let opts = ScrollIntoViewOptions::new();
            opts.set_behavior(ScrollBehavior::Smooth);
            el.scroll_into_view_with_scroll_into_view_options(&opts);
        }
    })
    .forget();
}

#[function_component(App)]
pub fn app() -> Html {
    let prefs = use_reducer_eq(Prefs::load);

    {
        let current = (*prefs).clone();
        use_effect_with(current, apply_to_document);
    }

    html! {
        <ContextProvider<UseReducerHandle<Prefs>> context={prefs}>
            <HashRouter>
                <Shell />
            </HashRouter>
        </ContextProvider<UseReducerHandle<Prefs>>>
    }
}

#[function_component(Shell)]
fn shell() -> Html {
    let route = use_route::<Route>();

    // À chaque changement de page, on repart du haut, et les nouveaux
    // éléments `.reveal` apparaîtront à leur entrée à l'écran.
    use_effect_with(route, |_| {
        gloo::utils::window().scroll_to_with_x_and_y(0.0, 0.0);
        Timeout::new(30, crate::fx::observe_reveals).forget();
    });

    html! {
        <>
            <Navbar />
            <main id="main" class="page">
                <Switch<Route> render={switch} />
            </main>
            <Footer />
        </>
    }
}

/// Trois sortes d'entrées : ancres de l'accueil, routes du site, liens externes.
enum NavItem {
    Section(&'static str, &'static str),
    Page(Route, &'static str),
    External(&'static str, &'static str),
}

const NAV_ITEMS: [NavItem; 7] = [
    NavItem::Section("features", "nav.features"),
    NavItem::Section("pricing", "nav.pricing"),
    NavItem::Section("doc", "nav.doc"),
    NavItem::Page(Route::Salon, "nav.salon"),
    NavItem::Page(Route::Server, "nav.server"),
    NavItem::External(BROCOLIS_URL, "nav.brocolis"),
    NavItem::External(REPO_URL, "nav.github"),
];

#[function_component(Navbar)]
fn navbar() -> Html {
    let prefs = use_prefs();
    let open = use_state_eq(|| false);
    let scrolled = use_state_eq(|| false);
    let navigator = use_navigator().expect("dans le routeur");
    let route = use_route::<Route>();

    // Ombre de la barre dès qu'on a défilé.
    {
        let scrolled = scrolled.clone();
        use_effect_with((), move |_| {
            let listener = EventListener::new(&gloo::utils::window(), "scroll", move |_| {
                let y = gloo::utils::window().scroll_y().unwrap_or(0.0);
                scrolled.set(y > 8.0);
            });
            move || drop(listener)
        });
    }

    // Échap ferme le menu mobile.
    {
        let open = open.clone();
        use_effect_with(*open, move |is_open| {
            let listener = is_open.then(|| {
                let open = open.clone();
                EventListener::new(&gloo::utils::document(), "keydown", move |e| {
                    if let Some(e) = e.dyn_ref::<KeyboardEvent>() {
                        if e.key() == "Escape" {
                            open.set(false);
                        }
                    }
                })
            });
            move || drop(listener)
        });
    }

    let close = {
        let open = open.clone();
        Callback::from(move |_: MouseEvent| open.set(false))
    };
    let toggle = {
        let open = open.clone();
        Callback::from(move |_: MouseEvent| open.set(!*open))
    };

    let items = NAV_ITEMS.iter().map(|item| match item {
        NavItem::Section(id, key) => {
            let id = *id;
            let open = open.clone();
            let navigator = navigator.clone();
            let on_home = matches!(route, Some(Route::Home) | Some(Route::NotFound));
            let onclick = Callback::from(move |e: MouseEvent| {
                e.prevent_default();
                open.set(false);
                if !on_home {
                    navigator.push(&Route::Home);
                }
                scroll_to_section(id);
            });
            html! { <li><a href={format!("#/{id}")} {onclick}>{ prefs.t(key) }</a></li> }
        }
        NavItem::Page(to, key) => {
            let active = route.as_ref() == Some(to);
            html! {
                <li onclick={close.clone()}>
                    <Link<Route> to={to.clone()} classes={classes!(active.then_some("active"))}>
                        { prefs.t(key) }
                    </Link<Route>>
                </li>
            }
        }
        NavItem::External(href, key) => html! {
            <li>
                <a href={*href} target="_blank" rel="noopener noreferrer" onclick={close.clone()}>
                    { prefs.t(key) }<span class="ext" aria-hidden="true">{ "↗" }</span>
                </a>
            </li>
        },
    });

    html! {
        <nav class={classes!("navbar", scrolled.then_some("scrolled"), open.then_some("is-open"))}>
            <div class="nav-inner">
                <span onclick={close.clone()}>
                    <Link<Route> to={Route::Home} classes="nav-brand">
                        <span class="nav-leaf" aria-hidden="true">{ "🥦" }</span>
                        <span>{ "Brocolis" }</span>
                        <span class="nav-brand-sub">{ "messageries" }</span>
                    </Link<Route>>
                </span>

                <button
                    type="button"
                    class={classes!("nav-toggle", open.then_some("open"))}
                    aria-label={prefs.t("nav.menu")}
                    aria-expanded={open.to_string()}
                    onclick={toggle}
                >
                    <span /><span /><span />
                </button>

                <div class={classes!("nav-drawer", open.then_some("open"))}>
                    <ul class="nav-links">{ for items }</ul>
                    <Switchers />
                </div>
            </div>
        </nav>
    }
}

#[function_component(Switchers)]
fn switchers() -> Html {
    let prefs = use_prefs();

    let langs = Lang::ALL.into_iter().map(|lang| {
        let active = prefs.lang == lang;
        let onclick = {
            let prefs = prefs.clone();
            Callback::from(move |_: MouseEvent| prefs.dispatch(PrefsAction::SetLang(lang)))
        };
        html! {
            <button type="button" class={classes!("pill", active.then_some("active"))}
                    aria-pressed={active.to_string()} {onclick}>
                { lang.code().to_uppercase() }
            </button>
        }
    });

    let themes = Theme::ALL.into_iter().map(|theme| {
        let active = prefs.theme == theme;
        let onclick = {
            let prefs = prefs.clone();
            Callback::from(move |_: MouseEvent| prefs.dispatch(PrefsAction::SetTheme(theme)))
        };
        html! {
            <button type="button" class={classes!("pill", active.then_some("active"))}
                    aria-pressed={active.to_string()} title={prefs.t(theme.label_key())}
                    aria-label={prefs.t(theme.label_key())} {onclick}>
                { theme.icon() }
            </button>
        }
    });

    html! {
        <div class="switchers">
            <div class="switcher" role="group" aria-label={prefs.t("switch.lang")}>{ for langs }</div>
            <div class="switcher" role="group" aria-label={prefs.t("switch.theme")}>{ for themes }</div>
        </div>
    }
}

#[function_component(Footer)]
fn footer() -> Html {
    let prefs = use_prefs();
    html! {
        <footer class="footer">
            <div class="footer-inner">
                <div class="footer-brand">
                    <span class="footer-leaf" aria-hidden="true">{ "🥦" }</span>
                    <p class="footer-tagline">{ prefs.t("footer.tagline") }</p>
                </div>
                <nav class="footer-links" aria-label={prefs.t("nav.menu")}>
                    <Link<Route> to={Route::Salon}>{ prefs.t("nav.salon") }</Link<Route>>
                    <Link<Route> to={Route::Server}>{ prefs.t("nav.server") }</Link<Route>>
                    <Link<Route> to={Route::License}>{ prefs.t("nav.license") }</Link<Route>>
                    <a href={REPO_URL} target="_blank" rel="noopener noreferrer">{ prefs.t("cta.repo") }</a>
                    <a href={BROCOLIS_URL} target="_blank" rel="noopener noreferrer">{ "brocolis" }</a>
                </nav>
                <p class="footer-meta">
                    <span class="footer-credit">{ prefs.t("footer.credit") }</span>
                    <span class="footer-stack">{ prefs.t("footer.stack") }</span>
                </p>
            </div>
        </footer>
    }
}
