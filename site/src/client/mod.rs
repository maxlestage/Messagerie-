//! Le code du navigateur (WebAssembly) : il hydrate les îlots avec Active,
//! puis démarre les animations de la page. Sans lui, le site reste lisible :
//! tout le contenu est dans le HTML envoyé par le serveur.

pub mod burst;
pub mod chat;
pub mod coffre;
pub mod film;
pub mod live;
pub mod motion;
pub mod rain;

use std::cell::RefCell;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{IntersectionObserver, IntersectionObserverEntry, IntersectionObserverInit};

use crate::i18n::Lang;

#[wasm_bindgen(start)]
pub fn start() {
    // Une adresse de l'ancien site (`/#/salon`) : on part vers la nouvelle.
    if let Some(target) = location_hash().and_then(|h| crate::routes::legacy_hash(page_lang(), &h))
    {
        let _ = window().location().replace(&target);
        return;
    }
    active::hydrate(&crate::islands::ISLANDS);
    motion::init();
    if let Some(film) = document().get_element_by_id("film") {
        film::start(film);
    }
    if let Ok(Some(canvas)) = document().query_selector(".hero-rain") {
        rain::start(canvas);
    }
    burst::init();
}

pub fn window() -> web_sys::Window {
    web_sys::window().expect("window")
}

pub fn document() -> web_sys::Document {
    window().document().expect("document")
}

pub fn root() -> web_sys::HtmlElement {
    document()
        .document_element()
        .expect("<html>")
        .unchecked_into()
}

fn location_hash() -> Option<String> {
    window().location().hash().ok().filter(|h| !h.is_empty())
}

pub fn matches(query: &str) -> bool {
    window()
        .match_media(query)
        .ok()
        .flatten()
        .is_some_and(|m| m.matches())
}

/// Le visiteur a demandé à réduire les animations.
pub fn reduced_motion() -> bool {
    matches("(prefers-reduced-motion: reduce)")
}

/// Une souris (et pas un écran tactile).
pub fn fine_pointer() -> bool {
    matches("(hover: hover) and (pointer: fine)")
}

/// La langue de la page (`<html lang>`).
pub fn page_lang() -> Lang {
    document()
        .document_element()
        .and_then(|h| h.get_attribute("lang"))
        .and_then(|l| Lang::parse(&l))
        .unwrap_or(Lang::Fr)
}

/// Le temps depuis le chargement, en millisecondes.
pub fn now() -> f64 {
    window().performance().map_or(0.0, |p| p.now())
}

/// Un nombre au hasard dans [0, 1).
pub fn random() -> f64 {
    js_sys::Math::random()
}

/// Écoute un événement pendant toute la vie de la page.
pub fn on<E: JsCast + 'static>(
    target: &web_sys::EventTarget,
    event: &str,
    f: impl FnMut(E) + 'static,
) {
    let mut f = f;
    let closure =
        Closure::<dyn FnMut(web_sys::Event)>::new(move |e: web_sys::Event| f(e.unchecked_into()));
    let _ = target.add_event_listener_with_callback(event, closure.as_ref().unchecked_ref());
    closure.forget();
}

/// Comme [`on`], avec `{ passive: true }` (défilement et pointeur).
pub fn on_passive<E: JsCast + 'static>(
    target: &web_sys::EventTarget,
    event: &str,
    f: impl FnMut(E) + 'static,
) {
    let mut f = f;
    let closure =
        Closure::<dyn FnMut(web_sys::Event)>::new(move |e: web_sys::Event| f(e.unchecked_into()));
    let options = web_sys::AddEventListenerOptions::new();
    options.set_passive(true);
    let _ = target.add_event_listener_with_callback_and_add_event_listener_options(
        event,
        closure.as_ref().unchecked_ref(),
        &options,
    );
    closure.forget();
}

type FrameCallback = Closure<dyn FnMut(f64)>;

/// Appelle `f(temps_ms)` à chaque image tant qu'elle renvoie `true`.
pub fn request_frame(f: impl FnMut(f64) -> bool + 'static) {
    let f = Rc::new(RefCell::new(f));
    let slot: Rc<RefCell<Option<FrameCallback>>> = Rc::new(RefCell::new(None));
    let again = slot.clone();
    *slot.borrow_mut() = Some(Closure::new(move |now: f64| {
        if (f.borrow_mut())(now) {
            if let Some(cb) = again.borrow().as_ref() {
                let _ = window().request_animation_frame(cb.as_ref().unchecked_ref());
            }
        } else {
            again.borrow_mut().take();
        }
    }));
    if let Some(cb) = slot.borrow().as_ref() {
        let _ = window().request_animation_frame(cb.as_ref().unchecked_ref());
    }
}

/// Tous les éléments qui correspondent à `selector`.
pub fn all(selector: &str) -> Vec<web_sys::HtmlElement> {
    let Ok(list) = document().query_selector_all(selector) else {
        return Vec::new();
    };
    (0..list.length())
        .filter_map(|i| list.item(i)?.dyn_into().ok())
        .collect()
}

/// Appelle `f` une fois, dans `ms` millisecondes.
pub fn later(ms: i32, f: impl FnOnce() + 'static) {
    let f = Closure::once_into_js(f);
    let _ = window().set_timeout_with_callback_and_timeout_and_arguments_0(f.unchecked_ref(), ms);
}

/// Appelle `f` toutes les `ms` millisecondes, pendant toute la vie de la page.
pub fn every(ms: i32, f: impl FnMut() + 'static) {
    let closure = Closure::<dyn FnMut()>::new(f);
    let _ = window().set_interval_with_callback_and_timeout_and_arguments_0(
        closure.as_ref().unchecked_ref(),
        ms,
    );
    closure.forget();
}

/// Appelle `f` une seule fois, quand `element` entre à l'écran.
pub fn when_visible(element: &web_sys::Element, threshold: f64, f: impl FnOnce() + 'static) {
    let f = RefCell::new(Some(f));
    let callback = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
        move |entries: js_sys::Array, observer: IntersectionObserver| {
            let visible = entries.iter().any(|e| {
                e.dyn_into::<IntersectionObserverEntry>()
                    .is_ok_and(|e| e.is_intersecting())
            });
            if visible {
                observer.disconnect();
                if let Some(f) = f.borrow_mut().take() {
                    f();
                }
            }
        },
    );
    let options = IntersectionObserverInit::new();
    options.set_threshold(&threshold.into());
    if let Ok(observer) =
        IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &options)
    {
        observer.observe(element);
    }
    callback.forget();
}

/// Écrit un cookie d'un an, pour tout le site.
pub fn set_cookie(name: &str, value: &str) {
    if let Ok(doc) = document().dyn_into::<web_sys::HtmlDocument>() {
        let _ = doc.set_cookie(&format!(
            "{name}={value}; Path=/; Max-Age=31536000; SameSite=Lax"
        ));
    }
}

/// Le localStorage, s'il est disponible.
pub fn storage() -> Option<web_sys::Storage> {
    window().local_storage().ok().flatten()
}
