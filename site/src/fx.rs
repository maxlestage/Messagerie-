//! Effets d'interface : rideau d'ouverture, curseur qui suit, boutons aimantés,
//! apparitions au défilement. Tous s'effacent avec `prefers-reduced-motion`,
//! et le curseur comme l'aimant n'existent qu'avec une souris.

use gloo::events::EventListener;
use gloo::timers::callback::Timeout;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{Element, HtmlElement, IntersectionObserver, IntersectionObserverEntry};

fn matches(query: &str) -> bool {
    gloo::utils::window()
        .match_media(query)
        .ok()
        .flatten()
        .is_some_and(|m| m.matches())
}

fn calm() -> bool {
    matches("(prefers-reduced-motion: reduce)")
}

/// Lève le rideau d'ouverture (posé dans index.html), puis le retire. Il reste
/// au moins ~1,3 s, le temps que la marque se trace (sauf mouvement réduit).
pub fn lift_curtain() {
    let elapsed = gloo::utils::window()
        .performance()
        .map(|p| p.now())
        .unwrap_or(0.0);
    let wait = if calm() {
        0.0
    } else {
        (1300.0 - elapsed).max(0.0)
    };
    Timeout::new(wait as u32, raise).forget();
}

fn raise() {
    let doc = gloo::utils::document();
    if let Some(root) = doc.document_element() {
        let _ = root.class_list().add_1("ready");
    }
    if let Some(curtain) = doc.get_element_by_id("splash") {
        let _ = curtain.class_list().add_1("done");
        Timeout::new(900, move || curtain.remove()).forget();
    }
}

/// Curseur en anneau qui suit la souris avec un léger retard, et grossit sur
/// ce qui se clique. Les boutons `.btn` sont aimantés : ils glissent vers le
/// pointeur. Rien de tout ça sur écran tactile.
pub fn install_pointer_effects() {
    if calm() || !matches("(hover: hover) and (pointer: fine)") {
        return;
    }
    let doc = gloo::utils::document();
    let Ok(ring) = doc.create_element("div") else {
        return;
    };
    ring.set_class_name("cursor");
    let _ = ring.set_attribute("aria-hidden", "true");
    if let Some(body) = doc.body() {
        let _ = body.append_child(&ring);
    }
    let Ok(ring) = ring.dyn_into::<HtmlElement>() else {
        return;
    };

    let listener = EventListener::new(&gloo::utils::window(), "pointermove", move |e| {
        let Some(e) = e.dyn_ref::<web_sys::PointerEvent>() else {
            return;
        };
        if e.pointer_type() != "mouse" {
            return;
        }
        let (x, y) = (e.client_x() as f64, e.client_y() as f64);
        let style = ring.style();
        let _ = style.set_property("transform", &format!("translate3d({x}px, {y}px, 0)"));
        let _ = ring.class_list().add_1("live");

        let target = e.target().and_then(|t| t.dyn_into::<Element>().ok());
        let clickable = target
            .as_ref()
            .and_then(|t| t.closest("a, button, .pill, input, label").ok().flatten());
        let _ = ring
            .class_list()
            .toggle_with_force("hover", clickable.is_some());

        // Aimant : le bouton se décale vers le pointeur (au plus ~25 % de l'écart).
        if let Some(btn) = target
            .and_then(|t| t.closest(".btn, .nav-toggle").ok().flatten())
            .and_then(|b| b.dyn_into::<HtmlElement>().ok())
        {
            let r = btn.get_bounding_client_rect();
            let dx = (x - (r.left() + r.width() / 2.0)) * 0.25;
            let dy = (y - (r.top() + r.height() / 2.0)) * 0.35;
            let _ = btn.style().set_property("--mx", &format!("{dx:.1}px"));
            let _ = btn.style().set_property("--my", &format!("{dy:.1}px"));
            let _ = btn.set_attribute("data-magnet", "");
        }
        // Les autres boutons aimantés reviennent en place.
        if let Ok(list) = gloo::utils::document().query_selector_all("[data-magnet]") {
            for i in 0..list.length() {
                let Some(el) = list.item(i).and_then(|n| n.dyn_into::<HtmlElement>().ok()) else {
                    continue;
                };
                let r = el.get_bounding_client_rect();
                let inside = x >= r.left() - 24.0
                    && x <= r.right() + 24.0
                    && y >= r.top() - 24.0
                    && y <= r.bottom() + 24.0;
                if !inside {
                    let _ = el.style().remove_property("--mx");
                    let _ = el.style().remove_property("--my");
                    let _ = el.remove_attribute("data-magnet");
                }
            }
        }
    });
    listener.forget(); // vit aussi longtemps que la page
}

/// Fait apparaître en douceur les éléments `.reveal` quand ils entrent à
/// l'écran (une seule fois). À rappeler après chaque rendu de page.
pub fn observe_reveals() {
    let doc = gloo::utils::document();
    let Ok(list) = doc.query_selector_all(".reveal:not(.in)") else {
        return;
    };
    if calm() {
        for i in 0..list.length() {
            if let Some(el) = list.item(i).and_then(|n| n.dyn_into::<Element>().ok()) {
                let _ = el.class_list().add_1("in");
            }
        }
        return;
    }
    let callback = Closure::<dyn FnMut(js_sys::Array, IntersectionObserver)>::new(
        |entries: js_sys::Array, observer: IntersectionObserver| {
            for entry in entries.iter() {
                let Ok(entry) = entry.dyn_into::<IntersectionObserverEntry>() else {
                    continue;
                };
                if entry.is_intersecting() {
                    let target = entry.target();
                    let _ = target.class_list().add_1("in");
                    observer.unobserve(&target);
                }
            }
        },
    );
    let options = web_sys::IntersectionObserverInit::new();
    options.set_root_margin("0px 0px -8% 0px");
    let Ok(observer) =
        IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &options)
    else {
        return;
    };
    callback.forget();
    for i in 0..list.length() {
        if let Some(el) = list.item(i).and_then(|n| n.dyn_into::<Element>().ok()) {
            observer.observe(&el);
        }
    }
}
