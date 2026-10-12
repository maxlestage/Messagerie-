//! Les animations que le CSS ne sait pas faire seul : rideau d'ouverture,
//! apparitions au défilement, titres qui se déchiffrent, compteurs, barre de
//! progression, navigation qui se cache, parallaxe, curseur, boutons aimantés,
//! cartes inclinées avec reflet, ondes au clic, transitions entre les pages,
//! changement de thème en cercle qui s'ouvre, menu, README dépliable.
//! Tout se dégrade en page statique, et `prefers-reduced-motion` coupe le
//! superflu.

use std::cell::Cell;
use std::rc::Rc;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use web_sys::{
    Element, HtmlElement, IntersectionObserver, IntersectionObserverEntry, IntersectionObserverInit,
};

use super::{
    all, document, fine_pointer, later, now, on, on_passive, random, reduced_motion, request_frame,
    root, set_cookie, storage, window,
};
use crate::{LANG_COOKIE, THEME_COOKIE};

pub fn init() {
    curtain();
    reveals();
    scroll_effects();
    menu();
    themes();
    languages();
    readme();
    ripples();
    page_transitions();
    if fine_pointer() && !reduced_motion() {
        if let Some(body) = document().body() {
            let _ = body.class_list().add_1("has-cursor");
        }
        cursor();
        magnetic();
        tilt();
        hover_scramble();
        parallax();
    }
}

fn set(el: &HtmlElement, name: &str, value: &str) {
    let _ = el.style().set_property(name, value);
}

fn viewport() -> (f64, f64) {
    let win = window();
    let size = |v: Result<JsValue, JsValue>| v.ok().and_then(|v| v.as_f64()).unwrap_or(0.0);
    (size(win.inner_width()), size(win.inner_height()))
}

fn scroll_y() -> f64 {
    window().scroll_y().unwrap_or(0.0)
}

// ── Rideau d'ouverture ────────────────────────────────────────────────────────

/// Le CSS lève déjà le rideau seul ; ici on le retire du document une fois
/// levé (et plus tôt si le visiteur réduit les animations).
fn curtain() {
    let Some(curtain) = document().get_element_by_id("splash") else {
        return;
    };
    let wait = if reduced_motion() {
        0.0
    } else {
        (1500.0 - now()).max(0.0)
    };
    later(wait as i32, move || {
        let _ = curtain.class_list().add_1("done");
        later(1000, move || curtain.remove());
    });
}

// ── Apparitions ───────────────────────────────────────────────────────────────

fn in_view(el: &Element) -> bool {
    let r = el.get_bounding_client_rect();
    let (_, h) = viewport();
    r.top() < h && r.bottom() > 0.0
}

/// Ce qui arrive quand un élément `.reveal` entre à l'écran.
fn arrive(el: &Element) {
    let _ = el.class_list().add_1("in");
    // Les titres et les chiffres de l'élément se déchiffrent.
    if el.has_attribute("data-scramble") {
        scramble_text(el);
    }
    if let Ok(list) = el.query_selector_all("[data-scramble]") {
        for i in 0..list.length() {
            if let Some(child) = list.item(i).and_then(|n| n.dyn_into::<Element>().ok()) {
                scramble_text(&child);
            }
        }
    }
    if let Ok(list) = el.query_selector_all("[data-count]") {
        for i in 0..list.length() {
            if let Some(child) = list.item(i).and_then(|n| n.dyn_into::<Element>().ok()) {
                count_up(&child, 1300.0);
            }
        }
    }
}

/// Les éléments `.reveal` montent en se dévoilant quand ils entrent à l'écran.
/// Ceux déjà visibles sont marqués avant que le CSS ne cache les autres : rien
/// ne clignote.
fn reveals() {
    let items = all(".reveal");
    for el in &items {
        if in_view(el) {
            let _ = el.class_list().add_1("in");
        }
    }
    let _ = root().class_list().add_1("anim");
    if reduced_motion() {
        for el in &items {
            let _ = el.class_list().add_1("in");
        }
        return;
    }
    let callback = Closure::<dyn Fn(js_sys::Array, IntersectionObserver)>::new(
        |entries: js_sys::Array, io: IntersectionObserver| {
            for entry in entries.iter() {
                let Ok(entry) = entry.dyn_into::<IntersectionObserverEntry>() else {
                    continue;
                };
                if entry.is_intersecting() {
                    let target = entry.target();
                    arrive(&target);
                    io.unobserve(&target);
                }
            }
        },
    );
    let options = IntersectionObserverInit::new();
    options.set_root_margin("0px 0px -8% 0px");
    if let Ok(io) =
        IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &options)
    {
        for el in items {
            if el.class_list().contains("in") {
                // Déjà à l'écran : ses chiffres défilent quand même.
                arrive(&el);
            } else {
                io.observe(&el);
            }
        }
        // Les chiffres du héros (hors `.reveal`) se déchiffrent à l'ouverture.
        let delay = if root().class_list().contains("intro") {
            1700
        } else {
            500
        };
        later(delay, || {
            for el in all(".stats [data-scramble]") {
                scramble_text(&el);
            }
        });
    }
    callback.forget();
}

// ── Texte qui se déchiffre ────────────────────────────────────────────────────

const GLYPHS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=#%&";

fn glyph() -> char {
    GLYPHS[(random() * GLYPHS.len() as f64) as usize % GLYPHS.len()] as char
}

/// Brouille le texte de `el`, puis le révèle de gauche à droite en
/// `duration` ms, jusqu'à `final_text`.
pub fn scramble(el: &Element, final_text: &str, duration: f64) {
    if reduced_motion() || el.has_attribute("data-scrambling") {
        return;
    }
    let chars: Vec<char> = final_text.chars().collect();
    let total = chars.len().max(1) as f64;
    let target = final_text.to_owned();
    let el = el.clone();
    let _ = el.set_attribute("data-scrambling", "");
    let start = now();
    let mut last_draw = 0.0;
    request_frame(move |t| {
        let p = ((t - start) / duration).clamp(0.0, 1.0);
        if p >= 1.0 {
            el.set_text_content(Some(&target));
            let _ = el.remove_attribute("data-scrambling");
            return false;
        }
        if t - last_draw < 45.0 {
            return true; // ~22 images/s : le brouillage reste lisible
        }
        last_draw = t;
        let shown = (p * p * total) as usize;
        let text: String = chars
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i < shown || c.is_whitespace() {
                    *c
                } else {
                    glyph()
                }
            })
            .collect();
        el.set_text_content(Some(&text));
        true
    });
}

/// Déchiffre le texte actuel de `el` (titres, chiffres clés, 404).
fn scramble_text(el: &Element) {
    // Seulement un texte simple : on ne touche pas aux éléments qui ont des enfants.
    if el.child_element_count() > 0 {
        return;
    }
    let text = el.text_content().unwrap_or_default();
    if !text.trim().is_empty() {
        let duration = (text.chars().count() as f64 * 35.0).clamp(500.0, 1100.0);
        scramble(el, &text, duration);
    }
}

/// Au survol, les liens de la navigation se brouillent un instant.
fn hover_scramble() {
    for el in all(".nav-links a[data-scramble]") {
        let target = el.clone();
        on::<web_sys::Event>(&el, "mouseenter", move |_| scramble_text(&target));
    }
}

// ── Compteurs ─────────────────────────────────────────────────────────────────

/// Fait défiler le nombre de `el` depuis zéro.
pub fn count_up(el: &Element, duration: f64) {
    if reduced_motion() {
        return;
    }
    let original = el.text_content().unwrap_or_default();
    let Some((before, value, decimals, sep, after)) = crate::islands::parse_number(&original)
    else {
        return;
    };
    let el = el.clone();
    let start = now();
    request_frame(move |t| {
        let p = ((t - start) / duration).clamp(0.0, 1.0);
        if p >= 1.0 {
            el.set_text_content(Some(&original));
            return false;
        }
        let eased = 1.0 - 2f64.powf(-10.0 * p);
        let n = format!("{:.*}", decimals, value * eased).replace('.', &sep.to_string());
        el.set_text_content(Some(&format!("{before}{n}{after}")));
        true
    });
}

// ── Défilement : progression, navigation, retour en haut ─────────────────────

fn scroll_effects() {
    let progress = document()
        .get_element_by_id("progress")
        .and_then(|e| e.dyn_into::<HtmlElement>().ok());
    let navbar = document().get_element_by_id("navbar");
    let to_top = all(".to-top").into_iter().next();
    if let Some(button) = &to_top {
        on::<web_sys::Event>(button, "click", |_| {
            let options = web_sys::ScrollToOptions::new();
            options.set_top(0.0);
            options.set_behavior(web_sys::ScrollBehavior::Smooth);
            window().scroll_to_with_scroll_to_options(&options);
        });
    }
    let last = Rc::new(Cell::new(scroll_y()));
    let pending = Rc::new(Cell::new(false));
    let update = {
        let last = last.clone();
        move || {
            let y = scroll_y();
            let (_, vh) = viewport();
            let height = document()
                .document_element()
                .map_or(1.0, |d| d.scroll_height() as f64);
            let p = (y / (height - vh).max(1.0)).clamp(0.0, 1.0);
            if let Some(bar) = &progress {
                set(bar, "transform", &format!("scaleX({p:.4})"));
            }
            if let Some(nav) = &navbar {
                let list = nav.class_list();
                let _ = list.toggle_with_force("scrolled", y > 8.0);
                // La barre se cache en descendant, revient en remontant.
                let open = root().class_list().contains("menu-open");
                let down = y > last.get() + 4.0;
                let up = y < last.get() - 4.0;
                if !open && down && y > 320.0 {
                    let _ = list.add_1("nav-hidden");
                } else if up || y < 320.0 {
                    let _ = list.remove_1("nav-hidden");
                }
            }
            if let Some(button) = &to_top {
                let _ = button.class_list().toggle_with_force("show", y > 700.0);
            }
            last.set(y);
        }
    };
    update();
    let update = Rc::new(update);
    on_passive::<web_sys::Event>(&window(), "scroll", move |_| {
        if pending.replace(true) {
            return;
        }
        let update = update.clone();
        let pending = pending.clone();
        request_frame(move |_| {
            pending.set(false);
            update();
            false
        });
    });
}

// ── Parallaxe : les taches du héros suivent le défilement et la souris ────────

fn parallax() {
    let blobs = all("[data-speed]");
    let logo = all(".logo-wrap").into_iter().next();
    if blobs.is_empty() {
        return;
    }
    let pointer = Rc::new(Cell::new((0.0, 0.0)));
    {
        let pointer = pointer.clone();
        on_passive::<web_sys::PointerEvent>(&window(), "pointermove", move |e| {
            let (w, h) = viewport();
            pointer.set((
                e.client_x() as f64 / w.max(1.0) - 0.5,
                e.client_y() as f64 / h.max(1.0) - 0.5,
            ));
        });
    }
    let mut eased = (0.0, 0.0);
    request_frame(move |_| {
        let y = scroll_y();
        let (_, vh) = viewport();
        if y < vh * 1.5 {
            let (px, py) = pointer.get();
            eased.0 += (px - eased.0) * 0.06;
            eased.1 += (py - eased.1) * 0.06;
            for blob in &blobs {
                let speed: f64 = blob
                    .get_attribute("data-speed")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0.0);
                set(
                    blob,
                    "transform",
                    &format!(
                        "translate3d({:.1}px, {:.1}px, 0)",
                        eased.0 * 120.0 * speed * 4.0,
                        y * speed + eased.1 * 90.0 * speed * 4.0
                    ),
                );
            }
            if let Some(logo) = &logo {
                set(
                    logo,
                    "--tilt",
                    &format!(
                        "rotateY({:.2}deg) rotateX({:.2}deg)",
                        eased.0 * 24.0,
                        -eased.1 * 24.0
                    ),
                );
            }
        }
        true
    });
}

// ── Curseur, aimants, cartes inclinées ────────────────────────────────────────

/// Un anneau qui suit la souris avec un léger retard, un point qui la suit
/// exactement ; l'anneau grossit sur ce qui se clique.
fn cursor() {
    let doc = document();
    let make = |class: &str| -> Option<HtmlElement> {
        let el = doc.create_element("div").ok()?;
        el.set_class_name(class);
        let _ = el.set_attribute("aria-hidden", "true");
        doc.body()?.append_child(&el).ok()?;
        el.dyn_into().ok()
    };
    let (Some(ring), Some(dot)) = (make("cursor"), make("cursor-dot")) else {
        return;
    };
    let target = Rc::new(Cell::new((-100.0, -100.0)));
    {
        let target = target.clone();
        let ring = ring.clone();
        let dot = dot.clone();
        on_passive::<web_sys::PointerEvent>(&window(), "pointermove", move |e| {
            if e.pointer_type() != "mouse" {
                return;
            }
            let (x, y) = (e.client_x() as f64, e.client_y() as f64);
            target.set((x, y));
            set(&dot, "transform", &format!("translate3d({x}px, {y}px, 0)"));
            let _ = ring.class_list().add_1("live");
            let _ = dot.class_list().add_1("live");
            let hit = e
                .target()
                .and_then(|t| t.dyn_into::<Element>().ok())
                .and_then(|t| {
                    t.closest("a, button, .pill, input, textarea, label, [data-burst]")
                        .ok()
                        .flatten()
                });
            let _ = ring.class_list().toggle_with_force("hover", hit.is_some());
        });
    }
    {
        let ring = ring.clone();
        on::<web_sys::Event>(&document(), "mousedown", move |_| {
            let _ = ring.class_list().add_1("press");
        });
    }
    {
        let ring = ring.clone();
        on::<web_sys::Event>(&document(), "mouseup", move |_| {
            let _ = ring.class_list().remove_1("press");
        });
    }
    {
        let (ring, dot) = (ring.clone(), dot.clone());
        on::<web_sys::Event>(&document(), "mouseleave", move |_| {
            let _ = ring.class_list().remove_1("live");
            let _ = dot.class_list().remove_1("live");
        });
    }
    let mut pos = (-100.0, -100.0);
    request_frame(move |_| {
        let (tx, ty) = target.get();
        pos.0 += (tx - pos.0) * 0.2;
        pos.1 += (ty - pos.1) * 0.2;
        set(
            &ring,
            "transform",
            &format!("translate3d({:.1}px, {:.1}px, 0)", pos.0, pos.1),
        );
        true
    });
}

/// Les boutons glissent vers le pointeur quand il s'approche.
fn magnetic() {
    for el in all(".btn, .nav-toggle, .to-top, .pill") {
        let strength = if el.class_list().contains("pill") {
            0.18
        } else {
            0.3
        };
        let target = el.clone();
        on::<web_sys::PointerEvent>(&el, "pointermove", move |e| {
            let r = target.get_bounding_client_rect();
            let dx = (e.client_x() as f64 - (r.left() + r.width() / 2.0)) * strength;
            let dy = (e.client_y() as f64 - (r.top() + r.height() / 2.0)) * strength * 1.3;
            set(&target, "--mx", &format!("{dx:.1}px"));
            set(&target, "--my", &format!("{dy:.1}px"));
        });
        let target = el.clone();
        on::<web_sys::Event>(&el, "pointerleave", move |_| {
            let _ = target.style().remove_property("--mx");
            let _ = target.style().remove_property("--my");
        });
    }
}

/// Les cartes `.tilt` s'inclinent vers le pointeur, et un reflet le suit.
fn tilt() {
    for el in all(".tilt") {
        let target = el.clone();
        on::<web_sys::PointerEvent>(&el, "pointermove", move |e| {
            let r = target.get_bounding_client_rect();
            let x = (e.client_x() as f64 - r.left()) / r.width().max(1.0);
            let y = (e.client_y() as f64 - r.top()) / r.height().max(1.0);
            set(&target, "--rx", &format!("{:.2}deg", (0.5 - y) * 10.0));
            set(&target, "--ry", &format!("{:.2}deg", (x - 0.5) * 12.0));
            set(&target, "--sx", &format!("{:.1}%", x * 100.0));
            set(&target, "--sy", &format!("{:.1}%", y * 100.0));
            let _ = target.class_list().add_1("tilting");
        });
        let target = el.clone();
        on::<web_sys::Event>(&el, "pointerleave", move |_| {
            for p in ["--rx", "--ry"] {
                let _ = target.style().remove_property(p);
            }
            let _ = target.class_list().remove_1("tilting");
        });
    }
}

// ── Ondes au clic (aussi au toucher) ──────────────────────────────────────────

fn ripples() {
    on::<web_sys::PointerEvent>(&document(), "pointerdown", |e| {
        let Some(btn) = e
            .target()
            .and_then(|t| t.dyn_into::<Element>().ok())
            .and_then(|t| t.closest(".btn, .pill, .toggle").ok().flatten())
        else {
            return;
        };
        if reduced_motion() {
            return;
        }
        let r = btn.get_bounding_client_rect();
        let Ok(wave) = document().create_element("span") else {
            return;
        };
        wave.set_class_name("ripple");
        let size = r.width().max(r.height()) * 2.2;
        let _ = wave.set_attribute(
            "style",
            &format!(
                "width:{size:.0}px;height:{size:.0}px;left:{:.0}px;top:{:.0}px",
                e.client_x() as f64 - r.left() - size / 2.0,
                e.client_y() as f64 - r.top() - size / 2.0
            ),
        );
        let _ = btn.append_child(&wave);
        later(650, move || wave.remove());
    });
}

// ── Menu (téléphone et tablette) ──────────────────────────────────────────────

fn menu() {
    let Some(toggle) = all(".nav-toggle").into_iter().next() else {
        return;
    };
    let drawer = document().get_element_by_id("nav-drawer");
    let set_open = {
        let toggle = toggle.clone();
        move |open: bool| {
            let _ = toggle.set_attribute("aria-expanded", &open.to_string());
            let _ = toggle.class_list().toggle_with_force("open", open);
            if let Some(d) = &drawer {
                let _ = d.class_list().toggle_with_force("open", open);
            }
            let _ = root().class_list().toggle_with_force("menu-open", open);
        }
    };
    let set_open = Rc::new(set_open);
    {
        let set_open = set_open.clone();
        let t = toggle.clone();
        on::<web_sys::Event>(&toggle, "click", move |_| {
            set_open(t.get_attribute("aria-expanded").as_deref() != Some("true"));
        });
    }
    {
        let set_open = set_open.clone();
        on::<web_sys::KeyboardEvent>(&document(), "keydown", move |e| {
            if e.key() == "Escape" {
                set_open(false);
            }
        });
    }
    for link in all(".nav-drawer a") {
        let set_open = set_open.clone();
        on::<web_sys::Event>(&link, "click", move |_| set_open(false));
    }
}

// ── Thèmes et langues ─────────────────────────────────────────────────────────

fn apply_theme(code: &'static str) {
    let _ = root().set_attribute("data-theme", code);
    for b in all("[data-theme-set]") {
        let on = b.get_attribute("data-theme-set").as_deref() == Some(code);
        let _ = b.class_list().toggle_with_force("active", on);
        let _ = b.set_attribute("aria-pressed", &on.to_string());
    }
    let bar = match code {
        "dark" => "#0b110d",
        "light" => "#ffffff",
        _ => "#e9f4ec",
    };
    for meta in all(r#"meta[name="theme-color"]"#) {
        let _ = meta.set_attribute("content", bar);
    }
    set_cookie(THEME_COOKIE, code);
}

/// Change de thème ; avec les « View Transitions », le nouveau thème s'ouvre
/// en cercle depuis le bouton touché.
fn switch_theme(code: &'static str, x: f64, y: f64) {
    let doc = document();
    let start = js_sys::Reflect::get(&doc, &JsValue::from_str("startViewTransition"))
        .ok()
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok());
    let Some(start) = start.filter(|_| !reduced_motion()) else {
        apply_theme(code);
        return;
    };
    let (w, h) = viewport();
    let radius = (x.max(w - x).powi(2) + y.max(h - y).powi(2)).sqrt();
    let html = root();
    set(&html, "--vt-x", &format!("{x:.0}px"));
    set(&html, "--vt-y", &format!("{y:.0}px"));
    set(&html, "--vt-r", &format!("{radius:.0}px"));
    let update = Closure::once_into_js(move || apply_theme(code));
    let _ = start.call1(&doc, &update);
}

fn themes() {
    // L'ancienne vitrine gardait le thème dans le localStorage.
    let chosen = document()
        .dyn_into::<web_sys::HtmlDocument>()
        .ok()
        .and_then(|d| d.cookie().ok())
        .unwrap_or_default()
        .contains(THEME_COOKIE);
    let old = storage()
        .and_then(|s| s.get_item("messagerie.theme").ok().flatten())
        .and_then(|t| crate::theme(&t));
    if let (false, Some(code)) = (chosen, old) {
        apply_theme(code);
    }
    for b in all("[data-theme-set]") {
        let Some(code) = b
            .get_attribute("data-theme-set")
            .as_deref()
            .and_then(crate::theme)
        else {
            continue;
        };
        on::<web_sys::MouseEvent>(&b, "click", move |e| {
            switch_theme(code, e.client_x() as f64, e.client_y() as f64);
        });
    }
}

fn languages() {
    for a in all("[data-lang]") {
        let code = a.get_attribute("data-lang").unwrap_or_default();
        on::<web_sys::Event>(&a, "click", move |_| set_cookie(LANG_COOKIE, &code));
    }
}

// ── README dépliable ──────────────────────────────────────────────────────────

fn readme() {
    let (Some(button), Some(boxed)) = (
        all(".readme-toggle").into_iter().next(),
        document().get_element_by_id("readme"),
    ) else {
        return;
    };
    let b = button.clone();
    on::<web_sys::Event>(&button, "click", move |_| {
        let open = !boxed.class_list().contains("open");
        let _ = boxed.class_list().toggle_with_force("open", open);
        let _ = b.set_attribute("aria-expanded", &open.to_string());
        let label = b
            .get_attribute(if open { "data-less" } else { "data-more" })
            .unwrap_or_default();
        b.set_text_content(Some(&label));
        if !open {
            boxed.scroll_into_view();
        }
    });
}

// ── Transitions entre les pages ───────────────────────────────────────────────

/// Un lien vers une autre page du site : un voile vert passe, puis la page
/// suivante arrive en fondu (CSS).
fn page_transitions() {
    if reduced_motion() {
        return;
    }
    on::<web_sys::MouseEvent>(&document(), "click", |e| {
        if e.default_prevented()
            || e.button() != 0
            || e.meta_key()
            || e.ctrl_key()
            || e.shift_key()
            || e.alt_key()
        {
            return;
        }
        let Some(link) = e
            .target()
            .and_then(|t| t.dyn_into::<Element>().ok())
            .and_then(|t| t.closest("a[href]").ok().flatten())
            .and_then(|a| a.dyn_into::<web_sys::HtmlAnchorElement>().ok())
        else {
            return;
        };
        if link.target() == "_blank" || link.has_attribute("download") {
            return;
        }
        let here = window().location();
        let same_origin = here.origin().ok() == Some(link.origin());
        let same_page = here.pathname().ok() == Some(link.pathname())
            && here.search().ok() == Some(link.search());
        if !same_origin || same_page {
            return;
        }
        e.prevent_default();
        let href = link.href();
        let _ = root().class_list().add_1("leaving");
        later(380, move || {
            let _ = window().location().assign(&href);
        });
    });
    // Retour arrière (cache du navigateur) : la page revient sans voile.
    on::<web_sys::Event>(&window(), "pageshow", |_| {
        let _ = root().class_list().remove_1("leaving");
    });
}
