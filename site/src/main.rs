//! Vitrine Brocolis 🥦 messageries — Rust + WebAssembly (Yew).

mod app;
mod config;
mod i18n;
mod markdown;
mod pages;
mod prefs;

fn main() {
    yew::Renderer::<app::App>::new().render();
    // L'app est montée : on retire l'écran d'attente.
    if let Some(splash) = gloo::utils::document().get_element_by_id("splash") {
        splash.remove();
    }
}
