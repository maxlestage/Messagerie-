//! Vitrine Brocolis 🥦 messageries — Rust + WebAssembly (Yew).

mod app;
mod config;
mod film;
mod fx;
mod i18n;
mod markdown;
mod pages;
mod prefs;

fn main() {
    // Monté dans #app : le rideau d'ouverture et le grain, posés à côté dans
    // index.html, restent en place.
    let root = gloo::utils::document()
        .get_element_by_id("app")
        .expect("<div id=\"app\"> dans index.html");
    yew::Renderer::<app::App>::with_root(root).render();
    // L'app est montée : on lève le rideau d'ouverture et on branche les effets.
    fx::lift_curtain();
    fx::install_pointer_effects();
}
