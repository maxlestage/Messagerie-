# Vitrine Brocolis 🥦 — Rust + WebAssembly (Yew)

| Outil | Version |
|---|---|
| Rust (stable) | 1.99 — édition 2024 |
| [Yew](https://yew.rs) | 0.23 (rendu côté client) |
| yew-router | 0.20 (`HashRouter`) |
| [Trunk](https://trunk-rs.github.io/trunk/) | 0.21.14 |
| wasm-bindgen | 0.2.129 · wasm-opt (binaryen) version_133 |
| pulldown-cmark | 0.13 (rendu du README) |

## Lancer

```sh
rustup target add wasm32-unknown-unknown
cargo install --locked trunk   # ou le binaire des releases GitHub
trunk serve                    # http://localhost:8080
trunk build --release          # → dist/
cargo test                     # dictionnaire FR/EN/ES, rendu Markdown
```

`index.html` recopie `../README.md` et `public/photo.png` dans `dist/`. Les
chemins sont relatifs (`public_url = "./"`) : la même sortie sert sur GitHub
Pages (`/Messagerie-/`), sur le serveur Heroku (`/` et `/site/`) et en local.

## Organisation

- `src/app.rs` — routes (`#/`, `#/salon`, `#/serveur`, `#/license`), barre de
  navigation, sélecteurs langue/thème, pied de page
- `src/pages/` — accueil (héros, fonctionnalités, formules, README), Salon,
  Serveur, Licence
- `src/i18n.rs` — textes FR / EN / ES (les tests vérifient que les trois
  langues ont les mêmes clés)
- `src/prefs.rs` — langue et thème, mémorisés dans le localStorage
- `src/markdown.rs` — README → HTML (liens relatifs vers GitHub, HTML brut
  échappé)
- `src/config.rs` — adresses (dépôt, serveur de rendez-vous)
- `style.css` — thèmes vert / clair / sombre
