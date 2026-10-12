# Vitrine Brocolis 🥦 — Rust avec Active

| Outil | Rôle |
|---|---|
| [Active](https://maxlestage.github.io/Active/) | pages rendues par le serveur (SEO complet), îlots hydratés en WebAssembly |
| [Vitesse](https://maxlestage.github.io/Vitesse/) | le serveur qui sert les pages (dans `../server-rust`, à côté de l'API) |
| wasm-bindgen 0.2.129 | le pont entre le WebAssembly et le navigateur |
| pulldown-cmark 0.13 | le README du dépôt, rendu en HTML sur l'accueil |

Le site est en français, anglais et espagnol (`/fr/`, `/en/`, `/es/`), avec
quatre pages : accueil, Salon, Serveur, Licence. Sans WebAssembly, tout reste
lisible : le contenu est dans le HTML.

## Ce qui bouge

- **rideau d'ouverture** (première page de la visite) : la marque se trace, un
  compteur monte, le rideau se lève — en CSS, même sans WebAssembly ;
- **pluie de chiffré** derrière le héros (canvas) : près du pointeur, les
  caractères s'illuminent et des 🥦 apparaissent ;
- **film de grains** (WebGL) : des milliers de particules se recomposent d'une
  forme à l'autre au fil du défilement, avec son fil de progression ;
- **démo** « ce que tu écris, ce que voit l'app » (îlot) : les `((secrets))`
  se brouillent en jetons `[[BROCOLIS:v1:…]]` pendant la frappe ;
- **schéma d'appairage** animé : les clés publiques voyagent, la clé secrète
  apparaît des deux côtés sans passer par le fil ;
- **salon en direct** (îlot) : radar, participants qui arrivent avec un visage
  tiré de leur clé publique, lien partageable `?code=…` ;
- **serveur en direct** (îlot) : latence et son graphique, chiffres publics qui
  défilent, horloge « en ligne depuis » ;
- titres qui se **déchiffrent**, mots qui montent, **compteurs** de prix,
  bandeau qui défile, mots qui tournent, cartes **inclinées** avec reflet,
  boutons **aimantés**, ondes au clic, **curseur**, barre de progression,
  navigation qui se cache, **transitions entre pages**, **thème** qui s'ouvre en
  cercle, **gerbe de 🥦** sur le logo, 404 qui « glitche ».

Tout respecte `prefers-reduced-motion`.

## Lancer

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129   # la version de Cargo.lock
# 1. Le code du navigateur → site/pkg
cargo build --lib --target wasm32-unknown-unknown --profile wasm-release
wasm-bindgen --target web --no-typescript --out-dir pkg target/wasm32-unknown-unknown/wasm-release/brocolis_site.wasm
# 2. Le serveur (API + pages), sur http://localhost:8788
cd ../server-rust && cargo run
cargo test   # ici : textes FR/EN/ES, adresses, démo, rendu de chaque page
```

## Organisation

- `src/i18n.rs` — textes FR / EN / ES (les tests vérifient les mêmes clés)
- `src/routes.rs` — les adresses, et la traduction des anciennes (`#/salon`…)
- `src/islands.rs` — les îlots : démo, salon, état du serveur
- `src/demo.rs` — la découpe `((secrets))` et les jetons factices de la démo
- `src/server/` — rendu des pages (Active) et routes ajoutées à l'app Vitesse
- `src/client/` — le code du navigateur : hydratation, animations, film WebGL,
  pluie de chiffré, gerbe de 🥦, appels au serveur
- `assets/` — feuille de style (thèmes vert / clair / sombre) et logo
