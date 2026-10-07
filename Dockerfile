# Déploiement Heroku EN CONTENEUR — service messagerie Brocolis 🥦 en RUST
# (Actix + SeaORM). Remplace l'ancien serveur Node. Référencé par heroku.yml.
#
# Contexte de build = racine du dépôt. Deux étages de build :
#   1. site/   → vitrine Rust/WebAssembly (Yew) compilée par Trunk (dist/)
#   2. server-rust/ → binaire Actix
# L'image finale sert l'API ET la vitrine (accueil, doc, Salon) à la racine.
# Persistance durable native : Postgres (add-on Heroku). Le serveur ne relaie
# que du chiffré.

# ── 1. Vitrine Yew (statique) ────────────────────────────────────────────────
FROM rust:1-slim-trixie AS site
ARG TRUNK_VERSION=0.21.14
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add wasm32-unknown-unknown \
    && curl -sSfL "https://github.com/trunk-rs/trunk/releases/download/v${TRUNK_VERSION}/trunk-x86_64-unknown-linux-gnu.tar.gz" \
       | tar -xz -C /usr/local/bin trunk
WORKDIR /site
# index.html recopie ../README.md dans dist/ : il faut le README du dépôt.
COPY README.md /README.md
COPY site/ ./
RUN trunk build --release --locked

# ── 2. Binaire Rust ──────────────────────────────────────────────────────────
FROM rust:1-slim-trixie AS build
WORKDIR /app

# Outils de build pour les crates natives (ring, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config perl make \
    && rm -rf /var/lib/apt/lists/*

# Cache des dépendances : compile un projet vide (deps figées par Cargo.lock).
COPY server-rust/Cargo.toml server-rust/Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked || true

# Sources réelles puis build final.
COPY server-rust/src ./src
RUN touch src/main.rs && cargo build --release --locked

# ── 3. Image finale ──────────────────────────────────────────────────────────
# Même Debian que l'étage de build (glibc identique).
FROM debian:trixie-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/brocolis-messagerie /usr/local/bin/brocolis-messagerie
# Vitrine pré-construite, servie par le serveur à la racine.
COPY --from=site /site/dist /app/public
ENV PUBLIC_DIR=/app/public
ENV MESSAGE_RETENTION_DAYS=7
# Heroku fournit PORT et DATABASE_URL (Postgres). REDIS_URL / APNS_* optionnels.
CMD ["brocolis-messagerie"]
