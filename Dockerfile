# Déploiement Heroku EN CONTENEUR — service messagerie Brocolis 🥦 en RUST
# (Actix + SeaORM). Remplace l'ancien serveur Node. Référencé par heroku.yml.
#
# Contexte de build = racine du dépôt. Deux étages de build :
#   1. site/   → vitrine React (Vite) compilée en statique (dist/)
#   2. server-rust/ → binaire Actix
# L'image finale sert l'API ET la vitrine (accueil, doc, Salon) à la racine.
# Persistance durable native : Postgres (add-on Heroku). Le serveur ne relaie
# que du chiffré.

# ── 1. Vitrine React (statique) ──────────────────────────────────────────────
FROM node:20-slim AS site
WORKDIR /site
# copy-readme.mjs (prebuild) recopie le README du dépôt : il faut donc le repo.
COPY site/package.json site/package-lock.json* ./
RUN npm ci
COPY README.md /README.md
COPY site/ ./
RUN npm run build

# ── 2. Binaire Rust ──────────────────────────────────────────────────────────
FROM rust:1-slim AS build
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
FROM debian:bookworm-slim
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
