# Déploiement Heroku EN CONTENEUR — service messagerie Brocolis 🥦 en RUST
# (Actix + SeaORM). Remplace l'ancien serveur Node. Référencé par heroku.yml.
#
# Contexte de build = racine du dépôt ; on ne prend que server-rust/.
# Persistance durable native : Postgres (add-on Heroku). Le serveur ne relaie
# que du chiffré.

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

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/brocolis-messagerie /usr/local/bin/brocolis-messagerie
ENV MESSAGE_RETENTION_DAYS=7
# Heroku fournit PORT et DATABASE_URL (Postgres). REDIS_URL / APNS_* optionnels.
CMD ["brocolis-messagerie"]
