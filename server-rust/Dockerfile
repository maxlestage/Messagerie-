# Build multi-étage du service messagerie Rust (Actix + SeaORM).
# ⚠️ NON câblé dans heroku.yml : la prod reste le serveur Node tant que ce
# service n'est pas prouvé. Pour tester : déployer ce Dockerfile sur une app
# Heroku dédiée avec add-on Postgres (DATABASE_URL fourni automatiquement).

FROM rust:1-slim AS build
WORKDIR /app
# Cache des dépendances : on compile d'abord un projet vide (deps figées par
# Cargo.lock pour un build reproductible).
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --locked || true
# Puis les vraies sources.
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/brocolis-messagerie /usr/local/bin/brocolis-messagerie
ENV MESSAGE_RETENTION_DAYS=7
# Heroku fournit PORT et DATABASE_URL (add-on Postgres).
CMD ["brocolis-messagerie"]
