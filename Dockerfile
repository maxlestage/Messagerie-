# Déploiement Heroku EN CONTENEUR — serveur Brocolis 🥦, tout en Rust, écrit
# avec Paquets 📦 :
#   - Vitesse  : le serveur web (API de messagerie, rendez-vous X25519, SSE) ;
#   - Securite : le bouclier devant chaque requête (WAF, CSP, limites…) ;
#   - Memoire  : les données, en mémoire (ni Postgres ni Redis : aucun add-on) ;
#   - Active   : le site, rendu par le serveur et animé en WebAssembly.
# Référencé par heroku.yml. Contexte de build = racine du dépôt.

FROM rust:1-slim-trixie AS build
ARG WASM_BINDGEN_VERSION=0.2.129
# Outils de build (ring pour rustls), cible WebAssembly, et wasm-bindgen à la
# version de site/Cargo.lock (binaire publié, pas de compilation).
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates pkg-config perl make \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add wasm32-unknown-unknown \
    && curl -sSfL "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
       | tar -xz --strip-components=1 -C /usr/local/bin \
         "wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl/wasm-bindgen"

WORKDIR /src
# Le site embarque le README du dépôt (rendu en HTML sur l'accueil).
COPY README.md ./README.md
COPY site ./site
COPY server-rust ./server-rust

# 1. Le code du navigateur (îlots + animations) → site/pkg
RUN cd site \
    && cargo build --lib --target wasm32-unknown-unknown --profile wasm-release --locked \
    && wasm-bindgen --target web --no-typescript --out-dir pkg \
         target/wasm32-unknown-unknown/wasm-release/brocolis_site.wasm

# 2. Le serveur (API + pages du site)
RUN cd server-rust && cargo build --release --locked

# ── Image finale ──────────────────────────────────────────────────────────────
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home brocolis
WORKDIR /app
# Pour MEMOIRE_PATH=/app/data/brocolis.memoire (facultatif).
RUN mkdir -p /app/data && chown brocolis /app/data
COPY --from=build /src/server-rust/target/release/brocolis-messagerie /usr/local/bin/brocolis-messagerie
COPY --from=build /src/site/assets /app/site/assets
COPY --from=build /src/site/pkg /app/site/pkg
USER brocolis
ENV SITE_DIR=/app/site
ENV MESSAGE_RETENTION_DAYS=7
# Heroku fournit PORT. Plus de DATABASE_URL ni de REDIS_URL : tout est en
# mémoire. APNS_*, BROCOLIS_PRO_* et MEMOIRE_PATH restent facultatifs.
CMD ["brocolis-messagerie"]
