# Build en deux étapes : compilation Rust, puis image d'exécution minimale.
FROM rust:1-slim AS build
WORKDIR /app

# Cache des dépendances : on compile d'abord un projet vide avec le vrai
# Cargo.toml, puis on ajoute les sources. Un changement de code ne recompile
# alors pas tout l'arbre de dépendances.
COPY Cargo.toml ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src

COPY src ./src
# Force la recompilation du binaire (le main factice est plus récent en cache).
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/target/release/messagerie-api /usr/local/bin/messagerie-api
ENV PORT=8080
EXPOSE 8080
USER 1000:1000
CMD ["messagerie-api"]
