# Messagerie Brocolis 🥦 — service Rust (Actix + SeaORM)

Portage **en parallèle** du serveur Node (`../server/`). Objectif : remplacer à
terme le Node, mais **la prod reste le Node** tant que ce service n'est pas
prouvé sur une app de test.

Le serveur ne stocke que du **chiffré** (jetons Brocolis illisibles). Postgres
est la source de vérité (persistance durable native, pas de snapshot SQLite).

## Déjà porté
- `GET /health`
- `POST /v1/messages` (idempotent sur `(conversationId, id)`, `seq` = BIGSERIAL)
- `GET /v1/messages?conversationId=&after=` → `{ messages, cursor, readers }`
- `POST /v1/read` (curseur de lecture monotone → « Distribué / Lu »)
- Rétention 7 jours (purge périodique, `MESSAGE_RETENTION_DAYS`)
- Schéma Postgres créé au démarrage (idempotent)

## À porter (TODO)
- Rendez-vous X25519 (`/rendezvous…`) — relai de clés publiques
- Flux temps réel `GET /v1/stream` (SSE Actix)
- Push APNs (Live Activity)
- Redis (temps réel inter-dynos) — via `fred`/`redis`
- Conversations à participants + endpoints associés
- Vitrine statique `/site/`

## Lancer en local
```bash
DATABASE_URL=postgres://user:pass@localhost/brocolis PORT=8788 cargo run
```

## Déployer sur Heroku (app de test dédiée)
Utiliser `Dockerfile` (build multi-étage) avec un add-on Postgres. `PORT` et
`DATABASE_URL` sont fournis automatiquement. Ne PAS pointer l'app iOS dessus
tant que tous les endpoints ne sont pas portés et testés.
