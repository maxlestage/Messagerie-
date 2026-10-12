# Serveur Brocolis 🥦 — Vitesse + Memoire

Le serveur de messagerie chiffrée et de rendez-vous X25519, **tout en Rust** :

- [Vitesse](https://maxlestage.github.io/Vitesse/) pour le web (routes façon
  Express, SSE, CORS, fichiers statiques) ;
- [Memoire](https://maxlestage.github.io/Memoire/) pour les données, **en
  mémoire** : plus de Postgres ni de Redis, aucun add-on ;
- les pages du site ([`../site`](../site), écrit avec Active) sont rendues ici
  même, à côté de l'API.

Le serveur ne voit et ne garde que du **chiffré** (jetons Brocolis illisibles
sans la clé), une semaine au plus.

## API (inchangée pour les apps)

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/health` | `ok` |
| `GET` | `/stats` | totaux publics (messages, conversations, octets, salons, connexions, uptime) |
| `POST` / `GET` | `/pair` | rendez-vous X25519 : publier / lire les clés publiques d'un code |
| `POST` / `GET` | `/wrap` | clé de groupe emballée pour chaque membre |
| `POST` | `/push/live-activity/token`, `/push/live-activity/update` | push Live Activity (APNs) |
| `POST` / `GET` | `/v1/conversations` | conversations à participants |
| `POST` | `/v1/messages` | envoi chiffré, idempotent sur `(conversationId, id)` |
| `GET` | `/v1/messages?conversationId=&after=&limit=` | `{ messages, cursor, readers, hasMore, limit }` |
| `POST` | `/v1/read` | accusé de lecture (monotone) |
| `GET` | `/v1/stream?conversationId=` | temps réel (SSE) : messages et `{"type":"read",…}` |
| `GET` | `/v1/plan`, `POST`/`DELETE` `/v1/plan/apple` | accès offerts |

En-tête `X-User-Id` sur `/v1/*`. CORS ouvert (tout ce qui passe est public ou
chiffré).

## Données en mémoire

- **`seq`** ne fait que monter, même d'un démarrage à l'autre (il part de
  l'heure × 1000) : un client qui rattrape avec `after=` ne saute rien.
- **Rétention** : purge horaire au-delà de `MESSAGE_RETENTION_DAYS` (7).
- **Budget** : au-delà de `MEMORY_BUDGET_MB` (200) de chiffré, les plus vieux
  messages partent les premiers.
- **`MEMOIRE_PATH`** (facultatif) : Memoire écrit aussi chaque changement dans
  ce fichier, relu au démarrage — utile sur un disque durable (pas sur Heroku,
  dont le disque est effacé à chaque redémarrage).

## Lancer

```bash
# Le site d'abord (code du navigateur), voir ../site/README.md, puis :
cargo run                       # http://localhost:8788 (PORT pour changer)
cargo test                      # unitaires + intégration (API, site, flux SSE)
```

Déploiement Heroku : [`../docs/DEPLOY_RUST.md`](../docs/DEPLOY_RUST.md) ;
montée en charge : [`../docs/SCALING.md`](../docs/SCALING.md).

## Organisation

- `src/api.rs` — les routes de l'API (Vitesse)
- `src/store.rs` — les données (modèles Memoire, rétention, budget)
- `src/broadcast.rs` — temps réel dans le processus (un canal par conversation)
- `src/rendezvous.rs` — relais éphémères `/pair`, `/wrap`, tokens Live Activity
- `src/apns.rs`, `src/apple_signin.rs` — push APNs, « Se connecter avec Apple »
- `src/lib.rs` — l'application complète (API + site), partagée avec les tests
- `tests/api.rs` — tests bout-en-bout sur la vraie application
