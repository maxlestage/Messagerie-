# Serveur Brocolis 🥦 — écrit avec Paquets 📦

Le serveur de messagerie chiffrée et de rendez-vous X25519, **tout en Rust**,
écrit avec [Paquets](https://maxlestage.github.io/Paquets/), le framework
full-stack qui assemble :

- [Vitesse](https://maxlestage.github.io/Vitesse/) pour le web (routes façon
  Express, SSE, CORS, fichiers statiques) ;
- [Securite](https://maxlestage.github.io/Securite/) pour le **bouclier 🔒**
  devant chaque requête (voir plus bas) ;
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

## Le bouclier 🔒

Chaque requête passe par les middlewares de Securite, branchés par Paquets
(`src/bouclier.rs`) avant même le CORS et les routes :

| Garde | Réglage |
|---|---|
| WAF | injection SQL, XSS, RCE, Log4Shell, traversée… sensibilité **moyenne** (URI, requête, en-têtes) |
| Anti-inondation | 50 req/s par adresse (rafales de 200), en plus des plafonds par appareil et par usage de `src/limits.rs` |
| Bannissement auto | 20 refus (401/403 : pare-feu, robots…) en une minute → 15 min de ban, puis de plus en plus long ; les 429 ne comptent pas (pas de ban de toute une box pour un appareil trop bavard) |
| Concurrence | 128 requêtes simultanées par adresse (flux SSE compris) |
| Corps | 8 Mo sur `/v1/messages` (médias chiffrés), 256 Ko ailleurs ; **JSON uniquement** (415 sinon) |
| Anti-robots | sqlmap, nikto, nuclei, gobuster… refusés |
| CSRF | Fetch Metadata ; l'API (CORS ouvert, par choix) en est exemptée |
| HTTPS | redirection HTTP → HTTPS derrière le routeur Heroku, HSTS deux ans |
| En-têtes | CSP sur mesure (le seul code inline permis est celui des pages, par empreinte SHA-256), `nosniff`, `X-Frame-Options: DENY`, COOP/CORP, Permissions-Policy (micro seulement, pour les vocaux) |
| Hygiène | URI et en-têtes bornés, méthodes HTTP connues seulement, `X-Request-Id` partout |
| Cookies | `Secure`, `HttpOnly`, `SameSite` |

`GET /stats` expose le bouclier en chiffres (`shield` : gardes, requêtes vues
et refusées, par garde). Les tests (`tests/api.rs`) vérifient chaque garde.

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

- `src/lib.rs` — l'`App` Paquets : bouclier, API, site
- `src/bouclier.rs` — le bouclier Securite et la CSP du site
- `src/api.rs` — les routes de l'API (Vitesse)
- `src/store.rs` — les données (modèles Memoire, rétention, budget)
- `src/broadcast.rs` — temps réel dans le processus (un canal par conversation)
- `src/rendezvous.rs` — relais éphémères `/pair`, `/wrap`, tokens Live Activity
- `src/apns.rs`, `src/apple_signin.rs` — push APNs, « Se connecter avec Apple »
- `src/lib.rs` — l'application complète (API + site), partagée avec les tests
- `tests/api.rs` — tests bout-en-bout sur la vraie application
