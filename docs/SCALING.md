# Passage à l'échelle — serveur Brocolis 🥦 (Rust · Actix)

Guide pratique pour faire monter le serveur de messagerie chiffrée en charge.
La règle d'or : **le serveur ne relaie que du chiffré** et il est **sans état**
(toute la vérité est dans Postgres ; Redis ne sert qu'à rediffuser le temps réel
entre dynos). On peut donc scaler **horizontalement** sans coordination.

> ⚠️ La montée à très grande échelle est d'abord une histoire d'**infra**
> (dynos, pooler, plan Postgres, CDN), pas de crates. Le code est déjà **borné
> partout** (aucune requête ne grossit avec le nombre total d'utilisateurs).

---

## 1. Ce qui est déjà en place côté code

| Sujet | État | Où |
|------|------|-----|
| Liste des conversations d'un utilisateur | Index `conversation_members(user_id)` — **O(ses conversations)**, plus de balayage de table | `GET /v1/conversations` |
| Pool de connexions Postgres | **Borné** (`DB_MAX_CONNECTIONS`, défaut 10) + timeouts | `main()` |
| Latence temps réel | `TCP_NODELAY` activé | `HttpServer` |
| Historique de conversation | **Paginé** (`limit` défaut 200, plafond 500, `hasMore`/`cursor`) | `GET /v1/messages` |
| Table `messages` | **Partitionnée HASH par `conversation_id`** (16 partitions) → *partition pruning* | schéma |
| Temps réel multi-dynos | **Redis** (pub/sub) déjà câblé | `realtime.rs` |
| Rétention | `DELETE` indexé (`sent_at`), fenêtre `MESSAGE_RETENTION_DAYS` (7 j) | `retention_loop` |

**Conséquence** : passer à l'échelle est surtout une question de réglages d'infra
ci-dessous, pas de réécriture applicative.

---

## 2. Variables d'environnement utiles

| Variable | Rôle | Défaut |
|----------|------|--------|
| `DATABASE_URL` | Postgres (fournie par Heroku) | — |
| `DB_MAX_CONNECTIONS` | Taille **max du pool par dyno** | `10` |
| `REDIS_URL` | Redis pour le SSE inter-dynos (sans ⇒ temps réel intra-dyno) | — |
| `MESSAGE_RETENTION_DAYS` | Fenêtre de rétention des messages | `7` |
| `MAX_PEERS` | Plafond de participants par salon de rendez-vous | `16` |
| `PUBLIC_DIR` | Répertoire de la vitrine statique servie à `/` | `public` |
| `APNS_*` | Push Live Activity (facultatif) | — |

---

## 3. Étapes d'infra Heroku, dans l'ordre

### 3.1 Scaler les dynos web (le plus simple, sans état)

Le process web est **stateless** et le SSE inter-dynos passe par Redis : on peut
en lancer plusieurs sans rien changer au code.

```bash
# Plus de dynos (horizontal)
heroku ps:scale web=4 -a <app>

# Dynos plus gros (vertical : plus de RAM/CPU par dyno)
heroku ps:type web=standard-2x -a <app>
```

> Sans `REDIS_URL`, chaque dyno ne rediffuse le temps réel qu'à SES abonnés :
> un message posté sur le dyno A n'atteindrait pas un client branché en SSE sur
> le dyno B. **Dès 2 dynos, `REDIS_URL` est requis** (voir 3.4).

### 3.2 Respecter le plafond de connexions Postgres ⚠️

C'est **la** panne classique en montée en charge. Contrainte à tenir :

```
DB_MAX_CONNECTIONS  ×  (nb de dynos web)   ≤   cap de connexions du plan Postgres
```

Ordres de grandeur des caps Heroku Postgres (vérifier le plan exact) :

| Plan | Connexions max |
|------|----------------|
| essential-0 / mini | ~20 |
| essential-1 / basic | ~20 |
| standard-0 | ~120 |
| standard-2 | ~400 |

Exemple : plan à 120 connexions, 8 dynos → `DB_MAX_CONNECTIONS ≤ 15`.

```bash
heroku config:set DB_MAX_CONNECTIONS=12 -a <app>
```

Garde une marge (migrations, `retention_loop`, `psql` manuel consomment aussi).

### 3.3 PgBouncer (mutualiser les connexions) — dès que 3.2 devient serré

Un *pooler* en mode **transaction** permet à des centaines de clients logiques de
partager quelques dizaines de connexions physiques Postgres. C'est **l'** étape
qui débloque le vrai scaling horizontal.

```bash
# Buildpack PgBouncer Heroku
heroku buildpacks:add heroku/pgbouncer -a <app>
# Configurer le pool (voir la doc du buildpack : PGBOUNCER_* )
# Puis abaisser le pool applicatif, PgBouncer faisant le gros du travail :
heroku config:set DB_MAX_CONNECTIONS=5 -a <app>
```

> Le code force déjà `sslmode=require` sur les URLs distantes ; garde ce
> comportement compatible avec la chaîne PgBouncer.

### 3.4 Redis (temps réel inter-dynos)

```bash
heroku addons:create heroku-redis:mini -a <app>   # fournit REDIS_URL
```

Le serveur détecte `REDIS_URL` et bascule automatiquement en pub/sub. Le TLS au
certificat auto-signé de Heroku Key-Value est déjà géré (mode « insecure »
équivalent au `rejectUnauthorized:false` du Node). Monter le plan Redis quand le
nombre d'abonnés SSE simultanés grimpe.

### 3.5 Monter le plan Postgres

Plus de connexions, de RAM (cache), et d'IOPS. À faire quand `pg:diagnose`
signale de la pression (cache hit ratio bas, attentes de connexions).

```bash
heroku pg:info -a <app>
heroku pg:diagnose -a <app>
```

### 3.6 CDN pour la vitrine

La vitrine React (`site/`) est statique et **incompressible côté API** (les
tokens sont chiffrés) — mais le HTML/JS/CSS, lui, gagne à être servi par un CDN,
pas par les dynos.

Deux options :
1. **CDN devant Heroku** (Cloudflare/Fastly) avec cache long sur `/assets/*`.
2. **Héberger la vitrine ailleurs** (Cloudflare Pages / Netlify / GitHub Pages)
   et pointer `SERVER_URL` (dans `site/src/config.ts`) vers l'API. Les dynos ne
   servent alors plus que l'API.

Dans les deux cas, l'API reste sur les dynos ; seul le trafic statique est
déchargé.

---

## 4. Base de données à grande échelle

### 4.1 Partitionnement (déjà fait)

`messages` est partitionnée **HASH par `conversation_id`** (16 partitions) :
chaque conversation vit dans une partition, et les requêtes filtrées par
conversation (envoi, historique, idempotence) ne scannent qu'**une** partition.
`EXPLAIN` le confirme (pas de balayage des 16).

### 4.2 Sharding distribué (Citus) — cap suivant

Le partitionnement HASH par conversation **s'aligne** naturellement sur un
sharding distribué type **Citus** : on distribue `messages` (et
`conversation_members`, `read_cursors`, `conversations`) par `conversation_id`,
et chaque shard vit sur un worker. Aucune requête chaude ne traverse plusieurs
conversations, donc la co-localisation est parfaite.

### 4.3 Rétention : `DELETE` aujourd'hui, partitionnement par temps plus tard

Aujourd'hui la purge est un `DELETE FROM messages WHERE sent_at < cutoff`,
appuyé sur l'index `idx_msg_sent_at`. **Suffisant à toute échelle réaliste**
pour une fenêtre de 7 jours.

**Pourquoi on ne partitionne PAS (encore) par temps**, malgré l'attrait du
`DROP PARTITION` quasi gratuit :

- Il faudrait du **sous-partitionnement** (HASH conversation × RANGE temps),
  donc **re-réécrire** la table `messages`.
- L'**INSERT** deviendrait **dépendant d'un cron** qui pré-crée les partitions
  temporelles futures : si le cron rate, le serveur **ne peut plus insérer de
  message**. Pour une messagerie, c'est un **risque de disponibilité**, pas une
  optimisation.
- Le gain (`DROP` vs `DELETE`) n'apparaît qu'à **très gros volume d'écriture**,
  quand le `DELETE` + le *vacuum* deviennent un point chaud mesuré.

**Déclencheur d'adoption** : quand `pg:diagnose` / les métriques montrent que la
purge de rétention (ou le bloat post-`DELETE`) est un goulot réel. À ce
moment-là, adopter le sous-partitionnement **avec** un cron robuste de
création/`DROP` de partitions et une **partition `DEFAULT`** de sécurité pour ne
jamais bloquer l'INSERT.

### 4.4 Hygiène des métadonnées

À surveiller à très grande échelle : `conversations` et `conversation_members`
ne sont pas purgés par la rétention (seuls les messages le sont). Prévoir, si
besoin, un nettoyage des conversations sans message depuis longtemps.

---

## 5. Observabilité

```bash
heroku logs --tail -a <app>            # logs applicatifs
heroku pg:info -a <app>                # connexions, taille, cache
heroku pg:diagnose -a <app>            # recommandations automatiques
heroku redis:info -a <app>            # mémoire / clients Redis
```

Points à surveiller en priorité : **connexions Postgres utilisées vs cap**,
cache hit ratio, latence des requêtes `/v1/messages`, mémoire Redis.

---

## 6. Checklist ordonnée (quoi faire, quand)

1. **1 dyno, peu d'utilisateurs** : rien à faire (état actuel).
2. **Latence / 2ᵉ dyno** : ajouter `REDIS_URL`, puis `heroku ps:scale web=2+`.
3. **Connexions Postgres qui montent** : ajuster `DB_MAX_CONNECTIONS` selon la
   formule (3.2), puis monter le plan Postgres.
4. **Beaucoup de dynos** : **PgBouncer** (3.3) et baisser `DB_MAX_CONNECTIONS`.
5. **Trafic vitrine** : **CDN** ou héberger la vitrine hors dynos (3.6).
6. **Postgres saturé en écriture** : **Citus** (4.2) ; envisager le
   partitionnement par temps pour la rétention (4.3) **seulement** si la purge
   devient un point chaud mesuré.
