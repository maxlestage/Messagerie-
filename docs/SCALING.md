# Passage à l'échelle — serveur Brocolis 🥦 (Vitesse · Memoire)

Le serveur ne relaie que du **chiffré** et garde tout **en mémoire** avec
[Memoire](https://maxlestage.github.io/Memoire/) : ni Postgres ni Redis, aucun
add-on Heroku. C'est simple et rapide, avec une conséquence à garder en tête :
**un seul processus détient les données**. On monte donc en charge
**verticalement** (un dyno plus gros), pas en multipliant les dynos.

---

## 1. Ce qui est en place côté code

| Sujet | État | Où |
|------|------|-----|
| Serveur web | [Vitesse](https://maxlestage.github.io/Vitesse/) sur tokio, `TCP_NODELAY`, SSE avec commentaire toutes les 25 s (Heroku coupe à 55 s) | `server-rust/src/api.rs` |
| Messages | Table Memoire en mémoire, index sur `conversation_id`, unicité `(conversation_id, msg_id)` = idempotence | `server-rust/src/store.rs` |
| Curseur `seq` | Monotone **même d'un démarrage à l'autre** : il part de l'heure × 1000, un client qui a gardé son `after=` ne rate rien | `first_seq` |
| Historique | **Paginé** (`limit` défaut 200, plafond 500, `hasMore`/`cursor`) | `GET /v1/messages` |
| Rétention | Purge horaire au-delà de `MESSAGE_RETENTION_DAYS` (7 j) | `spawn_maintenance` |
| Budget mémoire | Au-delà de `MEMORY_BUDGET_MB` de chiffré, les plus vieux messages partent les premiers (retour à 90 %) | `Store::enforce_budget` |
| Temps réel | Un canal par conversation, dans le processus ; canaux abandonnés purgés chaque minute | `broadcast.rs` |
| Rendez-vous X25519 | En mémoire, TTL 10 min, plafond `MAX_PEERS` | `rendezvous.rs` |

---

## 2. Variables d'environnement utiles

| Variable | Rôle | Défaut |
|----------|------|--------|
| `PORT` | Port d'écoute (fourni par Heroku) | `8788` |
| `MEMORY_BUDGET_MB` | Taille maximale du chiffré gardé en mémoire | `200` |
| `MEMOIRE_PATH` | Facultatif : Memoire écrit aussi chaque changement dans ce fichier, relu au démarrage | — |
| `MESSAGE_RETENTION_DAYS` | Fenêtre de rétention des messages | `7` |
| `MAX_PEERS` | Plafond de participants par salon de rendez-vous | `16` |
| `SITE_DIR` | Dossier du site (`assets/`, `pkg/`) | détecté |
| `APNS_*` | Push Live Activity (facultatif) | — |
| `BROCOLIS_PRO_IDS`, `BROCOLIS_PRO_EMAILS` | Accès offerts | — |

---

## 3. Ce que « tout en mémoire » implique

- **Un redémarrage efface les messages en transit.** Ils sont déjà sur les
  téléphones (le serveur n'est qu'un relais d'une semaine au plus), et le
  curseur `seq` continue de monter : les clients reprennent sans trou.
- **Les e-mails Apple rattachés** (`POST /v1/plan/apple`) disparaissent aussi au
  redémarrage : la personne retouche « Se connecter avec Apple ». Pour un accès
  offert qui ne dépend de rien, préférer `BROCOLIS_PRO_IDS` (identifiant
  d'appareil, relu à chaque requête).
- **Sur Heroku, le disque d'un dyno est effacé à chaque redémarrage** (au moins
  une fois par jour) : `MEMOIRE_PATH` n'y aide qu'en cas de plantage du
  processus. Sur une machine à disque durable (VPS, volume Fly.io, Render
  Disk…), `MEMOIRE_PATH=/app/data/brocolis.memoire` garde tout d'un démarrage à
  l'autre.

---

## 4. Monter en charge

### 4.1 Un seul dyno, plus gros

```bash
heroku ps:scale web=1 -a <app>               # toujours UN processus
heroku ps:type web=standard-2x -a <app>      # plus de RAM et de CPU
heroku config:set MEMORY_BUDGET_MB=600 -a <app>
```

Garder `MEMORY_BUDGET_MB` sous ~40 % de la RAM du dyno : le reste sert aux
requêtes en cours (corps jusqu'à 8 Mo pour les médias chiffrés), aux index et
au site.

> ⚠️ **Ne pas lancer plusieurs dynos web** : chacun aurait sa propre mémoire,
> un message posté sur l'un n'arriverait pas aux abonnés de l'autre, et un
> appairage commencé sur l'un ne se finirait pas sur l'autre.

### 4.2 Décharger le site

Les fichiers du site (`/assets/…?v=`, `/pkg/…?v=`) portent une empreinte et
sont servis avec `cache-control: immutable` : un CDN devant Heroku
(Cloudflare, Fastly) les garde sans jamais solliciter le dyno.

### 4.3 Au-delà d'une machine

Memoire parle aussi Postgres, SQLite, Redis et MongoDB avec la même API : le
jour où un seul processus ne suffit plus, `store.rs` est le seul fichier à
changer (et `broadcast.rs` pour relayer le temps réel entre processus).

---

## 5. Observabilité

```bash
heroku logs --tail -a <app>                       # journaux (rétention, APNs…)
curl https://<app>.herokuapp.com/stats            # totaux publics, en JSON
```

`/stats` donne le nombre de messages et de conversations, les octets de
chiffré en mémoire, les salons ouverts, les connexions temps réel et le temps
depuis le démarrage. La page **Serveur** du site les affiche en direct.
