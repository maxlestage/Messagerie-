# Serveur de rendez-vous brocolis 🥦

Petit serveur (Node, sans dépendance) qui permet à deux appareils partageant un
même **code court** d'échanger automatiquement leurs **clés publiques X25519**.

## Ce qu'il fait (et ne fait pas)

- Il met en relation des appareils par code et **n'échange que des clés
  publiques**. Chacun **dérive ensuite seul** la clé symétrique AES (ECDH +
  HKDF) : **le serveur ne voit jamais la clé secrète ni les messages**.
- Stockage **éphémère** (TTL 10 min). Plafond de participants par code
  **configurable** via `MAX_PEERS` (défaut 16).

- **Groupe (3+)** : un fondateur génère une clé de groupe et la **distribue
  emballée (chiffrée) pour chaque membre** via X25519 (routes `/wrap`). Le
  serveur stocke des **blobs chiffrés** qu'il ne peut pas déballer. Tous les
  membres obtiennent ainsi la même clé automatiquement.

## Lancer

```sh
cd server
npm start                 # écoute sur le port 8788 (PORT pour changer)
MAX_PEERS=32 npm start     # relève le plafond de participants par code
npm test                  # tests (rendez-vous, multi-participants, accord de clé)
```

Dans l'app (écran **Appairage**), renseigne l'URL du serveur :

- **Simulateur iOS** : `http://localhost:8788`
- **iPhone réel (même Wi-Fi)** : `http://<IP-de-ta-machine>:8788`
- **Hors réseau local** : héberge avec TLS et utilise `https://…` (Render,
  Railway, Fly.io… : le serveur écoute sur `process.env.PORT`).

> iOS bloque par défaut le HTTP non chiffré (ATS). En production, sers le
> rendez-vous en **HTTPS**.

## Docker

```sh
cd server
docker build -t brocolis-rendezvous .
docker run -p 8788:8788 -e MAX_PEERS=32 brocolis-rendezvous
# santé : curl http://localhost:8788/health  -> ok
```

Image minimale (Node Alpine, **aucune dépendance**), utilisateur non-root,
`HEALTHCHECK` sur `/health`. Le serveur écoute sur `process.env.PORT` (défaut
8788) : l'image fonctionne telle quelle sur Render, Railway, Fly.io ou un VPS.
Ces plateformes fournissent le **TLS** → utilise `https://…` (donc `wss`-grade
sécurité) côté app.

## docker-compose + HTTPS automatique (Caddy)

Pour un VPS, `docker-compose.yml` lance le rendez-vous **derrière Caddy**, qui
obtient et renouvelle **tout seul** un certificat Let's Encrypt.

Pré-requis : un **domaine** dont le DNS (A/AAAA) pointe vers la machine, et les
ports **80 + 443** ouverts.

```sh
cd server
cp .env.example .env        # renseigne DOMAIN=relais.example.com
docker compose up -d
```

Caddy expose `https://<DOMAIN>` et relaie vers le service interne `rendezvous`
(non exposé publiquement). Dans l'app, mets `https://<DOMAIN>` comme serveur
d'appairage. Les certificats sont persistés dans le volume `caddy_data`.

> Test local sans domaine : `docker run -p 8788:8788 brocolis-rendezvous` puis
> `http://<IP-locale>:8788` (même Wi-Fi). Pour de l'usage à distance, le HTTPS
> de Caddy est requis (ATS iOS).

## Déployer sur Heroku

Heroku fournit **le HTTPS et le port** automatiquement : **pas besoin de Caddy
ni de docker-compose** ici. Le serveur lit déjà `process.env.PORT`.

Le serveur étant dans le sous-dossier `server/`, on le pousse comme racine de
l'app avec `git subtree`.

**Option A — buildpack Node (le plus simple)** — utilise `Procfile` :

```sh
heroku create mon-relais-brocolis
git subtree push --prefix server heroku main
# (optionnel) heroku config:set MAX_PEERS=32
```

**Option B — conteneur (réutilise le Dockerfile)** — utilise `heroku.yml` :

```sh
heroku create mon-relais-brocolis
heroku stack:set container -a mon-relais-brocolis
git subtree push --prefix server heroku main
```

Dans l'app, serveur d'appairage = `https://mon-relais-brocolis.herokuapp.com`.
Vérif : `curl https://mon-relais-brocolis.herokuapp.com/health` → `ok`.

> Stockage **en mémoire** (éphémère) : l'appairage prend quelques secondes, donc
> le redémarrage périodique des dynos n'est pas gênant. Reste sur **un seul
> dyno `web`** (le rendez-vous n'est pas partagé entre plusieurs dynos).

## API

```
POST /pair   { code, peerId, pub }                          -> { peers: [{ peerId, pub }, ...] }
GET  /pair?code=...&peerId=...                               -> { peers: [...] }
POST /wrap   { code, fromPeerId, fromPub, items:[{toPeerId, blob}] } -> { ok, count }
GET  /wrap?code=...&peerId=...                               -> { wrap: { from, fromPub, blob } | null }
GET  /health                                                -> "ok"
```

`blob` est la clé de groupe chiffrée pour un membre (AES-256-GCM, clé d'emballage
dérivée par X25519). Le serveur ne peut pas la déballer.

`pub` est une clé publique X25519 (32 octets, base64). L'app publie la sienne
puis sonde jusqu'à recevoir celle du correspondant, et dérive la clé partagée.

### Messagerie chiffrée (E2E)

Le même serveur héberge une **messagerie** : il route et stocke des messages
**déjà chiffrés** (jetons Brocolis). Il ne détient aucune clé — que du charabia.
Toutes ces routes exigent l'en-tête **`X-User-Id`**.

```
POST /v1/conversations  { participants:[{id,displayName}] }        -> Conversation (201)
GET  /v1/conversations                                             -> [Conversation] de l'appelant
POST /v1/messages       { id?, conversationId, senderId, ciphertext } -> StoredMessage (201)
GET  /v1/messages?conversationId=..&after=<seq>                    -> { messages:[…], cursor }
GET  /v1/stream?conversationId=..                                  -> flux SSE (data: {json})
```

- **`ciphertext`** : jeton chiffré (`[[BROCOLIS:v1:…]]`), illisible sans la clé.
- **Conversation « scellée »** : un `POST /v1/messages` vers un `conversationId`
  inconnu crée la conversation sans participants. L'id étant dérivé côté client
  d'une **clé partagée** (empreinte), l'accès est cryptographique : qui a la clé
  lit, les autres ne voient que du charabia. Avec des `participants` explicites,
  l'appartenance est vérifiée.
- **`seq`** : curseur monotone ; repasse `cursor` dans `?after=` pour ne
  récupérer que la suite (rattrapage après coupure).
- **SSE** : chaque nouveau message arrive en `data: {json}\n\n`, avec un
  `:keep-alive` toutes les 25 s (Heroku coupe une connexion inactive vers 55 s).
  À la reprise, l'app rattrape via `GET /v1/messages?after=`.
- Stockage **SQLite** (module intégré `node:sqlite`, aucune dépendance externe)
  quand `DB_PATH` est défini ; sinon **en mémoire**. Le serveur ne stocke que du
  chiffré. Voir ci-dessous.

### Persistance des messages (SQLite)

Les messages sont conservés dans **SQLite** dès que la variable **`DB_PATH`** est
renseignée (chemin du fichier `.db`). Sans elle, le stockage reste **en mémoire**
(tests, ou usage jetable). Le code choisit tout seul et retombe proprement en
mémoire si `node:sqlite` est indisponible.

```sh
DB_PATH=./data/messages.db npm start   # persiste dans un fichier
```

- Le conteneur Docker définit déjà `DB_PATH=/tmp/brocolis-messages.db`.
- **⚠️ Heroku** : le disque d'un dyno est **éphémère**. SQLite survit aux
  redémarrages du *process*, mais le fichier est **effacé à chaque déploiement /
  recyclage de dyno**. Pour une persistance **durable** sur Heroku, il faut une
  base **gérée (Heroku Postgres)** — le stockage est isolé dans
  `messages-store.js`, donc y brancher Postgres ne touche pas au reste.
- Curseur `seq` **monotone** (clé auto-incrémentée), idempotence sur
  `(conversationId, id)`. La diffusion temps réel (SSE) reste en mémoire.

## Sécurité

Le code court n'authentifie pas les participants : un intercepteur pourrait
rejoindre le rendez-vous (MITM). L'app affiche une **empreinte de sécurité**
dérivée des deux clés publiques — comparez-la de vive voix : si elle est
identique des deux côtés, la connexion n'a pas été interceptée.
