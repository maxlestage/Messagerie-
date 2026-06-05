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

## Sécurité

Le code court n'authentifie pas les participants : un intercepteur pourrait
rejoindre le rendez-vous (MITM). L'app affiche une **empreinte de sécurité**
dérivée des deux clés publiques — comparez-la de vive voix : si elle est
identique des deux côtés, la connexion n'a pas été interceptée.
