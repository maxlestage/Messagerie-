# Serveur de rendez-vous brocolis 🥦

Petit serveur (Node, sans dépendance) qui permet à deux appareils partageant un
même **code court** d'échanger automatiquement leurs **clés publiques X25519**.

## Ce qu'il fait (et ne fait pas)

- Il met en relation des appareils par code et **n'échange que des clés
  publiques**. Chacun **dérive ensuite seul** la clé symétrique AES (ECDH +
  HKDF) : **le serveur ne voit jamais la clé secrète ni les messages**.
- Stockage **éphémère** (TTL 10 min). Plafond de participants par code
  **configurable** via `MAX_PEERS` (défaut 16).

> ⚠️ **Groupe (3+)** : relever le plafond permet à N personnes de se *rejoindre*
> sous un code, mais la dérivation automatique de l'app reste **par paire**
> (X25519 entre 2 clés publiques). Pour une vraie **clé de groupe commune**, les
> membres doivent convenir de la même clé autrement — le plus simple : une
> personne la **génère et la partage**, les autres l'**importent** (déjà
> possible dans l'app). L'emballage de clé de groupe (une clé distribuée
> chiffrée à chaque membre) n'est pas implémenté.

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

## API

```
POST /pair   { code, peerId, pub }   -> { peers: [{ peerId, pub }, ...] }
GET  /pair?code=...&peerId=...        -> { peers: [...] }
GET  /health                          -> "ok"
```

`pub` est une clé publique X25519 (32 octets, base64). L'app publie la sienne
puis sonde jusqu'à recevoir celle du correspondant, et dérive la clé partagée.

## Sécurité

Le code court n'authentifie pas les participants : un intercepteur pourrait
rejoindre le rendez-vous (MITM). L'app affiche une **empreinte de sécurité**
dérivée des deux clés publiques — comparez-la de vive voix : si elle est
identique des deux côtés, la connexion n'a pas été interceptée.
