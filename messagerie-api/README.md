# Messagerie chiffrée — API (Rust + Actix-web)

Backend de la **section messagerie**. Il route et stocke des messages **déjà
chiffrés** (AES-256-GCM, fait sur l'appareil). Le serveur **ne détient aucune
clé** : il ne voit que du charabia base64.

> En clair dans l'app, illisible partout ailleurs (base de données, journaux,
> interception réseau…).

C'est le pendant Rust du protocole `MessagingBackend` du client Swift : là où le
client appelle `send` / `observeMessages` / `fetchConversations`, cette API
expose `POST /v1/messages`, `GET /v1/stream` (SSE) et `GET /v1/conversations`.

## Lancer

```sh
cd messagerie-api
cargo run                 # écoute sur 0.0.0.0:8080 (PORT pour changer)
cargo test                # tests d'intégration (create → send → fetch, accès, idempotence)
```

## Confidentialité (ce que le serveur voit / ne voit pas)

- **Voit** : `conversationId`, `senderId`, l'horodatage, et le `ciphertext`
  (base64 illisible). Les noms d'affichage des participants (à chiffrer côté
  client si tu ne veux pas les exposer).
- **Ne voit jamais** : le texte des messages ni la clé de chiffrement. Le
  déchiffrement se fait uniquement sur les appareils.
- L'échange de la clé partagée entre correspondants se fait **hors de cette
  API** (X25519, comme le serveur de rendez-vous dans `server/`). Cette API ne
  transporte que des messages chiffrés.

## Conversations scellées (modèle « clé partagée »)

Le client Brocolis n'a pas besoin de créer de conversation : il dérive un
`conversationId` **opaque à partir de la clé partagée** (empreinte SHA-256). Les
deux correspondants, qui possèdent la même clé, tombent sur le **même id** sans
que le serveur connaisse la clé.

- Un `POST /v1/messages` vers un `conversationId` inconnu **crée** une
  conversation « scellée » (sans liste de participants).
- Pour une conversation scellée, l'accès est **cryptographique** : n'importe quel
  appelant authentifié peut poster/lire *du chiffré*, mais **seul qui possède la
  clé peut déchiffrer**. Connaître l'id ne donne rien de lisible.
- Si tu préfères un contrôle d'accès explicite, crée la conversation via
  `POST /v1/conversations` avec ses `participants` : la vérification d'
  appartenance s'applique alors (voir le test `outsider_cannot_read`).

## Authentification

Toutes les routes `/v1` exigent l'en-tête **`X-User-Id`** (l'identité de
l'appelant). C'est volontairement minimal pour démarrer. Pour la production,
remplace `auth_user` dans `src/handlers.rs` par une vérification de **jeton signé
(JWT)** ou de session — le reste du code ne bouge pas.

## API

| Méthode | Route | Corps / Query | Réponse |
|---|---|---|---|
| `GET` | `/health` | — | `ok` |
| `POST` | `/v1/conversations` | `{ participants:[{id,displayName}] }` | `Conversation` (201) |
| `GET` | `/v1/conversations` | — | `[Conversation]` de l'appelant |
| `POST` | `/v1/messages` | `{ id?, conversationId, senderId, ciphertext }` | `StoredMessage` (201) |
| `GET` | `/v1/messages` | `?conversationId=..&after=<seq>` | `{ messages:[StoredMessage], cursor }` |
| `GET` | `/v1/stream` | `?conversationId=..` | flux **SSE** de nouveaux messages |

- **`ciphertext`** : base64 de `nonce || ciphertext || tag` (AES-256-GCM). Le
  serveur ne le déchiffre pas.
- **`seq`** : compteur monotone attribué par le serveur. Sers-t'en comme curseur :
  après un `GET /messages`, repasse `cursor` dans `?after=` pour ne récupérer que
  la suite (rattrapage après une coupure).
- **`id`** (envoi) : facultatif ; fournis-le pour rendre l'envoi **idempotent**
  (un renvoi réseau ne duplique pas le message).
- **SSE** : chaque nouveau message arrive en `data: {json}\n\n`. Garde la
  connexion ouverte pour l'affichage temps réel ; en cas de coupure, reconnecte
  puis rattrape avec `GET /messages?after=`.

### Exemple

```sh
# Créer une conversation
CID=$(curl -s -X POST localhost:8080/v1/conversations \
  -H 'X-User-Id: alice' -H 'content-type: application/json' \
  -d '{"participants":[{"id":"alice","displayName":"Alice"},{"id":"bob","displayName":"Bob"}]}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

# Écouter en temps réel (dans un autre terminal)
curl -N "localhost:8080/v1/stream?conversationId=$CID" -H 'X-User-Id: bob'

# Envoyer un message chiffré
curl -X POST localhost:8080/v1/messages \
  -H 'X-User-Id: alice' -H 'content-type: application/json' \
  -d "{\"conversationId\":\"$CID\",\"senderId\":\"alice\",\"ciphertext\":\"<base64 AES-GCM>\"}"
```

## Stockage

En mémoire (`RwLock<HashMap>`), suffisant pour démarrer et pour les tests. Toute
la persistance passe par `src/store.rs` : pour brancher **Postgres/SQLite**
(`sqlx`), tu ne réécris que ce fichier — handlers et modèles restent identiques.
⚠️ En l'état, un redémarrage vide les messages.

## Docker

```sh
docker build -t messagerie-api .
docker run -p 8080:8080 messagerie-api
```

## Note iOS (ATS)

iOS bloque le HTTP en clair : sers cette API en **HTTPS** en production (Fly.io,
Railway, Render… écoutent via `$PORT`). En développement sur simulateur,
`http://localhost:8080` passe.
