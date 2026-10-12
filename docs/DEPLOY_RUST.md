# Déployer le serveur Brocolis 🥦 sur Heroku

Le serveur est **tout en Rust** et **sans add-on** :

- [Vitesse](https://maxlestage.github.io/Vitesse/) pour le web : API de
  messagerie chiffrée, rendez-vous X25519, flux temps réel (SSE), push APNs ;
- [Memoire](https://maxlestage.github.io/Memoire/) pour les données, **en
  mémoire** : ni Postgres ni Redis ;
- [Active](https://maxlestage.github.io/Active/) pour le site, rendu par le
  serveur et animé en WebAssembly.

Il ne relaie que du **chiffré**, une semaine au plus (`MESSAGE_RETENTION_DAYS`).

> **Tout-en-un** : `server-rust/deploy-rust.sh` enchaîne les étapes ci-dessous
> (création de l'app, config APNs, build/release du conteneur, vérification),
> de façon idempotente :
> ```bash
> ./server-rust/deploy-rust.sh brocolis-serveur
> # avec APNs :
> APNS_KEY_ID=… APNS_TEAM_ID=… APNS_BUNDLE_ID=rs.brocolis.messagerie \
>   APNS_KEY_P8_FILE=./AuthKey_XXXX.p8 ./server-rust/deploy-rust.sh brocolis-serveur
> ```

---

## 0. Prérequis

- [CLI Heroku](https://devcenter.heroku.com/articles/heroku-cli) et `heroku login`.
- Docker lancé (pour `container:push`), ou le déploiement par Git (`heroku.yml`).

## 1. L'app (stack conteneur)

```bash
heroku create brocolis-serveur --stack container   # ou une app existante :
heroku stack:set container -a brocolis-serveur
```

**Aucun add-on à ajouter.** Si l'app avait encore Postgres ou Redis, on peut les
retirer sans risque : le serveur ne lit plus `DATABASE_URL` ni `REDIS_URL`.

## 2. Variables (toutes facultatives)

| Variable | Rôle | Défaut |
|---|---|---|
| `MESSAGE_RETENTION_DAYS` | Rétention des messages chiffrés | `7` |
| `MEMORY_BUDGET_MB` | Taille max. du chiffré en mémoire ; au-delà, les plus vieux partent | `200` |
| `MAX_PEERS` | Participants max. par code de rendez-vous | `16` |
| `MEMOIRE_PATH` | Fichier où Memoire garde aussi les données (disque durable seulement) | — |
| `APNS_KEY_P8`, `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_BUNDLE_ID`, `APNS_ENV` | Push Live Activity | — |
| `BROCOLIS_PRO_IDS`, `BROCOLIS_PRO_EMAILS` | Accès offerts ([guide](acces-offerts.md)) ; e-mails séparés par virgules, espaces ou retours à la ligne | — |
| `BROCOLIS_GRANT_SECRET` | Signe le ticket que l'app garde pour retrouver son accès offert après un redémarrage (sinon : la clé APNs) | — |

```bash
heroku config:set -a brocolis-serveur \
  APNS_KEY_ID=XXXXXXXXXX APNS_TEAM_ID=YYYYYYYYYY \
  APNS_BUNDLE_ID=rs.brocolis.messagerie APNS_ENV=sandbox
# La clé .p8 est multi-lignes : garde les retours à la ligne.
heroku config:set -a brocolis-serveur APNS_KEY_P8="$(cat AuthKey_XXXXXXXXXX.p8)"
```

Sans APNs, `/push/live-activity/update` répond `503` ; tout le reste marche.

## 3. Déployer

Par Git (Heroku lit `heroku.yml` puis construit le `Dockerfile` racine) :

```bash
git push heroku master
```

Ou en conteneur, depuis la racine du dépôt :

```bash
heroku container:push web -a brocolis-serveur
heroku container:release web -a brocolis-serveur
```

Le `Dockerfile` construit d'abord le code du navigateur (le site, compilé en
WebAssembly, puis `wasm-bindgen`), ensuite le serveur. La première build
compile toutes les dépendances : compter quelques minutes.

## 4. Vérifier

```bash
heroku logs -a brocolis-serveur --tail
```

On doit voir :

```
Données en mémoire seulement (Memoire) : rien n'est écrit sur disque.
APNs configuré : mises à jour de Live Activity actives.   (si APNs)
Brocolis 🥦 (Vitesse + Memoire + Active) à l'écoute sur le port …
```

```bash
curl https://brocolis-serveur.herokuapp.com/health    # -> ok
curl https://brocolis-serveur.herokuapp.com/stats     # totaux publics (JSON)
open https://brocolis-serveur.herokuapp.com/          # le site → /fr/, /en/ ou /es/
```

## 5. Les apps

Rien à changer côté iOS, Android ni montre : mêmes routes (`/pair`, `/wrap`,
`/v1/messages`, `/v1/stream`, `/v1/read`, `/v1/conversations`, `/v1/plan`,
`/push/live-activity/*`), mêmes corps JSON, mêmes codes de réponse.

**Un seul dyno web** : les données vivent dans le processus (voir
[SCALING.md](SCALING.md)). Pour plus de capacité, un dyno plus gros, pas plus de
dynos.

## Dépannage

- **APNs 503** : configuration incomplète (une des variables APNS_* manque, ou
  la clé .p8 est mal collée). `502` = APNs a refusé (topic, clé ou token).
- **Le site n'est pas animé** : le dossier `site/pkg` manque dans l'image
  (étape WebAssembly du `Dockerfile`) ; le serveur le signale au démarrage.
- **Messages disparus après un redémarrage** : normal, ils ne vivent qu'en
  mémoire (ils sont déjà sur les téléphones). Les clients reprennent sans trou :
  le curseur `seq` continue de monter d'un démarrage à l'autre.
- **Accès Pro offert par e-mail perdu après un redémarrage** : vérifier que
  `BROCOLIS_GRANT_SECRET` (ou la clé APNs) est défini — l'app renvoie alors son
  ticket signé et l'accès revient tout seul — puis retoucher une fois « Se
  connecter avec Apple » pour recevoir ce ticket.
- **Un e-mail listé reste « Gratuit »** : avec « Masquer mon adresse e-mail »,
  Apple transmet une adresse `…@privaterelay.appleid.com` ; c'est elle qu'il
  faut lister (elle s'affiche dans l'app après la connexion), ou se reconnecter
  en choisissant « Partager mon adresse e-mail ».
