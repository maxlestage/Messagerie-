# Déployer le service messagerie Rust sur Heroku

Ce guide déploie le service **Rust** (`server-rust/`, Actix + SeaORM) sur une
**app Heroku DÉDIÉE**, séparée de la prod Node. La prod (app iOS → serveur Node)
**n'est pas touchée** tant que tu ne bascules pas volontairement (voir la fin).

Le service ne relaie que du **chiffré**. Persistance **Postgres** native
(rétention 7 jours), temps réel **SSE** + **Redis** (multi-dynos), push **APNs**.

> **Tout-en-un** : le script `server-rust/deploy-rust.sh` enchaîne les étapes
> 1 à 5 (création app + add-ons + config APNs + build/release + logs), de façon
> idempotente. Ex. :
> ```bash
> cd server-rust
> ./deploy-rust.sh brocolis-rust
> # avec APNs :
> APNS_KEY_ID=… APNS_TEAM_ID=… APNS_BUNDLE_ID=rs.brocolis.messagerie \
>   APNS_KEY_P8_FILE=./AuthKey_XXXX.p8 ./deploy-rust.sh brocolis-rust
> ```
> Les sections ci-dessous détaillent chaque étape (utile si tu préfères la main).

---

## 0. Prérequis

- [CLI Heroku](https://devcenter.heroku.com/articles/heroku-cli) installée et `heroku login`.
- Docker installé et lancé (pour `container:push`).
- Depuis la racine du dépôt.

---

## 1. Créer l'app dédiée (stack conteneur)

```bash
heroku create brocolis-rust --stack container   # choisis ton nom d'app
```

## 2. Ajouter les add-ons

```bash
# Postgres (persistance durable) → fournit DATABASE_URL
heroku addons:create heroku-postgresql:essential-0 -a brocolis-rust

# Key-Value / Redis (temps réel inter-dynos) → fournit REDIS_URL
heroku addons:create heroku-redis:mini -a brocolis-rust
```

`DATABASE_URL` et `REDIS_URL` sont injectés automatiquement. Le service crée son
schéma Postgres au démarrage (idempotent) et gère le TLS Heroku tout seul
(Postgres `sslmode=require`, Redis `rediss://`).

## 3. Variables APNs (Live Activity) — optionnel

Sans elles, l'endpoint `/push/live-activity/update` répond simplement `503` ; le
reste marche. Pour activer le push :

```bash
heroku config:set -a brocolis-rust \
  APNS_KEY_ID=XXXXXXXXXX \
  APNS_TEAM_ID=YYYYYYYYYY \
  APNS_BUNDLE_ID=rs.brocolis.messagerie \
  APNS_ENV=sandbox        # "production" pour une build App Store

# La clé .p8 est multi-lignes : garde les retours à la ligne.
heroku config:set -a brocolis-rust APNS_KEY_P8="$(cat AuthKey_XXXXXXXXXX.p8)"
```

Réglages facultatifs : `MESSAGE_RETENTION_DAYS` (défaut 7), `MAX_PEERS` (défaut 16).

## 4. Déployer (méthode recommandée : container:push)

Isolé, n'utilise pas de `heroku.yml`, ne touche pas la prod :

```bash
cd server-rust
heroku container:push web -a brocolis-rust
heroku container:release web -a brocolis-rust
```

> La 1ʳᵉ build compile Rust + toutes les dépendances : compter quelques minutes.

## 5. Vérifier le démarrage

```bash
heroku logs -a brocolis-rust --tail
```

Tu dois voir :

```
Messagerie Brocolis 🥦 (Rust/Actix) à l'écoute sur le port ...
APNs configuré : mises à jour de Live Activity actives.   (si APNs configuré)
Redis branché : temps réel inter-dynos actif.             (si REDIS_URL)
```

Test rapide :

```bash
curl https://brocolis-rust.herokuapp.com/health      # -> ok
curl https://brocolis-rust.herokuapp.com/            # page d'accueil
```

## 6. Tester avec l'app iOS (sans toucher la prod)

Dans Brocolis, mets l'URL de test (`https://brocolis-rust.herokuapp.com`) comme
serveur de messagerie, puis vérifie : appairage (`/pair`), envoi/réception,
« Distribué / Lu », photo/vocal, et — si APNs configuré — la Live Activity.

---

## 7. Bascule en prod (quand c'est validé)

Deux options, au choix :

- **Simple** : garder deux apps et pointer l'app iOS (et le champ serveur) vers
  l'URL Rust. Le Node reste dispo en secours.
- **Remplacer** : faire du service Rust la nouvelle prod. Il faudra alors adapter
  le `heroku.yml` **racine** et le déploiement de l'app de prod pour construire
  `server-rust/Dockerfile` (ou migrer l'app de prod en `container:push` depuis
  `server-rust/`). À faire **délibérément**, une fois le Rust éprouvé.

> Astuce : migre les données en pointant la NOUVELLE app sur le MÊME add-on
> Postgres si tu veux conserver l'historique, ou repars propre (rétention 7 j).

---

## Dépannage

- **Boot qui plante sur Postgres / SSL** : le service force déjà `sslmode=require`
  pour une URL distante. Si besoin, vérifie `heroku config:get DATABASE_URL`.
- **Redis absent des logs** : sans `REDIS_URL`, c'est normal (temps réel
  intra-dyno). Avec l'add-on, vérifie que `REDIS_URL` commence par `rediss://`.
- **APNs 503** : configuration incomplète (une des 4 variables APNS_* manque ou
  la clé .p8 est mal collée). `502` = APNs a refusé (mauvais topic/clé/token).
- **La vitrine `/site/` renvoie 404** : normal, l'image Rust n'embarque pas les
  fichiers statiques (facultatifs). Règle `PUBLIC_DIR` si tu en ajoutes.
