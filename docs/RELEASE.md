# Guide de release — Brocolis 🥦

Checklist de bout en bout pour livrer l'app iOS, activer les notifications push,
et faire tourner le proxy `brocolis`. Team Apple : **`2FW8T4UX4L`**.

---

## 0. Prérequis (une fois)

- [ ] Compte **Apple Developer** payant (accès App Store Connect + APNs).
- [ ] Fusionner les PR d'intégration (`Messagerie-` #20, `brocolis` #17).
- [ ] Un Mac n'est **pas** requis pour builder : la CI GitHub le fait. Il l'est
      seulement si tu veux archiver toi-même depuis Xcode.

---

## 1. App iOS → TestFlight (CI automatique)

Détail : [`docs/ios-testflight.md`](ios-testflight.md).

**a. Clé API App Store Connect**
1. [ ] appstoreconnect.apple.com → **Users and Access → Integrations → App Store Connect API**.
2. [ ] **Generate API Key**, rôle *App Manager*.
3. [ ] Noter **Issuer ID** + **Key ID**, télécharger le **`.p8`** (téléchargeable une seule fois).

**b. Secrets GitHub** (dépôt `Messagerie-` → Settings → Secrets and variables → Actions)
- [ ] `ASC_KEY_ID` = Key ID
- [ ] `ASC_ISSUER_ID` = Issuer ID
- [ ] `ASC_KEY_P8` = contenu complet du `.p8`

**c. Enregistrer l'app** (une fois)
- [ ] App Store Connect → **Apps → +** → bundle **`rs.brocolis.messagerie`**.
- [ ] Régler la **conformité export** au premier build (l'app chiffre : voir ios-testflight.md).

**d. Livrer**
- [ ] `git tag v1.0.0 && git push origin v1.0.0` → le workflow **iOS TestFlight** archive, signe (cloud) et téléverse.
- [ ] Le **numéro de build** est géré par la CI ; le **numéro de version** (`MARKETING_VERSION`) se change dans Xcode pour une nouvelle version.

---

## 2. Notifications push — Live Activity (serveur)

Détail : [`docs/ios-push-live-activity.md`](ios-push-live-activity.md) et [`server/.env.example`](../server/.env.example).

**a. Clé APNs** (distincte de la clé App Store Connect)
1. [ ] developer.apple.com → **Certificates, IDs & Profiles → Keys → +**.
2. [ ] Cocher **Apple Push Notifications service (APNs)**, télécharger le `.p8`, noter le Key ID.

**b. Variables du serveur de rendez-vous** (Heroku ou autre)
- [ ] `APNS_KEY_P8` = contenu du `.p8`
- [ ] `APNS_KEY_ID` = Key ID de la clé APNs
- [ ] `APNS_TEAM_ID` = `2FW8T4UX4L`
- [ ] `APNS_BUNDLE_ID` = `rs.brocolis.messagerie`
- [ ] `APNS_ENV` = `sandbox` (builds development) ou `production` (TestFlight/App Store)
- [ ] Redéployer le serveur.

> Sans ces variables, tout fonctionne sauf l'envoi : `/push/live-activity/update`
> répond `503`. Le reste (appairage, chiffrement) est indépendant.

**c. Vérifier**
- [ ] Appairer deux appareils, activer Brocolis (Live Activity 🥦 visible).
- [ ] Toucher **« Notifier mes correspondants »** → l'activité du correspondant se met à jour.

---

## 3. Proxy brocolis (Rust, optionnel)

Détail : `Readme.md` du dépôt `brocolis`.

- [ ] `cargo build --release`
- [ ] `brocolis ca` → installer le CA généré dans le navigateur.
- [ ] `brocolis run` (ou `brocolis auto` pour régler aussi le proxy système).
- [ ] Parler à quelqu'un : `brocolis pair --code 4291` (à deux) ou
      `brocolis pair-group --code 4291 [--found]` (groupe). La clé dérivée
      s'ajoute à `brocolis.toml` ; redémarrer pour l'activer.

---

## Intégration continue

| Dépôt | Workflow | Vérifie |
|-------|----------|---------|
| `Messagerie-` | `ci.yml` | Build + XCTest de l'app iOS (simulateur) |
| `Messagerie-` | `ios-testflight.yml` | Archive + upload TestFlight : automatique après chaque passage au vert de « iOS build & tests » sur master, ou sur tag `v*` |
| `Messagerie-` | `server-tests.yml` | `node --test` du serveur de rendez-vous |
| `brocolis` | `rust.yml` | `cargo test` + `clippy -D warnings` |
