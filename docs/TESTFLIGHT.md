# Brocolis 🥦 — Lancer un build TestFlight

Le dépôt est **prêt** pour TestFlight. Ce qui suit ne peut se faire que depuis
**ton compte** (Xcode + App Store Connect) — je ne peux pas cliquer à ta place,
mais voici le chemin exact.

## Ce qui est déjà réglé côté dépôt ✅

- **Conformité export** : `ITSAppUsesNonExemptEncryption = NO`. Brocolis
  n'utilise que du chiffrement standard d'Apple (CryptoKit) → exempté. Mettre
  `YES` sans code de conformité déclenche le rejet **ITMS-90592**.
- **Numéro de build monotone** : `ci_scripts/ci_pre_xcodebuild.sh` réécrit
  `CURRENT_PROJECT_VERSION` depuis `CI_BUILD_NUMBER` (sinon le 2ᵉ upload est
  rejeté et TestFlight garde l'ancien build).
- **Icône** 1024×1024 sans alpha, **scheme partagé**, **hook** `ci_post_clone.sh`.

## Prérequis

- **Apple Developer Program** actif (99 €/an), rôle **Admin** ou **Account
  Holder** sur App Store Connect.
- Contrats « Paid/Free Apps » signés dans App Store Connect → *Business*.

## Étape 1 — Créer la fiche app sur App Store Connect

1. <https://appstoreconnect.apple.com> → **Apps** → **＋** → **Nouvelle app**.
2. Plateforme **iOS**, nom (ex. « Brocolis »), langue **Français**, **Bundle ID**
   `rs.brocolis.messagerie` (à créer dans *Certificates, Identifiers & Profiles*
   s'il n'apparaît pas), SKU libre (ex. `brocolis-1`).
3. Crée. (Pas besoin de remplir la fiche App Store pour TestFlight interne.)

> Les App IDs des extensions (`.action`, `.status`, `.keyboard`) et l'**App
> Group** `group.rs.brocolis.messagerie` : la signature automatique d'Xcode les
> crée en général au premier build. Sinon, ajoute-les à la main dans
> *Identifiers*.

## Étape 2 — Créer le workflow Xcode Cloud « Release »

Dans **Xcode**, projet ouvert :

1. Menu **Integrate → Create Workflow…** (ou ⌘9 → onglet **Cloud**), connecte-toi.
2. Nouveau workflow **Release TestFlight** :
   - **Environnement** : Xcode — Latest Release.
   - **Conditions de démarrage** : *Branch Changes* → `master` (ou *Manuel*
     pour lancer à la demande).
   - **Action** : **Archive** — Scheme `Brocolis`, plateforme **iOS**,
     configuration **Release**.
   - **Post-Action** : **TestFlight (Internal Testing Only)** → sélectionne (ou
     crée) un groupe de testeurs internes.
3. **Enregistre**.

## Étape 3 — Lancer le build

- Workflow → **Start Build** (ou pousse un commit sur `master` si tu as choisi
  ce déclencheur).
- Xcode Cloud : clone → `ci_post_clone.sh` → `ci_pre_xcodebuild.sh` (numéro de
  build) → **Archive** → **signe** (managed) → **uploade** sur App Store Connect.
- Suis l'avancement dans Xcode (onglet Cloud) ou App Store Connect → **TestFlight**.

## Étape 4 — Installer sur l'iPhone

1. App Store Connect → **TestFlight** : le build passe *Processing* puis devient
   dispo (le **test interne ne nécessite AUCUNE revue Apple** → immédiat).
2. Ajoute-toi comme testeur au groupe **Internal Testing** (jusqu'à 100 membres
   de l'équipe).
3. Installe l'app **TestFlight** sur l'iPhone, accepte l'invitation (email), et
   installe **Brocolis 🥦**.

## En cas de souci

| Symptôme | Cause / solution |
|---|---|
| Rejet **ITMS-90592** (export compliance) | `ITSAppUsesNonExemptEncryption` doit être `NO` (chiffrement standard Apple = exempté). `YES` sans code `ITSEncryptionExportComplianceCode` = rejet. |
| Le build n'apparaît pas / « rien ne s'actualise » | Numéro de build en double → `ci_pre_xcodebuild.sh` s'en charge ; vérifie qu'il est **exécutable** et que le run l'a bien exécuté (logs Xcode Cloud). |
| Erreur de signature | App ID + App Group manquants dans *Identifiers*, ou contrats non signés dans App Store Connect → *Business*. |
| « Missing app icon » | Icône présente ; vérifie qu'elle n'a pas d'alpha (la nôtre est en RGB). |
| Test **externe** demandé en revue | Le test **interne** évite la revue. La revue Beta ne concerne que les testeurs externes. |
