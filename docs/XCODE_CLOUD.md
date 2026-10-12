# Brocolis 🥦 — Configuration Xcode Cloud

Xcode Cloud est le CI/CD d'Apple. Il tourne sur l'infrastructure d'Apple (pas
sur les runners GitHub Actions), ce qui **contourne le blocage des runners
macOS** rencontré sur GitHub. Ce dépôt contient déjà tout ce qui doit y être ;
la création du workflow, elle, se fait dans Xcode / App Store Connect.

## Deux chaînes, deux rôles

| | À chaque poussée | Pour une sortie |
|---|---|---|
| **GitHub Actions** (`ios-testflight.yml`) | tests iOS puis **TestFlight**, builds **10000+** | — |
| **Xcode Cloud** | compile et **teste**, sans archiver | workflow **« Release »** (démarrage manuel) ou tag → TestFlight / App Store |

À régler une fois dans App Store Connect → Brocolis → Xcode Cloud :

1. **Workflow par défaut** : action **Test** (au lieu d'Archive), pas de
   post-action TestFlight.
2. **Workflow « Release »** : copie du précédent, Start Conditions → **Manual**,
   action **Archive**, post-action **TestFlight** et/ou **App Store**.
3. **Settings → Build Number** : prochain numéro **5000**. Xcode Cloud impose
   son propre compteur à la livraison (le script `ci_pre_xcodebuild.sh` n'y
   change rien) ; 5000+ reste sous les 10000+ de GitHub, sans jamais croiser.

## Ce qui est déjà prêt dans le dépôt

| Élément | Rôle |
|---|---|
| `project.yml` | Spéc **XcodeGen** : régénère `Brocolis.xcodeproj` de façon déclarative. |
| `ci_scripts/ci_post_clone.sh` | Exécuté après le clone : **arrête toute archive** sauf depuis un tag, un workflow nommé « Release » / « App Store », ou avec `BROCOLIS_XCODE_CLOUD_UPLOAD=1`. |
| `ci_scripts/ci_pre_xcodebuild.sh` | Force un **numéro de build monotone** (`CI_BUILD_NUMBER + 1000`) avant chaque archive — sans lui, TestFlight rejette les doublons `1.0 (1)` et « rien ne s'actualise ». |
| `Brocolis.xcodeproj/.../Brocolis.xcscheme` | **Scheme partagé** (requis par Xcode Cloud) qui inclut la cible de tests `BrocolisTests`. |

> **Numéro de build & TestFlight.** Le projet fige `CURRENT_PROJECT_VERSION = 1`.
> App Store Connect exige un `CFBundleVersion` **strictement croissant** : sans
> incrément, le 2ᵉ upload et les suivants sont traités puis **retirés** (mail
> `ITMS-90xxx`), et TestFlight garde l'ancien build. `ci_pre_xcodebuild.sh`
> règle ça en réécrivant le numéro à partir de `CI_BUILD_NUMBER`. La **version**
> affichée (`MARKETING_VERSION`, ex. `1.0`) reste gérée dans `project.yml`.

## 1. (Optionnel) Régénérer le projet avec XcodeGen

Le projet est écrit de façon déclarative dans `project.yml`. Après toute
modification (nouveau fichier, nouveau réglage), régénère et committe :

```sh
brew install xcodegen        # une seule fois
xcodegen generate            # réécrit Brocolis.xcodeproj depuis project.yml
git add Brocolis.xcodeproj project.yml
git commit -m "Régénère le projet"
```

> Le `Brocolis.xcodeproj` **reste commité** : Xcode Cloud l'utilise tel quel.
> `project.yml` sert à le régénérer proprement, sans éditer le pbxproj à la main.

## 2. Créer le workflow Xcode Cloud

Pré-requis : appartenance au **Apple Developer Program** (payant ; Xcode Cloud
inclut **25 h de calcul/mois** gratuites) et un rôle **Admin / Account Holder**
sur App Store Connect.

Dans **Xcode** (le projet ouvert) :

1. Menu **Integrate → Create Workflow…** (ou navigateur de rapports ⌘9 →
   onglet **Cloud**).
2. Connecte-toi avec ton Apple ID App Store Connect, choisis le produit
   **Brocolis**.
3. Autorise Xcode Cloud à accéder au dépôt GitHub `maxlestage/Messagerie-`
   (installe l'app GitHub « Xcode Cloud » quand c'est demandé).
4. Configure le workflow :
   - **Nom** : `Build & Test`
   - **Environnement** : *Xcode — Latest Release* ; macOS automatique.
   - **Conditions de démarrage** :
     - *Pull Request Changes* → branche cible `master` (vérifie chaque PR),
     - et/ou *Branch Changes* → `master`.
   - **Actions** :
     - **Build** — Scheme `Brocolis`, plateforme *iOS*.
     - **Test** — Scheme `Brocolis`, destination *iOS Simulator*
       (« Recommended Simulators » ou un iPhone récent). Lance `BrocolisTests`.
   - **Post-Actions** : aucune pour l'instant (ajouter *TestFlight (Internal
     Testing)* plus tard pour distribuer).
5. **Enregistre** → le premier build se lance.

Ensuite, Xcode Cloud publie automatiquement son **statut sur tes PR GitHub**
(coche verte/rouge), à la place de la CI GitHub Actions.

## 3. Signature

- **Build + Test sur simulateur** : aucun certificat requis.
- **Archive / TestFlight** : Xcode Cloud gère la signature **automatiquement**
  (managed signing). Assure-toi que les App IDs
  (`rs.brocolis.messagerie`, `.action`, `.status`, `.keyboard`) et l'**App
  Group** `group.rs.brocolis.messagerie` existent dans le portail développeur
  (la signature automatique d'Xcode les crée en général au premier build).

## 4. Pour TestFlight / App Store

- **Conformité export** : `INFOPLIST_KEY_ITSAppUsesNonExemptEncryption = NO`
  (dans `project.yml` **et** le `.xcodeproj`). Brocolis n'utilise que du
  chiffrement **standard fourni par Apple** (CryptoKit : AES-GCM, X25519) → il
  est **exempté**, donc `NO`. ⚠️ Mettre `YES` **sans** code de conformité
  (`ITSEncryptionExportComplianceCode`) provoque le rejet **ITMS-90592**. ✅
- **Numéro de build** : géré automatiquement par `ci_scripts/ci_pre_xcodebuild.sh`
  (voir plus haut). ✅
- **Icône** : `AppIcon-1024.png` (1024×1024, sans alpha) est présente. ✅

➡️ **Le pas-à-pas complet pour lancer le premier build TestFlight est dans
[TESTFLIGHT.md](TESTFLIGHT.md).**

## 5. Et la CI GitHub Actions ?

`.github/workflows/ci.yml` reste dans le dépôt mais **échoue actuellement**
(runners macOS non alloués côté GitHub). Une fois Xcode Cloud en place, tu peux
soit le laisser, soit le supprimer pour éviter des coches rouges parasites sur
les PR :

```sh
git rm .github/workflows/ci.yml && git commit -m "CI : passe à Xcode Cloud"
```
