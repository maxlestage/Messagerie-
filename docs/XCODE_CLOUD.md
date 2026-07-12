# Brocolis 🥦 — Configuration Xcode Cloud

Xcode Cloud est le CI/CD d'Apple. Il tourne sur l'infrastructure d'Apple (pas
sur les runners GitHub Actions), ce qui **contourne le blocage des runners
macOS** rencontré sur GitHub. Ce dépôt contient déjà tout ce qui doit y être ;
la création du workflow, elle, se fait dans Xcode / App Store Connect.

## Ce qui est déjà prêt dans le dépôt

| Élément | Rôle |
|---|---|
| `project.yml` | Spéc **XcodeGen** : régénère `Brocolis.xcodeproj` de façon déclarative. |
| `ci_scripts/ci_post_clone.sh` | Point d'accroche exécuté par Xcode Cloud après le clone (aucune dépendance à installer). |
| `Brocolis.xcodeproj/.../Brocolis.xcscheme` | **Scheme partagé** (requis par Xcode Cloud) qui inclut la cible de tests `BrocolisTests`. |

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

Dans `project.yml`, passe l'app en **non exemptée de chiffrement** :

```yaml
INFOPLIST_KEY_ITSAppUsesNonExemptEncryption: YES
```

(Brocolis chiffre en AES-256-GCM ; ce réglage évite le blocage « conformité
export » à chaque upload. Prévois l'auto-classification dans App Store Connect.)
Régénère ensuite avec `xcodegen generate`.

## 5. Et la CI GitHub Actions ?

`.github/workflows/ci.yml` reste dans le dépôt mais **échoue actuellement**
(runners macOS non alloués côté GitHub). Une fois Xcode Cloud en place, tu peux
soit le laisser, soit le supprimer pour éviter des coches rouges parasites sur
les PR :

```sh
git rm .github/workflows/ci.yml && git commit -m "CI : passe à Xcode Cloud"
```
