# Brocolis 🥦 — extension de chiffrement qui se greffe sur tes apps de messagerie (iOS)

Petite app iOS native (Swift) qui ajoute le **chiffrement sélectif de
[brocolis 🥦](https://maxlestage.github.io/brocolis/)** à **n'importe quelle app
de messagerie existante** (WhatsApp, iMessage, Messenger, Notes…) via une
**Action Extension** dans le menu **Partager**.

> 🌐 **Site vitrine** : une vitrine React (dans [`site/`](site/)) qui rend ce
> README. Elle est **servie par le serveur de rendez-vous lui-même**, sur la
> seconde page **`/site/`** :
> <https://brocolis-serveur-839b43057467.herokuapp.com/site/>. Pas besoin d'un
> hébergement séparé : une seule app Heroku sert l'API d'appairage **et** la
> vitrine.
>
> Pour régénérer la vitrine embarquée après une modif du README ou du site :
> `cd site && npm run build:embed` (construit `site/dist` et le recopie dans
> [`server/public/`](server/public/), d'où le serveur la sert).

## Pourquoi une extension (et pas un proxy en arrière-plan)

Sur un iPhone **non jailbreaké**, une app ne peut pas s'injecter dans une autre
(sandbox), et un proxy MITM en arrière-plan façon brocolis est **bloqué par le
TLS pinning** de WhatsApp/iMessage. Le moyen pris en charge par iOS pour « se
greffer » sur les apps existantes, c'est l'**extension système**. Ici on utilise
une **Action Extension** sur le texte sélectionné.

> 🌍 **Disponible dans toutes les apps.** L'extension utilise la règle
> d'activation `TRUEPREDICATE` : Brocolis 🥦 apparaît dans la feuille **Partager**
> de **n'importe quelle app** (pas seulement celles qui exposent le texte d'une
> manière particulière). Quand l'app partage du texte, Brocolis agit ; sinon, il
> l'indique. Le **clavier** Brocolis, lui, est universel par construction : il
> marche dans **tous** les champs de saisie.

## Comment ça marche

1. Ouvre l'app **Brocolis 🥦** pour gérer tes **clés nommées** (ex. « Maman »,
   « Travail ») : génère‑en, importe‑en, ou appaire‑toi. La **clé sélectionnée**
   sert à chiffrer ; au **déchiffrement, toutes tes clés sont essayées** (un
   message d'un correspondant se déchiffre avec la clé qui lui correspond).
   Transmets une clé par un canal sûr (ou utilise l'appairage).
2. Mets l'interrupteur **Actif** sur ON. Brocolis **reste actif** tant que tu ne
   le repasses pas sur OFF (ou que tu ne fermes pas l'app). Quand c'est actif,
   un **🥦 s'affiche dans la Dynamic Island** (et sur l'écran verrouillé) via
   une Live Activity — voir plus bas.
3. Dans **n'importe quelle app**, sélectionne du texte → **Partager** →
   **Brocolis 🥦**. Quand c'est actif, l'extension :
   - **chiffre toute la sélection** d'un bloc par défaut (réglage **« Tout
     chiffrer »**, activé) — pas besoin de marquer le texte, même quand tu es
     seul ;
   - si tu **désactives** « Tout chiffrer », elle ne chiffre que les segments
     `((entre doubles parenthèses))` et laisse le reste en clair ;
   - **déchiffre** automatiquement si la sélection contient des jetons
     `[[BROCOLIS:v1:…]]` (déchiffrement toujours prioritaire) ;
   - **copie** le résultat tout de suite — il n'y a plus qu'à coller.

> 📖 **Lire toute une conversation d'un coup, sans copier-coller.** Dans WhatsApp
> (et la plupart des messageries), tu peux **sélectionner plusieurs messages**
> (appui long sur un message → coche-en plusieurs) puis **Partager → Brocolis
> 🥦**. L'extension **agrège tous les messages** sélectionnés et affiche **toute
> la conversation en clair**, à l'écran, en un seul geste — c'est du *Partage*,
> pas du copier-coller. (iOS interdit à une app de lire directement les bulles
> d'une autre app ; le Partage multi-messages est le moyen le plus simple et
> **fiable** d'y arriver — contrairement à l'OCR d'une capture, qui se trompe sur
> le texte chiffré.)

La clé, l'état **Actif** et le réglage **« Tout chiffrer »** sont partagés
entre l'app et l'extension via un **App Group**.

### Lire (et répondre) à la volée — écran « Conversation »

Pour **ne plus déchiffrer message par message**, l'app a un écran **Conversation**
(bouton **« Ouvrir la conversation »** en haut de l'écran principal) :

- **colle toute la discussion** (ou Partage‑la vers Brocolis) → chaque ligne est
  rendue **automatiquement, à la volée** : les messages chiffrés avec **une de
  tes clés** s'affichent **en clair** (🔓), et ceux chiffrés avec **d'autres
  clés restent chiffrés** (🔒 — « pour les autres ») ;
- le **champ de saisie** chiffre **ta réponse au fil de la frappe** avec la clé
  sélectionnée : un tap **copie le jeton** `[[BROCOLIS:v1:…]]`, tu n'as plus
  qu'à le coller dans ta vraie messagerie.

> ⚠️ **Limite iOS** : une app ne peut pas lire ni réécrire le contenu d'une
> **autre** app (sandbox). Brocolis ne peut donc pas afficher le clair
> directement *dans* WhatsApp/iMessage. L'écran Conversation est l'endroit où la
> lecture/écriture devient **automatique** sans passer par le menu Partager pour
> chaque message.

### Envoyer chiffré **sans copier** — le Clavier Brocolis 🥦

Pour ne plus jamais copier-coller à l'envoi, Brocolis fournit un **clavier
personnalisé** qui chiffre/déchiffre **directement dans le champ de saisie**, sur
place, dans **n'importe quelle app** (WhatsApp, iMessage, Notes…) :

1. **Active-le une fois** : Réglages → Général → Clavier → Claviers → **Ajouter
   un clavier** → **Brocolis 🥦**, puis touche-le et active **Autoriser l'accès
   complet** (indispensable : sans ça, iOS isole le clavier et il ne voit pas tes
   clés de l'App Group).
2. **À l'usage** : tape ton message avec ton clavier habituel, bascule sur
   Brocolis avec le **🌐**, puis touche **🔒 Chiffrer** → le contenu du champ est
   **remplacé chiffré sur place**, prêt à envoyer, **sans aucune copie**. **🔓
   Déchiffrer** fait l'inverse sur un brouillon chiffré.
3. **Lire un message reçu sans changer d'app** : fais un **appui long → Copier**
   sur le message chiffré reçu (tu restes dans WhatsApp/iMessage), bascule sur le
   clavier Brocolis avec le **🌐**, puis touche **📋 Lire** → le message
   s'affiche **en clair directement sur le clavier**. Tu lis sans jamais quitter
   la conversation.

Le clavier respecte l'état **Actif**, la **clé sélectionnée** et l'**expiration**
comme l'extension Partager (mêmes clés via l'App Group). C'est un clavier
« action » : il ne remplace pas ta saisie habituelle, il ajoute juste les deux
gestes chiffrer/déchiffrer.

### Écrire à plusieurs personnes à la fois — destinataires multiples

Par défaut, un message est chiffré pour **une** clé (la clé sélectionnée). Tu
peux aussi le chiffrer pour **plusieurs clés en même temps** : dans l'app,
section **« Chiffrer pour »**, coche plusieurs clés (ex. « Maman » + « Travail »).

- Le message devient **lisible par tous les destinataires cochés**, mais reste
  illisible pour les autres.
- Techniquement, c'est un **chiffrement d'enveloppe** (jeton `[[BROCOLIS:v2:…]]`) :
  le texte est chiffré **une seule fois** sous une clé de message aléatoire,
  elle-même **emballée sous chaque clé** destinataire. Résultat : **un seul
  jeton**, chacun lit en clair, **aucun cadenas résiduel** (contrairement à un
  simple « un jeton par clé »).
- En **lecture**, rien à régler : toutes tes clés sont déjà essayées, et les
  jetons `v1` comme `v2` sont gérés.

> ⚠️ Le format `v2` est **spécifique à Brocolis** : il est lisible par une app
> Brocolis à jour, mais **pas par l'ancien proxy `brocolis` v1**. Pour rester
> 100 % interopérable avec brocolis, n'utilise qu'**une** clé (jeton `v1`).

### État « Actif »

- Brocolis reste actif **en permanence** : l'état est stocké dans l'App Group et
  **ne se remet jamais à zéro tout seul** — ni en sortant de l'app, ni à sa
  fermeture par iOS, ni au redémarrage du téléphone. Plus besoin de le relancer
  chaque jour.
- Le seul moyen de l'arrêter est de le **mettre en pause** toi-même (interrupteur
  dans l'app, bouton « En pause », ou raccourci Siri « Désactive Brocolis »).
- Tant qu'il est **en pause** (ou sans clé), l'extension n'agit pas et l'indique.
- Note : le 🥦 de la **Dynamic Island** (Live Activity) a une limite système
  (~8 h) et peut disparaître ; ce n'est qu'un *indicateur visuel* — le
  chiffrement, lui, continue de fonctionner via l'état stocké.

## Appairage automatique (sans copier la clé)

Plutôt que de copier-coller la clé symétrique, deux personnes peuvent
**l'obtenir automatiquement** par accord de clé **X25519 (ECDH)** :

1. Les deux ouvrent l'app → **Appairer automatiquement**, renseignent
   **le même code court** (ex. `ABC123`). Le serveur de rendez-vous est fixé
   dans l'app : <https://brocolis-serveur-839b43057467.herokuapp.com>.
2. Chaque téléphone publie sa **clé publique** sur le serveur de rendez-vous et
   récupère celle de l'autre, puis **dérive seul** la même clé AES (HKDF). La
   clé secrète n'est jamais transmise ; le serveur ne voit que des clés
   publiques.
3. L'app affiche une **empreinte de sécurité** : comparez-la de vive voix. Si
   elle est identique des deux côtés, personne n'a intercepté l'échange (MITM).

Le serveur de messagerie est dans [`server-rust/`](server-rust/) (Rust · Actix + SeaORM) ;
l'instance de production tourne sur Heroku (URL ci-dessus, fixée en dur dans
l'app). L'appairage active automatiquement Brocolis ; l'extension utilise
ensuite la clé dérivée comme d'habitude.

> Le code court ne sert qu'à se *rejoindre* : la sécurité réelle vient de X25519
> et de la vérification de l'empreinte.

### Groupe (3+) — automatique

Tout le monde saisit le même code, puis :

1. Les **membres** touchent **Rejoindre le groupe** (ils publient leur clé
   publique et attendent).
2. Le **fondateur** touche **Créer le groupe** : l'app génère une clé de groupe
   AES aléatoire et la **distribue, emballée (chiffrée) pour chaque membre** via
   X25519. Chaque membre la **déballe** avec sa clé privée.

Résultat : tous partagent **la même clé** automatiquement, sans copier-coller,
et l'extension fonctionne pour tout le groupe. Comparez l'**empreinte** (dérivée
de la clé de groupe) : elle doit être identique pour tous.

Le serveur ne voit que des **clés publiques** et des **blobs chiffrés** ; il ne
peut pas déballer la clé de groupe. Plafond de participants par code :
`MAX_PEERS` (défaut 16).

## Rotation & expiration de la clé

- **Expiration** : dans l'app, règle la **Validité de la clé** (Jamais / 1 h /
  24 h / 7 j). À l'installation d'une clé, sa date d'expiration est calculée.
  Au-delà, l'**extension refuse** de chiffrer/déchiffrer (« clé expirée ») tant
  qu'on ne renouvelle pas la clé.
- **Purge automatique à l'ouverture** : au lancement et au retour au premier
  plan, l'app **efface** une clé périmée (ce qui désactive Brocolis) et le
  signale. La clé expirée ne traîne donc pas sur l'appareil.
- **Préavis d'expiration** : une **notification locale** prévient avant
  l'échéance (≈ 1 h avant pour les longues durées, sinon la moitié du TTL),
  même app fermée, plus une notification à l'expiration. L'écran affiche aussi
  « Expire dans … » et passe en alerte quand l'échéance approche. (iOS demande
  l'autorisation de notifier la première fois qu'une clé a une durée de vie.)
- **Prolonger en un tap** : la notification porte deux actions —
  **« Prolonger la clé »** qui **réarme la validité** de la clé courante (même
  clé, sans ouvrir l'app) et reprogramme le préavis, et **« Ouvrir pour
  renouveler »** qui ouvre l'app directement sur l'écran d'appairage pour une
  **vraie rotation** (nouvelle clé de groupe).
- **Rotation** : pour un groupe, le fondateur relance **Créer le groupe** → une
  **nouvelle clé** est générée et redistribuée (le `/wrap` du serveur écrase
  l'ancienne) ; les membres la récupèrent en re-touchant **Rejoindre le
  groupe**. Installer une nouvelle clé réarme aussi l'horloge d'expiration.

## Interopérable avec brocolis

Même format de jeton (`[[BROCOLIS:v1:…]]`, AES-256-GCM,
`nonce(12) ‖ ciphertext ‖ tag(16)` = représentation `combined` de CryptoKit) :
une clé `brocolis keygen` fonctionne dans l'app, et les jetons sont
déchiffrables par brocolis (et inversement).

## Interopérable avec Android (app native disponible)

Le protocole n'utilise **que des standards ouverts** — rien de propriétaire
Apple : X25519 (RFC 7748, clés publiques en 32 octets bruts base64),
HKDF-SHA256 (RFC 5869, sels `brocolis-x25519` / `brocolis-x25519-wrap`,
info = concaténation triée des deux clés publiques) et AES-256-GCM (NIST).
Un client Android peut donc s'appairer avec un iPhone et échanger des jetons,
avec `java.security`/`javax.crypto` (X25519 natif depuis Android 13) ou
Tink/libsodium pour les versions antérieures.

L'**app Android native existe désormais** et est à **parité fonctionnelle** avec
cette app iOS — [**Messageries-kotlin**](https://github.com/maxlestage/Messageries-kotlin)
(Kotlin / Jetpack Compose). Elle reprend, point par point, les mêmes
fonctionnalités :

| Fonction iOS | Équivalent Android |
|---|---|
| Action Extension (menu Partager) | Activité `PROCESS_TEXT` + Partager |
| Écran Conversation (lecture à la volée) | `ConversationScreen` (logique pure partagée) |
| Réglage « Tout chiffrer » | identique (activé par défaut) |
| Clavier Brocolis (chiffre/déchiffre en place) | clavier IME `BrocolisKeyboardService` |
| Widget (état/clé/expiration) | App Widget d'écran d'accueil |
| Live Activity « actif » (Dynamic Island) | notification permanente silencieuse |
| Appairage X25519 (1:1 + groupe) | identique (même serveur de rendez-vous) |
| Rotation / expiration + préavis | identique (`AlarmManager`) |

L'interopérabilité est **vérifiée par des tests** : les tests de l'app ([`BrocolisTests`](BrocolisTests/))
valide les primitives contre les vecteurs officiels des RFC (ceux-là mêmes que
CryptoKit implémente), puis déroule le flux complet entre deux clients
indépendants — appairage, même clé dérivée, même empreinte, clé de groupe
emballée/déballée, jetons déchiffrés croisés dans les deux sens. Le cœur crypto
Android rejoue les **mêmes vecteurs RFC/NIST** côté JVM, garantissant la
compatibilité bit-à-bit : un message chiffré sur iPhone se déchiffre sur Android
(et inversement).

## Structure

```
Brocolis.xcodeproj
Shared/                       # code partagé app + extension
  BrocolisCrypto.swift        # AES-256-GCM, format de jeton brocolis
  BrocolisKeyStore.swift      # clé + état actif + appairage (App Group)
  BrocolisTransform.swift     # chiffre/déchiffre en un geste (auto-détection)
  BrocolisConversation.swift  # rend une discussion entière à la volée (logique pure)
  BrocolisKeyAgreement.swift  # accord de clé X25519 (ECDH + HKDF) + empreinte
  BrocolisActivityAttributes.swift # attributs de la Live Activity 🥦
Brocolis/                     # app hôte
  BrocolisApp.swift, RootView.swift, Assets, Brocolis.entitlements
  ConversationView.swift      # écran « Conversation » : lecture/écriture à la volée
  PairingView.swift           # écran d'appairage automatique
  PairingClient.swift         # client du serveur de rendez-vous
  BrocolisLiveActivity.swift  # démarre/termine la Live Activity « actif »
BrocolisAction/               # Action Extension (menu Partager)
  ActionViewController.swift, Info.plist, BrocolisAction.entitlements
BrocolisKeyboard/             # Clavier personnalisé (chiffre/déchiffre en place)
  KeyboardViewController.swift, Info.plist, BrocolisKeyboard.entitlements
BrocolisStatus/               # extension widget : Dynamic Island + écran d'accueil
  BrocolisStatusLiveActivity.swift # Live Activity (🥦 quand actif)
  BrocolisStatusWidget.swift  # widget accueil/verrouillage (état, clé, expiration)
  Info.plist, BrocolisStatus.entitlements
BrocolisiMessage/             # mini-app iMessage (envoyer chiffré depuis Messages)
  MessagesViewController.swift, Info.plist, BrocolisiMessage.entitlements
BrocolisWatch/                # app Apple Watch (watchOS 9+, embarquée dans l'app iOS)
  BrocolisWatchApp.swift      # point d'entrée SwiftUI de la montre
  WatchRootView.swift         # liste des clés synchronisées depuis l'iPhone
  WatchConversationView.swift # lire / répondre au poignet (déchiffré sur la montre)
  WatchSyncReceiver.swift     # réception WatchConnectivity (clés + état actif)
  BrocolisWatch.entitlements
BrocolisTests/                # tests XCTest (crypto, transform, accord de clé)
server-rust/                  # serveur de messagerie chiffrée (Rust · Actix + SeaORM)
```

## Lancer le projet

Pré-requis : **Xcode 15+**, iOS 16+.

```sh
open Brocolis.xcodeproj
```

> 🛠️ **Projet généré par XcodeGen** : la structure est décrite dans
> [`project.yml`](project.yml). Après une modif (nouveau fichier, réglage),
> régénère avec `brew install xcodegen && xcodegen generate`, plus besoin
> d'éditer le pbxproj à la main. **Attention** : une cible présente dans le
> pbxproj mais absente de `project.yml` est *supprimée* par la régénération,
> sans erreur. La CI le vérifie à chaque PR
> ([`.github/scripts/check_project_spec.py`](.github/scripts/check_project_spec.py),
> lançable à la main).
>
> ✅ **Tests à chaque PR** : [`ios-tests.yml`](.github/workflows/ios-tests.yml)
> compile l'app — extensions et app montre comprises — et lance les tests
> XCTest sur simulateur, dès qu'une PR touche du code iOS. Les runners macOS
> étant facturés 10× les runners Linux, le workflow filtre par chemins, annule
> les runs superposés, et fait tourner le contrôle `project.yml` sur Linux.
>
> ☁️ **CI via Xcode Cloud** (recommandé) : le guide pas à pas est dans
> [`docs/XCODE_CLOUD.md`](docs/XCODE_CLOUD.md). Il tourne sur l'infra d'Apple et
> publie le statut sur les PR — utile quand les runners macOS de GitHub Actions
> ne sont pas disponibles.

> 🥦 **Indicateur « actif »** : iOS n'autorise pas d'icône dans la barre de
> statut système. À la place, quand Brocolis est activé, une **Live Activity**
> affiche un 🥦 dans la **Dynamic Island** (iPhone 14 Pro et suivants) et une
> bannière sur l'écran verrouillé (iOS 16.1+). Elle disparaît quand tu
> désactives Brocolis (limite système : ~8 h, rouvre l'app pour la relancer).
>
> 📱 **Widget** : un widget **Brocolis 🥦** (appui long sur l'écran d'accueil →
> ➕ → Brocolis) montre en permanence l'état actif/inactif, la clé sélectionnée
> et son expiration. Disponible en **petit, moyen et grand** (accueil) et en
> **écran verrouillé** (cercle, ligne, rectangle). Il se met à jour à chaque
> changement dans l'app.
>
> 🔘 **Bouton interactif (iOS 17+)** : les widgets d'accueil (petit/moyen/grand)
> ont un bouton **Activer / Mettre en pause** qui bascule l'état de Brocolis
> **sans ouvrir l'app** (via un App Intent widget-safe). Sur iOS 16, le widget
> reste en simple affichage.
>
> ⚡️ **Raccourcis (Siri / app Raccourcis / bouton Action)** : trois App Intents
> — **Activer**, **Désactiver**, **Basculer** Brocolis — permettent de changer
> l'état sans ouvrir l'app (« Dis Siri, active Brocolis »). Ils mettent aussi à
> jour la Live Activity et les widgets. Voir `Brocolis/BrocolisShortcuts.swift`.
>
> 💬 **Live Activity de messagerie** : la même Live Activity sert de fil de
> messagerie. Elle affiche le **nombre de messages non lus**, le **nom** de
> l'expéditeur du dernier message et **l'heure** de réception — jamais le
> texte : le contenu reste chiffré de bout en bout et la Live Activity n'y a
> pas accès. Le compteur retombe à zéro dès que tu ouvres la conversation.
> Voir `Shared/BrocolisActivityAttributes.swift`.
>
> ⌚️ **Apple Watch** : `BrocolisWatch` est une **vraie app watchOS 9+**
> (single-target, embarquée dans le bundle iOS — installée automatiquement avec
> l'app sur l'iPhone appairé). Tes clés et l'état actif sont poussés depuis
> l'iPhone via **WatchConnectivity** (`Brocolis/BrocolisWatchSync.swift` →
> `BrocolisWatch/WatchSyncReceiver.swift`) ; la montre déchiffre et chiffre
> **elle-même**, avec le même `BrocolisCrypto` que l'iPhone. Tu peux donc lire
> et répondre au poignet sans sortir le téléphone.

Dans Xcode, pour **chaque** cible (`Brocolis`, `BrocolisAction`,
`BrocolisStatus` et `BrocolisKeyboard`) :

1. **Signing & Capabilities** → choisis ton équipe de signature.
2. Vérifie la capacité **App Groups** avec le groupe
   `group.rs.brocolis.messagerie` activé sur les **quatre** cibles (ou
   remplace par ton propre identifiant de groupe, identique partout et dans
   `BrocolisKeyStore.appGroup`) — le widget et le clavier lisent l'état via ce
   groupe.
3. Sélectionne le schéma **Brocolis**, un iPhone/simulateur, puis **Run**.

Pour tester l'extension : lance l'app (la clé), puis va dans une app avec du
texte (Notes, Messages…), sélectionne du texte → **Partager** → **Brocolis 🥦**.

## Tests

La cible **BrocolisTests** (XCTest) couvre le chiffrement et la transformation :
round-trips, format de jeton interopérable brocolis (`nonce|ct|tag`), Unicode /
emoji, mauvaise clé, jeton altéré/corrompu, marqueurs non fermés ou vides,
jetons adjacents, gros volumes, unicité des nonces, et l'auto-détection
chiffrer/déchiffrer de l'extension.

Elle inclut aussi l'**accord de clé X25519** (les deux côtés dérivent la même
clé AES, clé dérivée utilisable pour chiffrer/déchiffrer, format d'empreinte).

```
Cmd+U dans Xcode   (ou : xcodebuild test -scheme Brocolis -destination 'platform=iOS Simulator,name=iPhone 15')
```

Le **serveur de rendez-vous** a ses propres tests Node (exécutables partout) —
ils vérifient le flux d'appairage, que **les deux appareils dérivent une clé
identique**, et l'**interopérabilité iPhone ↔ Android** (vecteurs officiels
RFC 7748 / RFC 5869 / NIST GCM + flux croisé complet, voir
`BrocolisTests/`) :

```
cd server && npm test
```

## Sécurité — limites

- L'extension protège le contenu **marqué** (ou la sélection) ; elle ne chiffre
  pas automatiquement tout ce que tu envoies — c'est un geste explicite.
- La clé est en **App Group** (`UserDefaults` du conteneur partagé) par
  simplicité ; pour la production, préférer un groupe d'accès **Trousseau**
  partagé.
- Clé **symétrique** : sa diffusion doit passer par un canal sûr, comme brocolis.

## Publier sur TestFlight

Brocolis est une app iOS native : elle se partage via **TestFlight**. Le projet
est déjà prêt (équipe de signature, bundle IDs, App Group), il reste les étapes
côté Apple.

### Pré-requis
- **Apple Developer Program** actif (compte payant). L'équipe de signature est
  fixée dans le projet (`DEVELOPMENT_TEAM = 2FW8T4UX4L`).
- **Xcode 15+**.

### Identifiants à enregistrer (developer.apple.com)
La signature automatique de Xcode peut les créer, sinon vérifie qu'existent :
- les **6 App IDs** :
  - `rs.brocolis.messagerie` (app)
  - `rs.brocolis.messagerie.action` (Action Extension)
  - `rs.brocolis.messagerie.status` (widget / Live Activity)
  - `rs.brocolis.messagerie.keyboard` (clavier)
  - `rs.brocolis.messagerie.imessage` (mini-app iMessage)
  - `rs.brocolis.messagerie.watchkitapp` (app Apple Watch)
- l'**App Group** `group.rs.brocolis.messagerie`, activé sur **toutes** les cibles.

### Conformité export (chiffrement) — déjà déclarée
L'app chiffre (AES‑256‑GCM, X25519). La clé
**`ITSAppUsesNonExemptEncryption = YES`** est déclarée dans l'Info.plist généré
de la cible `Brocolis` (réglage `INFOPLIST_KEY_ITSAppUsesNonExemptEncryption`).
Comme la fonction principale de l'app **est** le chiffrement, prévois de fournir
ton **auto‑classification d'export (ERN/CCATS)** dans App Store Connect au premier
build. (Si tu estimes relever de l'exemption « chiffrement standard », repasse
cette valeur à `NO` — c'est une décision juridique qui t'appartient.)

### Étapes
1. Sur **App Store Connect**, crée la fiche app avec le bundle ID
   `rs.brocolis.messagerie` (icône 1024×1024 requise).
2. Dans Xcode : scheme **Brocolis**, destination **Any iOS Device**, puis
   **Product → Archive**.
3. Dans l'Organizer : **Distribute App → App Store Connect → Upload**.
4. App Store Connect → onglet **TestFlight** :
   - **Test interne** (jusqu'à 100 testeurs de ton équipe) : disponible
     quasi immédiatement, **sans revue**.
   - **Test externe** (jusqu'à 10 000) : passe par une **Beta App Review**
     (plus légère que la revue App Store).
5. Invite les testeurs (e‑mail ou lien public). Ils installent l'app
   **TestFlight** puis Brocolis.

> Pas de push distant ici : Live Activities et notifications locales
> fonctionnent en TestFlight sans configuration serveur. Le serveur de
> rendez‑vous (Heroku) est public, rien à changer pour la distribution.

## Licence

© 2026 **LESTAGE Maxime Nathan** — Tous droits réservés. Logiciel
**propriétaire** : voir le fichier [`LICENSE`](LICENSE). Ce projet accompagne
[brocolis](https://maxlestage.github.io/brocolis/), également propriétaire.
Fourni « TEL QUEL », sans garantie.
