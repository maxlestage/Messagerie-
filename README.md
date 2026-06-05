# Brocolis 🥦 — extension de chiffrement qui se greffe sur tes apps de messagerie (iOS)

Petite app iOS native (Swift) qui ajoute le **chiffrement sélectif de
[brocolis 🥦](https://github.com/maxlestage/brocolis)** à **n'importe quelle app
de messagerie existante** (WhatsApp, iMessage, Messenger, Notes…) via une
**Action Extension** dans le menu **Partager**.

## Pourquoi une extension (et pas un proxy en arrière-plan)

Sur un iPhone **non jailbreaké**, une app ne peut pas s'injecter dans une autre
(sandbox), et un proxy MITM en arrière-plan façon brocolis est **bloqué par le
TLS pinning** de WhatsApp/iMessage. Le moyen pris en charge par iOS pour « se
greffer » sur les apps existantes, c'est l'**extension système**. Ici on utilise
une **Action Extension** sur le texte sélectionné.

## Comment ça marche

1. Ouvre l'app **Brocolis 🥦** une fois pour **générer ou importer** la clé
   partagée (équivalent de `brocolis keygen`). Transmets cette clé à ton
   correspondant par un canal sûr.
2. Mets l'interrupteur **Actif** sur ON. Brocolis **reste actif** tant que tu ne
   le repasses pas sur OFF (ou que tu ne fermes pas l'app).
3. Dans **n'importe quelle app**, sélectionne du texte → **Partager** →
   **Brocolis 🥦**. Quand c'est actif, l'extension :
   - **chiffre** les segments `((entre doubles parenthèses))` (ou toute la
     sélection si aucun marqueur) en jetons `[[BROCOLIS:v1:…]]` ;
   - **déchiffre** automatiquement si la sélection contient des jetons ;
   - **copie** le résultat tout de suite — il n'y a plus qu'à coller.

La clé **et l'état Actif** sont partagés entre l'app et l'extension via un
**App Group**.

### État « Actif »

- L'interrupteur dans l'app est l'unique contrôle fiable : actif jusqu'à ce que
  tu le désactives. Sortir de l'app pour aller dans WhatsApp/Notes **ne le
  désactive pas** (sinon l'extension serait inutile).
- À la **fermeture** de l'app, Brocolis se désactive (`applicationWillTerminate`).
  ⚠️ iOS n'appelle pas ce hook en cas de *force-quit* (balayage de l'app) :
  dans ce cas l'état reste tel quel — utilise l'interrupteur pour être sûr.
- Tant qu'il est **inactif** (ou sans clé), l'extension n'agit pas et l'indique.

## Appairage automatique (sans copier la clé)

Plutôt que de copier-coller la clé symétrique, deux personnes peuvent
**l'obtenir automatiquement** par accord de clé **X25519 (ECDH)** :

1. Les deux ouvrent l'app → **Appairer automatiquement**, renseignent la même
   **URL de serveur** et **le même code court** (ex. `ABC123`).
2. Chaque téléphone publie sa **clé publique** sur le serveur de rendez-vous et
   récupère celle de l'autre, puis **dérive seul** la même clé AES (HKDF). La
   clé secrète n'est jamais transmise ; le serveur ne voit que des clés
   publiques.
3. L'app affiche une **empreinte de sécurité** : comparez-la de vive voix. Si
   elle est identique des deux côtés, personne n'a intercepté l'échange (MITM).

Le serveur de rendez-vous est dans [`server/`](server/) (Node, sans dépendance).
L'appairage active automatiquement Brocolis ; l'extension utilise ensuite la clé
dérivée comme d'habitude.

> Le code court ne sert qu'à se *rejoindre* : la sécurité réelle vient de X25519
> et de la vérification de l'empreinte.

### Groupe (3+)

Le **chiffrement** est de groupe par nature : toute personne ayant la clé lit
les jetons. Le **serveur de rendez-vous** accepte plusieurs participants par
code (plafond `MAX_PEERS`, défaut 16). En revanche, la **dérivation automatique
reste par paire** (X25519 entre 2 clés). Pour une **clé de groupe commune**, le
plus simple aujourd'hui : une personne **génère la clé et la partage**, les
autres l'**importent** (menu Clé partagée). La distribution automatique d'une
clé de groupe (emballée pour chaque membre) n'est pas implémentée.

## Interopérable avec brocolis

Même format de jeton (`[[BROCOLIS:v1:…]]`, AES-256-GCM,
`nonce(12) ‖ ciphertext ‖ tag(16)` = représentation `combined` de CryptoKit) :
une clé `brocolis keygen` fonctionne dans l'app, et les jetons sont
déchiffrables par brocolis (et inversement).

## Structure

```
Brocolis.xcodeproj
Shared/                       # code partagé app + extension
  BrocolisCrypto.swift        # AES-256-GCM, format de jeton brocolis
  BrocolisKeyStore.swift      # clé + état actif + appairage (App Group)
  BrocolisTransform.swift     # chiffre/déchiffre en un geste (auto-détection)
  BrocolisKeyAgreement.swift  # accord de clé X25519 (ECDH + HKDF) + empreinte
Brocolis/                     # app hôte
  BrocolisApp.swift, RootView.swift, Assets, Brocolis.entitlements
  PairingView.swift           # écran d'appairage automatique
  PairingClient.swift         # client du serveur de rendez-vous
BrocolisAction/               # Action Extension (menu Partager)
  ActionViewController.swift, Info.plist, BrocolisAction.entitlements
BrocolisTests/                # tests XCTest (crypto, transform, accord de clé)
server/                       # serveur de rendez-vous X25519 (Node)
```

## Lancer le projet

Pré-requis : **Xcode 15+**, iOS 16+.

```sh
open Brocolis.xcodeproj
```

Dans Xcode, pour **chaque** cible (`Brocolis` et `BrocolisAction`) :

1. **Signing & Capabilities** → choisis ton équipe de signature.
2. Vérifie la capacité **App Groups** avec le groupe
   `group.rs.brocolis.messagerie` activé sur les **deux** cibles (ou remplace
   par ton propre identifiant de groupe, identique des deux côtés et dans
   `BrocolisKeyStore.appGroup`).
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
ils vérifient le flux d'appairage et que **les deux appareils dérivent une clé
identique** :

```
cd server && npm test
```

## Sécurité — limites

- L'extension protège le contenu **marqué** (ou la sélection) ; elle ne chiffre
  pas automatiquement tout ce que tu envoies — c'est un geste explicite.
- La clé est en **App Group** (`UserDefaults` du conteneur partagé) pour la
  démo ; pour la production, préférer un groupe d'accès **Trousseau** partagé.
- Clé **symétrique** : sa diffusion doit passer par un canal sûr, comme brocolis.

## Licence

Accompagne brocolis, propriété de **LESTAGE Maxime Nathan**. Voir le dépôt
brocolis pour les termes. Fourni « TEL QUEL », sans garantie.
