# Messagerie 🥦 — messagerie chiffrée pour iPhone, bâtie sur [brocolis](https://github.com/maxlestage/brocolis)

Application **iOS native (SwiftUI)** de messagerie qui réutilise le
**chiffrement sélectif** du proxy [brocolis 🥦](https://github.com/maxlestage/brocolis).

Le principe est identique à brocolis : seul le contenu **explicitement marqué**
est chiffré. Tu écris un message ; chaque segment entre `((doubles parenthèses))`
est remplacé, **avant stockage**, par un jeton chiffré
`[[BROCOLIS:v1:<base64>]]` (AES-256-GCM). À l'affichage, les jetons sont
déchiffrés à la volée avec la clé partagée. Le clair des parties secrètes
n'est donc **jamais** écrit sur disque.

> ⚠️ Projet de démonstration / éducatif. Voir l'avertissement de licence ci-dessous.

## Pourquoi « s'appuie sur brocolis »

Le format du jeton est **interopérable au format près** avec la crate Rust de
brocolis :

| Élément        | brocolis (Rust, `aes-gcm`)            | Messagerie 🥦 (Swift, `CryptoKit`)        |
| -------------- | ------------------------------------- | ----------------------------------------- |
| Clé            | base64 de 32 octets (`brocolis keygen`) | identique                                |
| Préfixe/suffixe| `[[BROCOLIS:v1:` … `]]`                | identique                                 |
| Marqueurs clair| `((` … `))`                           | identiques                                |
| Empaquetage    | `nonce(12) ‖ ciphertext ‖ tag(16)`    | `AES.GCM.SealedBox.combined` (identique)  |

Une clé générée par `brocolis keygen` peut donc être collée dans l'app, et un
jeton produit par l'app peut être déchiffré par brocolis (et inversement).

## Fonctionnalités

- 🔑 **Gestion de clé** (Trousseau iOS) : générer, importer, partager, supprimer.
- 💬 **Conversations** persistées localement (JSON), triées par activité.
- 🟢 **Chiffrement sélectif** des `((secrets))` à l'envoi.
- 🔓 **Déchiffrement** automatique à l'affichage pour les détenteurs de la clé.
- 🔒 **Affichage « texte chiffré »** (bascule) pour voir ce qui voyage réellement.
- 📥 **Réception** : coller un message reçu d'un correspondant (chiffré ou non).

## Lancer le projet

Pré-requis : **Xcode 16+**, iOS 17+.

```sh
open Brocolis.xcodeproj
# Sélectionner le schéma "Brocolis", un simulateur iPhone, puis Cmd+R
```

Tests unitaires (chiffrement / interopérabilité) : `Cmd+U`.

### Premier usage

1. Touche l'icône 🔑 → **Générer une nouvelle clé** (ou importe une clé
   `brocolis keygen`).
2. Ouvre/crée une conversation.
3. Écris un message avec un secret, ex. :
   `Le code du coffre est ((1234)) à ne pas oublier`.
4. Envoie : seul `1234` est stocké chiffré (`[[BROCOLIS:v1:…]]`). Active
   « Voir le texte chiffré » pour le constater.
5. Partage la même clé avec un correspondant pour qu'il puisse lire le clair.

## Architecture

```
Brocolis/
  BrocolisApp.swift          // point d'entrée SwiftUI
  Crypto/BrocolisCrypto.swift // chiffrement sélectif AES-256-GCM (CryptoKit)
  Models/                    // Message, Conversation
  Store/                     // KeyStore (Keychain), ChatStore (JSON)
  Views/                     // ContentView, ChatView, MessageBubble, KeyView
BrocolisTests/               // tests crypto + interopérabilité de format
```

## Sécurité — limites connues

- App de **démonstration** : pas de transport réseau intégré (l'échange de
  messages se fait par copier-coller / partage, à la main).
- Le chiffrement protège uniquement les parties **marquées** ; les métadonnées
  (titres, horodatages) et le texte non marqué restent en clair.
- La clé est partagée **symétriquement** ; sa diffusion doit passer par un
  canal sûr, comme pour brocolis.

## Licence

Ce projet accompagne brocolis, propriété de **LESTAGE Maxime Nathan**. Voir le
dépôt brocolis pour les termes de licence applicables. Fourni « TEL QUEL », sans
garantie. Utilisation à vos propres risques.
