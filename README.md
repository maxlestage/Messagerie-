# Messagerie 🥦 — messagerie chiffrée (React Native) bâtie sur [brocolis](https://github.com/maxlestage/brocolis)

Application **React Native (Expo + TypeScript)** de messagerie qui réutilise le
**chiffrement sélectif** du proxy [brocolis 🥦](https://github.com/maxlestage/brocolis).
Pensée pour **iPhone** (tourne dans **Expo Go**), sans dépendance native exotique.

Le principe est identique à brocolis : seul le contenu **explicitement marqué**
est chiffré. Tu écris un message ; chaque segment entre `((doubles parenthèses))`
est remplacé, **avant stockage**, par un jeton chiffré `[[BROCOLIS:v1:<base64>]]`
(AES-256-GCM). À l'affichage, les jetons sont déchiffrés à la volée avec la clé
partagée. Le clair des parties secrètes n'est donc **jamais** écrit sur disque.

> ⚠️ Projet de démonstration / éducatif.

## Pourquoi « s'appuie sur brocolis »

Le format du jeton est **interopérable au format près** avec la crate Rust de
brocolis :

| Élément         | brocolis (Rust, `aes-gcm`)              | Messagerie 🥦 (JS, `@noble/ciphers`)     |
| --------------- | --------------------------------------- | ---------------------------------------- |
| Clé             | base64 de 32 octets (`brocolis keygen`) | identique                                |
| Préfixe/suffixe | `[[BROCOLIS:v1:` … `]]`                  | identique                                |
| Marqueurs clair | `((` … `))`                             | identiques                               |
| Empaquetage     | `nonce(12) ‖ ciphertext ‖ tag(16)`      | identique (`AES-GCM`, tag de 16 octets)  |

Une clé générée par `brocolis keygen` se colle telle quelle dans l'app, et un
jeton produit par l'app est déchiffrable par brocolis (et inversement). Le test
`__tests__/brocolisCrypto.test.ts` vérifie ce format.

## Stack technique

- **Expo SDK 51** / React Native 0.74 / TypeScript
- `@noble/ciphers` — AES-256-GCM en JS pur (pas de module natif)
- `@scure/base` — base64
- `expo-crypto` — aléa CSPRNG (clé, nonce, UUID)
- `expo-secure-store` — clé partagée dans le Trousseau iOS
- `@react-native-async-storage/async-storage` — conversations (JSON)
- `@react-navigation/native-stack` — navigation

## Lancer le projet

Pré-requis : Node 18+, l'app **Expo Go** sur ton iPhone.

```sh
npm install
npm start          # puis scanne le QR code avec Expo Go (iPhone)
# ou : npm run ios  (simulateur iOS, sur macOS avec Xcode)
```

Tests unitaires (chiffrement / interopérabilité) :

```sh
npm test
```

### Premier usage

1. Touche 🔑 (en haut à gauche) → **Générer une nouvelle clé** (ou importe une
   clé `brocolis keygen`).
2. Crée une conversation (✏️ en haut à droite).
3. Écris un message avec un secret, ex. :
   `Le code du coffre est ((1234)) à ne pas oublier`.
4. Envoie : seul `1234` est stocké chiffré (`[[BROCOLIS:v1:…]]`). Via le menu ⋯
   → **Voir le texte chiffré**, tu constates ce qui voyage réellement.
5. Partage la même clé avec un correspondant pour qu'il lise le clair. Le menu ⋯
   → **Recevoir un message** permet de coller un message reçu.

## Architecture

```
App.tsx                        # navigation + providers
src/
  crypto/brocolisCrypto.ts     # chiffrement sélectif AES-256-GCM
  models/types.ts              # Message, Conversation, params de navigation
  state/AppContext.tsx         # clé (SecureStore) + conversations (AsyncStorage)
  components/MessageBubble.tsx
  screens/                     # Conversations, Chat, Key
__tests__/brocolisCrypto.test.ts
```

## Sécurité — limites connues

- App de **démonstration** : pas de transport réseau intégré (l'échange se fait
  par copier-coller / partage, à la main).
- Le chiffrement protège uniquement les parties **marquées** ; les métadonnées
  (titres, horodatages) et le texte non marqué restent en clair.
- Clé **symétrique** partagée : sa diffusion doit passer par un canal sûr, comme
  pour brocolis.

## Licence

Ce projet accompagne brocolis, propriété de **LESTAGE Maxime Nathan**. Voir le
dépôt brocolis pour les termes de licence applicables. Fourni « TEL QUEL », sans
garantie. Utilisation à vos propres risques.
