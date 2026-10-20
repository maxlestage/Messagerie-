# Brocolis 🥦 — Android (Kotlin / Jetpack Compose)

Port Android natif de l'app iOS Brocolis. Même messagerie chiffrée de bout en
bout, **interopérable** avec l'app iOS et le serveur Rust : les jetons, la
dérivation de clé et l'`conversationId` sont identiques au bit près.

## Ouvrir / compiler

Ouvre le dossier `android/` dans **Android Studio** (Giraffe+), laisse-le
synchroniser Gradle, puis Run. En ligne de commande : `./gradlew assembleDebug`
(le wrapper Gradle sera généré par Android Studio, ou via `gradle wrapper`).

- `minSdk 26`, `targetSdk/compileSdk 34`, Kotlin 1.9, Compose BOM 2024.06.
- `applicationId = rs.brocolis.messagerie`.

## Correspondance avec l'app iOS

| iOS (Swift) | Android (Kotlin) |
|---|---|
| `BrocolisCrypto` (CryptoKit) | `crypto/BrocolisCrypto.kt` (javax.crypto) |
| `BrocolisKeyAgreement` (X25519) | `crypto/BrocolisKeyAgreement.kt` (BouncyCastle) |
| `BrocolisConversation` | `crypto/BrocolisConversation.kt` |
| `BrocolisKeyStore` (App Group) | `store/BrocolisKeyStore.kt` (SharedPreferences) |
| `MessagingPrefs` | `store/MessagingPrefs.kt` |
| `PairingClient` | `net/PairingClient.kt` (OkHttp) |
| `BrocolisMessagingClient` (+ SSE) | `net/BrocolisMessagingClient.kt` (OkHttp SSE) |
| `BrocolisSplashView` | `ui/SplashScreen.kt` |
| `RootView` | `ui/RootScreen.kt` |
| `ConversationView` | `ui/ConversationScreen.kt` |
| `MessagingView` | `ui/MessagingScreen.kt` |
| `PairingView` | `ui/PairingScreen.kt` |
| Extension « Partager » / Action | `ui/ShareActivity.kt` (ACTION_SEND / PROCESS_TEXT) |
| Verrou Face ID / code (LocalAuthentication) | `ui/BiometricLock.kt` (BiometricPrompt) |
| `loc(fr,en,es)` | `i18n/Loc.kt` |
| `BrocolisProto` (protocole v3, `proto-swift/`) | module `:proto` (`proto/`, paquet `rs.brocolis.messagerie.proto`, BouncyCastle) — pas encore branché sur l'interface : voir [`proto/README.md`](proto/README.md) |

## Interopérabilité (garantie par construction)

- **AES-256-GCM** : jeton `nonce(12) || ciphertext || tag(16)` en base64 =
  format `combined` de CryptoKit ; même chose côté Rust `aes-gcm`.
- **Jetons** : `[[BROCOLIS:v1:…]]` (une clé) et `[[BROCOLIS:v2:…]]`
  (multi-destinataire, enveloppe) — mêmes octets que iOS.
- **X25519 + HKDF-SHA256** : secret partagé brut, `info = concat lexicographique
  des deux clés publiques`, `salt = "brocolis-x25519"`, 32 octets → clé AES.
  Empreinte = SHA-256(info), 8 octets, hex groupé.
- **conversationId** = base64url(SHA-256("brocolis-conv-v1" ‖ clé)) sans padding.
- **API** : `POST/GET /v1/messages`, `POST /v1/read`, SSE `/v1/stream`,
  en-tête `X-User-Id`. Serveur par défaut = l'instance Heroku du projet.

## Ce qui diffère d'iOS (spécificités plateforme)

Certaines fonctions iOS n'ont pas d'équivalent 1:1 sur Android et sont adaptées
ou hors périmètre de cette première version :

- **Widget d'écran d'accueil** : présent (`widget/BrocolisWidgetProvider.kt`,
  RemoteViews) — état Actif/En pause + nombre de clés, tap pour ouvrir l'app.
  La **Live Activity** iOS n'a pas d'équivalent Android.
- **Contacts** : « Ajouter depuis mes contacts » présent (sélecteur de numéro,
  sans permission) — comme `BrocolisContacts` sur iOS.
- **Clavier Brocolis (IME)**, **extension iMessage**, **raccourcis Siri** :
  propres à iOS. Sur Android, le chiffrement « dans les autres apps » passe par
  l'écran **Partager** (`ShareActivity`, ACTION_SEND et « Traiter le texte »).
- **Notifications push / APNs** : non incluses ici (FCM à ajouter plus tard).
- Le stockage des clés utilise `SharedPreferences` (comme iOS utilise
  `UserDefaults` pour la démo) — à durcir (Keystore Android) pour la production.

## Statut

Écrit sans compilateur Android disponible dans l'environnement de génération :
**à compiler/vérifier dans Android Studio**. Le cœur cryptographique et réseau
est porté à l'identique pour garantir l'interopérabilité ; l'UI Compose reproduit
les écrans principaux (garde/chargement, réglages/clés, messagerie temps réel,
conversation à la volée, appairage, partage).
