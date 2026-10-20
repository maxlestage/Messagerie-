# Brocolis 🥦 et Talka : la sécurité, repensée

Ce document est la référence commune aux deux dépôts
([Talka](https://github.com/maxlestage/Talka) et
[Brocolis](https://github.com/maxlestage/messagerie-)). Chaque format décrit ici
a une implémentation de référence en Rust et des **vecteurs de test** que les
autres implémentations (Swift pour l'iPhone, Kotlin pour Android, Rust
WebAssembly pour les navigateurs) doivent retrouver octet pour octet.

Il s'inspire des outils qui font référence : **Signal** (X3DH, PQXDH, Double
Ratchet, Sender Keys, remplissage, numéros de sécurité), **iMessage PQ3**,
**age** et **libsodium** (primitives modernes, formats simples), **KeePassXC**,
**Bitwarden** et **1Password** (Argon2id, coffre chiffré), les **clés matérielles**
(Secure Enclave, StrongBox, YubiKey, passkeys), **MLS** (RFC 9420) pour les
groupes, et les outils d'audit (**Wycheproof**, **cargo-audit**, **cargo-deny**,
**CodeQL**, **Semgrep**, **fuzzing**).

Rien n'est « inviolable » dans l'absolu : ce document dit précisément contre
quoi chaque mesure protège, et ce qui reste hors de portée.

## 1. Modèle de menace

| Adversaire | Ce qu'il peut faire | Ce qu'on garantit |
|---|---|---|
| Le serveur (relais Talka, salon Brocolis), ou quiconque le contrôle | lire, garder, rejouer, réordonner, supprimer tout ce qui passe | il ne lit aucun message ni aucune clé ; un message modifié est refusé ; un rejeu est ignoré |
| Le réseau, une messagerie hôte (WhatsApp, iMessage…) qui transporte les jetons Brocolis | idem, et garder les jetons des années | idem ; **confidentialité persistante** : voler une clé plus tard n'ouvre pas les messages passés |
| L'attaquant « qui garde tout pour plus tard » avec un ordinateur quantique | casser X25519 et P-256 rétroactivement | l'établissement des sessions est **hybride X25519 + ML-KEM-768** : il faut casser les deux |
| Le vol d'un appareil verrouillé, la copie de ses fichiers, une sauvegarde | lire le stockage | les secrets sont emballés par une clé **matérielle non extractible** (Secure Enclave, Android Keystore/StrongBox, WebCrypto non extractible) ; rien n'est dans les sauvegardes de l'OS |
| La compromission passagère d'un appareil (un logiciel espion qui part) | lire l'état des sessions à un instant | **guérison** (post-compromise security) : le ratchet Diffie-Hellman reprend le secret au premier aller-retour |
| Un correspondant usurpé (homme du milieu à l'appairage) | substituer ses clés | empreintes et numéros de sécurité comparés de vive voix ; **alerte** dès qu'une clé d'identité change |
| Qui devine une phrase secrète ou un code | essais hors ligne sur GPU | **Argon2id** (gourmand en mémoire) ; un code à 4–6 chiffres reste faible : il protège par la clé matérielle, pas par lui-même |

**Hors de portée** (aucun logiciel ne le promet honnêtement) : un appareil
déverrouillé entre de mauvaises mains, un correspondant qui fait une capture
d'écran, un système d'exploitation compromis pendant l'usage, les métadonnées
visibles de la messagerie hôte (qui écrit à qui, quand).

## 2. Primitives

| Rôle | Choix | Pourquoi |
|---|---|---|
| Échange de clés | **X25519** | Signal, age, WireGuard ; partout (CryptoKit, RustCrypto, Android) |
| Post-quantique | **ML-KEM-768** (FIPS 203), en hybride | Signal PQXDH, iMessage PQ3 ; CryptoKit (iOS 26), RustCrypto `ml-kem`, BouncyCastle |
| Signature | **Ed25519** (Brocolis) ; ECDSA P-256 existante (identité Talka) | Sender Keys, paquets de clés publiés |
| Chiffrement | **AES-256-GCM** | matériel partout, déjà utilisé ; nonces jamais réutilisés (clé neuve par message) |
| Dérivation | **HKDF-SHA256**, **HMAC-SHA256** | Signal |
| Mots de passe | **Argon2id** (RFC 9106) | KeePassXC, Bitwarden ; remplace PBKDF2 |
| Hasard | CSPRNG du système uniquement | `SecRandomCopyBytes`, `SecureRandom`, `crypto.getRandomValues` |

Règles d'hygiène, partout : comparaisons en temps constant ; secrets effacés de
la mémoire après usage quand le langage le permet (`zeroize` en Rust) ; aucun
secret dans les journaux ; aucune primitive « maison ».

## 3. Phase 1 — durcir sans rien casser

### 3.1 Les secrets au repos

| Plateforme | Où | Protégé par |
|---|---|---|
| iPhone (Talka, Brocolis) | Trousseau, `AfterFirstUnlockThisDeviceOnly` (groupe de l'App Group pour Brocolis) | Secure Enclave et le code de l'iPhone ; jamais iCloud ni sauvegarde |
| Android (Brocolis) | valeurs chiffrées AES-256-GCM par une clé `AndroidKeyStore` non exportable (StrongBox si présent) | matériel ; préférences exclues des sauvegardes et transferts |
| Navigateur (Talka) | `brocolis_sealed` : clé tirée du code de verrouillage | code (faible seul) ; à terme passkey (§3.5) |
| Navigateur (site Brocolis) | valeurs chiffrées par une clé WebCrypto **non extractible** gardée dans IndexedDB | le navigateur ne la donne jamais au code |

### 3.2 Clé protégée par une phrase secrète

`[[BROCOLIS-CLE:v1:…]]` (PBKDF2-SHA256, 600 000 tours) reste lisible.
Nouveau format par défaut, **v2 avec Argon2id** :

    [[BROCOLIS-CLE:v2:<base64>]]

    octet 0       : 0x02 (version)
    octets 1–4    : m, mémoire en Kio, u32 gros-boutiste (défaut 65 536 = 64 Mio)
    octet 5       : t, passes (défaut 3)
    octet 6       : p, parallélisme (défaut 1)
    octets 7–22   : sel (16)
    octets 23–34  : nonce (12)
    octets 35–82  : AES-256-GCM(clé brute 32) ‖ tag 16
    clé de chiffrement = Argon2id(phrase UTF-8, sel, m, t, p, 32 octets)
    données associées  = les octets 0–34 (en-tête et paramètres compris)

À l'import, refuser m < 19 456, t < 2, ou m > 1 048 576 (un jeton piégé ne
doit pas épuiser la mémoire), et aussi t > 16, p = 0 et m < 8p (un jeton
piégé ne doit pas non plus tourner des heures ; voir §7.1).

### 3.3 Remplissage (padding)

La longueur d'un message ne doit pas se lire sur le jeton. Avant
chiffrement : texte UTF-8 ‖ `0x80` ‖ des `0x00` jusqu'au **multiple de 160
octets** suivant (comme Signal) : longueur totale = (⌊n / 160⌋ + 1) × 160,
donc 159 octets → 160, 160 → 320. Au déchiffrement : refuser une longueur qui
n'est pas un multiple non nul de 160, retirer les `0x00` de fin puis le
`0x80` ; absent → refusé (§7.2). S'applique à v3 (§4) ; v1/v2 restent tels
quels pour rester lisibles par les anciennes versions.

### 3.4 L'écran et le presse-papiers

- iPhone et Android : contenu masqué dans le sélecteur d'apps ;
  `FLAG_SECURE` sur Android (pas de capture) ; sur iPhone, les clés et
  phrases ne s'affichent jamais en clair.
- Presse-papiers : local à l'appareil (pas de presse-papiers universel),
  expiration après 2 minutes (iOS) ; marqué « sensible » (Android 13+).

### 3.5 Plus tard dans la phase 1 : passkey (WebAuthn PRF)

Dans les navigateurs, la clé qui scelle le coffre pourra venir d'une passkey
(extension PRF de WebAuthn : un secret stable que seul l'authentificateur
matériel — Face ID, Windows Hello, YubiKey — sait produire), au lieu du code.

### 3.6 Contrôles automatiques (CI)

- `cargo audit` et `cargo deny` (failles connues, licences, sources) sur toutes
  les crates ;
- CodeQL (Swift, Kotlin, Rust) et Semgrep ;
- vecteurs **Wycheproof** pour AES-GCM, X25519, HKDF : chaque implémentation
  doit refuser les cas piégés ;
- fuzzing (`cargo fuzz`) des lecteurs de jetons et du déchiffrement v3 :
  aucune entrée ne doit faire planter ni boucler.

## 4. Phase 2 — le protocole v3

v3 remplace la clé fixe (Brocolis v1/v2, et l'ECDH fixe de Talka) par des
**sessions à cliquet** : une clé neuve par message, effacée aussitôt utilisée.

### 4.1 Paquet de clés publiques

Chaque appareil a :

- **IK** : clé d'identité X25519, longue durée (et, pour Brocolis, une clé
  Ed25519 de signature ; pour Talka, l'identité ECDSA P-256 existante signe) ;
- **SPK** : clé pré-signée X25519, renouvelée chaque semaine (l'ancienne
  gardée un mois pour les messages en retard) ;
- **PQPK** : clé d'encapsulation ML-KEM-768, signée, renouvelée chaque semaine.

Le paquet `IK ‖ SPK ‖ PQPK ‖ signatures` s'échange à l'appairage (salon
Brocolis), ou se publie sur le relais (Talka). L'empreinte et le numéro de
sécurité portent sur IK : comparés de vive voix, ils authentifient tout le
paquet (signé par IK).

### 4.2 Établissement (inspiré de PQXDH)

L'initiateur A, qui connaît le paquet de B, tire une clé éphémère EK et :

    DH1 = X25519(IK_A, SPK_B)
    DH2 = X25519(EK_A, IK_B)
    DH3 = X25519(EK_A, SPK_B)
    (CT, SS) = ML-KEM-768.Encaps(PQPK_B)
    SK = HKDF-SHA256(sel = 32 × 0x00,
                     ikm = 32 × 0xFF ‖ DH1 ‖ DH2 ‖ DH3 ‖ SS,
                     info = "Brocolis_v3_X25519_MLKEM768_SHA-256", 32)
    AD = IK_A ‖ IK_B          (les clés X25519 d'identité, 32 + 32 octets)

Puis le Double Ratchet (§4.3) part comme chez Signal : la clé de cliquet
initiale de B est sa SPK ; A tire une clé de cliquet neuve et calcule
`(RK, CKs) = KDF_RK(SK, X25519(cliquet_A, SPK_B))`. Toute clé publique X25519
reçue doit être canonique (bit 255 nul, u < 2²⁵⁵ − 19) et tout DH nul est
refusé (§7.3).

Si l'un des appareils ne sait pas faire ML-KEM (iPhone avant iOS 26), le
drapeau `pq = 0` retire `SS` et l'info devient `"Brocolis_v3_X25519_SHA-256"`.
L'appli l'affiche (« session non post-quantique »).

**Clé Brocolis partagée sans appairage** : la clé symétrique sert de secret
pré-partagé, `SK = HKDF(sel = 32 × 0x00, ikm = clé, info =
"Brocolis_v3_PSK_SHA-256", 32)`, et le ratchet Diffie-Hellman ajoute la
confidentialité persistante dès le premier aller-retour. Une telle session
vaut ce que vaut la clé partagée tant que personne n'a répondu. La clé de
cliquet initiale du répondeur, l'AD et le premier message sont précisés au
§7.4 (mode `0x02`).

### 4.3 Double Ratchet

Comme la [spécification de Signal](https://signal.org/docs/specifications/doubleratchet/),
avec :

    KDF_RK(rk, dh) = HKDF-SHA256(sel = rk, ikm = dh, info = "Brocolis_v3_Ratchet", 64)
                     → (rk', ck)
    KDF_CK(ck)     = mk = HMAC-SHA256(ck, 0x01), ck' = HMAC-SHA256(ck, 0x02)
    ENCRYPT(mk)    = HKDF-SHA256(sel = 32 × 0x00, ikm = mk,
                                 info = "Brocolis_v3_MessageKeys", 44)
                     → clé AES (32) ‖ nonce (12)
    en-tête        = DH_pub (32) ‖ PN (u32 BE) ‖ N (u32 BE)
    chiffré        = AES-256-GCM(clé, nonce, pad(texte), AD ‖ en-tête)
    MAX_SKIP       = 1 000 clés sautées gardées par session, 30 jours au plus

Les messages arrivent dans le désordre (copier-coller, hors ligne) : les clés
sautées sont gardées puis effacées à l'usage. Un message rejoué ne trouve plus
sa clé : il est ignoré.

### 4.4 Le jeton v3

    [[BROCOLIS:v3:<base64>]]

    octet 0 : type — 0x01 premier message (établit la session), 0x02 message
    octets  : identifiant de session (8) = SHA-256(AD)[0..8]
    type 0x01 : IK_A (32) ‖ EK_A (32) ‖ mode (1) ‖ [CT (1 088) si mode = 1] ‖ id SPK (4) ‖ id PQPK (4)
    puis    : en-tête (40) ‖ chiffré
    mode    : 0x00 X25519 seul (id PQPK = 0), 0x01 X25519 + ML-KEM-768,
              0x02 clé partagée (IK_A, id SPK, id PQPK nuls ; §7.4)
    chiffré : 160·k + 16 octets, k ≥ 1 ; toute autre longueur est refusée
    type 0x03 : comme 0x02, données associées AD ‖ en-tête ‖ 0x03 (§7.6)

L'initiateur envoie des messages de type 0x01 tant qu'il n'a pas reçu de
réponse (comme les « prekey messages » de Signal).

### 4.5 Groupes : Sender Keys

Chaque membre tire une **chaîne d'envoi** (clé de chaîne 32 octets + clé de
signature Ed25519) et la distribue à chaque membre par sa session v3 à deux
(type 0x03). Ses messages de groupe (type 0x04) :

    id de groupe (16) ‖ id d'expéditeur (8) ‖ itération (u32 BE) ‖ chiffré ‖ signature Ed25519 (64)

La chaîne avance par `KDF_CK` (confidentialité persistante dans la chaîne).
Un membre qui part : chacun tire une chaîne neuve (le partant ne lit plus
rien). C'est le modèle de Signal ; MLS (RFC 9420) est la cible pour les très
grands groupes.

### 4.6 Compatibilité

- v1 et v2 restent **lisibles** pour toujours.
- Tout ce qui part est en **v3** dès qu'une session existe (ou peut être
  établie : paquet connu, ou clé partagée → §4.2).
- Talka : le relais transporte le paquet de clés (§4.1) ; les enveloppes de
  Talka portent des jetons v3 à l'intérieur de son propre chiffrement.

## 5. Phase 3 — vérifier et durcir encore

- Post-quantique partout où l'OS le permet (§4.2), et affiché.
- **Alerte de changement de clé** : un IK différent pour un contact connu
  bloque l'envoi jusqu'à une nouvelle vérification (comme Signal).
- En-têtes de ratchet chiffrés (header encryption) : un observateur ne relie
  plus les messages d'une même session.
- Fuzzing continu, revue de sécurité extérieure du protocole avant de le dire
  « stable ».

## 6. Implémentations et vecteurs

| Brique | Rust (référence) | Swift | Kotlin |
|---|---|---|---|
| Jetons v1/v2, clé protégée v1 | `talka-web::jetons` | TalkaKit `Brocolis`, Brocolis `BrocolisCrypto`, `BrocolisProto` | `BrocolisCrypto.kt` |
| Clé protégée v2 (Argon2id), padding | `brocolis-proto` (`proto/`) | `BrocolisProto` (`proto-swift/`) | |
| v3 (établissement, ratchet, Sender Keys) | `brocolis-proto` (`proto/`) | `BrocolisProto` (`proto-swift/`) | |

`BrocolisProto` est le paquet SwiftPM à la racine du dépôt (`Package.swift`),
que les apps (Brocolis, Talka) prennent par l'URL du dépôt et une révision ;
ses écarts imposés par CryptoKit sont dans `proto-swift/README.md`.

Les vecteurs de référence sont `proto/vectors.json` (regénérés par
`cargo run --example vectors`, vérifiés indépendamment par
`proto/scripts/verifier_vecteurs.py` avec OpenSSL).

Toute implémentation passe les vecteurs de la référence Rust **et** les
vecteurs Wycheproof des primitives. Aucune n'est publiée sans eux.

## 7. Précisions de l'implémentation de référence

Ce que la spécification laissait ouvert, et la façon dont `brocolis-proto` le
tranche. Chaque point fait partie du contrat : les portages font pareil.

### 7.1 Clé protégée v2

- Argon2id version 0x13, sans secret ni données associées Argon2, sortie
  32 octets.
- Bornes à l'import : 19 456 ≤ m ≤ 1 048 576, 2 ≤ t ≤ **16**, p ≥ **1**,
  m ≥ 8p. Les bornes en gras sont ajoutées : t ≤ 255 avec 1 Gio ferait
  tourner un jeton piégé pendant des dizaines de minutes ; p = 0 et m < 8p
  sont refusés par Argon2 lui-même.
- Export : phrase de 8 caractères au moins (comme la v1). Dans un texte
  collé, `[[BROCOLIS-CLE:v2:` est cherché avant `v1`.
- Les vecteurs donnent m = 19 456, t = 2, p = 1 (rapide) **et** le défaut.

### 7.2 Remplissage

Longueur totale (⌊n / 160⌋ + 1) × 160 (au moins un octet de remplissage). Au
retrait, une longueur qui n'est pas un multiple non nul de 160 est refusée :
plus strict que le texte d'origine, sans effet sur l'interopérabilité
(un émetteur conforme produit toujours un multiple).

### 7.3 Paquet de clés (§4.1) et établissement (§4.2)

Format binaire v1 du paquet :

    octet 0      : 0x01 (version)
    1–32         : IK X25519        33–64 : IK Ed25519
    65–68        : id SPK (u32 BE)  69–100 : SPK
    101–164      : Ed25519(IK, "Brocolis_v3_SPK" ‖ IK X25519 ‖ id SPK ‖ SPK)
    165          : 0x00 sans ML-KEM, 0x01 avec
    si 0x01 :
      166–169    : id PQPK (u32 BE, non nul)
      170–1353   : PQPK (clé d'encapsulation ML-KEM-768)
      1354–1417  : Ed25519(IK, "Brocolis_v3_PQPK" ‖ IK X25519 ‖ id PQPK ‖ PQPK)

- La spécification dit « l'empreinte porte sur IK » et « signé par IK » :
  une clé X25519 ne signe pas. Les signatures sont faites par IK Ed25519 et
  portent IK X25519 (ce qui lie les deux moitiés de l'identité) ; l'empreinte
  et le numéro de sécurité portent sur **IK X25519 ‖ IK Ed25519** :
  `SHA-256(IK X25519 ‖ IK Ed25519)[0..8]`, écrit `XXXX-XXXX-XXXX-XXXX`.
- Vérification Ed25519 **stricte** (RFC 8032 §5.1.7 : S canonique, R et A
  pas de petit ordre). La PQPK doit être une clé ML-KEM valide (contrôle du
  module de FIPS 203).
- Secret ML-KEM gardé sous sa forme FIPS 203 « graine » `d ‖ z` (64 octets).
  L'aléa d'encapsulation `m` (32 octets) est tiré par l'appelant ; les
  vecteurs le donnent (CryptoKit n'accepte pas de `m` imposé : un portage
  vérifie alors par la décapsulation).
- AD = IK_A ‖ IK_B avec les clés **X25519** d'identité.
- La clé de cliquet initiale de B est SPK_B ; celle de A est tirée à part
  (pas EK_A).
- Toute clé publique X25519 reçue doit être **canonique** (bit 255 nul,
  u < 2²⁵⁵ − 19), et un DH nul (clé de petit ordre) est refusé. Sans cela,
  EK_A avec le bit 255 levé donne les mêmes DH : un premier message rejoué
  ainsi « réécrit » passait la mémoire des clés éphémères (trouvé par les
  tests d'altération).
- **Rejeu d'un premier message** : sans clés pré-signées à usage unique
  (les « one-time prekeys » de Signal), un premier message rejoué rouvrirait
  la session tant que la SPK vit. Le répondeur garde donc les EK déjà vues
  (4 096 au plus, 37 jours = la vie d'une SPK) et refuse un premier message
  dont EK a déjà servi. Ajouter des clés à usage unique (Talka : publiées sur
  le relais) fermerait ce point pour de bon.
- Le mode `0x00` (sans ML-KEM) est accepté même si les deux appareils savent
  faire ML-KEM : un attaquant ne peut pas le forcer (il faudrait le secret
  d'IK_A), c'est un choix de l'initiateur, que l'appli affiche.
- Renouvellement : SPK et PQPK neuves chaque semaine, les anciennes gardées
  30 jours après leur remplacement, puis effacées.

### 7.4 Clé partagée (PSK)

La spécification ne disait ni la clé de cliquet initiale du répondeur, ni
l'AD, ni le premier message. Choix :

    SK = HKDF(sel = 32 × 0x00, ikm = clé, "Brocolis_v3_PSK_SHA-256", 32)
    r  = HKDF(sel = 32 × 0x00, ikm = SK, "Brocolis_v3_PSK_Ratchet", 32)   (secret X25519, connu des deux)
    R  = X25519(r, 9)
    AD = EK_A ‖ R
    A : clé de cliquet initiale = EK_A ; (RK, CKs) = KDF_RK(SK, X25519(EK_A, R))
    B : clé de cliquet initiale = (r, R)
    premier message : mode 0x02, IK_A = 32 × 0x00, id SPK = id PQPK = 0,
                      en-tête.DH = EK_A (vérifié)

Le répondeur essaie chacune de ses clés : l'identifiant de session
(`SHA-256(AD)[0..8]`) dit laquelle. Il garde les EK vues (comme §7.3). Dès
que B répond (clé de cliquet neuve), quelqu'un qui n'a que la clé partagée ne
lit plus rien. **Deux personnes seulement** : une clé connue de trois
personnes ou plus reste en v1/v2 (plusieurs répondeurs se disputeraient la
même session).

### 7.5 Double Ratchet

- `MAX_SKIP` = 1 000 : un message qui demanderait de sauter plus de 1 000
  clés d'un coup est refusé, et la session ne garde jamais plus de 1 000 clés
  sautées (les plus anciennes partent d'abord) ; une clé sautée de plus de
  30 jours est effacée. L'heure est fournie par l'appelant (secondes Unix).
- Déchiffrement **transactionnel** : un échec (altération, rejeu, saut trop
  grand) laisse l'état exactement tel quel.
- Rejeu reconnu : numéro déjà passé sur la chaîne courante, ou clé de
  cliquet distante parmi les 16 dernières, ou notre propre clé de cliquet ;
  l'appli l'ignore sans bruit.
- Compteurs u32 : une chaîne épuisée (2³² messages) refuse d'envoyer.
- Un premier message (0x01) de même identifiant de session mais d'une autre
  EK est une nouvelle session (A a perdu la sienne) : `NouvelleSession`, à
  accepter comme un premier message.
- Tailles : texte de 200 Kio au plus, jeton décodé de 256 Kio au plus.

### 7.6 Distribution (type 0x03)

    0x03 ‖ id session (8) ‖ en-tête (40) ‖ chiffré
    chiffré = AES-256-GCM(clé, nonce, pad(distribution), AD ‖ en-tête ‖ 0x03)
    distribution (92) = id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE)
                        ‖ clé de chaîne (32) ‖ clé publique Ed25519 (32)

Le `0x03` final authentifie le type : sinon un 0x03 relu comme 0x02
afficherait la clé de chaîne comme un texte. Pour 0x01/0x02 le type n'est
pas authentifié (le changer ne sert à rien : 0x01 → 0x02 retire le préambule
d'un message déjà valide). **Proposition pour une future version** :
`AD ‖ type ‖ en-tête` pour tous les types. Un 0x03 n'a pas de préambule : un
initiateur non confirmé l'envoie après un 0x01 ; reçu avant, il donne
`SessionInconnue` et l'appli le garde pour plus tard.

### 7.7 Groupes (type 0x04)

- id expéditeur = `SHA-256(clé publique Ed25519 de la chaîne)[0..8]` (il
  change à chaque chaîne neuve) ; id groupe : 16 octets aléatoires.
- `mk` de l'itération i par `KDF_CK`, puis `ENCRYPT(mk)` du §4.3 (même info
  `Brocolis_v3_MessageKeys`) ; données associées AES-GCM = les 29 premiers
  octets (type ‖ id groupe ‖ id expéditeur ‖ itération) ; signature
  Ed25519 (stricte) de tout ce qui précède, type compris, **vérifiée
  avant** tout le reste.
- Mêmes règles que §7.5 : `MAX_SKIP`, 30 jours, rejeu ignoré,
  transactionnel.

### 7.8 Hygiène

Comparaisons de secrets en temps constant (tags GCM, identifiants dérivés
d'une clé partagée), secrets effacés (`zeroize`), aucune panique sur une
entrée hostile, aucune heure ni hasard implicite (passés par l'appelant :
`wasm32-unknown-unknown` n'a pas d'horloge).

## 8. Intégration dans Brocolis

Comment l'app iPhone, le site (discussion en ligne) et, à leur suite,
l'app Android passent au v3 sans casser ce qui existe. Comme le §7, chaque
point fait partie du contrat : un portage fait **exactement** pareil (format
des échanges, choix du format d'envoi, empreinte). Ce qui reste local à une
plateforme (forme du stockage, verrou) est dit comme tel.

### 8.1 L'appareil v3

- **Un `Device` par installation** (iPhone : partagé par l'app et ses
  extensions ; un navigateur ; une app Android). Créé au premier besoin, avec
  ML-KEM-768 si la plateforme l'a (iPhone : iOS 26 ; navigateur : toujours ;
  Android : selon la bibliothèque), sinon en X25519 seul.
- **Entretien à chaque transaction (§8.3)** : SPK et PQPK neuves chaque
  semaine (`needs_rotation` → `rotate`), ML-KEM ajouté dès qu'il devient
  disponible (iPhone passé à iOS 26 : `enable_pq`), purge des clés
  remplacées depuis 30 jours et de la mémoire des premiers messages.
- **Où** :

  | Plateforme | `Device` (JSON de la référence) | Sessions et messages ouverts (§8.2) |
  |---|---|---|
  | iPhone | Trousseau, service `rs.brocolis.messagerie.secrets`, compte `v3_device`, groupe d'accès = l'App Group, `AfterFirstUnlockThisDeviceOnly` | fichier `BrocolisV3/etat.bin` du conteneur de l'App Group, chiffré AES-256-GCM par une clé de 32 octets du Trousseau (compte `v3_state_key`, mêmes attributs) ; dossier exclu des sauvegardes |
  | Navigateur | coffre (`coffre.rs`), entrée `brocolis.web.v3.device` | coffre, entrée `brocolis.web.v3.state` |
  | Android | valeur chiffrée par la clé `AndroidKeyStore` (§3.1) | idem |

  Sur l'iPhone, **aucun repli** vers les `UserDefaults` pour ces secrets
  (contrairement aux clés nommées) : Trousseau illisible (appareil jamais
  déverrouillé depuis le démarrage, clavier sans « accès complet ») = v3
  indisponible pour cette opération, qui se fait alors en v1/v2 (§8.5).
  Fichier d'état : `nonce (12) ‖ AES-256-GCM(JSON) ‖ tag (16)`, données
  associées `brocolis-v3-etat-v1` ; écrit dans un fichier temporaire puis
  renommé (jamais à moitié écrit). Un fichier illisible (clé perdue,
  sauvegarde restaurée) est remplacé par un état vide : les sessions se
  rouvrent (§8.6).

### 8.2 L'état : sessions et messages ouverts

- **Sessions par contact** : la clé du contact est son IK X25519 (en
  hexadécimal). Au plus **deux** sessions par contact (celle que j'ai
  ouverte, celle qu'il a ouverte : AD = IK de l'initiateur ‖ IK du
  répondeur, donc deux identifiants au plus) ; ranger une session remplace
  celle de même identifiant et retire la plus ancienne au-delà de deux. La
  **session d'envoi** est la dernière qui a servi (à l'envoi comme à la
  réception). C'est le choix de Talka : si les deux écrivent en même temps
  leur premier message, chacun lit l'autre.
- **Sessions à clé partagée (PSK)** : rangées par identifiant de clé
  nommée, mêmes règles (deux au plus, la dernière qui a servi). On garde
  aussi la liste des clés sur lesquelles un message PSK est **arrivé**
  (§8.5) et la mémoire des clés éphémères PSK déjà vues (`ReplayGuard`,
  §7.4).
- **Messages ouverts** : un message v3 ne se déchiffre qu'**une** fois (la
  clé de message est effacée). Son clair est donc gardé, dans le même état
  chiffré, sous `h = hex(SHA-256(jeton normalisé))` — le jeton
  `[[BROCOLIS:v3:…]]` dont on a retiré tout blanc (une messagerie peut
  couper une longue ligne). Mes propres envois y entrent au chiffrement.
  2 000 entrées et 1 Mio de clair au plus ; les plus anciennes partent
  d'abord. C'est ce qui permet de relire une conversation, de rouvrir le
  clavier sur un message déjà lu, de recharger la page du site.

### 8.3 Une transaction à la fois (app, clavier, Partager, iMessage…)

Plusieurs processus (l'app et ses extensions) écrivent le même état. Un
message ne doit **jamais** être chiffré deux fois avec la même clé de
message, ni déchiffré avec deux états différents. Toute opération qui lit ou
change l'appareil ou l'état est donc une **transaction** :

    verrou exclusif → lire Device et état → entretien (§8.1)
      → chiffrer / déchiffrer (et ranger le clair, §8.2)
      → écrire Device s'il a changé → écrire l'état s'il a changé
      → lâcher le verrou → seulement alors rendre le jeton (ou le clair)

- iPhone : `flock(LOCK_EX)` sur `BrocolisV3/verrou` du conteneur de l'App
  Group, un descripteur ouvert **par transaction** (deux fils d'un même
  processus s'excluent donc aussi). La transaction est synchrone (aucune
  attente réseau dedans) : le verrou dure quelques millisecondes, iOS ne
  suspend pas l'app en le tenant.
- Le `Device` est écrit **avant** l'état : sa mémoire des premiers messages
  n'est jamais en retard sur les sessions (un premier message rejoué reste
  refusé). Si une écriture échoue, l'opération échoue : un jeton n'est
  jamais rendu sans que l'état qui l'a produit soit écrit (« état écrit
  avant l'envoi »).
- Navigateur : `navigator.locks.request("brocolis-v3", …)` (plusieurs
  onglets), sinon (navigateur ancien) sans verrou entre onglets.
- Android : un verrou du processus et `FileChannel.lock()` sur un fichier de
  verrou (le clavier peut tourner dans un autre processus).

### 8.4 Appairage → session v3

Le salon (`/pair`, `/wrap`) ne change pas pour un ancien client : tout ce qui
suit est **optionnel**.

- **Publier son paquet** : `POST /pair` porte en plus
  `"bundle": "<base64 du paquet §7.3>"` (166 ou 1 418 octets), à chaque
  publication (invitation, réponse, mode compatible, reprise à l'ouverture).
  Le serveur vérifie le paquet (`KeyBundle::from_bytes` : format, clés,
  signatures) — invalide : `400` —, le garde avec le participant et le
  rend dans la liste des participants (`{ "peerId", "pub", "bundle" }`, sans
  `bundle` s'il n'en a pas). Le republier avec la même identité
  (`IK X25519 ‖ IK Ed25519`) le remplace (rotation) ; avec une autre identité
  : `409`, comme une autre clé publique. Republier sans `bundle` garde celui
  qui est connu.
- **Retrouver le paquet du correspondant** : l'invitant prend celui du
  participant à qui il remet la clé ; celui qui rejoint prend celui du
  participant `peerId = wrap.from` et `pub = wrap.fromPub` (liste relue
  après l'arrivée de la clé, `GET /pair`).
- **À deux ou en groupe** (`duo`) : l'invitant est « à deux » tant qu'il a
  remis la clé à **une** personne ; à la deuxième, la clé devient une clé
  de groupe, pour toujours. Celui qui rejoint est « à deux » si le salon
  compte exactement un autre participant quand la clé arrive ; pendant les
  8 jours suivants, à chaque ouverture de l'app, il relit le salon et passe
  en groupe s'il y voit plus d'un autre participant. Le mode compatible
  (« Appairer à deux ») est toujours à deux.
- **Empreinte** (comparée de vive voix) : à deux, avec les deux paquets,

      P   = IK X25519 ‖ IK Ed25519 de chaque appareil (64 octets)
      F   = SHA-256("Brocolis_v3_Appairage" ‖ K ‖ min(P_A, P_B) ‖ max(P_A, P_B))[0..8]
      affichée XXXX-XXXX-XXXX-XXXX (hexadécimal majuscule)

  avec K la clé partagée (32 octets) et min/max dans l'ordre
  lexicographique des 64 octets. Elle couvre la clé **et** les deux
  identités v3 : un paquet substitué change l'empreinte d'un côté au moins.
  Sinon (groupe, ou un côté sans paquet) : l'empreinte d'avant
  (`SHA-256(K)[0..8]`, ou celle du mode compatible). Un serveur qui retire
  le paquet d'un seul côté fait afficher deux empreintes différentes ; s'il
  les retire des deux, l'appairage reste en ancien format, **affiché** comme
  tel (§8.8).

  Vecteur : K = 32 × `0x07`, P_A = 64 × `0x01`, P_B = 64 × `0x02` →
  `F = 1D47-6221-06A0-8AC5`.

- **Le contact** : la clé nommée garde le paquet du correspondant, sa date
  d'arrivée et `duo` (données publiques ; sur l'iPhone, avec la clé au
  Trousseau). L'invitant ouvre aussitôt la session (`initiate`, hybride si
  le paquet et l'appareil ont ML-KEM) : elle part avec son premier message
  (0x01). Celui qui rejoint ouvre la sienne au premier envoi, s'il n'a rien
  reçu avant.

### 8.5 Le format d'un envoi

Pour **une** clé destinataire K (clavier, Partager, iMessage, écran
Conversation, messagerie, site), dans cet ordre :

1. K a un contact v3 **à deux** : sa session d'envoi ; sans session, une
   session neuve vers son paquet **s'il a moins de 30 jours** (au-delà, sa
   SPK a pu être effacée : on passe au 3).
2. Sinon, **PSK** si K est marquée « à deux, double cliquet » par
   l'utilisateur, ou si un message PSK est déjà arrivé sur K (l'autre est à
   jour et s'en sert : on suit) : sa session PSK d'envoi, ou
   `initiate_psk(K)`. Jamais de PSK automatique sur une clé sans signe que
   l'autre est à jour : un ancien client ne lirait rien.
3. Sinon : v1 — v2 pour plusieurs clés. Une clé de groupe (3 personnes ou
   plus) reste toujours en v1/v2 (§7.4) ; tout ce qui ne tient pas dans un
   jeton v3 (200 Kio) aussi.

Le v3 indisponible (Trousseau fermé, état illisible et non réécrivable)
fait passer au 3. Les jetons v1/v2 restent lisibles pour toujours.

### 8.6 La réception d'un jeton v3

1. Normaliser le jeton, chercher `h` dans les messages ouverts (§8.2) :
   trouvé, c'est le clair.
2. Décoder ; chercher la session par son identifiant parmi celles des
   contacts et des clés PSK ; `decrypt`. Réussi : ranger le clair, la
   session devient celle d'envoi.
3. Session inconnue (ou `NouvelleSession`) et premier message (0x01) :
   - mode `0x02` (PSK) : essayer `accept_psk` clé par clé (la mémoire PSK
     des clés éphémères en garde) ; la clé qui l'ouvre reçoit la session et
     passe en PSK (§8.5, 2) ;
   - modes `0x00`/`0x01` : **seulement** si `IK_A` est l'IK X25519 d'un
     contact (un paquet reçu à l'appairage) — sinon refusé, expéditeur
     inconnu —, puis `Device::accept`.
4. `Rejoue` sans clair gardé : « déjà lu sur cet appareil ». Toute autre
   erreur : le jeton reste chiffré.
5. **Réparation** (comme Talka, `needs_repair`) : seulement dans une
   conversation de la messagerie (la clé du correspondant est connue), pour
   un message **de l'autre**, et seulement si l'erreur est `SessionInconnue`
   ou `CleInconnue` : on oublie les sessions de ce contact, le prochain
   envoi en ouvre une neuve (0x01) que l'autre accepte. Un échec de
   déchiffrement sur une session connue (rejeu d'un vieux message,
   falsification) ne répare **rien** : sinon rejouer suffirait à faire
   tomber la session.

### 8.7 La messagerie (serveur) et la discussion du site

- L'identifiant de conversation ne change pas (dérivé de K) ; le serveur
  transporte des jetons v3 au lieu de v1, sans le savoir.
- **Mes messages** reviennent du serveur : ils ne sont jamais déchiffrés
  (impossible, et ce n'est pas de l'autre), seulement relus dans les
  messages ouverts ; à défaut : « 🔐 envoyé depuis cet appareil ».
- **Photos, vocaux, longs textes** (clair commençant par `BRCM1:` ou de plus
  de 16 Kio) : une clé de média `K_m` (32 octets aléatoires) part dans le
  message v3, le média dans un jeton v1 sous `K_m`, collé derrière :

      clair v3          = "BRCM3:" ‖ base64(K_m)
      champ ciphertext  = [[BROCOLIS:v3:…]][[BROCOLIS:v1:…]]   (v1 = AES-256-GCM sous K_m du clair « BRCM1:img:… »)

  La confidentialité persistante couvre le média (K_m n'existe que dans un
  message à cliquet). À la lecture : ouvrir le v3, puis le v1 qui suit avec
  `K_m`.
- **La montre** n'a pas les sessions (elles ne quittent pas l'iPhone : deux
  appareils sur un même état réutiliseraient des clés de message) : un
  message v3 y reste « 🔐 à lire sur l'iPhone », et ce qu'elle envoie part
  en v1.
- Le site garde le même modèle pour sa discussion : un appareil par
  navigateur, le paquet échangé dans le salon, sessions et messages ouverts
  au coffre ; « Quitter » efface la clé et l'état v3 de la discussion
  (l'appareil reste).

### 8.8 Ce que l'interface affiche

Partout où s'affiche une clé ou un contact (liste des clés, correspondants
de la messagerie, en-tête d'une conversation, fin d'appairage, clavier,
Partager, iMessage, site) :

| Cas | Libellé |
|---|---|
| contact v3 à deux, session (ou session à venir) hybride | 🔐 double cliquet (post-quantique) |
| contact v3 à deux, X25519 seul (iPhone avant iOS 26, paquet sans ML-KEM) | 🔐 double cliquet (classique) |
| PSK (§8.5, 2) | 🔐 double cliquet, clé partagée (PSK) |
| tout le reste (groupe, ancien client, paquet trop vieux) | ancien format |

Sans session encore, le libellé dit ce que ferait le prochain envoi.

### 8.9 Clé protégée par une phrase

L'export écrit la **v2** (Argon2id, m = 64 Mio, t = 3, p = 1 ; §3.2) ;
l'import lit v1 et v2. L'iPhone refuse en plus, à l'import, une v2 qui
demanderait plus de 256 Mio (le système tuerait l'app avant la fin) — en
deçà de la borne du §3.2, sans effet sur ce qu'écrit un client conforme.

### 8.10 Ce que voit le serveur, ce qui reste à faire

- Le serveur voit en plus les **paquets de clés publiques** (publics par
  nature, signés) ; ni clé privée, ni clé de session, ni clair.
- Restent en v1/v2 : les clés de groupe (Sender Keys par sessions à deux,
  §4.5, à venir), ce que la montre envoie, ce qui dépasse 200 Kio hors
  messagerie.
- Pas encore : rafraîchir le paquet d'un contact sans réappairer (au-delà de
  30 jours sans session, l'envoi repasse en v1 et l'affiche) ; chiffrement
  des en-têtes (§5).
