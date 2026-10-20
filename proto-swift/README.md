# BrocolisProto

Le protocole de sécurité de Brocolis 🥦 et Talka
([`docs/SECURITE.md`](../docs/SECURITE.md)) en Swift, porté de
l'implémentation de référence Rust ([`proto/`](../proto)). Il retrouve
[`proto/vectors.json`](../proto/vectors.json) octet pour octet et passe les
vecteurs Wycheproof des primitives.

| Swift | Rust (`brocolis_proto::`) | Spec |
|---|---|---|
| `CleProtegee`, `Argon2Params` | `cle_protegee` (v1 PBKDF2 en lecture, v2 Argon2id) | §3.2, §7.1 |
| `Jetons` | `jetons` (v1/v2, `((…))`, `masked`, empreintes) | §4.6 |
| `Remplissage` | `remplissage` | §3.3, §7.2 |
| `Device`, `KeyBundle`, `IdentitySecret`, `ReplayGuard`, `Paquet` | `paquet` | §4.1, §7.3 |
| `Session`, `Content`, `KemEncapsulation` | `session` (classique, hybride, PSK ; Double Ratchet) | §4.2–4.3, §7.4–7.5 |
| `Token`, `JetonV3` | `jeton_v3` | §4.4 |
| `SenderKeyState`, `ReceivedSenderKey`, `SenderKeyDistribution`, `Groupe` | `groupe` | §4.5, §7.6–7.7 |
| `Kdf`, `MlKem`, `Argon2`, `Base64` | `kdf`, ML-KEM, Argon2 | — |
| `Erreur`, `Protocole`, `CryptoRng`, `Hasard`, `Deterministic` | `Erreur`, constantes, `hasard` | — |

## Dépendre du paquet

```swift
.package(url: "https://github.com/maxlestage/messagerie-.git", revision: "<sha>"),
// …
.product(name: "BrocolisProto", package: "messagerie-"),
```

iOS 16, macOS 13, watchOS 9, tvOS 16, visionOS 1 (CryptoKit) ; Linux, Android,
Windows avec swift-crypto **4.x** (la première série qui a ML-KEM ; elle
demande Swift 6). Un paquet qui dépend aussi de swift-crypto 3.x (TalkaKit :
`"3.0.0"..<"4.0.0"`) doit élargir sa contrainte à `"3.0.0"..<"5.0.0"`, sinon
SwiftPM ne trouve pas de version commune.

## En bref

```swift
import BrocolisProto

let rng = Hasard.system()
let alice = Device.generate(rng: rng, now: now, pq: true)    // IK, SPK, PQPK si ML-KEM
let bob = Device.generate(rng: rng, now: now, pq: true)
let paquet = try bob.bundle().toBytes()                       // échangé à l'appairage

let a = try alice.initiateBest(bundle: try KeyBundle.fromBytes(paquet), rng: rng)
let jeton = try a.encrypt("Salut 🥦")                          // [[BROCOLIS:v3:…]] (0x01)

guard case .initial(let premier) = try Token.decode(jeton) else { … }
let (b, contenu) = try bob.accept(premier, now: now, rng: rng)  // .text("Salut 🥦")
let reponse = try b.encrypt("Bien reçu")                       // 0x02
_ = try a.decryptText(reponse, now: now, rng: rng)             // a.isConfirmed
```

Recevoir : décoder, chercher la session par `Token.sessionId`,
`Session.decrypt` ; un 0x01 sans session (ou `.nouvelleSession`) va à
`Device.accept` ou, en clé partagée, à `Session.acceptPsk`. `.rejoue` :
message déjà lu, à ignorer. Les états (`Device`, `Session`, `SenderKeyState`,
`ReceivedSenderKey`, `ReplayGuard`) se sauvent en JSON (`toJson`/`fromJson`),
**de la même forme que la référence** (mêmes champs, octets en base64, `null`
écrits) : un état écrit par Rust se relit en Swift et inversement. À garder
chiffrés par la clé matérielle (§3.1). Octets : `[UInt8]` partout.

## Ce que CryptoKit impose (sans effet sur le format)

- **ML-KEM-768** vient de CryptoKit à partir d'iOS/macOS/watchOS 26 (Xcode 26),
  de swift-crypto sous Linux ; jamais réécrit ici. Ailleurs
  `MlKem.isAvailable` est faux : `Device.generate(pq: true)` ne crée pas de
  PQPK, `bundle()` n'en propose pas, `initiate(pq: true)` et un premier
  message hybride donnent `.pqIndisponible`, et `initiateBest` établit en
  X25519 seul (« session non post-quantique », §4.2). Le contrôle du module
  de FIPS 203 sur une PQPK reçue est fait en Swift, partout.
- **L'aléa `m` de l'encapsulation** est tiré par la bibliothèque : les
  vecteurs se vérifient par la décapsulation, et `Session.initiateWith`
  prend le résultat d'une encapsulation (`KemEncapsulation`) au lieu de `m`.
  `initiate(pq: true)` tire quand même 32 octets là où Rust tire `m`, pour
  que les tirages suivants restent alignés.
- **Ed25519, vérification stricte** : CryptoKit (et BoringSSL) acceptent une
  clé publique ou un R de petit ordre — la signature « universelle » A = R =
  identité, S = 0 passe. `Kdf.ed25519Verify` ajoute les contrôles de
  `verify_strict` (A et R des points qui ne sont pas de petit ordre, S < L),
  comparés à curve25519-dalek et prouvés par Wycheproof.
- **Signatures Ed25519** : CryptoKit signe avec de l'aléa ; les signatures
  de paquet et de groupe sont valides mais pas identiques à celles des
  vecteurs (BoringSSL, sous Linux, les retrouve octet pour octet).
- **Argon2id** (RFC 9106) et BLAKE2b sont écrits ici (CryptoKit n'en a
  pas) : 64 Mio, t = 3 en 0,26 s (Linux x86-64, `-c release`).
- **Effacement** au mieux : les tableaux temporaires et les états à leur
  destruction ; une copie faite par Swift (copie à l'écriture) peut y
  échapper.

## Vérifier

```sh
swift test                 # vecteurs, Wycheproof, propriétés, robustesse, interop Rust
swift test -c release
```

Les tests lisent `proto/vectors.json` et `proto/tests/wycheproof/` sur place
(simulateur ou Mac : pas sur un iPhone physique). `Fixtures/reference-rust.json`
vient de la référence Rust (`Fixtures/reference-rust.rs`).
