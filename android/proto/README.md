# Module `:proto` — le protocole en Kotlin

Le protocole de sécurité de Brocolis 🥦 et Talka
([`docs/SECURITE.md`](../../docs/SECURITE.md)) en Kotlin, porté de
l'implémentation de référence Rust ([`proto/`](../../proto)). Il retrouve
[`proto/vectors.json`](../../proto/vectors.json) octet pour octet (signatures
Ed25519 et chiffrés ML-KEM compris), passe les vecteurs Wycheproof des
primitives et relit les états JSON écrits par Rust.

Bibliothèque Android (`minSdk 26`), paquet `rs.brocolis.messagerie.proto`,
sans aucune dépendance à `android.*` : tout se teste sur la JVM. L'app s'en
sert pour le v3 (docs/SECURITE.md §8) : `crypto/BrocolisV3Engine.kt` (la
logique, comme `Shared/BrocolisV3.swift`), `store/BrocolisV3Store.kt`
(Keystore, verrou entre fils et processus) et la façade
`crypto/BrocolisV3.kt` (Partager, Conversation, messagerie, appairage).

| Kotlin | Rust (`brocolis_proto::`) | Spec |
|---|---|---|
| `CleProtegee`, `Argon2Params` | `cle_protegee` (v1 PBKDF2 en lecture, v2 Argon2id) | §3.2, §7.1 |
| `Jetons` | `jetons` (v1/v2, `((…))`, `masked`, empreintes) | §4.6 |
| `Remplissage` | `remplissage` | §3.3, §7.2 |
| `Device`, `KeyBundle`, `IdentitySecret`, `IdentityPublic`, `PqBundle`, `ReplayGuard`, `Paquet` | `paquet` | §4.1, §7.3 |
| `Session`, `Content` | `session` (classique, hybride, PSK ; Double Ratchet) | §4.2–4.3, §7.4–7.5 |
| `Token`, `Initial`, `Envelope`, `Header`, `GroupMessage`, `Mode` | `jeton_v3` | §4.4 |
| `Session4`, `Mode4`, `Device.initiate4` / `accept4`, `Device.caps4`, `Paquet.verifyCaps4` | `session4`, `paquet` (v4 : triple cliquet, en-têtes chiffrés) | §9 |
| `Token4`, `Header4`, `Body4`, `Preamble4` | `jeton_v4` | §9.3–9.4 |
| `SenderKeyState`, `ReceivedSenderKey`, `SenderKeyDistribution`, `Groupe` | `groupe` | §4.5, §7.6–7.7 |
| `Kdf`, `MlKem` | `kdf`, ML-KEM | — |
| `Erreur` + `BrocolisException`, `Protocole`, `CryptoRng`, `Hasard`, `Deterministic`, `Octets` | `Erreur`, constantes, `hasard` | — |

## En bref

```kotlin
val rng = Hasard.system()
val alice = Device.generate(rng, now, pq = true)            // IK, SPK, PQPK
val bob = Device.generate(rng, now, pq = true)
val paquet = bob.bundle().toBytes()                          // échangé à l'appairage

val a = alice.initiate(KeyBundle.fromBytes(paquet), pq = true, rng)
val jeton = a.encrypt("Salut 🥦")                             // [[BROCOLIS:v3:…]] (0x01)

val premier = (Token.decode(jeton) as Token.InitialMessage).initial
val (b, contenu) = bob.accept(premier, now, rng)              // Content.Text("Salut 🥦")
val reponse = b.encrypt("Bien reçu")                          // 0x02
a.decryptText(reponse, now, rng)                              // a.isConfirmed
```

Recevoir : décoder, chercher la session par `Token.sessionId`,
`Session.decrypt` ; un 0x01 sans session (ou `Erreur.NouvelleSession`) va à
`Device.accept` ou, en clé partagée, à `Session.acceptPsk`.
`Erreur.Rejoue` : message déjà lu, à ignorer. Toute erreur est une
`BrocolisException` (champ `erreur`) ; une entrée hostile n'en lève jamais
d'autre. Les états (`Device`, `Session`, `SenderKeyState`,
`ReceivedSenderKey`, `ReplayGuard`) se sauvent en JSON (`toJson`/`fromJson`),
**de la même forme que la référence** (mêmes champs dans le même ordre,
octets en base64, `null` écrits) : un état écrit par Rust ou Swift se relit
ici et inversement. À garder chiffrés par la clé matérielle (§3.1). L'heure
(secondes Unix) et le hasard sont passés par l'appelant. Argon2id (64 Mio)
et PBKDF2 (600 000 tours) : hors du fil principal.

## Primitives

Jamais réécrites ici : **BouncyCastle** `bcprov-jdk18on` 1.86 (X25519,
Ed25519, ML-KEM-768 FIPS 203, Argon2id, HKDF, HMAC, SHA-256, PBKDF2) et
**javax.crypto** pour AES-256-GCM (Conscrypt, donc l'AES matériel, sur
Android). Le code du module ne fait que les contrôles de format que la
spécification exige (canonicité X25519, base64 et UTF-8 stricts…).

- **ML-KEM-768** : la graine `d ‖ z` (64 octets) est gardée comme en Rust.
  BouncyCastle accepte un aléa `m` imposé (`internalGenerateEncapsulated`) :
  les chiffrés des vecteurs sont refaits **par l'encapsulation** (pas
  seulement relus par la décapsulation, comme en Swift), et
  `Session.initiateWith` prend `m` comme la référence. Le contrôle du module
  de FIPS 203 sur une PQPK reçue est celui de BouncyCastle.
- **Ed25519** : signatures déterministes (RFC 8032), identiques à celles de
  dalek : paquets et messages de groupe des vecteurs retrouvés octet pour
  octet.

## Écarts avec la référence (sans effet sur le format)

- **Ed25519, vérification stricte** : BouncyCastle refuse déjà S ≥ L, une
  clé A de petit ordre et toute écriture non canonique, mais accepte un R de
  petit ordre et suit une équation (« Straus 128 bits ») qui n'est
  exactement celle, sans cofacteur, de `verify_strict` que pour des points
  sans torsion. `Kdf.ed25519Verify` exige donc que A et R soient d'ordre L
  (`validatePublicKeyFull`) avant l'équation. Conséquence : une signature
  que dalek accepterait est refusée ici **seulement** si la clé A elle-même
  a une composante de torsion ou une écriture de y non réduite (aucun
  appareil honnête n'en produit : A = [a]B) — plus strict, jamais plus
  laxiste. La validité d'une clé seule (`ed25519IsValidPublic`, le
  `!is_weak()` de dalek) suit dalek exactement, y compris y non réduit,
  comparée à curve25519-dalek sur 494 encodages.
- **Entiers JSON** : les heures (u64 en Rust) sont lues en `Long` ; une
  heure au-delà de 2⁶³ − 1 secondes est refusée (`Erreur.Etat`).
- **Effacement** au mieux : les tableaux temporaires et les états remplacés
  sont mis à zéro, mais la JVM (ramasse-miettes, chaînes, base64) peut en
  garder des copies ; c'est la clé matérielle (§3.1) qui protège l'état au
  repos.

## Vérifier

```sh
cd android
gradle :proto:testDebugUnitTest      # ou testDebugUnitTest pour tout le projet
```

Les tests (`src/test/…/proto/`) lisent `proto/vectors.json`,
`proto/tests/wycheproof/` et
`proto-swift/Tests/BrocolisProtoTests/Fixtures/reference-rust.json` sur
place (une seule source) :

- `VecteursTest` : chaque valeur de `vectors.json` (427 comparaisons) ;
- `VecteursV4Test` : les sessions v4 de `vectors.json` (`sessions_v4`,
  paquet et clé partagée : 294 comparaisons, chaque encapsulation ML-KEM du
  cliquet refaite à l'identique) ;
- `ProtocoleV4Test` : les tests unitaires de `session4.rs` et `jeton_v4.rs`
  et `proto/tests/robustesse_v4.rs`, portés ;
- `WycheproofTest` : X25519, Ed25519, AES-256-GCM, HKDF, HMAC, ML-KEM-768
  (1 196 cas), avec la politique de `proto/tests/wycheproof.rs` ;
- `ReferenceRustTest` : états JSON écrits par Rust relus, réécrits sous la
  même forme et continués ; points Ed25519 de dalek ; Argon2id de la crate
  `argon2`. Avec `BROCOLIS_INTEROP_OUT=<fichier>`, il écrit aussi des états
  et jetons Kotlin que `reference-rust phase3 <fichier>` (le programme
  `reference-rust.rs` de la même fixture) relit ;
- `ProtocoleTest`, `RobustesseTest`, `ModulesTest` : les tests de propriétés
  (désordre, pertes, rejeux, altérations d'un bit, MAX_SKIP, persistance),
  le fuzzing « du pauvre » et les tests unitaires de la référence, portés.
