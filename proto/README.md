# brocolis-proto

L'implémentation de référence, en Rust, du protocole de sécurité de
Brocolis 🥦 et Talka ([`docs/SECURITE.md`](../docs/SECURITE.md), qui est le
contrat). Swift (iPhone), Kotlin (Android) et WebAssembly (navigateurs)
retrouvent ses vecteurs [`vectors.json`](vectors.json) octet pour octet.

| Module | Ce qu'il fait | Spec |
|---|---|---|
| `cle_protegee` | clé protégée par une phrase : v1 PBKDF2 (lecture), v2 Argon2id | §3.2 |
| `jetons` | jetons v1/v2 et passages `((…))`, comme Talka et l'app | §4.6 |
| `remplissage` | texte ‖ `0x80` ‖ `0x00…` au multiple de 160 | §3.3 |
| `paquet` | appareil, IK X25519 + Ed25519, SPK, PQPK ML-KEM-768, paquet signé | §4.1 |
| `session` | établissement (X25519, hybride ML-KEM, clé partagée), Double Ratchet | §4.2–4.3 |
| `jeton_v3` | `[[BROCOLIS:v3:…]]`, types 0x01–0x04, décodage strict | §4.4 |
| `groupe` | Sender Keys : distribution (0x03), messages signés (0x04) | §4.5 |
| `session4`, `jeton_v4` | **v4** : triple cliquet (X25519 + ML-KEM-768 à chaque tour), en-têtes chiffrés, identité de l'expéditeur cachée, `[[BROCOLIS:v4:…]]`, capacité signée | §9 |
| `kdf` | chaque dérivation, exposée pour les vecteurs | — |

Uniquement RustCrypto et dalek, `#![forbid(unsafe_code)]`, aucune panique sur
une entrée hostile (erreurs typées `Erreur`), secrets effacés (`zeroize`),
déchiffrement transactionnel. L'heure (secondes Unix) et le hasard
(`&mut impl CryptoRng`, `hasard::system()` en production) sont fournis par
l'appelant : la crate compile telle quelle en `wasm32-unknown-unknown`.

## En bref

```rust
use brocolis_proto::{hasard, Content, Device, KeyBundle, Token};

let mut rng = hasard::system();
let alice = Device::generate(&mut rng, now, true);      // IK, SPK, PQPK
let mut bob = Device::generate(&mut rng, now, true);
let paquet = bob.bundle()?.to_bytes();                   // échangé à l'appairage

let mut a = alice.initiate(&KeyBundle::from_bytes(&paquet)?, true, &mut rng)?;
let jeton = a.encrypt("Salut 🥦")?;                       // [[BROCOLIS:v3:…]] (type 0x01)

let Token::Initial(premier) = Token::decode(&jeton)? else { … };
let (mut b, Content::Text(texte)) = bob.accept(&premier, now, &mut rng)? else { … };
let reponse = b.encrypt("Bien reçu")?;                   // type 0x02
a.decrypt_text(&reponse, now, &mut rng)?;                // a.is_confirmed() == true
```

Recevoir : décoder, chercher la session par `Token::session_id()`,
`Session::decrypt` ; un 0x01 sans session (ou `Erreur::NouvelleSession`) va à
`Device::accept` ou, en clé partagée, à `Session::accept_psk`.
`Erreur::Rejoue` : message déjà lu, à ignorer. Les états (`Device`,
`Session`, `SenderKeyState`, `ReceivedSenderKey`) se sauvent en JSON
(`to_json`/`from_json`), à garder chiffrés par la clé matérielle (§3.1).

## Vérifier

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings
cargo test                        # unitaires, propriétés, Wycheproof, robustesse, vecteurs
cargo test --release
cargo build --target wasm32-unknown-unknown
cargo run --example vectors       # regénère vectors.json (déterministe)
python3 -I scripts/verifier_vecteurs.py vectors.json   # vérification indépendante (OpenSSL)
cargo audit && cargo deny check
cargo +nightly fuzz run decodage_jetons    # aussi dechiffrement_v3, groupe
```

`tests/wycheproof/` : vecteurs [C2SP/wycheproof](https://github.com/C2SP/wycheproof)
(Apache 2.0) pour AES-GCM, X25519, HKDF, HMAC, Ed25519 et ML-KEM-768.

## Pour les portages

`vectors.json` donne, pour chaque étape, les entrées et les sorties : KDF,
SK, racines et chaînes, clés et nonces de chaque message, en-têtes, jetons
complets, remplissages, clés protégées v1 et v2 (Argon2id minimal *et* par
défaut), paquets, groupes. Les secrets tirés pendant le cliquet sont écrits
(`*_drawn`) ; le générateur déterministe est décrit dans le fichier. Les
précisions et écarts par rapport à la spécification sont au §7 de
`docs/SECURITE.md` : à lire avant de porter.
