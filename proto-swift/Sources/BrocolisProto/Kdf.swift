// Les primitives et chaque dérivation du protocole, exposées telles quelles
// pour que les vecteurs vérifient chaque étape intermédiaire
// (`brocolis_proto::kdf`).
//
// | Fonction | Spécification |
// |---|---|
// | `skX3dh` | §4.2 : `HKDF(0³², FF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ SS], info)` |
// | `skPsk` | §4.2 : clé partagée |
// | `kdfRk` | §4.3 `KDF_RK` |
// | `kdfCk` | §4.3 `KDF_CK` |
// | `messageKey` | §4.3 `ENCRYPT(mk)` → clé AES ‖ nonce |
// | `sessionId` | §4.4 `SHA-256(AD)[0..8]` |
//
// Les longueurs des clés passées à ces fonctions sont des invariants (32
// octets, nonce 12) : une autre longueur est une erreur de programmation
// (`precondition`). Toute donnée venue de l'extérieur (jeton, paquet, JSON)
// est mesurée avant d'arriver ici.

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum Kdf {
    /// `"Brocolis_v3_X25519_MLKEM768_SHA-256"` : l'info de SK avec ML-KEM.
    public static let infoPq = Array("Brocolis_v3_X25519_MLKEM768_SHA-256".utf8)
    /// `"Brocolis_v3_X25519_SHA-256"` : l'info de SK sans ML-KEM (`pq = 0`).
    public static let infoClassique = Array("Brocolis_v3_X25519_SHA-256".utf8)
    /// `"Brocolis_v3_PSK_SHA-256"` : l'info de SK pour une clé partagée.
    public static let infoPsk = Array("Brocolis_v3_PSK_SHA-256".utf8)
    /// `"Brocolis_v3_PSK_Ratchet"` : la clé de cliquet initiale du répondeur
    /// d'une session à clé partagée (§7.4).
    public static let infoPskRatchet = Array("Brocolis_v3_PSK_Ratchet".utf8)
    /// `"Brocolis_v3_Ratchet"` : l'info de `KDF_RK`.
    public static let infoRatchet = Array("Brocolis_v3_Ratchet".utf8)
    /// `"Brocolis_v3_MessageKeys"` : l'info de `ENCRYPT(mk)`.
    public static let infoMessage = Array("Brocolis_v3_MessageKeys".utf8)
    /// 32 octets nuls : le sel des HKDF « sans sel » de la spécification.
    public static let selNul = [UInt8](repeating: 0, count: 32)

    // MARK: Primitives

    /// HKDF-SHA256 (RFC 5869) de longueur quelconque ; refuse
    /// (`.tropGrand`) une longueur au-delà de 255 × 32 octets.
    public static func hkdfSha256(salt: [UInt8], ikm: [UInt8], info: [UInt8], length: Int) throws -> [UInt8] {
        guard length >= 0, length <= 255 * 32 else { throw Erreur.tropGrand }
        if length == 0 { return [] }
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }

    /// HKDF-SHA256 de longueur fixe (≤ 64 dans tout le protocole).
    static func hkdf(_ salt: [UInt8], _ ikm: [UInt8], _ info: [UInt8], _ length: Int) -> [UInt8] {
        precondition(length > 0 && length <= 255 * 32)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: info, outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }

    /// HMAC-SHA256.
    public static func hmacSha256(key: [UInt8], data: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    /// SHA-256.
    public static func sha256(_ data: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: data))
    }

    /// AES-256-GCM, nonce de 12 octets : chiffré ‖ tag (16).
    public static func aesGcmSeal(key: [UInt8], nonce: [UInt8], aad: [UInt8], message: [UInt8]) throws -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 12, "AES-256-GCM : clé de 32 octets, nonce de 12")
        do {
            let box = try AES.GCM.seal(
                message, using: SymmetricKey(data: key), nonce: try AES.GCM.Nonce(data: nonce), authenticating: aad)
            return Array(box.ciphertext) + Array(box.tag)
        } catch {
            throw Erreur.tropGrand
        }
    }

    /// Ouvre un AES-256-GCM (chiffré ‖ tag) ; le tag est vérifié en temps
    /// constant par CryptoKit.
    public static func aesGcmOpen(key: [UInt8], nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 12, "AES-256-GCM : clé de 32 octets, nonce de 12")
        guard ciphertext.count >= 16 else { throw Erreur.dechiffrement }
        do {
            let box = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertext[0..<(ciphertext.count - 16)],
                tag: ciphertext[(ciphertext.count - 16)...])
            return Array(try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
        } catch {
            throw Erreur.dechiffrement
        }
    }

    /// La clé publique X25519 d'un secret de 32 octets (bruts, réduits par
    /// RFC 7748 au moment du calcul : comme x25519-dalek et BouncyCastle).
    public static func x25519Public(_ secret: [UInt8]) -> [UInt8] {
        precondition(secret.count == 32, "X25519 : secret de 32 octets")
        // Un secret de 32 octets est toujours accepté.
        let key = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
        return Array(key.publicKey.rawRepresentation)
    }

    /// Vrai si une clé publique X25519 est **canonique** : 32 octets, bit 255
    /// nul et u < 2²⁵⁵ − 19 (§7.3).
    public static func x25519IsCanonical(_ publicKey: [UInt8]) -> Bool {
        guard publicKey.count == 32 else { return false }
        if publicKey[31] & 0x80 != 0 { return false }
        // u ≥ p ⇔ u = 2²⁵⁵ − 19 + k, k < 19 : 0x7f, 30 × 0xff, puis ≥ 0xed.
        return !(publicKey[31] == 0x7f && publicKey[1..<31].allSatisfy { $0 == 0xff } && publicKey[0] >= 0xed)
    }

    /// X25519(secret, public). Refuse (`.cleInvalide`) une clé publique non
    /// canonique et un résultat nul (clé publique de petit ordre).
    public static func x25519(_ secret: [UInt8], _ publicKey: [UInt8]) throws -> [UInt8] {
        precondition(secret.count == 32, "X25519 : secret de 32 octets")
        guard x25519IsCanonical(publicKey) else { throw Erreur.cleInvalide }
        do {
            let key = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: secret)
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
            let shared = try key.sharedSecretFromKeyAgreement(with: peer)
            var out = shared.withUnsafeBytes { Array($0) }
            if Octets.isZero(out) {
                effacer(&out)
                throw Erreur.cleInvalide
            }
            return out
        } catch {
            throw Erreur.cleInvalide
        }
    }

    /// La clé publique Ed25519 d'une graine de 32 octets.
    public static func ed25519Public(seed: [UInt8]) -> [UInt8] {
        precondition(seed.count == 32, "Ed25519 : graine de 32 octets")
        let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return Array(key.publicKey.rawRepresentation)
    }

    /// Signe avec une graine Ed25519. Sous Linux (BoringSSL) la signature est
    /// celle de RFC 8032, déterministe, comme la référence ; CryptoKit peut
    /// la rendre aléatoire (toujours valide, pas forcément identique).
    public static func ed25519Sign(seed: [UInt8], message: [UInt8]) -> [UInt8] {
        precondition(seed.count == 32, "Ed25519 : graine de 32 octets")
        let key = try! Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        // La signature Ed25519 n'échoue pas.
        return Array(try! key.signature(for: message))
    }

    /// Vérifie une signature Ed25519 **stricte** (RFC 8032 §5.1.7, comme
    /// `verify_strict` d'ed25519-dalek) : A doit être un point qui n'est pas
    /// de petit ordre (sinon `.cleInvalide`) ; S canonique, R un point qui
    /// n'est pas de petit ordre et l'équation vraie (sinon `.signature`).
    public static func ed25519Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) throws {
        guard publicKey.count == 32, !Ed25519Strict.isWeak(publicKey) else { throw Erreur.cleInvalide }
        guard signature.count == 64 else { throw Erreur.signature }
        let r = Array(signature[0..<32]), s = Array(signature[32..<64])
        guard Ed25519Strict.isCanonicalScalar(s), !Ed25519Strict.isWeak(r) else { throw Erreur.signature }
        let key: Curve25519.Signing.PublicKey
        do {
            key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        } catch {
            throw Erreur.cleInvalide
        }
        guard key.isValidSignature(signature, for: message) else { throw Erreur.signature }
    }

    /// Vrai si une clé publique Ed25519 est utilisable : un point de la
    /// courbe qui n'est pas de petit ordre (`VerifyingKey::from_bytes` puis
    /// `is_weak`).
    public static func ed25519IsValidPublic(_ publicKey: [UInt8]) -> Bool {
        publicKey.count == 32 && !Ed25519Strict.isWeak(publicKey)
    }

    // MARK: Dérivations du protocole

    /// SK de l'établissement (§4.2) : `HKDF-SHA256(sel = 32 × 0x00, ikm = 32 ×
    /// 0xFF ‖ DH1 ‖ DH2 ‖ DH3 [‖ SS], info)`. Avec `ss`, l'info est
    /// `infoPq` ; sans, `infoClassique`.
    public static func skX3dh(dh1: [UInt8], dh2: [UInt8], dh3: [UInt8], ss: [UInt8]?) -> [UInt8] {
        var ikm = [UInt8](repeating: 0xFF, count: 32) + dh1 + dh2 + dh3
        defer { effacer(&ikm) }
        if let ss {
            ikm += ss
            return hkdf(selNul, ikm, infoPq, 32)
        }
        return hkdf(selNul, ikm, infoClassique, 32)
    }

    /// SK d'une session à clé partagée (§4.2) :
    /// `HKDF-SHA256(sel = 32 × 0x00, ikm = clé, "Brocolis_v3_PSK_SHA-256", 32)`.
    public static func skPsk(_ key: [UInt8]) -> [UInt8] {
        hkdf(selNul, key, infoPsk, 32)
    }

    /// Le secret X25519 de la clé de cliquet initiale du répondeur d'une
    /// session à clé partagée :
    /// `HKDF-SHA256(sel = 32 × 0x00, ikm = SK, "Brocolis_v3_PSK_Ratchet", 32)`.
    public static func pskRatchetSecret(_ sk: [UInt8]) -> [UInt8] {
        hkdf(selNul, sk, infoPskRatchet, 32)
    }

    /// `KDF_RK(rk, dh) = HKDF-SHA256(sel = rk, ikm = dh,
    /// "Brocolis_v3_Ratchet", 64)` → `(rk', ck)`.
    public static func kdfRk(_ rk: [UInt8], _ dh: [UInt8]) -> (rk: [UInt8], ck: [UInt8]) {
        var out = hkdf(rk, dh, infoRatchet, 64)
        defer { effacer(&out) }
        return (Array(out[0..<32]), Array(out[32..<64]))
    }

    /// `KDF_CK(ck)` → `(ck', mk)` avec `mk = HMAC-SHA256(ck, 0x01)` et
    /// `ck' = HMAC-SHA256(ck, 0x02)`.
    public static func kdfCk(_ ck: [UInt8]) -> (ck: [UInt8], mk: [UInt8]) {
        let mk = hmacSha256(key: ck, data: [0x01])
        let next = hmacSha256(key: ck, data: [0x02])
        return (next, mk)
    }

    /// `ENCRYPT(mk)` : `HKDF-SHA256(sel = 32 × 0x00, ikm = mk,
    /// "Brocolis_v3_MessageKeys", 44)` → clé AES (32) et nonce (12).
    public static func messageKey(_ mk: [UInt8]) -> (key: [UInt8], nonce: [UInt8]) {
        var out = hkdf(selNul, mk, infoMessage, 44)
        defer { effacer(&out) }
        return (Array(out[0..<32]), Array(out[32..<44]))
    }

    /// L'identifiant de session : `SHA-256(AD)[0..8]` (§4.4).
    public static func sessionId(_ ad: [UInt8]) -> [UInt8] {
        Array(sha256(ad)[0..<8])
    }

    /// L'empreinte à comparer de vive voix (`AB12-CD34-EF56-7890`) : les 8
    /// premiers octets du SHA-256 des données, en hexadécimal majuscule.
    public static func fingerprint(_ data: [UInt8]) -> String {
        let hex = Octets.hex(sha256(data)[0..<8]).uppercased()
        let c = Array(hex)
        return stride(from: 0, to: 16, by: 4).map { String(c[$0..<$0 + 4]) }.joined(separator: "-")
    }
}
