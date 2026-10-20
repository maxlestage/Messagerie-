//
//  BrocolisKeyAgreement.swift
//  Brocolis 🥦 (partagé)
//
//  Accord de clé X25519 (ECDH) : chaque appareil possède une paire de clés ;
//  on échange les CLÉS PUBLIQUES (via le serveur de rendez-vous), puis chacun
//  dérive de son côté la MÊME clé symétrique AES-256 (HKDF-SHA256). Plus besoin
//  de copier la clé secrète : elle n'est jamais transmise.
//
//  Une empreinte courte (issue des deux clés publiques) permet de détecter un
//  intercepteur (MITM) en la comparant de vive voix.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

enum BrocolisKeyAgreement {

    private static let salt = Data("brocolis-x25519".utf8)
    private static let wrapSalt = Data("brocolis-x25519-wrap".utf8)

    enum AgreementError: LocalizedError {
        case badPeerKey
        var errorDescription: String? { "Clé publique du correspondant invalide." }
    }

    struct Derived {
        let symmetricKeyBase64: String
        let fingerprint: String
    }

    /// Récupère la clé privée X25519 locale (persistée), ou en crée une.
    static func loadOrCreatePrivateKey() -> Curve25519.KeyAgreement.PrivateKey {
        if let b64 = BrocolisKeyStore.privateKeyBase64,
           let data = Data(base64Encoded: b64),
           let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data) {
            return key
        }
        let key = Curve25519.KeyAgreement.PrivateKey()
        BrocolisKeyStore.setPrivateKeyBase64(key.rawRepresentation.base64EncodedString())
        return key
    }

    static func publicKeyBase64(of priv: Curve25519.KeyAgreement.PrivateKey) -> String {
        priv.publicKey.rawRepresentation.base64EncodedString()
    }

    /// Dérive la clé AES partagée + l'empreinte, à partir de la clé publique du
    /// correspondant (base64).
    static func derive(
        myPrivate priv: Curve25519.KeyAgreement.PrivateKey,
        peerPublicBase64 peerB64: String
    ) throws -> Derived {
        let trimmed = peerB64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let peerData = Data(base64Encoded: trimmed) else { throw AgreementError.badPeerKey }
        guard let peerKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerData) else {
            throw AgreementError.badPeerKey
        }

        let shared = try priv.sharedSecretFromKeyAgreement(with: peerKey)
        let myPub = priv.publicKey.rawRepresentation
        let info = sortedConcat(myPub, peerData) // identique des deux côtés

        let symKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32
        )
        let raw = symKey.withUnsafeBytes { Data(Array($0)) }
        return Derived(
            symmetricKeyBase64: raw.base64EncodedString(),
            fingerprint: fingerprint(info)
        )
    }

    // MARK: Clé de groupe (key-wrapping X25519)

    /// Génère une clé de groupe AES-256 aléatoire (base64).
    static func generateGroupKeyBase64() -> String {
        BrocolisCrypto.generateKeyBase64()
    }

    /// Emballe (chiffre) la clé de groupe à destination d'un membre, via la clé
    /// pairwise dérivée de ma clé privée et de SA clé publique. Renvoie un blob
    /// base64 que seul ce membre pourra déballer.
    static func wrapGroupKey(
        groupKeyBase64: String,
        forPeerPublicBase64 peerB64: String,
        myPrivate priv: Curve25519.KeyAgreement.PrivateKey
    ) throws -> String {
        guard let groupKey = Data(base64Encoded: groupKeyBase64) else { throw AgreementError.badPeerKey }
        let peerPub = try peerPublicData(peerB64)
        let wrapKey = try pairwiseWrapKey(myPrivate: priv, peerPub: peerPub)
        let sealed = try AES.GCM.seal(groupKey, using: wrapKey)
        guard let combined = sealed.combined else { throw AgreementError.badPeerKey }
        return combined.base64EncodedString()
    }

    /// Déballe la clé de groupe reçue, via la clé pairwise dérivée de ma clé
    /// privée et de la clé publique de l'émetteur. Renvoie la clé AES (base64).
    static func unwrapGroupKey(
        blobBase64: String,
        fromPeerPublicBase64 fromB64: String,
        myPrivate priv: Curve25519.KeyAgreement.PrivateKey
    ) throws -> String {
        guard let packed = Data(base64Encoded: blobBase64) else { throw AgreementError.badPeerKey }
        let fromPub = try peerPublicData(fromB64)
        let wrapKey = try pairwiseWrapKey(myPrivate: priv, peerPub: fromPub)
        guard let box = try? AES.GCM.SealedBox(combined: packed) else { throw AgreementError.badPeerKey }
        let groupKey = try AES.GCM.open(box, using: wrapKey)
        return groupKey.base64EncodedString()
    }

    /// Empreinte d'une clé de groupe (identique pour tous les membres).
    static func groupFingerprint(groupKeyBase64: String) -> String {
        let data = Data(base64Encoded: groupKeyBase64) ?? Data()
        return fingerprint(data)
    }

    /// Clé symétrique pairwise (même secret des deux côtés) servant à emballer.
    private static func pairwiseWrapKey(
        myPrivate priv: Curve25519.KeyAgreement.PrivateKey,
        peerPub: Data
    ) throws -> SymmetricKey {
        guard let peerKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPub) else {
            throw AgreementError.badPeerKey
        }
        let shared = try priv.sharedSecretFromKeyAgreement(with: peerKey)
        let info = sortedConcat(priv.publicKey.rawRepresentation, peerPub)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: wrapSalt, sharedInfo: info, outputByteCount: 32)
    }

    private static func peerPublicData(_ b64: String) throws -> Data {
        guard let d = Data(base64Encoded: b64.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw AgreementError.badPeerKey
        }
        return d
    }

    // MARK: Outils

    private static func sortedConcat(_ a: Data, _ b: Data) -> Data {
        lexLessOrEqual(a, b) ? a + b : b + a
    }

    private static func lexLessOrEqual(_ a: Data, _ b: Data) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        return a.count <= b.count
    }

    /// Empreinte lisible (8 octets en hex, groupés) à comparer de vive voix.
    static func fingerprint(_ info: Data) -> String {
        let digest = SHA256.hash(data: info)
        let hex = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
        var out = ""
        for (i, ch) in hex.enumerated() {
            if i != 0 && i % 4 == 0 { out += "-" }
            out.append(ch)
        }
        return out
    }
}
