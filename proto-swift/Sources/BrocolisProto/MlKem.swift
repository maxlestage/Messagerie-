// ML-KEM-768 (FIPS 203) : jamais réécrit ici. Il vient de CryptoKit
// (`MLKEM768`, iOS 26 / macOS 26 / watchOS 26 et suivants) ou de
// swift-crypto 4 (Linux). Ailleurs (iPhone avant iOS 26), `MlKem.isAvailable`
// est faux : le mode hybride répond `.pqIndisponible` et l'établissement se
// fait en X25519 seul (§4.2, « session non post-quantique »).
//
// Deux écarts imposés par les bibliothèques, sans effet sur le format :
//
// - le secret est la graine FIPS 203 `d ‖ z` (64 octets), comme la
//   référence ;
// - l'encapsulation tire son aléa `m` elle-même (CryptoKit n'accepte pas de
//   `m` imposé) : les vecteurs se vérifient par la décapsulation (§7.3).
//
// Le contrôle du module (FIPS 203 §7.2 : chaque coefficient de t̂ < q) est
// fait ici, en clair, pour qu'un paquet soit accepté ou refusé de la même
// façon partout, même là où ML-KEM manque.

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// ML-KEM-768, par la bibliothèque du système.
public enum MlKem {
    /// La longueur d'une clé d'encapsulation.
    public static let publicKeyLength = 1_184
    /// La longueur d'un chiffré.
    public static let ciphertextLength = 1_088
    /// La longueur de la graine `d ‖ z`.
    public static let seedLength = 64

    /// Vrai si ML-KEM-768 est disponible sur cet appareil.
    public static var isAvailable: Bool {
        #if canImport(CryptoKit)
        #if compiler(>=6.2)
        if #available(iOS 26, macOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
            return true
        }
        #endif
        return false
        #else
        return true
        #endif
    }

    /// Le contrôle du module de FIPS 203 (§7.2) : 1 184 octets, et chacun
    /// des 768 coefficients de 12 bits de t̂ est < q = 3 329.
    public static func isValidPublicKey(_ ek: [UInt8]) -> Bool {
        guard ek.count == publicKeyLength else { return false }
        var i = 0
        while i < 1_152 {
            let b0 = UInt16(ek[i]), b1 = UInt16(ek[i + 1]), b2 = UInt16(ek[i + 2])
            let c0 = b0 | (b1 & 0x0F) << 8
            let c1 = b1 >> 4 | b2 << 4
            if c0 >= 3_329 || c1 >= 3_329 { return false }
            i += 3
        }
        return true
    }

    /// La clé d'encapsulation (1 184 octets) d'une graine `d ‖ z`.
    public static func publicKey(seed: [UInt8]) throws -> [UInt8] {
        guard seed.count == seedLength else { throw Erreur.format }
        #if canImport(CryptoKit)
        #if compiler(>=6.2)
        if #available(iOS 26, macOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
            guard let key = try? MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil) else {
                throw Erreur.format
            }
            return Array(key.publicKey.rawRepresentation)
        }
        #endif
        throw Erreur.pqIndisponible
        #else
        guard let key = try? MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil) else {
            throw Erreur.format
        }
        return Array(key.publicKey.rawRepresentation)
        #endif
    }

    /// ML-KEM-768.Encaps : `(CT, SS)`, l'aléa tiré par la bibliothèque.
    /// Refuse (`.cleInvalide`) une clé d'encapsulation invalide.
    public static func encapsulate(_ ek: [UInt8]) throws -> (ciphertext: [UInt8], shared: [UInt8]) {
        guard isValidPublicKey(ek) else { throw Erreur.cleInvalide }
        #if canImport(CryptoKit)
        #if compiler(>=6.2)
        if #available(iOS 26, macOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
            guard let key = try? MLKEM768.PublicKey(rawRepresentation: ek),
                  let r = try? key.encapsulate()
            else { throw Erreur.cleInvalide }
            return (Array(r.encapsulated), r.sharedSecret.withUnsafeBytes { Array($0) })
        }
        #endif
        throw Erreur.pqIndisponible
        #else
        guard let key = try? MLKEM768.PublicKey(rawRepresentation: ek),
              let r = try? key.encapsulate()
        else { throw Erreur.cleInvalide }
        return (Array(r.encapsulated), r.sharedSecret.withUnsafeBytes { Array($0) })
        #endif
    }

    /// ML-KEM-768.Decaps (rejet implicite : un chiffré altéré donne un secret
    /// faux, sans erreur, et le message est ensuite refusé). Un chiffré de
    /// mauvaise longueur : `.format`.
    public static func decapsulate(seed: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard seed.count == seedLength, ciphertext.count == ciphertextLength else { throw Erreur.format }
        #if canImport(CryptoKit)
        #if compiler(>=6.2)
        if #available(iOS 26, macOS 26, watchOS 26, tvOS 26, visionOS 26, *) {
            guard let key = try? MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil),
                  let ss = try? key.decapsulate(ciphertext)
            else { throw Erreur.format }
            return ss.withUnsafeBytes { Array($0) }
        }
        #endif
        throw Erreur.pqIndisponible
        #else
        guard let key = try? MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: nil),
              let ss = try? key.decapsulate(ciphertext)
        else { throw Erreur.format }
        return ss.withUnsafeBytes { Array($0) }
        #endif
    }
}
