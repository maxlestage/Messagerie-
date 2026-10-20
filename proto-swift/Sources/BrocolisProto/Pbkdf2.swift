// PBKDF2-HMAC-SHA256 (RFC 8018), un seul bloc de 32 octets : la clé
// protégée v1 (600 000 tours). CommonCrypto sur les plateformes Apple ;
// ailleurs, HMAC<SHA256> de swift-crypto (comme TalkaKit `TalkaCrypto.pbkdf2`),
// l'état HMAC de la phrase calculé une fois puis copié à chaque tour.

#if canImport(CommonCrypto)
import CommonCrypto
#endif

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

enum Pbkdf2 {
    /// PBKDF2-HMAC-SHA256(phrase, sel, tours), 32 octets.
    static func sha256(password: [UInt8], salt: [UInt8], rounds: UInt32) -> [UInt8] {
        #if canImport(CommonCrypto)
        var out = [UInt8](repeating: 0, count: 32)
        let status = password.withUnsafeBufferPointer { p in
            salt.withUnsafeBufferPointer { s in
                p.withMemoryRebound(to: Int8.self) { p8 in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2), p8.baseAddress, p.count,
                        s.baseAddress, s.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), rounds, &out, out.count)
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 (CommonCrypto)")
        return out
        #else
        // T1 = U1 ⊕ … ⊕ Uc, U1 = HMAC(P, S ‖ INT(1)), Ui = HMAC(P, Ui−1).
        let base = HMAC<SHA256>(key: SymmetricKey(data: password))
        var mac = base
        mac.update(data: salt + [0, 0, 0, 1])
        var u = Array(mac.finalize())
        var t = u
        if rounds > 1 {
            for _ in 1..<rounds {
                var h = base
                h.update(data: u)
                let next = Array(h.finalize())
                effacer(&u)
                u = next
                for i in 0..<32 { t[i] ^= u[i] }
            }
        }
        effacer(&u)
        return t
        #endif
    }
}
