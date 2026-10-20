// Les vecteurs Wycheproof (C2SP/wycheproof, `testvectors_v1`, Apache 2.0 :
// proto/tests/wycheproof/LICENSE) des primitives du protocole, passés aux
// fonctions du paquet elles-mêmes, avec la même politique que la référence
// (proto/tests/wycheproof.rs). Chaque cas « invalid » doit être refusé.

import XCTest
@testable import BrocolisProto

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class WycheproofTests: XCTestCase {
    func tests(_ v: [String: Any]) throws -> [(group: [String: Any], test: [String: Any])] {
        var out: [(group: [String: Any], test: [String: Any])] = []
        for g in try XCTUnwrap(v["testGroups"] as? [[String: Any]]) {
            for t in try XCTUnwrap(g["tests"] as? [[String: Any]]) { out.append((g, t)) }
        }
        return out
    }

    func flags(_ t: [String: Any]) -> [String] {
        t["flags"] as? [String] ?? []
    }

    func compter(_ n: Int, _ quoi: String) {
        Compteur.shared.ajouter("wycheproof", n)
        print("Wycheproof \(quoi) : \(n) cas")
    }

    func testAes256Gcm() throws {
        var n = 0
        for (g, t) in try tests(try Depot.wycheproof("aes_gcm_test.json")) {
            // Le protocole n'utilise qu'AES-256, nonce 96 bits, tag 128 bits.
            guard g["keySize"] as? Int == 256, g["ivSize"] as? Int == 96, g["tagSize"] as? Int == 128 else { continue }
            let id = t["tcId"] as? Int ?? -1
            let key = unhex(t["key"]), iv = unhex(t["iv"]), aad = unhex(t["aad"]), msg = unhex(t["msg"])
            let ct = unhex(t["ct"]) + unhex(t["tag"])
            if t["result"] as? String == "valid" {
                XCTAssertEqual(try Kdf.aesGcmSeal(key: key, nonce: iv, aad: aad, message: msg), ct, "tcId \(id)")
                XCTAssertEqual(try Kdf.aesGcmOpen(key: key, nonce: iv, aad: aad, ciphertext: ct), msg, "tcId \(id)")
            } else {
                attendreEchec("tcId \(id)") { try Kdf.aesGcmOpen(key: key, nonce: iv, aad: aad, ciphertext: ct) }
            }
            n += 1
        }
        XCTAssertGreaterThanOrEqual(n, 60)
        compter(n, "AES-256-GCM")
    }

    func testX25519() throws {
        var n = 0
        for (_, t) in try tests(try Depot.wycheproof("x25519_test.json")) {
            let id = t["tcId"] as? Int ?? -1
            let priv = unhex(t["private"]), pub = unhex(t["public"]), shared = unhex(t["shared"])
            let f = flags(t)
            let r = try? Kdf.x25519(priv, pub)
            // Notre politique : refuser un secret nul (petit ordre) et une clé
            // publique non canonique (bit 255 levé ou u ≥ p). Tout le reste
            // doit donner exactement le secret attendu.
            if f.contains("ZeroSharedSecret") || f.contains("NonCanonicalPublic") {
                XCTAssertNil(r, "tcId \(id) \(f)")
            } else if t["result"] as? String == "invalid" {
                XCTAssertTrue(r == nil || r != shared, "tcId \(id)")
            } else {
                XCTAssertEqual(r, shared, "tcId \(id) \(f)")
            }
            n += 1
        }
        XCTAssertGreaterThan(n, 500)
        compter(n, "X25519")
    }

    func testHkdfSha256() throws {
        var n = 0
        for (_, t) in try tests(try Depot.wycheproof("hkdf_sha256_test.json")) {
            let size = try XCTUnwrap(t["size"] as? Int)
            let id = t["tcId"] as? Int ?? -1
            let r = try? Kdf.hkdfSha256(salt: unhex(t["salt"]), ikm: unhex(t["ikm"]), info: unhex(t["info"]), length: size)
            if t["result"] as? String == "valid" {
                XCTAssertEqual(r, unhex(t["okm"]), "tcId \(id)")
            } else {
                XCTAssertNil(r, "tcId \(id)")
            }
            n += 1
        }
        XCTAssertGreaterThan(n, 80)
        compter(n, "HKDF-SHA256")
    }

    func testHmacSha256() throws {
        var n = 0
        for (g, t) in try tests(try Depot.wycheproof("hmac_sha256_test.json")) {
            let bits = try XCTUnwrap(g["tagSize"] as? Int)
            let tag = Kdf.hmacSha256(key: unhex(t["key"]), data: unhex(t["msg"]))
            let same = Array(tag[0..<(bits / 8)]) == unhex(t["tag"])
            XCTAssertEqual(same, t["result"] as? String == "valid", "tcId \(t["tcId"] ?? "")")
            n += 1
        }
        compter(n, "HMAC-SHA256")
    }

    /// La vérification **stricte** : chaque cas « invalid » de Wycheproof est
    /// refusé (dont S non canonique et les points de petit ordre), chaque cas
    /// « valid » accepté.
    func testEd25519Strict() throws {
        var n = 0
        for (g, t) in try tests(try Depot.wycheproof("ed25519_test.json")) {
            let pk = unhex((g["publicKey"] as? [String: Any])?["pk"])
            let sig = unhex(t["sig"])
            let ok = (try? Kdf.ed25519Verify(publicKey: pk, message: unhex(t["msg"]), signature: sig)) != nil
            XCTAssertEqual(ok, t["result"] as? String == "valid", "tcId \(t["tcId"] ?? "") \(t["comment"] ?? "")")
            n += 1
        }
        XCTAssertGreaterThan(n, 140)
        compter(n, "Ed25519")
    }

    /// Ce que la vérification de la bibliothèque seule (CryptoKit, ou
    /// BoringSSL sous Linux) accepterait à tort, et que les contrôles
    /// stricts refusent : la preuve que ces contrôles servent.
    func testEd25519BibliothequeSeuleMoinsStricte() throws {
        func raw(_ pk: [UInt8], _ msg: [UInt8], _ sig: [UInt8]) -> Bool {
            guard let k = try? Curve25519.Signing.PublicKey(rawRepresentation: pk) else { return false }
            return k.isValidSignature(sig, for: msg)
        }
        var rawWrong = 0
        for (g, t) in try tests(try Depot.wycheproof("ed25519_test.json")) {
            let pk = unhex((g["publicKey"] as? [String: Any])?["pk"])
            if raw(pk, unhex(t["msg"]), unhex(t["sig"])) != (t["result"] as? String == "valid") { rawWrong += 1 }
        }
        print("Wycheproof Ed25519 : \(rawWrong) cas mal jugés par la bibliothèque seule, 0 en strict")
        // A = R = l'identité (petit ordre), S = 0 : l'équation
        // [S]B = R + [k]A tient pour tout message. La bibliothèque seule
        // l'accepte (ni BoringSSL ni, a priori, CryptoKit ne refusent A de
        // petit ordre) ; la vérification stricte, non.
        var identity = [UInt8](repeating: 0, count: 32)
        identity[0] = 1
        let forged = identity + [UInt8](repeating: 0, count: 32)
        let msg = Array("n'importe quel message".utf8)
        print("Signature universelle (A = R = identité, S = 0) acceptée par la bibliothèque seule : \(raw(identity, msg, forged))")
        attendreErreur(.cleInvalide) { try Kdf.ed25519Verify(publicKey: identity, message: msg, signature: forged) }
        // S + L (malléabilité) sur une vraie signature.
        let seed = h32("ed25519/s+l"), pk = Kdf.ed25519Public(seed: seed)
        let sig = Kdf.ed25519Sign(seed: seed, message: msg)
        var s = Array(sig[32..<64]), carry = 0
        for i in 0..<32 {
            let v = Int(s[i]) + Int(Ed25519Strict.order[i]) + carry
            s[i] = UInt8(v & 0xff)
            carry = v >> 8
        }
        print("S + L accepté par la bibliothèque seule : \(raw(pk, msg, Array(sig[0..<32]) + s))")
        attendreErreur(.signature) { try Kdf.ed25519Verify(publicKey: pk, message: msg, signature: Array(sig[0..<32]) + s) }
        // R de petit ordre avec A valide : refusé.
        attendreErreur(.signature) {
            try Kdf.ed25519Verify(publicKey: pk, message: msg, signature: identity + Array(sig[32..<64]))
        }
    }

    func testMlKem768() throws {
        guard MlKem.isAvailable else {
            throw XCTSkip("ML-KEM-768 indisponible sur cette plateforme (iOS/macOS < 26)")
        }
        var n = 0
        for (_, t) in try tests(try Depot.wycheproof("mlkem_768_test.json")) {
            let id = t["tcId"] as? Int ?? -1
            let seed = unhex(t["seed"])
            let valid = t["result"] as? String == "valid"
            if seed.count != 64 {
                // Graine de mauvaise longueur : refusée.
                XCTAssertFalse(valid, "tcId \(id)")
                attendreErreur(.format, "tcId \(id)") { try MlKem.decapsulate(seed: seed, ciphertext: unhex(t["c"])) }
                n += 1
                continue
            }
            if t["ek"] != nil {
                XCTAssertEqual(try MlKem.publicKey(seed: seed), unhex(t["ek"]), "tcId \(id)")
                XCTAssertTrue(MlKem.isValidPublicKey(unhex(t["ek"])), "tcId \(id)")
            }
            let r = try? MlKem.decapsulate(seed: seed, ciphertext: unhex(t["c"]))
            if valid {
                XCTAssertEqual(r, unhex(t["K"]), "tcId \(id)")
            } else {
                XCTAssertNil(r, "tcId \(id)")
            }
            n += 1
        }
        XCTAssertGreaterThan(n, 190)
        compter(n, "ML-KEM-768")
    }

    override class func tearDown() {
        print("Cas Wycheproof vérifiés : \(Compteur.shared.total("wycheproof"))")
        super.tearDown()
    }
}
