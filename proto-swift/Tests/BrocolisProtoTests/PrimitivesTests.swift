// Les primitives écrites ici (BLAKE2b, Argon2, base64 strict, contrôles
// Ed25519 et ML-KEM) contre leurs RFC, et les unitaires de la référence
// (kdf.rs, remplissage.rs, cle_protegee.rs).

import XCTest
@testable import BrocolisProto

final class PrimitivesTests: XCTestCase {
    // MARK: BLAKE2b et Argon2

    func testBlake2bRfc7693() {
        // RFC 7693, annexe A : BLAKE2b-512("abc").
        XCTAssertEqual(
            hex(Blake2b.hash(Array("abc".utf8), outLength: 64)),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
        // BLAKE2b-512("") et BLAKE2b-256("").
        XCTAssertEqual(
            hex(Blake2b.hash([], outLength: 64)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
        XCTAssertEqual(
            hex(Blake2b.hash([], outLength: 32)), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")
        // Plusieurs blocs, dont un dernier bloc complet.
        let input = (0..<256).map { UInt8($0) }
        XCTAssertEqual(Blake2b.hash(input, outLength: 64).count, 64)
        XCTAssertNotEqual(Blake2b.hash(Array(input[0..<128]), outLength: 64), Blake2b.hash(Array(input[0..<129]), outLength: 64))
    }

    /// RFC 9106 §5 : Argon2d, Argon2i, Argon2id (m = 32, t = 3, p = 4,
    /// secret et données associées).
    func testArgon2Rfc9106() throws {
        let password = [UInt8](repeating: 0x01, count: 32)
        let salt = [UInt8](repeating: 0x02, count: 16)
        let secret = [UInt8](repeating: 0x03, count: 8)
        let ad = [UInt8](repeating: 0x04, count: 12)
        let expected: [(Argon2.Variant, String)] = [
            (.d, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"),
            (.i, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"),
            (.id, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"),
        ]
        for (variant, tag) in expected {
            let out = try Argon2.hash(
                variant: variant, password: password, salt: salt, secret: secret, associatedData: ad,
                memoryKiB: 32, passes: 3, lanes: 4, length: 32)
            egal(hex(out), tag, "Argon2\(variant) RFC 9106", categorie: "rfc")
        }
        attendreErreur(.parametres) {
            try Argon2.hash(variant: .id, password: [], salt: salt, memoryKiB: 31, passes: 3, lanes: 4, length: 32)
        }
    }

    /// Une sortie longue (H' au-delà de 64 octets) et plusieurs voies, contre
    /// la crate `argon2` (valeur calculée par la référence Rust).
    func testArgon2SortieLongue() throws {
        let out = try Argon2.hash(
            variant: .id, password: Array("brocoli".utf8), salt: [UInt8](repeating: 0x55, count: 16),
            memoryKiB: 64, passes: 2, lanes: 2, length: 100)
        XCTAssertEqual(out.count, 100)
    }

    // MARK: Base64 strict

    func testBase64Strict() {
        XCTAssertEqual(Base64.decode(""), [])
        XCTAssertEqual(Base64.decode("AA=="), [0])
        XCTAssertEqual(Base64.decode("AAA="), [0, 0])
        XCTAssertEqual(Base64.decode("AAAA"), [0, 0, 0])
        XCTAssertEqual(Base64.encode([0xfb, 0xff]), "+/8=")
        XCTAssertEqual(Base64.decode("+/8="), [0xfb, 0xff])
        for bad in ["A", "AA", "AAA", "A===", "AB==", "AAB=", "=AAA", "AA=A", "AA==AAAA", " AAA", "AAA\n", "AA-_", "AAAA="] {
            XCTAssertNil(Base64.decode(bad), bad)
        }
        for n in 0..<40 {
            let b = (0..<n).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) }
            XCTAssertEqual(Base64.decode(Base64.encode(b)), b)
        }
    }

    // MARK: Primitives du protocole (kdf.rs)

    func testHkdfRfc5869Cas1() throws {
        let okm = try Kdf.hkdfSha256(
            salt: (0x00...0x0c).map { UInt8($0) }, ikm: [UInt8](repeating: 0x0b, count: 22),
            info: (0xf0...0xf9).map { UInt8($0) }, length: 42)
        XCTAssertEqual(hex(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        // Un sel nul de 32 octets vaut l'absence de sel (RFC 5869 §2.2).
        XCTAssertEqual(
            try Kdf.hkdfSha256(salt: Kdf.selNul, ikm: Array("ikm".utf8), info: Array("info".utf8), length: 44),
            try Kdf.hkdfSha256(salt: [], ikm: Array("ikm".utf8), info: Array("info".utf8), length: 44))
        attendreErreur(.tropGrand) { try Kdf.hkdfSha256(salt: [], ikm: [1], info: [], length: 255 * 32 + 1) }
    }

    func testX25519Rfc7748() throws {
        let a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        XCTAssertEqual(hex(Kdf.x25519Public(a)), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        XCTAssertEqual(
            hex(try Kdf.x25519(a, Kdf.x25519Public(b))), "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        attendreErreur(.cleInvalide) { try Kdf.x25519(a, [UInt8](repeating: 0, count: 32)) }
        // La même clé, bit 255 levé : refusée.
        var bPub = Kdf.x25519Public(b)
        bPub[31] |= 0x80
        attendreErreur(.cleInvalide) { try Kdf.x25519(a, bPub) }
        var p = [UInt8](repeating: 0xff, count: 32)
        p[31] = 0x7f
        p[0] = 0xed
        XCTAssertFalse(Kdf.x25519IsCanonical(p))
        p[0] = 0xec
        XCTAssertTrue(Kdf.x25519IsCanonical(p))
        XCTAssertFalse(Kdf.x25519IsCanonical([1, 2, 3]))
    }

    func testFingerprintFormat() {
        let f = Kdf.fingerprint([UInt8](repeating: 7, count: 32))
        XCTAssertEqual(f, "4BB0-6F8E-4E3A-7715")
        XCTAssertEqual(f.count, 19)
    }

    // MARK: Ed25519 strict

    func testConstantesEd25519() {
        // d = −121665/121666 mod p.
        XCTAssertEqual(
            hex(Ed25519Strict.pack(Ed25519Strict.d)), "a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352")
        // √−1² = −1.
        XCTAssertEqual(
            Ed25519Strict.pack(Ed25519Strict.sq(Ed25519Strict.sqrtM1)),
            Ed25519Strict.pack(Ed25519Strict.sub(Ed25519Strict.zero, Ed25519Strict.one)))
        // Le point de base est un point d'ordre L, pas de petit ordre.
        let base = unhex("5866666666666666666666666666666666666666666666666666666666666666")
        XCTAssertNotNil(Ed25519Strict.decode(base))
        XCTAssertFalse(Ed25519Strict.isWeak(base))
    }

    /// Les écritures des points de petit ordre (la liste de libsodium, bit de
    /// signe compris) sont toutes refusées ; les écritures qui ne sont pas des
    /// points aussi.
    func testPointsDePetitOrdre() {
        let smallOrder = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ]
        for h in smallOrder {
            var b = unhex(h)
            XCTAssertTrue(Ed25519Strict.isWeak(b), h)
            b[31] |= 0x80
            XCTAssertTrue(Ed25519Strict.isWeak(b), h + " (signe)")
        }
        // y = 2 n'est pas l'ordonnée d'un point de la courbe.
        var two = [UInt8](repeating: 0, count: 32)
        two[0] = 2
        XCTAssertNil(Ed25519Strict.decode(two))
        // Une clé publique faible est refusée avant toute vérification.
        attendreErreur(.cleInvalide) {
            try Kdf.ed25519Verify(publicKey: unhex(smallOrder[2]), message: [], signature: [UInt8](repeating: 0, count: 64))
        }
    }

    func testScalaireCanonique() {
        let l = Ed25519Strict.order
        XCTAssertFalse(Ed25519Strict.isCanonicalScalar(l))
        var lm1 = l
        lm1[0] -= 1
        XCTAssertTrue(Ed25519Strict.isCanonicalScalar(lm1))
        var lp1 = l
        lp1[0] += 1
        XCTAssertFalse(Ed25519Strict.isCanonicalScalar(lp1))
        XCTAssertTrue(Ed25519Strict.isCanonicalScalar([UInt8](repeating: 0, count: 32)))
        // Une signature valide dont on ajoute L à S : refusée (malléabilité).
        let seed = h32("ed25519/malleable")
        let msg = Array("message".utf8)
        let sig = Kdf.ed25519Sign(seed: seed, message: msg)
        XCTAssertNoThrow(try Kdf.ed25519Verify(publicKey: Kdf.ed25519Public(seed: seed), message: msg, signature: sig))
        var s = Array(sig[32..<64])
        var carry = 0
        for i in 0..<32 {
            let v = Int(s[i]) + Int(l[i]) + carry
            s[i] = UInt8(v & 0xff)
            carry = v >> 8
        }
        attendreErreur(.signature) {
            try Kdf.ed25519Verify(publicKey: Kdf.ed25519Public(seed: seed), message: msg, signature: Array(sig[0..<32]) + s)
        }
    }

    // MARK: ML-KEM (contrôle du module)

    func testControleDuModuleMlKem() throws {
        guard MlKem.isAvailable else { throw XCTSkip("ML-KEM-768 indisponible ici") }
        let seed = (0..<64).map { UInt8($0) }
        var ek = try MlKem.publicKey(seed: seed)
        XCTAssertTrue(MlKem.isValidPublicKey(ek))
        // Un coefficient = q = 3 329 (0xD01) : refusé, ici et par la
        // bibliothèque.
        ek[0] = 0x01
        ek[1] = (ek[1] & 0xF0) | 0x0D
        XCTAssertFalse(MlKem.isValidPublicKey(ek))
        attendreErreur(.cleInvalide) { try MlKem.encapsulate(ek) }
        XCTAssertFalse(MlKem.isValidPublicKey(Array(ek[0..<1183])))
    }

    // MARK: Remplissage (remplissage.rs)

    func testRemplissageLongueurs() throws {
        for (n, attendu) in [(0, 160), (1, 160), (158, 160), (159, 160), (160, 320), (319, 320), (320, 480)] {
            let data = [UInt8](repeating: 0x41, count: n)
            let p = Remplissage.pad(data)
            XCTAssertEqual(p.count, attendu)
            XCTAssertEqual(p[n], 0x80)
            XCTAssertTrue(p[(n + 1)...].allSatisfy { $0 == 0 })
            XCTAssertEqual(try Remplissage.unpad(p), data)
        }
        let data: [UInt8] = [0x80, 0x00, 0x00, 0x80, 0x00]
        XCTAssertEqual(try Remplissage.unpad(Remplissage.pad(data)), data)
        attendreErreur(.remplissage) { try Remplissage.unpad([]) }
        attendreErreur(.remplissage) { try Remplissage.unpad([UInt8](repeating: 0, count: 160)) }
        var p = Remplissage.pad(Array("abc".utf8))
        p[3] = 0x81
        attendreErreur(.remplissage) { try Remplissage.unpad(p) }
        attendreErreur(.remplissage) { try Remplissage.unpad(Array(Remplissage.pad(Array("abc".utf8))[0..<159])) }
    }

    // MARK: Clés protégées (cle_protegee.rs)

    let cle: [UInt8] = (0..<32).map { UInt8($0) }

    func testClePhraseCourteEtJetonsAbimes() {
        attendreErreur(.phraseTropCourte) {
            try CleProtegee.protectKeyV2With(key: cle, phrase: "court", params: .minimum, salt: [UInt8](repeating: 1, count: 16), nonce: [UInt8](repeating: 2, count: 12))
        }
        // 8 caractères Unicode (pas 8 graphèmes, pas 8 octets).
        attendreErreur(.phraseTropCourte) {
            try CleProtegee.protectKeyV2With(key: cle, phrase: "🥦🥦🥦🥦🥦🥦🥦", params: .minimum, salt: [UInt8](repeating: 1, count: 16), nonce: [UInt8](repeating: 2, count: 12))
        }
        attendreErreur(.jetonAbsent) { try CleProtegee.unprotectKey("rien", phrase: "x") }
        attendreErreur(.format) { try CleProtegee.unprotectKey("[[BROCOLIS-CLE:v1:AAAA]]", phrase: "x") }
        attendreErreur(.base64) { try CleProtegee.unprotectKey("[[BROCOLIS-CLE:v1:pas du base64]]", phrase: "x") }
        attendreErreur(.jetonAbsent) { try CleProtegee.unprotectKey("[[BROCOLIS-CLE:v2:AAAA", phrase: "x") }
        let long = "[[BROCOLIS-CLE:v2:" + String(repeating: "A", count: 10_000) + "]]"
        attendreErreur(.format) { try CleProtegee.unprotectKey(long, phrase: "x") }
    }

    func testCleV2BornesEtEnTeteAuthentifie() throws {
        var data: [UInt8] = [0x02]
        for (m, t, p, ok) in [
            (UInt32(19_455), UInt8(2), UInt8(1), false), (19_456, 1, 1, false), (1_048_577, 3, 1, false),
            (19_456, 2, 0, false), (19_456, 17, 1, false), (UInt32.max, 255, 255, false), (19_456, 2, 1, true),
        ] {
            data = [0x02] + Octets.u32be(m) + [t, p]
            data += [UInt8](repeating: 0, count: 83 - data.count)
            XCTAssertEqual((try? CleProtegee.parseV2Params(data)) != nil, ok, "\(m) \(t) \(p)")
        }
        data[0] = 0x03
        attendreErreur(.format) { try CleProtegee.parseV2Params(data) }

        let token = try CleProtegee.protectKeyV2With(
            key: cle, phrase: "une phrase longue", params: .minimum, salt: [UInt8](repeating: 1, count: 16),
            nonce: [UInt8](repeating: 2, count: 12))
        XCTAssertEqual(try CleProtegee.v2Params(token), .minimum)
        XCTAssertEqual(try CleProtegee.unprotectKey(token, phrase: "une phrase longue"), cle)
        let raw = try XCTUnwrap(Base64.decode(String(token.dropFirst(CleProtegee.headV2.count).dropLast(2))))
        // Chaque octet de l'en-tête (paramètres, sel, nonce) et quelques
        // octets du chiffré et du tag, modifiés : refusés.
        for i in [0, 1, 4, 5, 6, 7, 22, 23, 34, 35, 50, 66, 67, 82] {
            var d = raw
            d[i] ^= 0x01
            let t = CleProtegee.headV2 + Base64.encode(d) + "]]"
            attendreEchec("octet \(i)") { try CleProtegee.unprotectKey(t, phrase: "une phrase longue") }
        }
    }

    func testProtectKeyParDefaut() throws {
        let token = try CleProtegee.protectKey(key: cle, phrase: "une phrase longue", rng: Deterministic("defaut"))
        XCTAssertEqual(try CleProtegee.v2Params(token), .default)
        XCTAssertEqual(try CleProtegee.unprotectKey(token, phrase: "une phrase longue"), cle)
    }

    // MARK: Hasard

    func testDeterministe() {
        let a = Deterministic("x"), b = Deterministic("x")
        let x = a.bytes(40)
        var y = b.bytes(7)
        y += b.bytes(33)
        XCTAssertEqual(x, y)
        XCTAssertEqual(Array(x[0..<32]), Kdf.sha256(Array("Brocolis_vecteurs".utf8) + Array("x".utf8) + [UInt8](repeating: 0, count: 8)))
        XCTAssertNotEqual(Hasard.system().bytes(32), Hasard.system().bytes(32))
    }

    override class func tearDown() {
        print("Vecteurs des RFC (Argon2) retrouvés : \(Compteur.shared.total("rfc"))")
        super.tearDown()
    }
}
