//
//  BrocolisCryptoTests.swift
//  Messagerie 🥦
//
//  Vérifie le chiffrement sélectif et la compatibilité de format avec brocolis.
//

import XCTest
import CryptoKit
@testable import Brocolis

final class BrocolisCryptoTests: XCTestCase {

    func testKeyBase64Roundtrip() throws {
        let b64 = BrocolisCrypto.generateKeyBase64()
        let key = try BrocolisCrypto.symmetricKey(fromBase64: b64)
        XCTAssertEqual(key.bitCount, 256)
    }

    func testBadKeyLengthRejected() {
        let short = Data(repeating: 0, count: 16).base64EncodedString()
        XCTAssertThrowsError(try BrocolisCrypto.symmetricKey(fromBase64: short))
    }

    func testBadKeyBase64Rejected() {
        XCTAssertThrowsError(try BrocolisCrypto.symmetricKey(fromBase64: "pas du base64 !!!"))
    }

    func testTokenRoundtrip() throws {
        let key = try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
        let token = try BrocolisCrypto.encryptToken(Data("hello world".utf8), key: key)
        XCTAssertTrue(token.hasPrefix(BrocolisCrypto.tokenPrefix))
        XCTAssertTrue(token.hasSuffix(BrocolisCrypto.tokenSuffix))

        let inner = String(token.dropFirst(BrocolisCrypto.tokenPrefix.count)
            .dropLast(BrocolisCrypto.tokenSuffix.count))
        let plain = try BrocolisCrypto.decryptToken(base64: inner, key: key)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "hello world")
    }

    func testMarkedRoundtrip() throws {
        let key = try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
        let src = "Coucou ((mon secret)) et ((un autre)) fin"
        let (enc, n) = BrocolisCrypto.encryptMarked(src, key: key)
        XCTAssertEqual(n, 2)
        XCTAssertFalse(enc.contains("mon secret"))
        XCTAssertTrue(enc.contains(BrocolisCrypto.tokenPrefix))

        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 2)
        XCTAssertEqual(dec, "Coucou mon secret et un autre fin")
    }

    func testWrongKeyKeepsToken() throws {
        let k1 = try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
        let k2 = try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
        let (enc, _) = BrocolisCrypto.encryptMarked("x ((s)) y", key: k1)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: k2)
        XCTAssertEqual(m, 0)
        XCTAssertEqual(dec, enc) // jeton conservé, pas de crash
    }

    func testUnclosedMarkerIsNoop() throws {
        let key = try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
        let (enc, n) = BrocolisCrypto.encryptMarked("debut ((pas ferme", key: key)
        XCTAssertEqual(n, 0)
        XCTAssertEqual(enc, "debut ((pas ferme")
    }

    /// Compatibilité de format : un jeton produit par CryptoKit doit être
    /// déchiffrable via le découpage `nonce(12) || ciphertext || tag(16)` que
    /// brocolis utilise côté Rust.
    func testWireFormatMatchesBrocolis() throws {
        let b64 = BrocolisCrypto.generateKeyBase64()
        let key = try BrocolisCrypto.symmetricKey(fromBase64: b64)
        let token = try BrocolisCrypto.encryptToken(Data("brocolis".utf8), key: key)
        let inner = String(token.dropFirst(BrocolisCrypto.tokenPrefix.count)
            .dropLast(BrocolisCrypto.tokenSuffix.count))
        let packed = try XCTUnwrap(Data(base64Encoded: inner))
        // nonce(12) + tag(16) + 8 octets de "brocolis" = 36
        XCTAssertEqual(packed.count, 12 + 8 + 16)
    }
}
