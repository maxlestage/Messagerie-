//
//  BrocolisKeyAgreementTests.swift
//  BrocolisTests
//
//  Vérifie l'accord de clé X25519 : les deux côtés dérivent la MÊME clé AES et
//  la MÊME empreinte, et la clé dérivée chiffre/déchiffre réellement.
//

import XCTest
import CryptoKit
@testable import Brocolis

final class BrocolisKeyAgreementTests: XCTestCase {

    func testBothSidesDeriveSameKeyAndFingerprint() throws {
        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        let aPub = a.publicKey.rawRepresentation.base64EncodedString()
        let bPub = b.publicKey.rawRepresentation.base64EncodedString()

        let da = try BrocolisKeyAgreement.derive(myPrivate: a, peerPublicBase64: bPub)
        let db = try BrocolisKeyAgreement.derive(myPrivate: b, peerPublicBase64: aPub)

        XCTAssertEqual(da.symmetricKeyBase64, db.symmetricKeyBase64)
        XCTAssertEqual(da.fingerprint, db.fingerprint)
        XCTAssertEqual(Data(base64Encoded: da.symmetricKeyBase64)?.count, 32)
    }

    func testDifferentPeerProducesDifferentKey() throws {
        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        let c = Curve25519.KeyAgreement.PrivateKey()

        let kb = try BrocolisKeyAgreement.derive(
            myPrivate: a, peerPublicBase64: b.publicKey.rawRepresentation.base64EncodedString())
        let kc = try BrocolisKeyAgreement.derive(
            myPrivate: a, peerPublicBase64: c.publicKey.rawRepresentation.base64EncodedString())

        XCTAssertNotEqual(kb.symmetricKeyBase64, kc.symmetricKeyBase64)
    }

    func testBadPeerKeyThrows() {
        let a = Curve25519.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(
            try BrocolisKeyAgreement.derive(myPrivate: a, peerPublicBase64: "pas-du-base64 !!"))
    }

    func testDerivedKeyEncryptsAndDecryptsCrossDevice() throws {
        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        let da = try BrocolisKeyAgreement.derive(
            myPrivate: a, peerPublicBase64: b.publicKey.rawRepresentation.base64EncodedString())
        let db = try BrocolisKeyAgreement.derive(
            myPrivate: b, peerPublicBase64: a.publicKey.rawRepresentation.base64EncodedString())

        let keyA = try BrocolisCrypto.symmetricKey(fromBase64: da.symmetricKeyBase64)
        let keyB = try BrocolisCrypto.symmetricKey(fromBase64: db.symmetricKeyBase64)

        // A chiffre, B déchiffre avec la clé dérivée de son côté.
        let token = try BrocolisCrypto.encryptToken(Data("secret partagé 🥦".utf8), key: keyA)
        let inner = String(token.dropFirst(BrocolisCrypto.tokenPrefix.count)
            .dropLast(BrocolisCrypto.tokenSuffix.count))
        let plain = try BrocolisCrypto.decryptToken(base64: inner, key: keyB)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "secret partagé 🥦")
    }

    func testFingerprintFormat() throws {
        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        let d = try BrocolisKeyAgreement.derive(
            myPrivate: a, peerPublicBase64: b.publicKey.rawRepresentation.base64EncodedString())
        // 8 octets -> 16 hex -> 4 groupes de 4 séparés par 3 tirets = 19 caractères.
        XCTAssertEqual(d.fingerprint.count, 19)
        XCTAssertTrue(d.fingerprint.allSatisfy { $0.isHexDigit || $0 == "-" })
    }

    // MARK: Clé de groupe (key-wrapping)

    func testGroupKeyWrapUnwrap() throws {
        let founder = Curve25519.KeyAgreement.PrivateKey()
        let member = Curve25519.KeyAgreement.PrivateKey()
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()

        let blob = try BrocolisKeyAgreement.wrapGroupKey(
            groupKeyBase64: groupKey,
            forPeerPublicBase64: member.publicKey.rawRepresentation.base64EncodedString(),
            myPrivate: founder)

        let got = try BrocolisKeyAgreement.unwrapGroupKey(
            blobBase64: blob,
            fromPeerPublicBase64: founder.publicKey.rawRepresentation.base64EncodedString(),
            myPrivate: member)

        XCTAssertEqual(got, groupKey)
        XCTAssertEqual(
            BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: got),
            BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey))
    }

    func testGroupKeyDistributedToSeveralMembersIsIdentical() throws {
        let founder = Curve25519.KeyAgreement.PrivateKey()
        let members = [Curve25519.KeyAgreement.PrivateKey(),
                       Curve25519.KeyAgreement.PrivateKey(),
                       Curve25519.KeyAgreement.PrivateKey()]
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()
        let founderPub = founder.publicKey.rawRepresentation.base64EncodedString()

        for member in members {
            let blob = try BrocolisKeyAgreement.wrapGroupKey(
                groupKeyBase64: groupKey,
                forPeerPublicBase64: member.publicKey.rawRepresentation.base64EncodedString(),
                myPrivate: founder)
            let got = try BrocolisKeyAgreement.unwrapGroupKey(
                blobBase64: blob, fromPeerPublicBase64: founderPub, myPrivate: member)
            XCTAssertEqual(got, groupKey)
        }
    }

    func testIntruderCannotUnwrapGroupKey() throws {
        let founder = Curve25519.KeyAgreement.PrivateKey()
        let member = Curve25519.KeyAgreement.PrivateKey()
        let intruder = Curve25519.KeyAgreement.PrivateKey()
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()

        let blob = try BrocolisKeyAgreement.wrapGroupKey(
            groupKeyBase64: groupKey,
            forPeerPublicBase64: member.publicKey.rawRepresentation.base64EncodedString(),
            myPrivate: founder)

        // L'intrus tente avec sa clé privée + la clé publique du fondateur.
        XCTAssertThrowsError(try BrocolisKeyAgreement.unwrapGroupKey(
            blobBase64: blob,
            fromPeerPublicBase64: founder.publicKey.rawRepresentation.base64EncodedString(),
            myPrivate: intruder))
    }

    func testGroupKeyUsableForEncryptionAcrossMembers() throws {
        let founder = Curve25519.KeyAgreement.PrivateKey()
        let member = Curve25519.KeyAgreement.PrivateKey()
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()
        let blob = try BrocolisKeyAgreement.wrapGroupKey(
            groupKeyBase64: groupKey,
            forPeerPublicBase64: member.publicKey.rawRepresentation.base64EncodedString(),
            myPrivate: founder)
        let memberKeyB64 = try BrocolisKeyAgreement.unwrapGroupKey(
            blobBase64: blob,
            fromPeerPublicBase64: founder.publicKey.rawRepresentation.base64EncodedString(),
            myPrivate: member)

        let founderKey = try BrocolisCrypto.symmetricKey(fromBase64: groupKey)
        let memberKey = try BrocolisCrypto.symmetricKey(fromBase64: memberKeyB64)
        let token = try BrocolisCrypto.encryptToken(Data("message de groupe 🥦".utf8), key: founderKey)
        let inner = String(token.dropFirst(BrocolisCrypto.tokenPrefix.count)
            .dropLast(BrocolisCrypto.tokenSuffix.count))
        let plain = try BrocolisCrypto.decryptToken(base64: inner, key: memberKey)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "message de groupe 🥦")
    }

    func testFingerprintIsOrderIndependent() throws {
        // L'empreinte ne dépend pas de "qui dérive" : A↔B == B↔A (déjà couvert),
        // ici on vérifie aussi qu'elle est stable sur plusieurs dérivations.
        let a = Curve25519.KeyAgreement.PrivateKey()
        let b = Curve25519.KeyAgreement.PrivateKey()
        let bPub = b.publicKey.rawRepresentation.base64EncodedString()
        let d1 = try BrocolisKeyAgreement.derive(myPrivate: a, peerPublicBase64: bPub)
        let d2 = try BrocolisKeyAgreement.derive(myPrivate: a, peerPublicBase64: bPub)
        XCTAssertEqual(d1.fingerprint, d2.fingerprint)
        XCTAssertEqual(d1.symmetricKeyBase64, d2.symmetricKeyBase64)
    }
}
