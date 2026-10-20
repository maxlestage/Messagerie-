//
//  BrocolisKeyProtectionTests.swift
//  BrocolisTests
//
//  Clé « inviolable » : (1) le jeton de clé protégée par une phrase secrète
//  `[[BROCOLIS-CLE:v1:…]]`, au format commun avec Talka et l'Android — vecteur
//  de test FIXE de la spécification ; (2) le déplacement des secrets des
//  `UserDefaults` vers le Trousseau, sans jamais rien perdre.
//
//  Le Trousseau lui-même n'est pas touché ici : la CI lance les tests sur
//  simulateur SANS signature (`CODE_SIGNING_ALLOWED=NO`), donc sans l'App
//  Group comme groupe d'accès — le vrai Trousseau y répond « entitlement
//  manquant ». On teste donc la logique de migration (`BrocolisSecretStore`)
//  avec un coffre en mémoire qu'on peut faire échouer à volonté, et des
//  `UserDefaults` jetables.
//

import XCTest
@testable import Brocolis

final class BrocolisKeyProtectionTests: XCTestCase {

    // MARK: Vecteur de la spécification

    private let vectorKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
    private let vectorPassphrase = "brocoli vert 2026"
    private let vectorToken = "[[BROCOLIS-CLE:v1:ERERERERERERERERERERESIiIiIiIiIiIiIiIsq57j18BXkqq/4VdIw82nQqzrax9Cfn2mfUJjWH8l327NAf2rWaSYCJh3BfGH4eWA==]]"

    func testSpecVectorSealsToExactToken() throws {
        let token = try BrocolisKeyToken.seal(keyBase64: vectorKey, passphrase: vectorPassphrase,
                                              salt: Data(repeating: 0x11, count: 16),
                                              nonce: Data(repeating: 0x22, count: 12))
        XCTAssertEqual(token, vectorToken)
    }

    func testSpecVectorOpens() throws {
        XCTAssertEqual(try BrocolisKeyToken.open(token: vectorToken, passphrase: vectorPassphrase), vectorKey)
    }

    func testSpecVectorRefusesWrongPassphrase() {
        XCTAssertThrowsError(try BrocolisKeyToken.open(token: vectorToken, passphrase: "brocoli vert 2025")) {
            XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .wrongPassphrase)
        }
    }

    // MARK: PBKDF2-HMAC-SHA256 (vecteurs connus, RFC 7914 §11 et usuels)

    func testPBKDF2KnownVectors() {
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        XCTAssertEqual(hex(BrocolisKeyToken.pbkdf2SHA256(password: Data("passwd".utf8), salt: Data("salt".utf8), iterations: 1)),
                       "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
        XCTAssertEqual(hex(BrocolisKeyToken.pbkdf2SHA256(password: Data("password".utf8), salt: Data("salt".utf8), iterations: 2)),
                       "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        XCTAssertEqual(hex(BrocolisKeyToken.pbkdf2SHA256(password: Data("password".utf8), salt: Data("salt".utf8), iterations: 4096)),
                       "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
    }

    // MARK: Aller-retour

    func testRoundTripWithRandomSaltAndNonce() throws {
        let key = BrocolisCrypto.generateKeyBase64()
        let a = try BrocolisKeyToken.seal(keyBase64: key, passphrase: "phrase très secrète 🥦")
        let b = try BrocolisKeyToken.seal(keyBase64: key, passphrase: "phrase très secrète 🥦")
        XCTAssertTrue(a.hasPrefix(BrocolisKeyToken.prefix))
        XCTAssertTrue(a.hasSuffix(BrocolisKeyToken.suffix))
        XCTAssertNotEqual(a, b, "sel et nonce doivent être tirés à chaque export")
        XCTAssertEqual(try BrocolisKeyToken.open(token: a, passphrase: "phrase très secrète 🥦"), key)
        XCTAssertEqual(try BrocolisKeyToken.open(token: b, passphrase: "phrase très secrète 🥦"), key)
    }

    func testTokenFoundInsideLongerTextEvenWrapped() throws {
        // Une messagerie a pu couper la ligne au milieu du base64.
        let wrapped = vectorToken.replacingOccurrences(of: "ESIiIiIi", with: "ESIi\n  IiIi")
        let message = "Voici notre clé 🥦 :\n\n\(wrapped)\n\nJe te dis la phrase de vive voix."
        XCTAssertTrue(BrocolisKeyToken.containsToken(message))
        XCTAssertEqual(try BrocolisKeyToken.open(token: message, passphrase: vectorPassphrase), vectorKey)
    }

    func testShortPassphraseRefusedAtExport() {
        XCTAssertThrowsError(try BrocolisKeyToken.seal(keyBase64: vectorKey, passphrase: "1234567")) {
            XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .passphraseTooShort)
        }
        XCTAssertNoThrow(try BrocolisKeyToken.seal(keyBase64: vectorKey, passphrase: "12345678"))
    }

    func testBadKeyRefusedAtExport() {
        let short = Data(repeating: 7, count: 16).base64EncodedString()
        XCTAssertThrowsError(try BrocolisKeyToken.seal(keyBase64: short, passphrase: vectorPassphrase)) {
            XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .badKey)
        }
    }

    // MARK: Jeton abîmé

    func testDamagedTokenRefused() {
        // Un octet du texte chiffré modifié : le tag GCM ne passe plus.
        var bytes = [UInt8](Data(base64Encoded: String(vectorToken.dropFirst(BrocolisKeyToken.prefix.count).dropLast(2)))!)
        bytes[40] ^= 0x01
        let flipped = BrocolisKeyToken.prefix + Data(bytes).base64EncodedString() + BrocolisKeyToken.suffix
        XCTAssertThrowsError(try BrocolisKeyToken.open(token: flipped, passphrase: vectorPassphrase)) {
            XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .wrongPassphrase)
        }

        // Tronqué (76 octets attendus) ou non refermé : refusé d'emblée.
        let truncated = BrocolisKeyToken.prefix + Data(bytes.prefix(60)).base64EncodedString() + BrocolisKeyToken.suffix
        let unclosed = String(vectorToken.dropLast(2))
        let garbage = BrocolisKeyToken.prefix + "pas du base64 !" + BrocolisKeyToken.suffix
        for bad in [truncated, unclosed, garbage, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="] {
            XCTAssertThrowsError(try BrocolisKeyToken.open(token: bad, passphrase: vectorPassphrase)) {
                XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .badToken, bad)
            }
        }
    }

    func testKeyTokenIsNotMistakenForAMessageToken() {
        XCTAssertFalse(BrocolisCrypto.containsToken(vectorToken))
    }

    // MARK: Trousseau — migration depuis les UserDefaults

    /// Coffre en mémoire, qu'on peut rendre illisible ou réfractaire à l'écriture.
    private final class MemoryVault: BrocolisSecretVault {
        var items: [String: Data] = [:]
        var readFails = false
        var writeFails = false

        func read(_ account: String) -> BrocolisVaultRead {
            if readFails { return .failed }
            return items[account].map { .found($0) } ?? .notFound
        }
        func write(_ data: Data, account: String) -> Bool {
            if writeFails { return false }
            items[account] = data
            return true
        }
        func delete(_ account: String) -> Bool {
            items[account] = nil
            return true
        }
    }

    private var suiteName = ""
    private var defaults: UserDefaults!

    override func setUp() {
        super.setUp()
        suiteName = "brocolis-tests-\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suiteName)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suiteName)
        defaults = nil
        super.tearDown()
    }

    private func keysJSON(_ ids: [String]) -> Data {
        try! JSONEncoder().encode(ids.map { NamedKey(id: $0, name: $0, base64: BrocolisCrypto.generateKeyBase64()) })
    }

    private func ids(_ data: Data?) -> [String] {
        guard let data, let ks = try? JSONDecoder().decode([NamedKey].self, from: data) else { return [] }
        return ks.map(\.id)
    }

    func testMigrationMovesSecretsToVaultThenErasesDefaults() {
        let vault = MemoryVault()
        let store = BrocolisSecretStore(vault: vault, defaults: defaults)
        let json = keysJSON(["A", "B"])
        defaults.set(json, forKey: "keys_json")                    // ancienne version : Data
        defaults.set("cGFzIHVuZSB2cmFpZSBjbMOp", forKey: "x25519_private_b64") // ancienne version : String

        XCTAssertEqual(store.data("keys_json"), json)
        XCTAssertEqual(store.data("x25519_private_b64"), Data("cGFzIHVuZSB2cmFpZSBjbMOp".utf8))

        XCTAssertEqual(vault.items["keys_json"], json)
        XCTAssertEqual(vault.items["x25519_private_b64"], Data("cGFzIHVuZSB2cmFpZSBjbMOp".utf8))
        XCTAssertNil(defaults.object(forKey: "keys_json"), "le secret ne doit plus traîner en clair")
        XCTAssertNil(defaults.object(forKey: "x25519_private_b64"))
    }

    func testMigrationKeepsDefaultsWhenVaultRefusesTheWrite() {
        let vault = MemoryVault()
        vault.writeFails = true
        let store = BrocolisSecretStore(vault: vault, defaults: defaults)
        let json = keysJSON(["A"])
        defaults.set(json, forKey: "keys_json")

        XCTAssertEqual(store.data("keys_json"), json)
        XCTAssertNotNil(defaults.object(forKey: "keys_json"), "écriture refusée : rien ne doit être effacé")
        XCTAssertTrue(vault.items.isEmpty)
    }

    func testUnreadableVaultFallsBackAndNeverOverwritesIt() {
        let vault = MemoryVault()
        vault.items["keys_json"] = keysJSON(["A", "B"])
        vault.readFails = true
        let store = BrocolisSecretStore(vault: vault, defaults: defaults)

        // Trousseau illisible : on ne voit rien, et une écriture va en repli
        // sans écraser la liste qu'on ne peut pas lire.
        XCTAssertNil(store.data("keys_json"))
        XCTAssertTrue(store.set(keysJSON(["C"]), for: "keys_json"))
        XCTAssertEqual(ids(vault.items["keys_json"]), ["A", "B"])
        XCTAssertEqual(ids(defaults.data(forKey: "keys_json")), ["C"])

        // Le Trousseau revient : les deux listes sont réunies, plus rien en clair.
        vault.readFails = false
        let merged = store.data("keys_json", merge: BrocolisKeyStore.mergeKeysJSON)
        XCTAssertEqual(ids(merged), ["C", "A", "B"])
        XCTAssertEqual(ids(vault.items["keys_json"]), ["C", "A", "B"])
        XCTAssertNil(defaults.object(forKey: "keys_json"))
    }

    func testWriteGoesToVaultAndClearsLeftover() {
        let vault = MemoryVault()
        let store = BrocolisSecretStore(vault: vault, defaults: defaults)
        defaults.set(keysJSON(["vieux"]), forKey: "keys_json")
        let json = keysJSON(["neuf"])
        XCTAssertTrue(store.set(json, for: "keys_json"))
        XCTAssertEqual(vault.items["keys_json"], json)
        XCTAssertNil(defaults.object(forKey: "keys_json"))
    }

    func testRemoveErasesBothLocations() {
        let vault = MemoryVault()
        vault.items["x25519_private_b64"] = Data("a".utf8)
        defaults.set("b", forKey: "x25519_private_b64")
        let store = BrocolisSecretStore(vault: vault, defaults: defaults)
        store.remove("x25519_private_b64")
        XCTAssertNil(vault.items["x25519_private_b64"])
        XCTAssertNil(defaults.object(forKey: "x25519_private_b64"))
        XCTAssertNil(store.data("x25519_private_b64"))
    }

    func testMergeIgnoresUnreadableCopies() {
        let good = keysJSON(["A"])
        XCTAssertEqual(BrocolisKeyStore.mergeKeysJSON(stored: good, leftover: Data("{".utf8)), good)
        XCTAssertEqual(BrocolisKeyStore.mergeKeysJSON(stored: Data("{".utf8), leftover: good), good)
    }
}
