//
//  BrocolisV3Tests.swift
//  BrocolisTests
//
//  Le v3 dans Brocolis (docs/SECURITE.md §8) : appairage → session, échanges,
//  désordre, doublons, PSK, clés de groupe, médias, état chiffré au repos,
//  Trousseau fermé, et la concurrence (plusieurs « processus » sur le même
//  état : jamais une clé de message réutilisée).
//
//  Tourne dans Xcode (simulateur) ET sous Linux (paquet de vérification avec
//  swift-crypto) : le coffre du Trousseau y est remplacé par des fichiers.
//

import XCTest
import BrocolisProto
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import Brocolis

/// Un coffre dans un dossier (un fichier par compte) : partagé par plusieurs
/// magasins, comme le Trousseau l'est par l'app et ses extensions.
final class BrocolisDirectoryVault: BrocolisSecretVault {
    let dir: URL
    var readFails = false

    init(dir: URL) {
        self.dir = dir
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    func read(_ account: String) -> BrocolisVaultRead {
        if readFails { return .failed }
        guard let data = try? Data(contentsOf: dir.appendingPathComponent(account)) else { return .notFound }
        return .found(data)
    }

    func write(_ data: Data, account: String) -> Bool {
        (try? data.write(to: dir.appendingPathComponent(account), options: .atomic)) != nil
    }

    func delete(_ account: String) -> Bool {
        try? FileManager.default.removeItem(at: dir.appendingPathComponent(account))
        return true
    }
}

final class BrocolisV3Tests: XCTestCase {

    private var dirs: [URL] = []
    private var savedStore: BrocolisV3Store?

    override func setUp() {
        super.setUp()
        savedStore = BrocolisV3.store
    }

    override func tearDown() {
        BrocolisV3.store = savedStore
        for d in dirs { try? FileManager.default.removeItem(at: d) }
        super.tearDown()
    }

    /// Un « téléphone » : son dossier d'App Group et son Trousseau.
    private func phone() -> BrocolisV3Store {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("brocolis-v3-\(UUID().uuidString)")
        dirs.append(root)
        return BrocolisV3Store(directory: root.appendingPathComponent("BrocolisV3"),
                               vault: BrocolisDirectoryVault(dir: root.appendingPathComponent("trousseau")))
    }

    /// Un autre processus du même téléphone (même dossier, même Trousseau).
    private func sibling(of store: BrocolisV3Store) -> BrocolisV3Store {
        BrocolisV3Store(directory: store.directory, vault: store.vault)
    }

    private func bundle(_ store: BrocolisV3Store) throws -> KeyBundle {
        try KeyBundle.fromBase64(try store.transaction { $0.bundleBase64! })
    }

    private func key(_ raw: [UInt8], peer: KeyBundle?, id: String = "k", group: Bool = false,
                     psk: Bool = false, at: UInt64 = BrocolisV3.now(), caps: [UInt8]? = nil) -> BrocolisV3Key {
        BrocolisV3Key(id: id, raw: raw, bundle: peer, bundleAt: at, group: group, psk: psk, caps: caps)
    }

    /// La capacité v4 signée que publie ce téléphone (§9.6).
    private func caps(_ store: BrocolisV3Store) throws -> [UInt8] {
        try XCTUnwrap(Base64.decode(try XCTUnwrap(try store.transaction { $0.capsBase64 })))
    }

    private func seal(_ store: BrocolisV3Store, _ text: String, _ k: BrocolisV3Key) throws -> String {
        try XCTUnwrap(try store.transaction { $0.seal(text, for: k, now: BrocolisV3.now()) })
    }

    private func open(_ store: BrocolisV3Store, _ token: String, _ k: BrocolisV3Key) throws -> BrocolisV3Opened {
        try store.transaction { $0.open(token, keys: [k], now: BrocolisV3.now()) }
    }

    // MARK: Appairage et empreinte

    func testPairingFingerprintMatchesTheSpecVector() {
        let k = [UInt8](repeating: 7, count: 32)
        let a = [UInt8](repeating: 1, count: 64), b = [UInt8](repeating: 2, count: 64)
        XCTAssertEqual(BrocolisV3Format.pairingFingerprint(key: k, a, b), "1D47-6221-06A0-8AC5")
        XCTAssertEqual(BrocolisV3Format.pairingFingerprint(key: k, b, a), "1D47-6221-06A0-8AC5")
    }

    func testPairedPhonesTalkInV3WithDisorderAndDuplicates() throws {
        let (alice, bob) = (phone(), phone())
        let (ba, bb) = (try bundle(alice), try bundle(bob))
        let raw = [UInt8](repeating: 9, count: 32)
        let ka = key(raw, peer: bb), kb = key(raw, peer: ba)
        // Les deux voient la même empreinte, qui couvre les identités v3.
        let fa = BrocolisV3Format.pairingFingerprint(
            key: raw, try alice.transaction { $0.identity }, BrocolisV3Format.identity(of: bb))
        let fb = BrocolisV3Format.pairingFingerprint(
            key: raw, try bob.transaction { $0.identity }, BrocolisV3Format.identity(of: ba))
        XCTAssertEqual(fa, fb)
        // L'invitant ouvre la session à l'appairage.
        XCTAssertTrue(try alice.transaction { $0.openSession(ka, now: BrocolisV3.now()) })
        let expected: BrocolisProtection = MlKem.isAvailable ? .postQuantum : .classic
        XCTAssertEqual(try alice.transaction { $0.protection(ka, now: BrocolisV3.now()) }, expected)

        let m1 = try seal(alice, "un 🥦", ka)
        let m2 = try seal(alice, "deux", ka)
        XCTAssertTrue(m1.hasPrefix(JetonV3.head))
        XCTAssertEqual(try open(bob, m2, kb), .text("deux"))
        XCTAssertEqual(try open(bob, m1, kb), .text("un 🥦"))
        XCTAssertEqual(try open(bob, m1, kb), .text("un 🥦"), "doublon : le clair gardé")
        let cut = String(m1.prefix(40)) + "\n  " + String(m1.dropFirst(40))
        XCTAssertEqual(try open(bob, cut, kb), .text("un 🥦"), "coupé par une messagerie")
        let r = try seal(bob, "réponse", kb)
        XCTAssertEqual(try open(alice, r, ka), .text("réponse"))
        XCTAssertEqual(try alice.transaction { $0.recall(m1) }, "un 🥦", "mes envois se relisent")
        // Un tiers qui n'est pas un contact : refusé.
        let carol = phone()
        XCTAssertEqual(try open(carol, m1, key(raw, peer: nil)), .failed(.sessionInconnue))
    }

    func testStateIsEncryptedAtRestAndSurvivesAReload() throws {
        let (alice, bob) = (phone(), phone())
        let ka = key([UInt8](repeating: 3, count: 32), peer: try bundle(bob))
        let kb = key([UInt8](repeating: 3, count: 32), peer: try bundle(alice))
        let m1 = try seal(alice, "secret au repos", ka)
        let file = try Data(contentsOf: alice.stateURL)
        XCTAssertNil(file.range(of: Data("secret au repos".utf8)), "l'état est chiffré")
        XCTAssertNil(file.range(of: Data("sessions".utf8)))
        // Un autre processus relit l'état : la clé suivante, pas la même.
        let m2 = try seal(sibling(of: alice), "après relecture", ka)
        XCTAssertEqual(try open(bob, m1, kb), .text("secret au repos"))
        XCTAssertEqual(try open(bob, m2, kb), .text("après relecture"))
        // Un fichier abîmé repart de zéro (sans planter) ; l'appareil reste.
        let identity = try alice.transaction { $0.identity }
        try Data("abîmé".utf8).write(to: alice.stateURL)
        XCTAssertEqual(try alice.transaction { $0.identity }, identity)
        XCTAssertEqual(try alice.transaction { $0.sessionCount(ka) }, 0)
    }

    func testClosedKeychainMeansNoV3AndNothingWritten() throws {
        let store = phone()
        (store.vault as! BrocolisDirectoryVault).readFails = true
        XCTAssertThrowsError(try store.transaction { _ in () }) {
            XCTAssertEqual($0 as? BrocolisV3StoreError, .unavailable)
        }
        BrocolisV3.store = store
        let k = NamedKey(name: "x", base64: BrocolisCrypto.generateKeyBase64(), psk: true)
        XCTAssertNil(BrocolisV3.seal("x", for: k), "v3 indisponible : l'appelant passe en v1")
        XCTAssertEqual(BrocolisV3.protection(k), .legacy)
        XCTAssertFalse(FileManager.default.fileExists(atPath: store.stateURL.path))
    }

    // MARK: Réparation, deux sessions, PSK, groupe

    func testBothStartAtOnceAndALostSessionHeals() throws {
        let (alice, bob) = (phone(), phone())
        let (ba, bb) = (try bundle(alice), try bundle(bob))
        let raw = [UInt8](repeating: 4, count: 32)
        let ka = key(raw, peer: bb), kb = key(raw, peer: ba)
        let x = try seal(alice, "a", ka)
        let y = try seal(bob, "b", kb)
        XCTAssertEqual(try open(bob, x, kb), .text("a"))
        XCTAssertEqual(try open(alice, y, ka), .text("b"))
        for i in 0..<3 {
            let p = try seal(alice, "a\(i)", ka), q = try seal(bob, "b\(i)", kb)
            XCTAssertEqual(try open(bob, p, kb), .text("a\(i)"))
            XCTAssertEqual(try open(alice, q, ka), .text("b\(i)"))
        }
        XCTAssertLessThanOrEqual(try alice.transaction { $0.sessionCount(ka) }, 2)
        // Bob perd son état (réinstallation) ; son appareil reste au Trousseau.
        try FileManager.default.removeItem(at: bob.stateURL)
        let lost = try seal(alice, "perdu ?", ka)
        guard case .failed(let e) = try open(bob, lost, kb) else { return XCTFail("illisible attendu") }
        XCTAssertTrue(BrocolisV3Format.needsRepair(e))
        let heal = try bob.transaction { e -> String? in
            e.repair(kb)
            return e.seal("je reviens", for: kb, now: BrocolisV3.now())
        }
        XCTAssertEqual(try open(alice, try XCTUnwrap(heal), ka), .text("je reviens"))
        XCTAssertEqual(try open(bob, try seal(alice, "bienvenue", ka), kb), .text("bienvenue"))
        // Un rejeu sur une session connue ne répare rien.
        XCTAssertFalse(BrocolisV3Format.needsRepair(.dechiffrement))
        XCTAssertFalse(BrocolisV3Format.needsRepair(.rejoue))
    }

    func testPskIsOptInAndTheOtherSideFollows() throws {
        let (alice, bob) = (phone(), phone())
        let raw = [UInt8](repeating: 5, count: 32)
        let plain = key(raw, peer: nil, id: "ka")
        XCTAssertEqual(try alice.transaction { $0.protection(plain, now: BrocolisV3.now()) }, .legacy)
        XCTAssertNil(try alice.transaction { $0.seal("x", for: plain, now: BrocolisV3.now()) })
        let ka = key(raw, peer: nil, id: "ka", psk: true), kb = key(raw, peer: nil, id: "kb")
        let m = try seal(alice, "en PSK", ka)
        XCTAssertEqual(try open(bob, m, kb), .text("en PSK"))
        XCTAssertEqual(try bob.transaction { $0.protection(kb, now: BrocolisV3.now()) }, .psk)
        XCTAssertEqual(try open(alice, try seal(bob, "reçu", kb), ka), .text("reçu"))
        // Rejouer le premier message après l'oubli du clair : refusé.
        XCTAssertEqual(try open(phone(), m, kb), .text("en PSK"), "un autre appareil qui a la clé, lui, le lit")
    }

    func testAGroupKeyNeverGoesV3() throws {
        let (alice, bob) = (phone(), phone())
        let g = key([UInt8](repeating: 6, count: 32), peer: try bundle(bob), group: true, psk: true)
        XCTAssertEqual(try alice.transaction { $0.protection(g, now: BrocolisV3.now()) }, .legacy)
        XCTAssertNil(try alice.transaction { $0.seal("à trois", for: g, now: BrocolisV3.now()) })
        _ = alice
    }

    func testAStaleBundleFallsBackToPsk() throws {
        let (alice, bob) = (phone(), phone())
        let raw = [UInt8](repeating: 7, count: 32)
        let old = BrocolisV3.now() - BrocolisV3Format.bundleMaxAge - 10
        let ka = key(raw, peer: try bundle(bob), at: old), kb = key(raw, peer: try bundle(alice))
        XCTAssertEqual(try alice.transaction { $0.protection(ka, now: BrocolisV3.now()) }, .psk)
        let m = try seal(alice, "vieux paquet", ka)
        XCTAssertEqual(try open(bob, m, kb), .text("vieux paquet"))
    }

    func testMediaTravelInTheEnvelope() throws {
        let (alice, bob) = (phone(), phone())
        let raw = [UInt8](repeating: 8, count: 32)
        let ka = key(raw, peer: try bundle(bob)), kb = key(raw, peer: try bundle(alice))
        let photo = "BRCM1:img:" + String(repeating: "A", count: 300 * 1024)
        let ct = try XCTUnwrap(try alice.transaction { $0.sealMessage(photo, for: ka, now: BrocolisV3.now()) })
        XCTAssertEqual(BrocolisV3Format.findTokens(ct).count, 1)
        XCTAssertTrue(ct.contains("[[BROCOLIS:v1:"))
        let read = { (s: BrocolisV3Store, k: BrocolisV3Key, mine: Bool) in
            try s.transaction { $0.openMessage(ct, keys: [k], conversation: k, mine: mine, now: BrocolisV3.now()) }
        }
        XCTAssertEqual(try read(bob, kb, false), .text(photo))
        XCTAssertEqual(try read(bob, kb, false), .text(photo), "relu plus tard")
        XCTAssertEqual(try read(alice, ka, true), .text(photo), "mon propre envoi")
        let v1 = try BrocolisCrypto.encryptToken(Data("ancien".utf8), key: SymmetricKey(data: raw))
        XCTAssertNil(try bob.transaction { $0.openMessage(v1, keys: [kb], conversation: kb, mine: false, now: 0) })
    }

    // MARK: Concurrence (§8.3)

    /// Huit « processus » (magasins distincts sur le même dossier et le même
    /// Trousseau) chiffrent en même temps pour le même contact : aucune clé
    /// de message n'est servie deux fois, et le correspondant lit tout.
    func testConcurrentWritersNeverReuseAMessageKey() throws {
        let (alice, bob) = (phone(), phone())
        let raw = [UInt8](repeating: 1, count: 32)
        let ka = key(raw, peer: try bundle(bob)), kb = key(raw, peer: try bundle(alice))
        _ = try alice.transaction { $0.openSession(ka, now: BrocolisV3.now()) }
        let writers = 8, each = 20
        let lock = NSLock()
        var tokens: [String] = []
        DispatchQueue.concurrentPerform(iterations: writers) { w in
            let me = sibling(of: alice)
            for i in 0..<each {
                if let t = try? me.transaction({ $0.seal("w\(w)-\(i)", for: ka, now: BrocolisV3.now()) }) {
                    lock.lock(); tokens.append(t); lock.unlock()
                }
            }
        }
        XCTAssertEqual(tokens.count, writers * each)
        var headers = Set<String>()
        for t in tokens {
            guard case .initial(let i) = try Token.decode(t) else { return XCTFail("premier message attendu") }
            headers.insert(Base64.encode(i.envelope.header.dh) + "#\(i.envelope.header.n)")
        }
        XCTAssertEqual(headers.count, tokens.count, "une clé de message par message")
        var read = Set<String>()
        for t in tokens.shuffled() {
            guard case .text(let s) = try open(bob, t, kb) else { return XCTFail("illisible : \(t.prefix(30))") }
            read.insert(s)
        }
        XCTAssertEqual(read.count, writers * each)
    }

    // MARK: Ce que voient l'app et les extensions

    func testTheCodecSealsV3ForAPairedKeyAndStillReadsV1V2() throws {
        let (alice, bob) = (phone(), phone())
        let keyB64 = BrocolisCrypto.generateKeyBase64()
        let ka = NamedKey(id: "a", name: "Bob", base64: keyB64,
                          v3Bundle: try bundle(bob).toBase64(), v3Since: Date(), duo: true)
        let kb = NamedKey(id: "b", name: "Alice", base64: keyB64,
                          v3Bundle: try bundle(alice).toBase64(), v3Since: Date(), duo: true)
        BrocolisV3.store = alice
        let sent = BrocolisTransform.auto("Salut ((Bob))", codec: BrocolisV3.codec(recipients: [ka], all: [ka]))
        XCTAssertTrue(sent.isEncrypted)
        XCTAssertTrue(sent.text.hasPrefix("Salut [[BROCOLIS:v3:"))
        let whole = BrocolisTransform.auto("tout", codec: BrocolisV3.codec(recipients: [ka], all: [ka]),
                                           encryptWholeAlways: true)
        BrocolisV3.store = bob
        let codecB = BrocolisV3.codec(recipients: [kb], all: [kb])
        XCTAssertEqual(BrocolisTransform.auto(sent.text, codec: codecB).text, "Salut Bob")
        XCTAssertEqual(BrocolisTransform.auto(whole.text, codec: codecB).text, "tout")
        // Les anciens formats restent lisibles par le même chemin.
        let sym = try BrocolisCrypto.symmetricKey(fromBase64: keyB64)
        let v1 = try BrocolisCrypto.encryptToken(Data("v1".utf8), key: sym)
        let v2 = try BrocolisCrypto.encryptTokenMulti(Data("v2".utf8), keys: [sym, SymmetricKey(size: .bits256)])
        XCTAssertEqual(BrocolisTransform.auto("\(v1) \(v2)", codec: codecB).text, "v1 v2")
        // Plusieurs destinataires : v2, comme avant.
        let multi = BrocolisV3.codec(recipients: [kb, NamedKey(name: "x", base64: BrocolisCrypto.generateKeyBase64())],
                                     all: [kb])
        XCTAssertTrue(multi.seal("à plusieurs")!.hasPrefix(BrocolisCrypto.tokenPrefixV2))
        // L'écran Conversation : jetons v3 et v1 mélangés.
        let rendered = BrocolisConversation.render("\(sent.text)\nclair\n\(v1)", codec: codecB)
        XCTAssertEqual(rendered.lines.map(\.display), ["Salut Bob", "clair", "v1"])
        XCTAssertEqual(rendered.decryptedCount, 2)
        XCTAssertEqual(BrocolisV3.protections([kb])["b"]?.isRatchet, true)
    }

    func testOldStoredKeysStillDecodeAndNewFieldsRoundTrip() throws {
        let old = #"[{"id":"1","name":"Maman","base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]"#
        let ks = try JSONDecoder().decode([NamedKey].self, from: Data(old.utf8))
        XCTAssertNil(ks[0].v3Bundle)
        XCTAssertNil(ks[0].duo)
        let k = NamedKey(id: "2", name: "Bob", base64: ks[0].base64, v3Bundle: "B", v3Since: Date(timeIntervalSince1970: 5),
                         duo: false, psk: true)
        let back = try JSONDecoder().decode(NamedKey.self, from: try JSONEncoder().encode(k))
        XCTAssertEqual(back, k)
    }

    // MARK: v4 (§9)

    func testCapsSwitchAContactToTheTripleRatchet() throws {
        guard MlKem.isAvailable else { throw XCTSkip("ML-KEM-768 indisponible ici : pas de v4") }
        let (alice, bob) = (phone(), phone())
        let (ba, bb) = (try bundle(alice), try bundle(bob))
        let (ca, cb) = (try caps(alice), try caps(bob))
        let raw = [UInt8](repeating: 11, count: 32)
        let ka = key(raw, peer: bb, caps: cb), kb = key(raw, peer: ba, caps: ca)
        let now = BrocolisV3.now()
        XCTAssertEqual(try alice.transaction { $0.protection(ka, now: now) }, .triple)
        XCTAssertEqual(BrocolisProtection.triple.label.contains("triple"), true)
        // Les deux voient la même empreinte, sous le contexte v4 (§9.7).
        let fa = try XCTUnwrap(try alice.transaction { $0.fingerprint(ka) })
        XCTAssertEqual(try bob.transaction { $0.fingerprint(kb) }, fa)
        let ida = try alice.transaction { $0.identity }, idb = try bob.transaction { $0.identity }
        XCTAssertEqual(fa, BrocolisV3Format.pairingFingerprint4(key: raw, ida, idb))
        XCTAssertNotEqual(fa, BrocolisV3Format.pairingFingerprint(key: raw, ida, idb))
        // L'invitant ouvre la session v4 à l'appairage.
        XCTAssertTrue(try alice.transaction { $0.openSession(ka, now: now) })
        let m1 = try seal(alice, "un", ka)
        let m2 = try seal(alice, "deux", ka)
        XCTAssertTrue(m1.hasPrefix(JetonV4.head))
        XCTAssertEqual(BrocolisV3Format.findTokens("x \(m1) y").count, 1)
        XCTAssertEqual(try open(bob, m2, kb), .text("deux"))
        XCTAssertEqual(try open(bob, m1, kb), .text("un"))
        XCTAssertEqual(try bob.transaction { $0.protection(kb, now: now) }, .triple)
        let r = try seal(bob, "réponse", kb)
        XCTAssertTrue(r.hasPrefix(JetonV4.head))
        XCTAssertEqual(try open(alice, r, ka), .text("réponse"))
        // Coupé par une messagerie : le même clair.
        let cut = String(m1.prefix(40)) + "\n  " + String(m1.dropFirst(40))
        XCTAssertEqual(try open(bob, cut, kb), .text("un"))
        // Un tiers : aucune de ses clés n'ouvre le préambule.
        XCTAssertEqual(try open(phone(), m1, key(raw, peer: nil)), .failed(.cleInconnue))
        // Un autre processus relit l'état : la conversation continue.
        let m3 = try seal(sibling(of: alice), "relu", ka)
        XCTAssertEqual(try open(bob, m3, kb), .text("relu"))
        XCTAssertEqual(try alice.transaction { $0.sessionCount(ka) }, 1)
    }

    func testARemovedCapsShowsInTheFingerprintAndNeverDowngrades() throws {
        guard MlKem.isAvailable else { throw XCTSkip("ML-KEM-768 indisponible ici : pas de v4") }
        let (alice, bob) = (phone(), phone())
        let (ba, bb) = (try bundle(alice), try bundle(bob))
        let cb = try caps(bob)
        let raw = [UInt8](repeating: 12, count: 32)
        let now = BrocolisV3.now()
        // Le serveur retire la capacité d'Alice chez Bob seulement.
        let ka = key(raw, peer: bb, caps: cb), kb = key(raw, peer: ba)
        XCTAssertNotEqual(try alice.transaction { $0.fingerprint(ka) }, try bob.transaction { $0.fingerprint(kb) })
        XCTAssertEqual(try bob.transaction { $0.protection(kb, now: now) }, .postQuantum)
        // Une capacité d'une autre identité ne vaut rien.
        let forged = key(raw, peer: ba, caps: cb)
        XCTAssertEqual(try bob.transaction { $0.protection(forged, now: now) }, .postQuantum)
        // Alice écrit en v4 : Bob le lit, puis ne redescend plus en v3.
        let m = try seal(alice, "v4", ka)
        XCTAssertEqual(try open(bob, m, kb), .text("v4"))
        XCTAssertEqual(try bob.transaction { $0.protection(kb, now: now) }, .triple)
        let r = try seal(bob, "toujours v4", kb)
        XCTAssertTrue(r.hasPrefix(JetonV4.head))
        XCTAssertEqual(try open(alice, r, ka), .text("toujours v4"))
        // Paquet trop vieux, plus de session : la PSK, en v4.
        let later = now + BrocolisV3Format.bundleMaxAge + 1
        let device = try bob.transaction { $0.device.toJson() }
        let seen = try bob.transaction { $0.stored.v4Seen }
        XCTAssertEqual(seen.count, 1)
        let b2 = BrocolisV3Engine(deviceJson: device, stored: BrocolisV3Stored(v4Seen: seen), now: later)
        let kbOld = key(raw, peer: ba, at: now)
        XCTAssertEqual(b2.protection(kbOld, now: later), .triplePsk)
        let p = try XCTUnwrap(b2.seal("par la clé", for: kbOld, now: later))
        XCTAssertTrue(p.hasPrefix(JetonV4.head))
        XCTAssertEqual(try alice.transaction { $0.open(p, keys: [ka], now: later) }, .text("par la clé"))
    }

    func testPskV4FollowsAReceivedPskV4() throws {
        guard MlKem.isAvailable else { throw XCTSkip("ML-KEM-768 indisponible ici : pas de v4") }
        let bob = phone()
        let raw = [UInt8](repeating: 13, count: 32)
        let now = BrocolisV3.now()
        let ka = key(raw, peer: nil, id: "ka"), kb = key(raw, peer: nil, id: "kb")
        // Alice a déjà reçu une PSK v4 sur la clé (d'un autre appareil à jour).
        let a = BrocolisV3Engine(deviceJson: nil, stored: BrocolisV3Stored(pskSeen: ["ka"], psk4Seen: ["ka"]), now: now)
        XCTAssertEqual(a.protection(ka, now: now), .triplePsk)
        let m = try XCTUnwrap(a.seal("psk v4", for: ka, now: now))
        XCTAssertTrue(m.hasPrefix(JetonV4.head))
        XCTAssertEqual(try open(bob, m, kb), .text("psk v4"))
        XCTAssertEqual(try bob.transaction { $0.protection(kb, now: now) }, .triplePsk)
        let r = try seal(bob, "suivi", kb)
        XCTAssertTrue(r.hasPrefix(JetonV4.head))
        XCTAssertEqual(a.open(r, keys: [ka], now: now), .text("suivi"))
        // Sans ce signe, la PSK reste en v3.
        XCTAssertEqual(try phone().transaction { $0.protection(key(raw, peer: nil, id: "kc", psk: true), now: now) }, .psk)
        // Une clé oubliée emporte ses sessions PSK v4.
        a.forget(keyId: "ka")
        XCTAssertEqual(a.sessionCount(ka), 0)
        XCTAssertEqual(a.protection(ka, now: now), .legacy)
    }

    func testAStateWrittenBeforeV4StillLoads() throws {
        let old = #"{"v":1,"peers":{},"psk":{},"pskSeen":["k"],"opened":[]}"#
        let s = try JSONDecoder().decode(BrocolisV3Stored.self, from: Data(old.utf8))
        XCTAssertEqual(s.pskSeen, ["k"])
        XCTAssertTrue(s.peers4.isEmpty)
        XCTAssertTrue(s.v4Seen.isEmpty)
        let back = try JSONDecoder().decode(BrocolisV3Stored.self, from: try JSONEncoder().encode(s))
        XCTAssertEqual(back.pskSeen, ["k"])
        // La capacité v4 d'une clé se range avec elle.
        let k = NamedKey(id: "3", name: "Bob", base64: BrocolisCrypto.generateKeyBase64(), v3Caps: "Q0FQUw==")
        XCTAssertEqual(try JSONDecoder().decode(NamedKey.self, from: try JSONEncoder().encode(k)).v3Caps, "Q0FQUw==")
    }

    // MARK: Alerte de changement d'identité (§9.8)

    func testARepairingWithAnotherIdentityBlocksSendingUntilConfirmed() throws {
        let (alice, bob, newBob) = (phone(), phone(), phone())
        let (ba, bb, bb2) = (try bundle(alice), try bundle(bob), try bundle(newBob))
        let keyB64 = BrocolisCrypto.generateKeyBase64()
        let k = NamedKey(id: "b", name: "Bob", base64: keyB64, v3Bundle: bb.toBase64(), v3Since: Date(), duo: true)
        // Même identité (nouvelle clé, même téléphone) : rien ne change.
        let same = BrocolisV3.repaired(k, key: BrocolisCrypto.generateKeyBase64(), bundle: bb.toBase64(), caps: nil)
        XCTAssertFalse(BrocolisV3.isBlocked(same))
        XCTAssertNil(same.v3PreviousIdentity)
        // Un autre téléphone répond au nom de Bob : alerte, l'ancienne gardée.
        let key2 = BrocolisCrypto.generateKeyBase64()
        let changed = BrocolisV3.repaired(k, key: key2, bundle: bb2.toBase64(), caps: nil)
        XCTAssertTrue(BrocolisV3.isBlocked(changed))
        XCTAssertEqual(changed.id, k.id)
        XCTAssertEqual(changed.base64, key2)
        XCTAssertEqual(changed.v3PreviousIdentity, Base64.encode(BrocolisV3Format.identity(of: bb)))
        // Encore un ré-appairage avant confirmation : l'identité d'avant la
        // première alerte reste.
        let again = BrocolisV3.repaired(changed, key: key2, bundle: try bundle(phone()).toBase64(), caps: nil)
        XCTAssertTrue(BrocolisV3.isBlocked(again))
        XCTAssertEqual(again.v3PreviousIdentity, changed.v3PreviousIdentity)
        // Rien ne part : ni v3/v4, ni v1/v2, par aucun chemin.
        BrocolisV3.store = alice
        XCTAssertEqual(BrocolisV3.protection(changed), .identityChanged)
        XCTAssertFalse(BrocolisV3.protection(changed).isRatchet)
        XCTAssertNil(BrocolisV3.seal("x", for: changed))
        XCTAssertNil(BrocolisV3.sealAny("x", for: changed))
        XCTAssertNil(BrocolisV3.sealMessage("x", for: changed))
        let codec = BrocolisV3.codec(recipients: [changed], all: [changed])
        XCTAssertNil(codec.seal("x"))
        let t = BrocolisTransform.auto("salut ((secret))", codec: codec)
        XCTAssertFalse(t.isEncrypted)
        XCTAssertEqual(try alice.transaction { e in e.seal("x", for: try XCTUnwrap(BrocolisV3.key(changed)), now: BrocolisV3.now()) }, nil)
        // Le v3 indisponible : l'alerte reste affichée.
        let closed = phone()
        (closed.vault as! BrocolisDirectoryVault).readFails = true
        BrocolisV3.store = closed
        XCTAssertEqual(BrocolisV3.protection(changed), .identityChanged)
        XCTAssertNil(BrocolisV3.sealAny("x", for: changed))
        // La lecture continue : le nouveau téléphone écrit, Alice lit.
        BrocolisV3.store = alice
        let fromNewBob = try seal(newBob, "c'est moi", key(Array(Data(base64Encoded: key2)!), peer: ba))
        XCTAssertEqual(BrocolisV3.openTokens(fromNewBob, keys: [changed]).text, "c'est moi")
        // « J'ai comparé l'empreinte » : l'envoi reprend.
        var confirmed = changed
        confirmed.identityChanged = nil
        confirmed.v3PreviousIdentity = nil
        XCTAssertNotNil(BrocolisV3.sealAny("ok", for: confirmed))
        XCTAssertTrue(BrocolisV3.protection(confirmed).isRatchet)
        // Le tout se range avec la clé.
        let back = try JSONDecoder().decode(NamedKey.self, from: try JSONEncoder().encode(changed))
        XCTAssertEqual(back, changed)
    }

    // MARK: Groupes à cliquet (§9.9)

    /// Ouvre chaque jeton d'un envoi de groupe : le texte du message de
    /// groupe, et combien de chaînes étaient pour moi.
    private func readGroup(_ store: BrocolisV3Store, _ out: String, _ keys: [BrocolisV3Key]) throws -> (String?, Int) {
        try store.transaction { e in
            var text: String? = nil
            var chains = 0
            for r in BrocolisV3Format.findTokens(out) {
                switch e.open(String(out[r]), keys: keys, now: BrocolisV3.now()) {
                case .hidden: chains += 1
                case .text(let t) where !t.isEmpty: text = t
                default: break
                }
            }
            return (text, chains)
        }
    }

    private func sealGroup(_ store: BrocolisV3Store, _ gid: [UInt8], _ members: [BrocolisV3Key], _ text: String) throws -> String? {
        try store.transaction { $0.sealGroup(groupId: gid, members: members, text: text, now: BrocolisV3.now()) }
    }

    func testARatchetGroupHandsOutChainsAndRenewsWhenSomeoneLeaves() throws {
        let (a, b, c) = (phone(), phone(), phone())
        let (ba, bb, bc) = (try bundle(a), try bundle(b), try bundle(c))
        let (kab, kac, kbc) = ([UInt8](repeating: 21, count: 32), [UInt8](repeating: 22, count: 32),
                               [UInt8](repeating: 23, count: 32))
        // Chacun a une session à deux possible avec chaque autre membre.
        let aB = key(kab, peer: bb, id: "ab"), aC = key(kac, peer: bc, id: "ac")
        let bA = key(kab, peer: ba, id: "ab"), bC = key(kbc, peer: bc, id: "bc")
        let cA = key(kac, peer: ba, id: "ac"), cB = key(kbc, peer: bb, id: "bc")
        let gid = [UInt8](repeating: 7, count: 16)
        let m1 = try XCTUnwrap(try sealGroup(a, gid, [aB, aC], "salut le groupe"))
        // Pour chacun : un premier message vide (session v3 pas encore
        // confirmée), sa chaîne ; puis le message de groupe.
        XCTAssertEqual(BrocolisV3Format.findTokens(m1).count, 5)
        let r1 = try readGroup(b, m1, [bA, bC])
        XCTAssertEqual(r1.0, "salut le groupe")
        XCTAssertEqual(r1.1, 1)
        let r2 = try readGroup(c, m1, [cA, cB])
        XCTAssertEqual(r2.0, "salut le groupe")
        XCTAssertEqual(r2.1, 1)
        // L'auteur est celui dont la session a remis la chaîne.
        let last = String(m1[try XCTUnwrap(BrocolisV3Format.findTokens(m1).last)])
        XCTAssertEqual(try b.transaction { $0.sender(last, keys: [bA, bC]) }, 0)
        XCTAssertEqual(try c.transaction { $0.sender(last, keys: [cB, cA]) }, 1)
        // Ensuite, le message seul.
        let m2 = try XCTUnwrap(try sealGroup(a, gid, [aB, aC], "deuxième"))
        XCTAssertEqual(BrocolisV3Format.findTokens(m2).count, 1)
        XCTAssertEqual(try readGroup(c, m2, [cA, cB]).0, "deuxième")
        // B répond au groupe avec sa propre chaîne.
        let r = try XCTUnwrap(try sealGroup(b, gid, [bA, bC], "bien reçu"))
        XCTAssertEqual(try readGroup(a, r, [aB, aC]).0, "bien reçu")
        XCTAssertEqual(try readGroup(c, r, [cA, cB]).0, "bien reçu")
        // Le texte collé, par la façade : les chaînes des autres membres ne
        // s'affichent pas ; un message d'une chaîne inconnue reste chiffré.
        BrocolisV3.store = c
        let named = { (id: String, raw: [UInt8], b: KeyBundle) in
            NamedKey(id: id, name: id, base64: Base64.encode(raw), v3Bundle: b.toBase64(), v3Since: Date(), duo: true)
        }
        let cKeys = [named("ac", kac, ba), named("bc", kbc, bb)]
        XCTAssertEqual(BrocolisV3.openTokens("« \(m2) »", keys: cKeys).text, "« deuxième »")
        // C quitte le groupe : A tire une chaîne neuve, C ne lit plus rien.
        let m3 = try XCTUnwrap(try sealGroup(a, gid, [aB], "sans C"))
        XCTAssertEqual(BrocolisV3Format.findTokens(m3).count, 2, "B a répondu : session confirmée")
        XCTAssertEqual(try readGroup(b, m3, [bA, bC]).0, "sans C")
        let lost = try readGroup(c, m3, [cA, cB])
        XCTAssertNil(lost.0)
        XCTAssertEqual(lost.1, 0)
        let shown = BrocolisV3.openTokens(m3, keys: cKeys).text
        XCTAssertTrue(shown.hasPrefix("[[BROCOLIS:v3:"), "le message de groupe reste chiffré : \(shown.prefix(30))")
        XCTAssertEqual(BrocolisV3Format.findTokens(shown).count, 1, "la chaîne remise à B est cachée")
        // L'état se relit (un autre processus de B).
        let m4 = try XCTUnwrap(try sealGroup(a, gid, [aB], "relu"))
        XCTAssertEqual(try readGroup(sibling(of: b), m4, [bA, bC]).0, "relu")
        // Un membre sans session possible : pas de groupe à cliquet…
        let d = key([UInt8](repeating: 24, count: 32), peer: nil, id: "ad")
        XCTAssertNil(try sealGroup(a, gid, [aB, d], "x"))
        // …la façade repart en v2 pour les clés des membres.
        BrocolisV3.store = a
        let aKeys = [named("ab", kab, bb), NamedKey(id: "ad", name: "Dan", base64: Base64.encode([UInt8](repeating: 24, count: 32)))]
        let v2 = try XCTUnwrap(BrocolisV3.sealGroup("à tous", groupId: gid, members: aKeys))
        XCTAssertTrue(v2.hasPrefix(BrocolisCrypto.tokenPrefixV2))
        XCTAssertEqual(BrocolisCrypto.decryptTokens(v2, keys: [SymmetricKey(data: [UInt8](repeating: 24, count: 32))]).text, "à tous")
        // À cliquet par la façade, quand chacun le permet.
        let aAll = [named("ab", kab, bb), named("ac", kac, bc)]
        let viaFacade = try XCTUnwrap(BrocolisV3.sealGroup("par la façade", groupId: gid, members: aAll))
        XCTAssertTrue(BrocolisV3Format.isGroupMessage(String(viaFacade[try XCTUnwrap(BrocolisV3Format.findTokens(viaFacade).last)])))
        XCTAssertEqual(try readGroup(c, viaFacade, [cA, cB]).0, "par la façade")
        // Une identité changée dans le groupe : rien ne part.
        var blocked = aAll[1]
        blocked.identityChanged = true
        XCTAssertNil(BrocolisV3.sealGroup("x", groupId: gid, members: [aAll[0], blocked]))
    }

    // MARK: Clé protégée (§8.9)

    func testProtectedKeyIsWrittenInV2AndV1StillOpens() throws {
        let key = BrocolisCrypto.generateKeyBase64()
        let v2 = try BrocolisKeyToken.seal(keyBase64: key, passphrase: "phrase très secrète 🥦")
        XCTAssertTrue(v2.hasPrefix(BrocolisKeyToken.prefixV2))
        XCTAssertTrue(BrocolisKeyToken.containsToken("voici : \(v2)"))
        let wrapped = String(v2.prefix(30)) + "\n " + String(v2.dropFirst(30))
        XCTAssertEqual(try BrocolisKeyToken.open(token: wrapped, passphrase: "phrase très secrète 🥦"), key)
        XCTAssertThrowsError(try BrocolisKeyToken.open(token: v2, passphrase: "mauvaise phrase")) {
            XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .wrongPassphrase)
        }
        let v1 = try BrocolisKeyToken.sealV1(keyBase64: key, passphrase: "phrase très secrète 🥦")
        XCTAssertTrue(v1.hasPrefix(BrocolisKeyToken.prefix))
        XCTAssertEqual(try BrocolisKeyToken.open(token: v1, passphrase: "phrase très secrète 🥦"), key)
        // Une v2 qui demanderait 1 Gio (dans les bornes du §3.2) : refusée
        // avant tout calcul. En-tête écrit à la main (rien n'est calculé).
        var payload: [UInt8] = [0x02, 0x00, 0x10, 0x00, 0x00, 2, 1]
        payload += [UInt8](repeating: 2, count: 16) + [UInt8](repeating: 3, count: 12)
        payload += [UInt8](repeating: 4, count: 48)
        let greedy = BrocolisKeyToken.prefixV2 + Data(payload).base64EncodedString() + "]]"
        XCTAssertEqual(try CleProtegee.v2Params(greedy).mKib, 1_048_576)
        XCTAssertThrowsError(try BrocolisKeyToken.open(token: greedy, passphrase: "phrase très secrète")) {
            XCTAssertEqual($0 as? BrocolisKeyToken.KeyTokenError, .tooDemanding)
        }
    }
}
