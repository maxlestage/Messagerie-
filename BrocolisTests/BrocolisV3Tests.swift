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
