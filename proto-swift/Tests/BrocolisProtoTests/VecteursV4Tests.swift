// proto/vectors.json, `sessions_v4` : les deux conversations v4 (par paquet
// et à clé partagée) retrouvées octet pour octet. Le scénario est celui du
// générateur (`session4_case` de proto/examples/vectors.rs) : A envoie deux
// premiers messages, B les reçoit dans le désordre, puis deux tours complets
// du triple cliquet, avec les mêmes générateurs déterministes.
//
// CryptoKit n'accepte pas d'aléa `m` imposé pour l'encapsulation ML-KEM :
// chaque encapsulation d'une nouvelle chaîne d'envoi est résolue par les
// vecteurs eux-mêmes (comme `Party4` de proto/scripts/verifier_vecteurs.py) —
// le chiffré `ct` est celui que porte le message suivant de l'expéditeur, et
// le secret est sa décapsulation par la graine du destinataire, connue des
// vecteurs. Les jetons de toute la conversation se retrouvent alors à
// l'identique ; seule la dernière racine (encapsulation qu'aucun message ne
// porte) ne peut pas être comparée.

import XCTest
@testable import BrocolisProto

/// L'encapsulation des vecteurs : les chiffrés dans l'ordre où la
/// conversation les produit, les graines ML-KEM connues par clé publique.
final class EncapsulationsDesVecteurs {
    var chiffres: [[UInt8]]
    var graines: [String: [UInt8]] = [:]
    /// Les `m` tirés par les sessions (comparés aux tirages des vecteurs).
    var tires: [[UInt8]] = []
    /// Faux dès qu'une encapsulation n'a pas pu être résolue (alors faite
    /// par la bibliothèque, au hasard).
    var resolue = true

    init(chiffres: [[UInt8]]) {
        self.chiffres = chiffres
    }

    func ajouterGraine(_ seed: [UInt8]) throws {
        graines[hex(try MlKem.publicKey(seed: seed))] = seed
    }

    func encapsuler(_ ek: [UInt8], _ m: [UInt8]) throws -> KemEncapsulation {
        tires.append(m)
        guard !chiffres.isEmpty, let seed = graines[hex(ek)] else {
            resolue = false
            return try Session4.encapsulerSysteme(ek, m)
        }
        let ct = chiffres.removeFirst()
        resolue = true
        return KemEncapsulation(ciphertext: ct, shared: try MlKem.decapsulate(seed: seed, ciphertext: ct))
    }
}

/// `h64(x) = h32(x + "/0") ‖ h32(x + "/1")`, comme le générateur.
func h64(_ label: String) -> [UInt8] {
    h32(label + "/0") + h32(label + "/1")
}

final class VecteursV4Tests: XCTestCase {
    let now: UInt64 = 1_790_000_000

    func testSessionsV4() throws {
        guard MlKem.isAvailable else { throw XCTSkip("ML-KEM-768 indisponible ici : sessions v4 des vecteurs sautées") }
        let cases = try XCTUnwrap(try Depot.vecteurs()["sessions_v4"] as? [[String: Any]])
        XCTAssertEqual(cases.count, 2)
        XCTAssertEqual(cases.map { $0["name"] as? String }, ["v4", "v4-psk"])
        for c in cases { try session4(c) }
    }

    /// Un appareil des vecteurs (avec ML-KEM), vérifié.
    func device(_ v: [String: Any]) throws -> Device {
        let identity = try IdentitySecret(dh: unhex(v["ik_x25519_secret"]), sign: unhex(v["ik_ed25519_seed"]))
        let spkId = UInt32(try XCTUnwrap(v["spk_id"] as? Int))
        let pqId = UInt32(try XCTUnwrap(v["pq_id"] as? Int))
        let d = try Device.fromSecrets(
            identity: identity, spk: (spkId, unhex(v["spk_secret"])), pq: (pqId, unhex(v["pq_seed"])), now: now)
        let b = try d.bundle()
        egal(hex(b.identity.dh), v["ik_x25519_public"] as? String, "IK X25519")
        egal(hex(b.identity.sign), v["ik_ed25519_public"] as? String, "IK Ed25519")
        egal(hex(b.spk), v["spk_public"] as? String, "SPK")
        egal(hex(try XCTUnwrap(b.pq).key), v["pq_public"] as? String, "PQPK")
        if ed25519Deterministe { egal(hex(b.toBytes()), v["bundle"] as? String, "paquet") }
        return d
    }

    /// Un message envoyé par `s`, comparé à l'étape des vecteurs.
    func send(_ s: Session4, _ step: [String: Any], from: String) throws -> Token4 {
        let text = try XCTUnwrap(step["text"] as? String)
        XCTAssertEqual(step["from"] as? String, from)
        let h = try XCTUnwrap(step["header"] as? [String: Any])
        let hks = try XCTUnwrap(s.debugHeaderKeys.hks)
        egal(hex(hks), h["hk"] as? String, "HKs « \(text) »")
        let t = try s.encryptToken(text)
        egal(t.encode(), step["token"] as? String, "jeton v4 « \(text) »")
        egal(Int(t.type), step["type"] as? Int, "type « \(text) »")
        let body = t.body
        egal(hex(body.headerNonce), h["header_nonce"] as? String, "nonce d'en-tête « \(text) »")
        egal(hex(body.header), h["encrypted"] as? String, "en-tête chiffré « \(text) »")
        egal(hex(body.ciphertext), h["ciphertext"] as? String, "chiffré « \(text) »")
        let plain = try Kdf.aesGcmOpen(key: hks, nonce: body.headerNonce, aad: [t.type], ciphertext: body.header)
        egal(hex(plain), h["plain"] as? String, "en-tête « \(text) »")
        let header = try Header4.fromBytes(plain)
        egal(hex(header.dh), h["dh"] as? String, "en-tête DH")
        egal(Int(header.pn), h["pn"] as? Int, "en-tête PN")
        egal(Int(header.n), h["n"] as? Int, "en-tête N")
        egal(hex(header.ek), h["ek"] as? String, "en-tête ek")
        if let ct = header.ct {
            egal(hex(ct), h["ct"] as? String, "en-tête ct")
        } else {
            XCTAssertTrue(h["ct"] is NSNull, "en-tête sans ct")
        }
        // Le jeton relu se réécrit à l'identique.
        let back = try Token4.decode(try XCTUnwrap(step["token"] as? String))
        egal(back.encode(), step["token"] as? String, "jeton v4 relu")
        return t
    }

    func session4(_ c: [String: Any]) throws {
        let name = try XCTUnwrap(c["name"] as? String)
        let mode = try XCTUnwrap(c["mode"] as? String)
        let setup = try XCTUnwrap(c["setup"] as? [String: Any])
        let steps = try XCTUnwrap(c["steps"] as? [[String: Any]])
        XCTAssertEqual(c["now"] as? Int, Int(now))
        XCTAssertEqual(steps.count, 11)
        let rngA = Recorder("\(name)/alice/cliquet")
        let rngB = Recorder("\(name)/bob/cliquet")
        let ek = unhex(setup["ek_secret"])
        egal(ek, h32("\(name)/ek"), "EK")
        egal(hex(Kdf.x25519Public(ek)), setup["ek_public"] as? String, "EK public")
        let kemSeed = unhex(setup["alice_kem_seed"])
        egal(kemSeed, h64("\(name)/alice/kem0"), "graine ML-KEM d'Alice")
        egal(hex(try MlKem.publicKey(seed: kemSeed)), setup["alice_kem_public"] as? String, "clé ML-KEM d'Alice")

        // Les encapsulations des nouvelles chaînes, dans l'ordre : B (à
        // l'acceptation), A, B, A — chacune portée par le message suivant de
        // son auteur.
        let messages = steps.filter { $0["token"] != nil }
        let events = steps.filter { $0["event"] != nil }
        XCTAssertEqual(messages.count, 6)
        XCTAssertEqual(events.count, 5)
        let chiffres = try messages[2...].map { m -> [UInt8] in
            let h = try XCTUnwrap(m["header"] as? [String: Any])
            return unhex(h["ct"])
        }
        let enc = EncapsulationsDesVecteurs(chiffres: chiffres)
        try enc.ajouterGraine(kemSeed)
        var tirages = [try XCTUnwrap(events[0]["bob_drawn"] as? String)]
        for e in events[1...] { tirages.append(try XCTUnwrap(e["drawn"] as? String)) }
        for t in tirages {
            let d = unhex(t)
            XCTAssertEqual(d.count, 128, "secret X25519 (32), graine ML-KEM (64), m (32)")
            try enc.ajouterGraine(Array(d[32..<96]))
        }

        let a: Session4
        let bobSide: (Token4) throws -> (Session4, Content)
        let sk: [UInt8]
        let firstDh: [UInt8]
        if mode == "psk" {
            let key = unhex(setup["key"])
            egal(key, h32("\(name)/cle"), "clé PSK")
            a = try Session4.initiatePskWith(key: key, ekSecret: ek, kemSeed: kemSeed)
            sk = Kdf.sk4Psk(key)
            let r = Kdf.psk4RatchetSecret(sk)
            egal(hex(r), setup["psk_ratchet_secret"] as? String, "cliquet PSK")
            egal(hex(Kdf.x25519Public(r)), setup["psk_ratchet_public"] as? String, "cliquet PSK public")
            firstDh = try Kdf.x25519(ek, Kdf.x25519Public(r))
            egal(a.mode, .psk, "mode")
            bobSide = { t in
                var g = ReplayGuard()
                return try Session4.acceptPsk(
                    keys: [key], token: t, guard: &g, now: self.now, rng: rngB, encapsuler: enc.encapsuler)
            }
        } else {
            let aliceV = try XCTUnwrap(setup["alice"] as? [String: Any])
            let bobV = try XCTUnwrap(setup["bob"] as? [String: Any])
            let alice = try device(aliceV)
            let bob = try device(bobV)
            // Les capacités v4 signées (§9.6).
            for (who, d, v) in [("alice", alice, aliceV), ("bob", bob, bobV)] {
                let caps = unhex(setup["\(who)_caps"])
                XCTAssertNoThrow(try Paquet.verifyCaps4(identity: d.identity(), signature: caps), who)
                Compteur.shared.ajouter("vecteurs")
                if ed25519Deterministe { egal(hex(try XCTUnwrap(d.caps4())), setup["\(who)_caps"] as? String, "caps \(who)") }
                XCTAssertNoThrow(try Paquet.verifyCaps4(identity: d.identity(), signature: try XCTUnwrap(d.caps4())))
                egal(d.identity().fingerprint(), v["fingerprint"] as? String, "empreinte \(who)")
            }
            attendreErreur(.signature) {
                try Paquet.verifyCaps4(identity: bob.identity(), signature: unhex(setup["alice_caps"]))
            }
            let bundle = try KeyBundle.fromBytes(unhex(bobV["bundle"]))
            let ratchet = unhex(setup["alice_ratchet_secret"])
            egal(ratchet, h32("\(name)/alice/cliquet0"), "cliquet d'Alice")
            egal(hex(Kdf.x25519Public(ratchet)), setup["alice_ratchet_public"] as? String, "cliquet d'Alice public")
            egal(unhex(setup["mlkem_m"]), h32("\(name)/mlkem_m"), "m")
            let ika = alice.identitySecret
            let dh1 = try Kdf.x25519(ika.dh, bundle.spk)
            let dh2 = try Kdf.x25519(ek, bundle.identity.dh)
            let dh3 = try Kdf.x25519(ek, bundle.spk)
            egal(hex(dh1), setup["dh1"] as? String, "DH1")
            egal(hex(dh2), setup["dh2"] as? String, "DH2")
            egal(hex(dh3), setup["dh3"] as? String, "DH3")
            // Le chiffré des vecteurs, vérifié par la décapsulation de Bob.
            let ct = unhex(setup["mlkem_ciphertext"])
            let ss = try MlKem.decapsulate(seed: unhex(bobV["pq_seed"]), ciphertext: ct)
            egal(hex(ss), setup["mlkem_shared"] as? String, "ML-KEM SS")
            sk = Kdf.sk4(dh1: dh1, dh2: dh2, dh3: dh3, ss: ss)
            let pre = Kdf.preambleKey4(dh3, ss)
            egal(hex(pre.key), setup["preamble_key"] as? String, "clé du préambule")
            egal(hex(pre.nonce), setup["preamble_nonce"] as? String, "nonce du préambule")
            a = try Session4.initiateWith(
                identity: ika, bundle: bundle, ekSecret: ek, ratchetSecret: ratchet,
                kem: KemEncapsulation(ciphertext: ct, shared: ss), kemSeed: kemSeed)
            egal(a.mode, .bundle, "mode")
            egal(a.peerIdentity, bundle.identity.dh, "identité de Bob")
            firstDh = try Kdf.x25519(ratchet, bundle.spk)
            bobSide = { t in try bob.accept4(t, now: self.now, rng: rngB, encapsuler: enc.encapsuler) }
        }
        a.encapsuler = enc.encapsuler
        egal(hex(sk), setup["sk"] as? String, "SK")
        let (hkAb, nhkBa) = Kdf.headerKeys4(sk)
        egal(hex(hkAb), setup["hk_ab"] as? String, "HK_AB")
        egal(hex(nhkBa), setup["nhk_ba"] as? String, "NHK_BA")
        egal(hex(firstDh), setup["alice_first_dh"] as? String, "premier DH")
        let (rk, ck, nhk) = Kdf.kdfRk4(sk, firstDh, nil)
        egal(hex(rk), setup["alice_root_key"] as? String, "racine d'Alice")
        egal(hex(ck), setup["alice_sending_chain"] as? String, "chaîne d'Alice")
        egal(hex(nhk), setup["alice_next_header_key"] as? String, "NHKs d'Alice")
        egal(hex(a.associatedData), setup["ad"] as? String, "AD")
        egal(a.sessionId, Kdf.sessionId(a.associatedData), "id local")
        egal(hex(a.debugRootKey), setup["alice_root_key"] as? String, "racine de la session d'Alice")
        egal(hex(try XCTUnwrap(a.debugSendingChain)), setup["alice_sending_chain"] as? String, "chaîne de la session")
        let keys = a.debugHeaderKeys
        egal(keys.hks, hkAb, "HKs = HK_AB")
        egal(keys.nhkr, nhkBa, "NHKr = NHK_BA")
        egal(hex(keys.nhks), setup["alice_next_header_key"] as? String, "NHKs")

        // A → B : deux premiers messages, le second reçu d'abord.
        let t1 = try send(a, steps[0], from: "alice")
        let t2 = try send(a, steps[1], from: "alice")
        if mode == "psk" {
            egal(t1.type, JetonV4.typeMessage, "premier message à clé partagée : un 0x02")
        } else {
            guard case .initial(let p, _) = t1 else { return XCTFail("0x01 attendu") }
            egal(hex(p.ephemeral), setup["ek_public"] as? String, "EK en clair")
            egal(hex(p.kemCiphertext), setup["mlkem_ciphertext"] as? String, "CT en clair")
            // L'identité d'Alice n'est pas dans le jeton.
            let ikA = Array(unhex(setup["ad"])[0..<32])
            XCTAssertNil(Octets.find(t1.toBytes(), ikA), "IK_A absente du jeton")
        }
        let (b, c2) = try bobSide(t2)
        egal(texte(c2), "Tu me lis ?", "B lit le message 2")
        egal(hex(rngB.take()), events[0]["bob_drawn"] as? String, "tirages de Bob")
        egal(texte(try b.decrypt(t1, now: now, rng: rngB)), "Salut Bob 🥦", "B lit le message 1")
        XCTAssertEqual(rngB.take(), [])
        egal(hex(b.debugRootKey), events[0]["bob_root_key"] as? String, "racine de Bob")
        if mode != "psk" { egal(b.peerIdentity, Array(a.associatedData[0..<32]), "IK_A retrouvée") }
        egal(b.sessionId, a.sessionId, "même id local")

        // Deux tours complets : chaque nouvelle chaîne encapsule vers l'autre.
        var tokens: [Token4] = [t1, t2]
        for i in 0..<4 {
            let step = steps[3 + 2 * i], event = steps[4 + 2 * i]
            let from = try XCTUnwrap(step["from"] as? String)
            let text = try XCTUnwrap(step["text"] as? String)
            let (sFrom, sTo, rngTo) = from == "bob" ? (b, a, rngA) : (a, b, rngB)
            let t = try send(sFrom, step, from: from)
            egal(t.type, JetonV4.typeMessage, "0x02")
            egal(t.body.header.count, JetonV4.headerLengthCt + 16, "chaque nouvelle chaîne encapsule")
            tokens.append(t)
            egal(texte(try sTo.decrypt(t, now: now, rng: rngTo)), text, "lu « \(text) »")
            let to = from == "bob" ? "alice" : "bob"
            XCTAssertEqual(event["drawn_by"] as? String, to)
            let drawn = rngTo.take()
            egal(hex(drawn), event["drawn"] as? String, "tirages de \(to)")
            XCTAssertEqual(drawn.count, 128)
            egal(enc.tires.last, Array(drawn.suffix(32)), "m tiré")
            if enc.resolue {
                egal(hex(sTo.debugRootKey), event["root_key"] as? String, "racine de \(to)")
            } else {
                // La dernière encapsulation n'est portée par aucun message.
                XCTAssertEqual(i, 3)
            }
        }
        XCTAssertTrue(a.isConfirmed)
        XCTAssertTrue(enc.chiffres.isEmpty)
        // Rejeux : refusés, sans changer la session.
        let avant = b.toJson()
        attendreErreur(.rejoue) { try b.decrypt(tokens[5], now: now, rng: rngB) }
        attendreErreur(.rejoue) { try b.decrypt(tokens[0], now: now, rng: rngB) }
        attendreErreur(.rejoue) { try a.decrypt(tokens[4], now: now, rng: rngA) }
        XCTAssertEqual(b.toJson(), avant)
        // L'état relu se réécrit à l'identique et continue la conversation.
        let b2 = try Session4.fromJson(b.toJson())
        XCTAssertEqual(b2.toJson(), b.toJson())
        let r = try b2.encrypt("après relecture")
        egal(texte(try a.decryptText(r, now: now, rng: rngA)), "après relecture", "relu après JSON")
        print("Session v4 « \(name) » des vecteurs retrouvée")
    }

    func testDerivationsV4() throws {
        // Les étiquettes de §9.1, telles quelles.
        XCTAssertEqual(Kdf.info4Sk, Array("Brocolis_v4_X25519_MLKEM768_SHA-256".utf8))
        XCTAssertEqual(Kdf.info4HeaderKeys, Array("Brocolis_v4_HeaderKeys".utf8))
        XCTAssertEqual(Paquet.sigContextCaps4, Array("Brocolis_v4_Caps".utf8))
        // KDF_RK4 : avec et sans ss, deux infos différentes.
        let rk = [UInt8](repeating: 1, count: 32), dh = [UInt8](repeating: 2, count: 32)
        let ss = [UInt8](repeating: 3, count: 32)
        let sans = Kdf.kdfRk4(rk, dh, nil), avec = Kdf.kdfRk4(rk, dh, ss)
        XCTAssertNotEqual(sans.rk, avec.rk)
        XCTAssertEqual(
            sans.rk + sans.ck + sans.nhk, try Kdf.hkdfSha256(salt: rk, ikm: dh, info: Kdf.info4Ratchet, length: 96))
        XCTAssertEqual(
            avec.rk + avec.ck + avec.nhk,
            try Kdf.hkdfSha256(salt: rk, ikm: dh + ss, info: Kdf.info4RatchetPq, length: 96))
        let mk = Kdf.messageKeys4(ss)
        XCTAssertEqual(
            mk.key + mk.nonce + mk.headerNonce,
            try Kdf.hkdfSha256(salt: Kdf.selNul, ikm: ss, info: Kdf.info4Message, length: 56))
    }
}
