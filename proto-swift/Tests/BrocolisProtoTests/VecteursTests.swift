// proto/vectors.json, retrouvé octet pour octet : chaque dérivation, chaque
// clé protégée, chaque jeton, chaque paquet, chaque étape des trois
// sessions (hybride, classique, clé partagée) et du groupe. Le scénario des
// sessions est celui du générateur (`proto/examples/vectors.rs`) : A envoie
// deux premiers messages, B les reçoit dans le désordre, répond, etc., avec
// les mêmes générateurs déterministes.

import XCTest
@testable import BrocolisProto

final class VecteursTests: XCTestCase {
    let now: UInt64 = 1_790_000_000

    // MARK: Primitives

    func testPrimitives() throws {
        let p = try XCTUnwrap(try Depot.vecteurs()["primitives"] as? [String: Any])
        let rkv = try XCTUnwrap(p["kdf_rk"] as? [String: Any])
        let (rk, ck) = Kdf.kdfRk(unhex(rkv["rk"]), unhex(rkv["dh"]))
        egal(hex(rk), rkv["rk_out"] as? String, "KDF_RK rk")
        egal(hex(ck), rkv["ck_out"] as? String, "KDF_RK ck")
        let ckv = try XCTUnwrap(p["kdf_ck"] as? [String: Any])
        let (ck2, mk) = Kdf.kdfCk(unhex(ckv["ck"]))
        egal(hex(ck2), ckv["ck_out"] as? String, "KDF_CK ck")
        egal(hex(mk), ckv["mk"] as? String, "KDF_CK mk")
        let mkv = try XCTUnwrap(p["message_key"] as? [String: Any])
        let (key, nonce) = Kdf.messageKey(unhex(mkv["mk"]))
        egal(hex(key), mkv["key"] as? String, "ENCRYPT(mk) clé")
        egal(hex(nonce), mkv["nonce"] as? String, "ENCRYPT(mk) nonce")
        for (name, withSs) in [("sk_classic", false), ("sk_hybrid", true)] {
            let v = try XCTUnwrap(p[name] as? [String: Any])
            let sk = Kdf.skX3dh(
                dh1: unhex(v["dh1"]), dh2: unhex(v["dh2"]), dh3: unhex(v["dh3"]), ss: withSs ? unhex(v["ss"]) : nil)
            egal(hex(sk), v["sk"] as? String, name)
        }
        let psk = try XCTUnwrap(p["sk_psk"] as? [String: Any])
        let sk = Kdf.skPsk(unhex(psk["key"]))
        egal(hex(sk), psk["sk"] as? String, "SK PSK")
        let r = Kdf.pskRatchetSecret(sk)
        egal(hex(r), psk["psk_ratchet_secret"] as? String, "cliquet PSK")
        egal(hex(Kdf.x25519Public(r)), psk["psk_ratchet_public"] as? String, "cliquet PSK public")
        let sid = try XCTUnwrap(p["session_id"] as? [String: Any])
        egal(hex(Kdf.sessionId(unhex(sid["ad"]))), sid["id"] as? String, "id de session")
        let fp = try XCTUnwrap(p["fingerprint"] as? [String: Any])
        egal(Kdf.fingerprint(unhex(fp["data"])), fp["fingerprint"] as? String, "empreinte")
        let x = try XCTUnwrap(p["x25519"] as? [String: Any])
        egal(hex(Kdf.x25519Public(unhex(x["secret"]))), x["public"] as? String, "X25519 public")
        egal(hex(Kdf.x25519Public(unhex(x["peer_secret"]))), x["peer_public"] as? String, "X25519 public (pair)")
        egal(hex(try Kdf.x25519(unhex(x["secret"]), unhex(x["peer_public"]))), x["shared"] as? String, "X25519")
        let m = try XCTUnwrap(p["mlkem768"] as? [String: Any])
        guard MlKem.isAvailable else {
            print("ML-KEM-768 indisponible ici : vecteur primitives.mlkem768 sauté")
            return
        }
        egal(hex(try MlKem.publicKey(seed: unhex(m["seed"]))), m["encapsulation_key"] as? String, "ML-KEM ek")
        egal(
            hex(try MlKem.decapsulate(seed: unhex(m["seed"]), ciphertext: unhex(m["ciphertext"]))),
            m["shared"] as? String, "ML-KEM décapsulation")
        // L'encapsulation (aléa tiré par la bibliothèque) se relit aussi.
        let enc = try MlKem.encapsulate(unhex(m["encapsulation_key"]))
        XCTAssertEqual(try MlKem.decapsulate(seed: unhex(m["seed"]), ciphertext: enc.ciphertext), enc.shared)
    }

    // MARK: Remplissage

    func testRemplissage() throws {
        let p = try XCTUnwrap(try Depot.vecteurs()["padding"] as? [String: Any])
        XCTAssertEqual(p["block"] as? Int, Remplissage.bloc)
        for c in try XCTUnwrap(p["cases"] as? [[String: Any]]) {
            egal(hex(Remplissage.pad(unhex(c["data"]))), c["padded"] as? String, "remplissage")
            egal(hex(try Remplissage.unpad(unhex(c["padded"]))), c["data"] as? String, "retrait")
        }
        for bad in try XCTUnwrap(p["invalid"] as? [String]) {
            attendreErreur(.remplissage, bad) { try Remplissage.unpad(unhex(bad)) }
            Compteur.shared.ajouter("vecteurs")
        }
    }

    // MARK: Clés protégées

    func testClesProtegees() throws {
        let p = try XCTUnwrap(try Depot.vecteurs()["protected_key"] as? [String: Any])
        let key = unhex(p["key"])
        let v1 = try XCTUnwrap(p["v1"] as? [String: Any])
        let phrase1 = try XCTUnwrap(v1["phrase"] as? String)
        egal(
            try CleProtegee.protectKeyV1With(key: key, phrase: phrase1, salt: unhex(v1["salt"]), nonce: unhex(v1["nonce"])),
            v1["token"] as? String, "clé protégée v1")
        let token1 = try XCTUnwrap(v1["token"] as? String)
        egal(try CleProtegee.unprotectKey("Voici : \(token1) !", phrase: phrase1), key, "clé v1 relue")
        attendreErreur(.dechiffrement) {
            try CleProtegee.unprotectKey(token1, phrase: try XCTUnwrap(v1["wrong_phrase"] as? String))
        }
        for v in try XCTUnwrap(p["v2"] as? [[String: Any]]) {
            let params = Argon2Params(
                mKib: UInt32(try XCTUnwrap(v["m_kib"] as? Int)), t: UInt8(try XCTUnwrap(v["t"] as? Int)),
                p: UInt8(try XCTUnwrap(v["p"] as? Int)))
            let phrase = try XCTUnwrap(v["phrase"] as? String)
            let name = v["name"] as? String ?? "?"
            let debut = Date()
            let k = try CleProtegee.argon2idKey(phrase: phrase, salt: unhex(v["salt"]), params: params)
            print("Argon2id \(name) (m = \(params.mKib) Kio, t = \(params.t)) : \(String(format: "%.2f", Date().timeIntervalSince(debut))) s")
            egal(hex(k), v["argon2id_key"] as? String, "Argon2id \(name)")
            let token = try CleProtegee.protectKeyV2With(
                key: key, phrase: phrase, params: params, salt: unhex(v["salt"]), nonce: unhex(v["nonce"]))
            egal(token, v["token"] as? String, "clé protégée v2 \(name)")
            egal(try CleProtegee.v2Params(token), params, "paramètres v2 \(name)")
            egal(try CleProtegee.unprotectKey(token, phrase: phrase), key, "clé v2 relue \(name)")
            attendreErreur(.dechiffrement) {
                try CleProtegee.unprotectKey(token, phrase: try XCTUnwrap(v["wrong_phrase"] as? String))
            }
        }
        // Les paramètres refusés : avant tout calcul.
        for r in try XCTUnwrap(p["v2_rejected_params"] as? [[String: Any]]) {
            let m = UInt32(try XCTUnwrap(r["m_kib"] as? Int))
            let t = UInt8(try XCTUnwrap(r["t"] as? Int)), par = UInt8(try XCTUnwrap(r["p"] as? Int))
            attendreErreur(.parametres) { try Argon2Params(mKib: m, t: t, p: par).check() }
            var data: [UInt8] = [0x02] + Octets.u32be(m) + [t, par]
            data += [UInt8](repeating: 0, count: 83 - data.count)
            let token = CleProtegee.headV2 + Base64.encode(data) + "]]"
            attendreErreur(.parametres) { try CleProtegee.unprotectKey(token, phrase: "brocoli vert 2026") }
            Compteur.shared.ajouter("vecteurs")
        }
    }

    // MARK: Jetons v1/v2

    func testAnciensJetons() throws {
        let l = try XCTUnwrap(try Depot.vecteurs()["legacy_tokens"] as? [String: Any])
        let keys = try XCTUnwrap(l["keys"] as? [String]).map { unhex($0) }
        let rng = Deterministic(try XCTUnwrap(l["rng_seed"] as? String))
        let v1 = try XCTUnwrap(l["v1"] as? [String: Any]), v2 = try XCTUnwrap(l["v2"] as? [String: Any])
        let marked = try XCTUnwrap(l["marked"] as? [String: Any])
        // Le même générateur, dans le même ordre : les mêmes jetons.
        egal(Jetons.sealWith(try XCTUnwrap(v1["text"] as? String), keys: [keys[0]], rng: rng), v1["token"] as? String, "jeton v1")
        egal(Jetons.sealWith(try XCTUnwrap(v2["text"] as? String), keys: keys, rng: rng), v2["token"] as? String, "jeton v2")
        egal(
            Jetons.sealWith(try XCTUnwrap(marked["input"] as? String), keys: [keys[0]], rng: rng),
            marked["sealed"] as? String, "passages (( ))")
        egal(Jetons.open(try XCTUnwrap(v1["token"] as? String), keys: keys).text, v1["text"] as? String, "v1 ouvert")
        egal(Jetons.open(try XCTUnwrap(v2["token"] as? String), keys: [keys[1]]).text, v2["text"] as? String, "v2 ouvert")
        egal(Jetons.open(try XCTUnwrap(marked["sealed"] as? String), keys: keys).text, marked["opened"] as? String, "(( )) ouverts")
    }

    // MARK: Sessions

    func testSessions() throws {
        let cases = try XCTUnwrap(try Depot.vecteurs()["sessions"] as? [[String: Any]])
        XCTAssertEqual(cases.count, 3)
        for c in cases {
            let mode = try XCTUnwrap(c["mode"] as? String)
            if mode == "hybrid" && !MlKem.isAvailable {
                print("ML-KEM-768 indisponible ici : session hybride des vecteurs sautée")
                continue
            }
            try session(c)
        }
    }

    /// Un appareil des vecteurs, vérifié champ par champ.
    func device(_ v: [String: Any], pq: Bool) throws -> Device {
        let identity = try IdentitySecret(dh: unhex(v["ik_x25519_secret"]), sign: unhex(v["ik_ed25519_seed"]))
        let spkId = UInt32(try XCTUnwrap(v["spk_id"] as? Int))
        let pqPart: (id: UInt32, seed: [UInt8])? = pq ? (UInt32(try XCTUnwrap(v["pq_id"] as? Int)), unhex(v["pq_seed"])) : nil
        let d = try Device.fromSecrets(identity: identity, spk: (spkId, unhex(v["spk_secret"])), pq: pqPart, now: now)
        let b = try d.bundle()
        egal(hex(b.identity.dh), v["ik_x25519_public"] as? String, "IK X25519")
        egal(hex(b.identity.sign), v["ik_ed25519_public"] as? String, "IK Ed25519")
        egal(hex(b.spk), v["spk_public"] as? String, "SPK")
        egal(b.identity.fingerprint(), v["fingerprint"] as? String, "empreinte d'identité")
        if pq {
            egal(hex(try XCTUnwrap(b.pq).key), v["pq_public"] as? String, "PQPK")
        } else {
            XCTAssertNil(b.pq)
        }
        let expected = unhex(v["bundle"])
        if ed25519Deterministe {
            egal(b.toBytes(), expected, "paquet")
            egal(hex(b.spkSignature), v["spk_signature"] as? String, "signature SPK")
            if pq { egal(hex(try XCTUnwrap(b.pq).signature), v["pq_signature"] as? String, "signature PQPK") }
        } else {
            // CryptoKit signe avec de l'aléa : tout sauf les signatures.
            var mine = b.toBytes(), theirs = expected
            for r in [101..<165] + (pq ? [1354..<1418] : []) {
                mine.replaceSubrange(r, with: [UInt8](repeating: 0, count: 64))
                theirs.replaceSubrange(r, with: [UInt8](repeating: 0, count: 64))
            }
            egal(mine, theirs, "paquet (hors signatures)")
            XCTAssertNoThrow(try KeyBundle.fromBytes(b.toBytes()))
        }
        // Le paquet des vecteurs se relit (signatures Ed25519 strictes).
        let parsed = try KeyBundle.fromBytes(expected)
        egal(parsed.identity.fingerprint(), v["fingerprint"] as? String, "empreinte du paquet relu")
        egal(parsed.toBytes(), expected, "paquet relu")
        return d
    }

    /// Les clés du prochain message envoyé par `s`, comparées aux vecteurs.
    func checkKeys(_ s: Session, _ keys: [String: Any], _ quoi: String) throws {
        let ck = try XCTUnwrap(s.debugChainKeys.sending)
        egal(hex(ck), keys["ck"] as? String, "\(quoi) ck")
        let (ck2, mk) = Kdf.kdfCk(ck)
        egal(hex(mk), keys["mk"] as? String, "\(quoi) mk")
        egal(hex(ck2), keys["ck_next"] as? String, "\(quoi) ck suivant")
        let (key, nonce) = Kdf.messageKey(mk)
        egal(hex(key), keys["key"] as? String, "\(quoi) clé AES")
        egal(hex(nonce), keys["nonce"] as? String, "\(quoi) nonce")
    }

    func send(_ s: Session, _ step: [String: Any], from: String) throws -> Token {
        let text = try XCTUnwrap(step["text"] as? String)
        XCTAssertEqual(step["from"] as? String, from)
        try checkKeys(s, try XCTUnwrap(step["keys"] as? [String: Any]), text)
        let t = try s.encryptToken(text)
        egal(t.encode(), step["token"] as? String, "jeton « \(text) »")
        egal(Int(t.type), step["type"] as? Int, "type « \(text) »")
        egal(hex(Remplissage.pad(Array(text.utf8))), step["padded"] as? String, "remplissage « \(text) »")
        let h = try XCTUnwrap(step["header"] as? [String: Any])
        let env: Envelope
        switch t {
        case .initial(let i): env = i.envelope
        case .message(let e): env = e
        default: throw Erreur.format
        }
        egal(hex(env.header.dh), h["dh"] as? String, "en-tête DH")
        egal(Int(env.header.pn), h["pn"] as? Int, "en-tête PN")
        egal(Int(env.header.n), h["n"] as? Int, "en-tête N")
        egal(hex(env.header.toBytes()), h["header"] as? String, "en-tête")
        egal(hex(env.ciphertext), h["ciphertext"] as? String, "chiffré")
        egal(hex(s.associatedData + env.header.toBytes()), step["aad"] as? String, "données associées")
        // Le jeton relu se réécrit à l'identique.
        let back = try Token.decode(try XCTUnwrap(step["token"] as? String))
        egal(back.encode(), step["token"] as? String, "jeton relu")
        return t
    }

    func session(_ c: [String: Any]) throws {
        let name = try XCTUnwrap(c["name"] as? String)
        let mode = try XCTUnwrap(c["mode"] as? String)
        let setup = try XCTUnwrap(c["setup"] as? [String: Any])
        let steps = try XCTUnwrap(c["steps"] as? [[String: Any]])
        XCTAssertEqual(c["now"] as? Int, Int(now))
        let rngA = Recorder("\(name)/alice/cliquet")
        let rngB = Recorder("\(name)/bob/cliquet")
        let a: Session
        let bobSide: (Initial) throws -> (Session, Content)

        if mode == "psk" {
            let key = unhex(setup["key"])
            egal(Base64.encode(key), setup["key_b64"] as? String, "clé PSK en base64")
            egal(hex(unhex(setup["ek_secret"])), hex(h32("\(name)/ek")), "EK")
            a = try Session.initiatePskWith(key: key, ekSecret: unhex(setup["ek_secret"]))
            egal(hex(Kdf.x25519Public(unhex(setup["ek_secret"]))), setup["ek_public"] as? String, "EK public")
            let sk = Kdf.skPsk(key)
            egal(hex(sk), setup["sk"] as? String, "SK")
            let r = Kdf.pskRatchetSecret(sk)
            egal(hex(r), setup["psk_ratchet_secret"] as? String, "cliquet PSK")
            egal(hex(Kdf.x25519Public(r)), setup["psk_ratchet_public"] as? String, "cliquet PSK public")
            egal(hex(try Kdf.x25519(unhex(setup["ek_secret"]), Kdf.x25519Public(r))), setup["alice_first_dh"] as? String, "premier DH")
            bobSide = { i in
                var g = ReplayGuard()
                return try Session.acceptPsk(keys: [key], message: i, guard: &g, now: self.now, rng: rngB)
            }
        } else {
            let pq = mode == "hybrid"
            let alice = try device(try XCTUnwrap(setup["alice"] as? [String: Any]), pq: pq)
            let bob = try device(try XCTUnwrap(setup["bob"] as? [String: Any]), pq: pq)
            let bobV = try XCTUnwrap(setup["bob"] as? [String: Any])
            let bundle = try KeyBundle.fromBytes(unhex(bobV["bundle"]))
            let ek = unhex(setup["ek_secret"])
            egal(hex(Kdf.x25519Public(ek)), setup["ek_public"] as? String, "EK public")
            let ratchet = unhex(setup["alice_ratchet_secret"])
            egal(hex(Kdf.x25519Public(ratchet)), setup["alice_ratchet_public"] as? String, "cliquet d'Alice")
            let ika = alice.identitySecret
            let dh1 = try Kdf.x25519(ika.dh, bundle.spk)
            let dh2 = try Kdf.x25519(ek, bundle.identity.dh)
            let dh3 = try Kdf.x25519(ek, bundle.spk)
            egal(hex(dh1), setup["dh1"] as? String, "DH1")
            egal(hex(dh2), setup["dh2"] as? String, "DH2")
            egal(hex(dh3), setup["dh3"] as? String, "DH3")
            var kem: KemEncapsulation? = nil
            if pq {
                // CryptoKit n'accepte pas de `m` imposé : le chiffré des
                // vecteurs est vérifié par la décapsulation de Bob.
                let ct = unhex(setup["mlkem_ciphertext"])
                let ss = try MlKem.decapsulate(seed: unhex(bobV["pq_seed"]), ciphertext: ct)
                egal(hex(ss), setup["mlkem_shared"] as? String, "ML-KEM SS")
                kem = KemEncapsulation(ciphertext: ct, shared: ss)
            } else {
                XCTAssertTrue(setup["mlkem_ciphertext"] is NSNull)
            }
            let sk = Kdf.skX3dh(dh1: dh1, dh2: dh2, dh3: dh3, ss: kem?.shared)
            egal(hex(sk), setup["sk"] as? String, "SK")
            a = try Session.initiateWith(identity: ika, bundle: bundle, ekSecret: ek, ratchetSecret: ratchet, kem: kem)
            egal(a.isPostQuantum, pq, "mode")
            egal(hex(try Kdf.x25519(ratchet, bundle.spk)), setup["alice_first_dh"] as? String, "premier DH")
            bobSide = { i in try bob.accept(i, now: self.now, rng: rngB) }
        }
        egal(hex(a.associatedData), setup["ad"] as? String, "AD")
        egal(hex(a.sessionId), setup["session_id"] as? String, "id de session")
        egal(hex(a.debugRootKey), setup["alice_root_key"] as? String, "racine d'Alice")
        egal(hex(try XCTUnwrap(a.debugChainKeys.sending)), setup["alice_sending_chain"] as? String, "chaîne d'Alice")

        // A → B : deux premiers messages (0x01), le second reçu d'abord.
        let t1 = try send(a, steps[0], from: "alice")
        let t2 = try send(a, steps[1], from: "alice")
        let (b, c2) = try bobSide(try XCTUnwrap(t2.initialMessage))
        egal(texte(c2), "Tu me lis ?", "B lit le message 2")
        let ev2 = steps[2]
        egal(hex(rngB.take()), ev2["bob_ratchet_secret_drawn"] as? String, "secret tiré par Bob")
        egal(texte(try b.decrypt(t1, now: now, rng: rngB)), "Salut Bob 🥦", "B lit le message 1")
        egal(hex(b.ratchetPublic), ev2["bob_ratchet_public"] as? String, "cliquet de Bob")
        egal(hex(b.debugRootKey), ev2["bob_root_key"] as? String, "racine de Bob")
        XCTAssertEqual(rngB.take(), [])
        // B → A (0x02) : A fait tourner le cliquet.
        let t3 = try send(b, steps[3], from: "bob")
        XCTAssertFalse(a.isConfirmed)
        egal(texte(try a.decrypt(t3, now: now, rng: rngA)), "Oui, cinq sur cinq.", "A lit la réponse")
        XCTAssertTrue(a.isConfirmed)
        let ev4 = steps[4]
        egal(hex(rngA.take()), ev4["alice_ratchet_secret_drawn"] as? String, "secret tiré par Alice")
        egal(hex(a.ratchetPublic), ev4["alice_ratchet_public"] as? String, "cliquet d'Alice")
        egal(hex(a.debugRootKey), ev4["alice_root_key"] as? String, "racine d'Alice")
        // A → B (0x02), puis B → A.
        let t4 = try send(a, steps[5], from: "alice")
        egal(texte(try b.decrypt(t4, now: now, rng: rngB)), "Parfait.", "B lit")
        let ev6 = steps[6]
        egal(hex(rngB.take()), ev6["bob_ratchet_secret_drawn"] as? String, "secret tiré par Bob")
        egal(hex(b.ratchetPublic), ev6["bob_ratchet_public"] as? String, "cliquet de Bob")
        egal(hex(b.debugRootKey), ev6["bob_root_key"] as? String, "racine de Bob")
        let t5 = try send(b, steps[7], from: "bob")
        egal(texte(try a.decrypt(t5, now: now, rng: rngA)), "", "A lit le texte vide")
        egal(hex(rngA.take()), steps[8]["alice_ratchet_secret_drawn"] as? String, "secret tiré par Alice")
        XCTAssertEqual(steps.count, 9)
        // Rejeux : ignorés.
        attendreErreur(.rejoue) { try b.decrypt(t4, now: now, rng: rngB) }
        attendreErreur(.rejoue) { try a.decrypt(t3, now: now, rng: rngA) }
        print("Session « \(name) » des vecteurs retrouvée")
    }

    // MARK: Groupe

    func testGroupe() throws {
        let g = try XCTUnwrap(try Depot.vecteurs()["group"] as? [String: Any])
        let gid = unhex(g["group_id"])
        egal(gid, Array(h32("groupe/id")[0..<16]), "id de groupe")
        let s = try SenderKeyState.generateWith(groupId: gid, chainKey: unhex(g["chain_key"]), signingSeed: unhex(g["signing_seed"]))
        let d = s.distribution()
        egal(hex(d.signingPublic), g["signing_public"] as? String, "clé publique de la chaîne")
        egal(hex(d.senderId), g["sender_id"] as? String, "id d'expéditeur")
        egal(hex(d.toBytes()), g["distribution"] as? String, "distribution")
        let received = try ReceivedSenderKey.fromDistribution(try SenderKeyDistribution.fromBytes(unhex(g["distribution"])))
        let messages = try XCTUnwrap(g["messages"] as? [[String: Any]])
        var chain = unhex(g["chain_key"])
        for m in messages {
            let text = try XCTUnwrap(m["text"] as? String)
            egal(hex(chain), m["chain_key"] as? String, "chaîne \(text)")
            let (next, mk) = Kdf.kdfCk(chain)
            egal(hex(mk), m["mk"] as? String, "mk \(text)")
            let (key, nonce) = Kdf.messageKey(mk)
            egal(hex(key), m["key"] as? String, "clé \(text)")
            egal(hex(nonce), m["nonce"] as? String, "nonce \(text)")
            let t = try s.encryptToken(text)
            let gm = try XCTUnwrap(t.groupMessage)
            egal(Int(gm.iteration), m["iteration"] as? Int, "itération \(text)")
            egal(hex(gm.prefix()), m["aad"] as? String, "données associées \(text)")
            egal(hex(gm.ciphertext), m["ciphertext"] as? String, "chiffré \(text)")
            if ed25519Deterministe {
                egal(hex(gm.signature), m["signature"] as? String, "signature \(text)")
                egal(t.encode(), m["token"] as? String, "jeton \(text)")
            }
            // Le jeton des vecteurs se lit (signature stricte vérifiée).
            let theirs = try XCTUnwrap(try Token.decode(try XCTUnwrap(m["token"] as? String)).groupMessage)
            egal(try received.decrypt(theirs, now: now), text, "lu \(text)")
            chain = next
        }
        // La distribution par une session à clé partagée (type 0x03).
        let dv = try XCTUnwrap(g["distribution_via_psk_session"] as? [String: Any])
        let key = unhex(dv["key"]), ek = unhex(dv["ek_secret"])
        let sess = try Session.initiatePskWith(key: key, ekSecret: ek)
        egal(try sess.encryptDistribution(d), dv["token"] as? String, "distribution 0x03")
        // Le répondeur de cette session (§7.4) la lit.
        let sk = Kdf.skPsk(key), r = Kdf.pskRatchetSecret(sk)
        let responder = Session.newResponder(
            mode: .psk, sk: sk, ad: Kdf.x25519Public(ek) + Kdf.x25519Public(r), ratchetSecret: r,
            initialEphemeral: Kdf.x25519Public(ek), peerIdentity: nil)
        let content = try responder.decryptText(try XCTUnwrap(dv["token"] as? String), now: now, rng: Deterministic("x"))
        egal(content, .distribution(d), "distribution lue")
        // Relue comme un 0x02, elle est refusée (type authentifié).
        guard case .distribution(let env) = try Token.decode(try XCTUnwrap(dv["token"] as? String)) else {
            return XCTFail("0x03 attendu")
        }
        let other = Session.newResponder(
            mode: .psk, sk: sk, ad: Kdf.x25519Public(ek) + Kdf.x25519Public(r), ratchetSecret: r,
            initialEphemeral: Kdf.x25519Public(ek), peerIdentity: nil)
        attendreErreur(.dechiffrement) { try other.decrypt(.message(env), now: now, rng: Deterministic("x")) }
    }

    override class func tearDown() {
        print("Valeurs des vecteurs retrouvées : \(Compteur.shared.total("vecteurs"))")
        super.tearDown()
    }
}
