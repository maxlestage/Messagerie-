package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * proto/vectors.json, retrouvé octet pour octet : chaque dérivation, chaque
 * clé protégée, chaque jeton, chaque paquet (signatures comprises :
 * BouncyCastle signe Ed25519 de façon déterministe, comme dalek), chaque
 * étape des trois sessions (hybride, classique, clé partagée) et du groupe.
 * Le scénario des sessions est celui du générateur
 * (`proto/examples/vectors.rs`) : A envoie deux premiers messages, B les
 * reçoit dans le désordre, répond, etc., avec les mêmes générateurs
 * déterministes. ML-KEM : BouncyCastle accepte un `m` imposé, le chiffré des
 * vecteurs est donc refait par l'encapsulation (et relu par la
 * décapsulation).
 */
class VecteursTest {
    private val now = 1_790_000_000L

    @Test
    fun primitives() {
        val p = Depot.vecteurs.o("primitives")
        val rkv = p.o("kdf_rk")
        val (rk, ck) = Kdf.kdfRk(rkv.b("rk"), rkv.b("dh"))
        egal(rkv.s("rk_out"), hex(rk), "KDF_RK rk")
        egal(rkv.s("ck_out"), hex(ck), "KDF_RK ck")
        val ckv = p.o("kdf_ck")
        val (ck2, mk) = Kdf.kdfCk(ckv.b("ck"))
        egal(ckv.s("ck_out"), hex(ck2), "KDF_CK ck")
        egal(ckv.s("mk"), hex(mk), "KDF_CK mk")
        val mkv = p.o("message_key")
        val (key, nonce) = Kdf.messageKey(mkv.b("mk"))
        egal(mkv.s("key"), hex(key), "ENCRYPT(mk) clé")
        egal(mkv.s("nonce"), hex(nonce), "ENCRYPT(mk) nonce")
        for ((name, withSs) in listOf("sk_classic" to false, "sk_hybrid" to true)) {
            val v = p.o(name)
            val sk = Kdf.skX3dh(v.b("dh1"), v.b("dh2"), v.b("dh3"), if (withSs) v.b("ss") else null)
            egal(v.s("sk"), hex(sk), name)
        }
        val psk = p.o("sk_psk")
        val sk = Kdf.skPsk(psk.b("key"))
        egal(psk.s("sk"), hex(sk), "SK PSK")
        val r = Kdf.pskRatchetSecret(sk)
        egal(psk.s("psk_ratchet_secret"), hex(r), "cliquet PSK")
        egal(psk.s("psk_ratchet_public"), hex(Kdf.x25519Public(r)), "cliquet PSK public")
        val sid = p.o("session_id")
        egal(sid.s("id"), hex(Kdf.sessionId(sid.b("ad"))), "id de session")
        val fp = p.o("fingerprint")
        egal(fp.s("fingerprint"), Kdf.fingerprint(fp.b("data")), "empreinte")
        val x = p.o("x25519")
        egal(x.s("public"), hex(Kdf.x25519Public(x.b("secret"))), "X25519 public")
        egal(x.s("peer_public"), hex(Kdf.x25519Public(x.b("peer_secret"))), "X25519 public (pair)")
        egal(x.s("shared"), hex(Kdf.x25519(x.b("secret"), x.b("peer_public"))), "X25519")
        val m = p.o("mlkem768")
        egal(m.s("encapsulation_key"), hex(MlKem.publicKey(m.b("seed"))), "ML-KEM ek")
        val (ct, ss) = MlKem.encapsulate(m.b("encapsulation_key"), m.b("m"))
        egal(m.s("ciphertext"), hex(ct), "ML-KEM encapsulation (m imposé) : chiffré")
        egal(m.s("shared"), hex(ss), "ML-KEM encapsulation (m imposé) : secret")
        egal(m.s("shared"), hex(MlKem.decapsulate(m.b("seed"), m.b("ciphertext"))), "ML-KEM décapsulation")
    }

    @Test
    fun remplissage() {
        val p = Depot.vecteurs.o("padding")
        egal(p.n("block"), Remplissage.BLOC.toLong(), "bloc")
        for (c in p.a("cases")) {
            val o = c.jsonObject
            egal(o.s("padded"), hex(Remplissage.pad(o.b("data"))), "remplissage")
            egal(o.s("data"), hex(Remplissage.unpad(o.b("padded"))), "retrait")
        }
        for (bad in p.a("invalid")) {
            attendreErreur(Erreur.Remplissage, bad.s()) { Remplissage.unpad(unhex(bad.s())) }
            Compteur.ajouter("vecteurs")
        }
    }

    @Test
    fun clesProtegees() {
        val p = Depot.vecteurs.o("protected_key")
        val key = p.b("key")
        val v1 = p.o("v1")
        val phrase1 = v1.s("phrase")
        egal(v1.s("token"), CleProtegee.protectKeyV1With(key, phrase1, v1.b("salt"), v1.b("nonce")), "clé protégée v1")
        egal(key, CleProtegee.unprotectKey("Voici : ${v1.s("token")} !", phrase1), "clé v1 relue")
        attendreErreur(Erreur.Dechiffrement) { CleProtegee.unprotectKey(v1.s("token"), v1.s("wrong_phrase")) }
        for (e in p.a("v2")) {
            val v = e.jsonObject
            val params = Argon2Params(v.n("m_kib"), v.n("t").toInt(), v.n("p").toInt())
            val phrase = v.s("phrase")
            val debut = System.nanoTime()
            val k = CleProtegee.argon2idKey(phrase, v.b("salt"), params)
            println("Argon2id ${v.s("name")} (m = ${params.mKib} Kio, t = ${params.t}) : %.2f s".format((System.nanoTime() - debut) / 1e9))
            egal(v.s("argon2id_key"), hex(k), "Argon2id ${v.s("name")}")
            val token = CleProtegee.protectKeyV2With(key, phrase, params, v.b("salt"), v.b("nonce"))
            egal(v.s("token"), token, "clé protégée v2 ${v.s("name")}")
            assertEquals(params, CleProtegee.v2Params(token))
            egal(key, CleProtegee.unprotectKey(token, phrase), "clé v2 relue ${v.s("name")}")
            attendreErreur(Erreur.Dechiffrement) { CleProtegee.unprotectKey(token, v.s("wrong_phrase")) }
        }
        // Les paramètres refusés : avant tout calcul.
        for (e in p.a("v2_rejected_params")) {
            val r = e.jsonObject
            val m = r.n("m_kib")
            val t = r.n("t").toInt()
            val par = r.n("p").toInt()
            attendreErreur(Erreur.Parametres) { Argon2Params(m, t, par).check() }
            val data = Octets.concat(byteArrayOf(0x02), Octets.u32be(m), byteArrayOf(t.toByte(), par.toByte())).copyOf(83)
            val token = CleProtegee.HEAD_V2 + Octets.b64(data) + "]]"
            attendreErreur(Erreur.Parametres) { CleProtegee.unprotectKey(token, "brocoli vert 2026") }
            Compteur.ajouter("vecteurs")
        }
    }

    @Test
    fun anciensJetons() {
        val l = Depot.vecteurs.o("legacy_tokens")
        val keys = l.a("keys").map { unhex(it.s()) }
        val rng = Deterministic(l.s("rng_seed"))
        val v1 = l.o("v1")
        val v2 = l.o("v2")
        val marked = l.o("marked")
        // Le même générateur, dans le même ordre : les mêmes jetons.
        egal(v1.s("token"), Jetons.sealWith(v1.s("text"), listOf(keys[0]), rng), "jeton v1")
        egal(v2.s("token"), Jetons.sealWith(v2.s("text"), keys, rng), "jeton v2")
        egal(marked.s("sealed"), Jetons.sealWith(marked.s("input"), listOf(keys[0]), rng), "passages (( ))")
        egal(v1.s("text"), Jetons.open(v1.s("token"), keys).text, "v1 ouvert")
        egal(v2.s("text"), Jetons.open(v2.s("token"), listOf(keys[1])).text, "v2 ouvert")
        egal(marked.s("opened"), Jetons.open(marked.s("sealed"), keys).text, "(( )) ouverts")
    }

    // ----- Sessions ---------------------------------------------------------

    @Test
    fun sessions() {
        val cases = Depot.vecteurs.a("sessions")
        assertEquals(3, cases.size)
        for (c in cases) session(c.jsonObject)
    }

    /** Un appareil des vecteurs, vérifié champ par champ (signatures comprises). */
    private fun device(v: JsonObject, pq: Boolean): Device {
        val identity = IdentitySecret(v.b("ik_x25519_secret"), v.b("ik_ed25519_seed"))
        val d = Device.fromSecrets(identity, v.n("spk_id") to v.b("spk_secret"), if (pq) v.n("pq_id") to v.b("pq_seed") else null, now)
        val b = d.bundle()
        egal(v.s("ik_x25519_public"), hex(b.identity.dh), "IK X25519")
        egal(v.s("ik_ed25519_public"), hex(b.identity.sign), "IK Ed25519")
        egal(v.s("spk_public"), hex(b.spk), "SPK")
        egal(v.s("spk_signature"), hex(b.spkSignature), "signature SPK")
        egal(v.s("fingerprint"), b.identity.fingerprint(), "empreinte d'identité")
        if (pq) {
            egal(v.s("pq_public"), hex(b.pq!!.key), "PQPK")
            egal(v.s("pq_signature"), hex(b.pq!!.signature), "signature PQPK")
        } else {
            assertNull(b.pq)
            assertTrue(v.isNull("pq_seed") && v.isNull("pq_public"))
        }
        egal(v.s("bundle"), hex(b.toBytes()), "paquet")
        // Le paquet des vecteurs se relit (signatures Ed25519 strictes).
        val parsed = KeyBundle.fromBytes(v.b("bundle"))
        egal(v.s("fingerprint"), parsed.identity.fingerprint(), "empreinte du paquet relu")
        egal(v.s("bundle"), hex(parsed.toBytes()), "paquet relu")
        return d
    }

    /** Les clés du prochain message envoyé par `s`, comparées aux vecteurs. */
    private fun checkKeys(s: Session, keys: JsonObject, quoi: String) {
        val ck = s.debugChainKeys.first!!
        egal(keys.s("ck"), hex(ck), "$quoi ck")
        val (ck2, mk) = Kdf.kdfCk(ck)
        egal(keys.s("mk"), hex(mk), "$quoi mk")
        egal(keys.s("ck_next"), hex(ck2), "$quoi ck suivant")
        val (key, nonce) = Kdf.messageKey(mk)
        egal(keys.s("key"), hex(key), "$quoi clé AES")
        egal(keys.s("nonce"), hex(nonce), "$quoi nonce")
    }

    private fun send(s: Session, step: JsonObject, from: String): Token {
        val text = step.s("text")
        assertEquals(from, step.s("from"))
        checkKeys(s, step.o("keys"), text)
        val t = s.encryptToken(text)
        egal(step.s("token"), t.encode(), "jeton « $text »")
        egal(step.n("type"), t.type.toLong(), "type « $text »")
        egal(step.s("padded"), hex(Remplissage.pad(Octets.utf8(text))), "remplissage « $text »")
        val h = step.o("header")
        val env = when (t) {
            is Token.InitialMessage -> t.initial.envelope
            is Token.Message -> t.envelope
            else -> error("type inattendu")
        }
        egal(h.s("dh"), hex(env.header.dh), "en-tête DH")
        egal(h.n("pn"), env.header.pn, "en-tête PN")
        egal(h.n("n"), env.header.n, "en-tête N")
        egal(h.s("header"), hex(env.header.toBytes()), "en-tête")
        egal(h.s("ciphertext"), hex(env.ciphertext), "chiffré")
        egal(step.s("aad"), hex(Octets.concat(s.associatedData, env.header.toBytes())), "données associées")
        // Le jeton relu se réécrit à l'identique.
        egal(step.s("token"), Token.decode(step.s("token")).encode(), "jeton relu")
        return t
    }

    private fun session(c: JsonObject) {
        val name = c.s("name")
        val mode = c.s("mode")
        val setup = c.o("setup")
        val steps = c.a("steps").map { it.jsonObject }
        assertEquals(now, c.n("now"))
        val rngA = Recorder("$name/alice/cliquet")
        val rngB = Recorder("$name/bob/cliquet")
        val a: Session
        val bobSide: (Initial) -> Pair<Session, Content>

        if (mode == "psk") {
            val key = setup.b("key")
            egal(setup.s("key_b64"), Octets.b64(key), "clé PSK en base64")
            egal(hex(h32("$name/ek")), setup.s("ek_secret"), "EK")
            a = Session.initiatePskWith(key, setup.b("ek_secret"))
            egal(setup.s("ek_public"), hex(Kdf.x25519Public(setup.b("ek_secret"))), "EK public")
            val sk = Kdf.skPsk(key)
            egal(setup.s("sk"), hex(sk), "SK")
            val r = Kdf.pskRatchetSecret(sk)
            egal(setup.s("psk_ratchet_secret"), hex(r), "cliquet PSK")
            egal(setup.s("psk_ratchet_public"), hex(Kdf.x25519Public(r)), "cliquet PSK public")
            egal(setup.s("alice_first_dh"), hex(Kdf.x25519(setup.b("ek_secret"), Kdf.x25519Public(r))), "premier DH")
            bobSide = { i -> Session.acceptPsk(listOf(key), i, ReplayGuard(), now, rngB) }
        } else {
            val pq = mode == "hybrid"
            assertEquals(if (pq) "hybride" else "classique", name)
            val alice = device(setup.o("alice"), pq)
            val bob = device(setup.o("bob"), pq)
            val bobV = setup.o("bob")
            val bundle = KeyBundle.fromBytes(bobV.b("bundle"))
            val ek = setup.b("ek_secret")
            egal(setup.s("ek_public"), hex(Kdf.x25519Public(ek)), "EK public")
            val ratchet = setup.b("alice_ratchet_secret")
            egal(setup.s("alice_ratchet_public"), hex(Kdf.x25519Public(ratchet)), "cliquet d'Alice")
            val ika = alice.identitySecret
            val dh1 = Kdf.x25519(ika.dh, bundle.spk)
            val dh2 = Kdf.x25519(ek, bundle.identity.dh)
            val dh3 = Kdf.x25519(ek, bundle.spk)
            egal(setup.s("dh1"), hex(dh1), "DH1")
            egal(setup.s("dh2"), hex(dh2), "DH2")
            egal(setup.s("dh3"), hex(dh3), "DH3")
            var m: ByteArray? = null
            var ss: ByteArray? = null
            if (pq) {
                m = setup.b("mlkem_m")
                egal(hex(h32("$name/mlkem_m")), hex(m), "m ML-KEM")
                val (ct, s1) = MlKem.encapsulate(bundle.pq!!.key, m)
                egal(setup.s("mlkem_ciphertext"), hex(ct), "ML-KEM CT (encapsulation, m imposé)")
                egal(setup.s("mlkem_shared"), hex(s1), "ML-KEM SS (encapsulation)")
                ss = MlKem.decapsulate(bobV.b("pq_seed"), setup.b("mlkem_ciphertext"))
                egal(setup.s("mlkem_shared"), hex(ss), "ML-KEM SS (décapsulation)")
            } else {
                assertTrue(setup.isNull("mlkem_ciphertext") && setup.isNull("mlkem_m") && setup.isNull("mlkem_shared"))
            }
            egal(setup.s("sk"), hex(Kdf.skX3dh(dh1, dh2, dh3, ss)), "SK")
            a = Session.initiateWith(ika, bundle, ek, ratchet, m)
            assertEquals(pq, a.isPostQuantum)
            egal(setup.s("alice_first_dh"), hex(Kdf.x25519(ratchet, bundle.spk)), "premier DH")
            bobSide = { i -> bob.accept(i, now, rngB) }
        }
        egal(setup.s("ad"), hex(a.associatedData), "AD")
        egal(setup.s("session_id"), hex(a.sessionId), "id de session")
        egal(setup.s("alice_root_key"), hex(a.debugRootKey), "racine d'Alice")
        egal(setup.s("alice_sending_chain"), hex(a.debugChainKeys.first!!), "chaîne d'Alice")

        // A → B : deux premiers messages (0x01), le second reçu d'abord.
        val t1 = send(a, steps[0], "alice")
        val t2 = send(a, steps[1], "alice")
        val (b, c2) = bobSide((t2 as Token.InitialMessage).initial)
        egal("Tu me lis ?", texte(c2), "B lit le message 2")
        val ev2 = steps[2]
        egal(ev2.s("bob_ratchet_secret_drawn"), hex(rngB.take()), "secret tiré par Bob")
        egal("Salut Bob 🥦", texte(b.decrypt(t1, now, rngB)), "B lit le message 1")
        egal(ev2.s("bob_ratchet_public"), hex(b.ratchetPublic), "cliquet de Bob")
        egal(ev2.s("bob_root_key"), hex(b.debugRootKey), "racine de Bob")
        assertEquals(0, rngB.take().size)
        // B → A (0x02) : A fait tourner le cliquet.
        val t3 = send(b, steps[3], "bob")
        assertFalse(a.isConfirmed)
        egal("Oui, cinq sur cinq.", texte(a.decrypt(t3, now, rngA)), "A lit la réponse")
        assertTrue(a.isConfirmed)
        val ev4 = steps[4]
        egal(ev4.s("alice_ratchet_secret_drawn"), hex(rngA.take()), "secret tiré par Alice")
        egal(ev4.s("alice_ratchet_public"), hex(a.ratchetPublic), "cliquet d'Alice")
        egal(ev4.s("alice_root_key"), hex(a.debugRootKey), "racine d'Alice")
        // A → B (0x02), puis B → A.
        val t4 = send(a, steps[5], "alice")
        egal("Parfait.", texte(b.decrypt(t4, now, rngB)), "B lit")
        val ev6 = steps[6]
        egal(ev6.s("bob_ratchet_secret_drawn"), hex(rngB.take()), "secret tiré par Bob")
        egal(ev6.s("bob_ratchet_public"), hex(b.ratchetPublic), "cliquet de Bob")
        egal(ev6.s("bob_root_key"), hex(b.debugRootKey), "racine de Bob")
        val t5 = send(b, steps[7], "bob")
        egal("", texte(a.decrypt(t5, now, rngA)), "A lit le texte vide")
        egal(steps[8].s("alice_ratchet_secret_drawn"), hex(rngA.take()), "secret tiré par Alice")
        assertEquals(9, steps.size)
        // Rejeux : ignorés.
        attendreErreur(Erreur.Rejoue) { b.decrypt(t4, now, rngB) }
        attendreErreur(Erreur.Rejoue) { a.decrypt(t3, now, rngA) }
        println("Session « $name » des vecteurs retrouvée")
    }

    // ----- Groupe -----------------------------------------------------------

    @Test
    fun groupe() {
        val g = Depot.vecteurs.o("group")
        val gid = g.b("group_id")
        egal(hex(h32("groupe/id").copyOf(16)), hex(gid), "id de groupe")
        val s = SenderKeyState.generateWith(gid, g.b("chain_key"), g.b("signing_seed"))
        val d = s.distribution()
        egal(g.s("signing_public"), hex(d.signingPublic), "clé publique de la chaîne")
        egal(g.s("sender_id"), hex(d.senderId), "id d'expéditeur")
        egal(g.s("distribution"), hex(d.toBytes()), "distribution")
        val received = ReceivedSenderKey.fromDistribution(SenderKeyDistribution.fromBytes(g.b("distribution")))
        var chain = g.b("chain_key")
        for (e in g.a("messages")) {
            val m = e.jsonObject
            val text = m.s("text")
            egal(m.s("chain_key"), hex(chain), "chaîne $text")
            val (next, mk) = Kdf.kdfCk(chain)
            egal(m.s("mk"), hex(mk), "mk $text")
            val (key, nonce) = Kdf.messageKey(mk)
            egal(m.s("key"), hex(key), "clé $text")
            egal(m.s("nonce"), hex(nonce), "nonce $text")
            val t = s.encryptToken(text) as Token.Group
            egal(m.n("iteration"), t.message.iteration, "itération $text")
            egal(m.s("aad"), hex(t.message.prefix()), "données associées $text")
            egal(m.s("ciphertext"), hex(t.message.ciphertext), "chiffré $text")
            egal(m.s("signature"), hex(t.message.signature), "signature $text")
            egal(m.s("token"), t.encode(), "jeton $text")
            // Le jeton des vecteurs se lit (signature stricte vérifiée).
            val theirs = (Token.decode(m.s("token")) as Token.Group).message
            egal(text, received.decrypt(theirs, now), "lu $text")
            chain = next
        }
        // La distribution par une session à clé partagée (type 0x03).
        val dv = g.o("distribution_via_psk_session")
        val key = dv.b("key")
        val ek = dv.b("ek_secret")
        val sess = Session.initiatePskWith(key, ek)
        egal(dv.s("token"), sess.encryptDistribution(d), "distribution 0x03")
        // Le répondeur de cette session (§7.4) la lit.
        val sk = Kdf.skPsk(key)
        val r = Kdf.pskRatchetSecret(sk)
        fun responder() = Session.newResponder(Mode.Psk, sk, Octets.concat(Kdf.x25519Public(ek), Kdf.x25519Public(r)), r, Kdf.x25519Public(ek), null)
        val content = responder().decryptText(dv.s("token"), now, Deterministic("x"))
        egal(hex(d.toBytes()), hex((content as Content.Distribution).distribution.toBytes()), "distribution lue")
        // Relue comme un 0x02, elle est refusée (type authentifié).
        val env = (Token.decode(dv.s("token")) as Token.Distribution).envelope
        attendreErreur(Erreur.Dechiffrement) { responder().decrypt(Token.Message(env), now, Deterministic("x")) }
    }

    companion object {
        @AfterClass
        @JvmStatic
        fun bilan() {
            println("Valeurs des vecteurs retrouvées : ${Compteur.total("vecteurs")}")
        }
    }
}
