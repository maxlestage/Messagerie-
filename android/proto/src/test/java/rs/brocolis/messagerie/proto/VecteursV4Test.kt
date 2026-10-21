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
 * proto/vectors.json, clé `sessions_v4` (§9), retrouvée octet pour octet :
 * chaque dérivation de l'établissement (paquet ou clé partagée), la capacité
 * v4 signée, chaque en-tête (en clair et chiffré), chaque jeton, chaque
 * tirage du cliquet et chaque clé racine. Le scénario est celui du
 * générateur (`proto/examples/vectors.rs`, `session4_case`) : A envoie deux
 * premiers messages, B les reçoit dans le désordre, puis deux tours complets
 * du triple cliquet, avec les mêmes générateurs déterministes. ML-KEM :
 * BouncyCastle accepte un `m` imposé, chaque encapsulation du cliquet est
 * donc refaite à l'identique (pas seulement relue).
 */
class VecteursV4Test {
    private val now = 1_790_000_000L

    @Test
    fun sessionsV4() {
        val cases = Depot.vecteurs.a("sessions_v4")
        assertEquals(2, cases.size)
        assertEquals(listOf("v4", "v4-psk"), cases.map { it.jsonObject.s("name") })
        for (c in cases) session(c.jsonObject)
    }

    /** Un appareil des vecteurs (avec ML-KEM), vérifié champ par champ. */
    private fun device(v: JsonObject): Device {
        val identity = IdentitySecret(v.b("ik_x25519_secret"), v.b("ik_ed25519_seed"))
        val d = Device.fromSecrets(identity, v.n("spk_id") to v.b("spk_secret"), v.n("pq_id") to v.b("pq_seed"), now)
        val b = d.bundle()
        egal(v.s("ik_x25519_public"), hex(b.identity.dh), "IK X25519", "v4")
        egal(v.s("ik_ed25519_public"), hex(b.identity.sign), "IK Ed25519", "v4")
        egal(v.s("spk_public"), hex(b.spk), "SPK", "v4")
        egal(v.s("pq_public"), hex(b.pq!!.key), "PQPK", "v4")
        egal(v.s("bundle"), hex(b.toBytes()), "paquet", "v4")
        egal(v.s("fingerprint"), b.identity.fingerprint(), "empreinte d'identité", "v4")
        return d
    }

    /** Un envoi : les clés du message, l'en-tête (clair et chiffré), le jeton. */
    private fun send(s: Session4, step: JsonObject, from: String): Token4 {
        val text = step.s("text")
        assertEquals(from, step.s("from"))
        val h = step.o("header")
        val hks = s.debugHeaderKeys[0]!!
        egal(h.s("hk"), hex(hks), "HKs « $text »", "v4")
        val (_, mk) = Kdf.kdfCk(s.debugChainKeys.first!!)
        val (_, _, hnonce) = Kdf.messageKeys4(mk)
        egal(h.s("header_nonce"), hex(hnonce), "nonce d'en-tête dérivé « $text »", "v4")
        val t = s.encryptToken(text)
        egal(step.s("token"), t.encode(), "jeton « $text »", "v4")
        egal(step.n("type"), t.kind.toLong(), "type « $text »", "v4")
        egal(h.s("header_nonce"), hex(t.body.headerNonce), "nonce d'en-tête « $text »", "v4")
        egal(h.s("encrypted"), hex(t.body.header), "en-tête chiffré « $text »", "v4")
        egal(h.s("ciphertext"), hex(t.body.ciphertext), "chiffré « $text »", "v4")
        val plain = Kdf.aesGcmOpen(hks, t.body.headerNonce, byteArrayOf(t.kind.toByte()), t.body.header)
        egal(h.s("plain"), hex(plain), "en-tête en clair « $text »", "v4")
        val header = Header4.fromBytes(plain)
        egal(h.s("dh"), hex(header.dh), "en-tête DH", "v4")
        egal(h.n("pn"), header.pn, "en-tête PN", "v4")
        egal(h.n("n"), header.n, "en-tête N", "v4")
        egal(h.s("ek"), hex(header.ek), "en-tête ek", "v4")
        if (h.isNull("ct")) assertNull(header.ct) else egal(h.s("ct"), hex(header.ct!!), "en-tête ct", "v4")
        egal(hex(header.toBytes()), hex(plain), "en-tête réécrit", "v4")
        // Le jeton relu se réécrit à l'identique.
        egal(step.s("token"), Token4.decode(step.s("token")).encode(), "jeton relu", "v4")
        return t
    }

    private fun session(c: JsonObject) {
        val name = c.s("name")
        val mode = c.s("mode")
        val setup = c.o("setup")
        val steps = c.a("steps").map { it.jsonObject }
        assertEquals(now, c.n("now"))
        assertEquals("$name/alice/cliquet", c.o("rng").s("alice"))
        assertEquals("$name/bob/cliquet", c.o("rng").s("bob"))
        val rngA = Recorder("$name/alice/cliquet")
        val rngB = Recorder("$name/bob/cliquet")
        val ek = setup.b("ek_secret")
        egal(hex(h32("$name/ek")), hex(ek), "EK", "v4")
        egal(setup.s("ek_public"), hex(Kdf.x25519Public(ek)), "EK public", "v4")
        val kemSeed = setup.b("alice_kem_seed")
        egal(hex(Octets.concat(h32("$name/alice/kem0/0"), h32("$name/alice/kem0/1"))), hex(kemSeed), "graine ML-KEM d'Alice", "v4")
        egal(setup.s("alice_kem_public"), hex(MlKem.publicKey(kemSeed)), "clé ML-KEM d'Alice", "v4")
        val a: Session4
        val bobSide: (Token4) -> Pair<Session4, Content>
        val sk: ByteArray
        val firstDh: ByteArray

        if (mode == "psk") {
            val key = setup.b("key")
            egal(hex(h32("$name/cle")), hex(key), "clé partagée", "v4")
            a = Session4.initiatePskWith(key, ek, kemSeed)
            sk = Kdf.sk4Psk(key)
            egal(setup.s("sk"), hex(sk), "SK_PSK", "v4")
            val r = Kdf.psk4RatchetSecret(sk)
            egal(setup.s("psk_ratchet_secret"), hex(r), "r_PSK", "v4")
            egal(setup.s("psk_ratchet_public"), hex(Kdf.x25519Public(r)), "R", "v4")
            firstDh = Kdf.x25519(ek, Kdf.x25519Public(r))
            egal(hex(Octets.concat(Kdf.x25519Public(ek), Kdf.x25519Public(r))), setup.s("ad"), "AD = EK_A ‖ R", "v4")
            assertEquals(Mode4.Psk, a.mode())
            assertNull(a.peerIdentity)
            bobSide = { t -> Session4.acceptPsk(listOf(key), t, ReplayGuard(), now, rngB) }
        } else {
            assertEquals("bundle", mode)
            val alice = device(setup.o("alice"))
            val bob = device(setup.o("bob"))
            val bobV = setup.o("bob")
            // La capacité v4 (§9.6) : signature déterministe, vérifiée.
            egal(setup.s("alice_caps"), hex(alice.caps4()!!), "caps d'Alice", "v4")
            egal(setup.s("bob_caps"), hex(bob.caps4()!!), "caps de Bob", "v4")
            Paquet.verifyCaps4(alice.identity(), setup.b("alice_caps"))
            Paquet.verifyCaps4(bob.identity(), setup.b("bob_caps"))
            attendreErreur(Erreur.Signature) { Paquet.verifyCaps4(bob.identity(), setup.b("alice_caps")) }
            val bundle = KeyBundle.fromBytes(bobV.b("bundle"))
            val ratchet = setup.b("alice_ratchet_secret")
            egal(hex(h32("$name/alice/cliquet0")), hex(ratchet), "cliquet d'Alice", "v4")
            egal(setup.s("alice_ratchet_public"), hex(Kdf.x25519Public(ratchet)), "cliquet d'Alice public", "v4")
            val ika = alice.identitySecret
            val dh1 = Kdf.x25519(ika.dh, bundle.spk)
            val dh2 = Kdf.x25519(ek, bundle.identity.dh)
            val dh3 = Kdf.x25519(ek, bundle.spk)
            egal(setup.s("dh1"), hex(dh1), "DH1", "v4")
            egal(setup.s("dh2"), hex(dh2), "DH2", "v4")
            egal(setup.s("dh3"), hex(dh3), "DH3", "v4")
            val m = setup.b("mlkem_m")
            egal(hex(h32("$name/mlkem_m")), hex(m), "m ML-KEM", "v4")
            val (ct, ss) = MlKem.encapsulate(bundle.pq!!.key, m)
            egal(setup.s("mlkem_ciphertext"), hex(ct), "ML-KEM CT (encapsulation, m imposé)", "v4")
            egal(setup.s("mlkem_shared"), hex(ss), "ML-KEM SS (encapsulation)", "v4")
            egal(setup.s("mlkem_shared"), hex(MlKem.decapsulate(bobV.b("pq_seed"), ct)), "ML-KEM SS (décapsulation)", "v4")
            sk = Kdf.sk4(dh1, dh2, dh3, ss)
            egal(setup.s("sk"), hex(sk), "SK", "v4")
            val (kPre, nPre) = Kdf.preambleKey4(dh3, ss)
            egal(setup.s("preamble_key"), hex(kPre), "clé du préambule", "v4")
            egal(setup.s("preamble_nonce"), hex(nPre), "nonce du préambule", "v4")
            a = Session4.initiateWith(ika, bundle, ek, ratchet, m, kemSeed)
            firstDh = Kdf.x25519(ratchet, bundle.spk)
            egal(hex(Octets.concat(alice.identity().dh, bob.identity().dh)), setup.s("ad"), "AD = IK_A ‖ IK_B", "v4")
            assertEquals(Mode4.Bundle, a.mode())
            egal(hex(bob.identity().dh), hex(a.peerIdentity!!), "identité du correspondant", "v4")
            bobSide = { t ->
                val (sb, cb) = bob.accept4(t, now, rngB)
                egal(hex(alice.identity().dh), hex(sb.peerIdentity!!), "IK_A retrouvée par le préambule", "v4")
                // Le premier message rejoué : refusé.
                attendreErreur(Erreur.Rejoue) { bob.accept4(t, now, rngB) }
                Pair(sb, cb)
            }
            // Le préambule s'ouvre avec la clé des vecteurs et donne IK_A.
            val t0 = Token4.decode(steps[0].s("token")) as Token4.Initial
            egal(hex(ek.let { Kdf.x25519Public(it) }), hex(t0.preamble.ephemeral), "EK_A du préambule", "v4")
            egal(setup.s("mlkem_ciphertext"), hex(t0.preamble.kemCiphertext), "CT du préambule", "v4")
            egal(
                hex(alice.identity().dh), hex(Kdf.aesGcmOpen(kPre, nPre, t0.preamble.aad(), t0.preamble.sealedIdentity)),
                "préambule chiffré", "v4",
            )
            // L'identité d'Alice n'est nulle part en clair.
            assertFalse(hex(t0.toBytes()).contains(hex(alice.identity().dh)))
        }
        val (hkAb, nhkBa) = Kdf.headerKeys4(sk)
        egal(setup.s("hk_ab"), hex(hkAb), "HK_AB", "v4")
        egal(setup.s("nhk_ba"), hex(nhkBa), "NHK_BA", "v4")
        egal(setup.s("alice_first_dh"), hex(firstDh), "premier DH", "v4")
        val (rk, ck, nhk) = Kdf.kdfRk4(sk, firstDh, null)
        egal(setup.s("alice_root_key"), hex(rk), "KDF_RK4 rk", "v4")
        egal(setup.s("alice_sending_chain"), hex(ck), "KDF_RK4 ck", "v4")
        egal(setup.s("alice_next_header_key"), hex(nhk), "KDF_RK4 nhk", "v4")
        egal(setup.s("ad"), hex(a.associatedData), "AD", "v4")
        egal(hex(Kdf.sessionId(setup.b("ad"))), hex(a.sessionId), "id local", "v4")
        egal(setup.s("alice_root_key"), hex(a.debugRootKey), "racine d'Alice", "v4")
        egal(setup.s("alice_sending_chain"), hex(a.debugChainKeys.first!!), "chaîne d'Alice", "v4")
        val hk = a.debugHeaderKeys
        egal(setup.s("hk_ab"), hex(hk[0]!!), "HKs d'Alice", "v4")
        assertNull(hk[1])
        egal(setup.s("alice_next_header_key"), hex(hk[2]!!), "NHKs d'Alice", "v4")
        egal(setup.s("nhk_ba"), hex(hk[3]!!), "NHKr d'Alice", "v4")

        // A → B : deux premiers messages, le second reçu d'abord.
        val t1 = send(a, steps[0], "alice")
        val t2 = send(a, steps[1], "alice")
        assertEquals(if (mode == "psk") Token4.TYPE_MESSAGE else Token4.TYPE_INITIAL, t1.kind)
        val (b, c2) = bobSide(t2)
        egal("Tu me lis ?", texte(c2), "B lit le message 2", "v4")
        val ev2 = steps[2]
        egal(ev2.s("bob_drawn"), hex(rngB.take()), "tirages de Bob", "v4")
        egal("Salut Bob 🥦", texte(b.decrypt(t1, now, rngB)), "B lit le message 1", "v4")
        assertEquals(0, rngB.take().size)
        egal(ev2.s("bob_root_key"), hex(b.debugRootKey), "racine de Bob", "v4")
        egal(hex(a.sessionId), hex(b.sessionId), "même id local", "v4")
        attendreErreur(Erreur.Rejoue) { b.decrypt(t1, now, rngB) }

        // Deux tours complets : chaque nouvelle chaîne encapsule vers l'autre.
        val script = listOf("bob" to "Oui, cinq sur cinq.", "alice" to "Parfait.", "bob" to "Le code : 4291", "alice" to "")
        var i = 3
        val sent = mutableListOf<Pair<Session4, Token4>>()
        for ((from, text) in script) {
            val (sFrom, sTo, rngTo) = if (from == "bob") Triple(b, a, rngA) else Triple(a, b, rngB)
            val t = send(sFrom, steps[i], from)
            assertEquals(Token4.TYPE_MESSAGE, t.kind)
            assertEquals(Token4.HEADER_LEN_CT + 16, t.body.header.size)
            if (from == "bob" && i == 3) assertFalse(a.isConfirmed)
            egal(text, texte(sTo.decrypt(t, now, rngTo)), "lu : « $text »", "v4")
            assertTrue(sTo.isConfirmed)
            val ev = steps[i + 1]
            val to = if (from == "bob") "alice" else "bob"
            assertEquals(to, ev.s("drawn_by"))
            val drawn = rngTo.take()
            assertEquals(128, drawn.size)
            egal(ev.s("drawn"), hex(drawn), "tirages de $to (X25519 32, graine 64, m 32)", "v4")
            egal(ev.s("root_key"), hex(sTo.debugRootKey), "racine de $to", "v4")
            sent.add(sTo to t)
            i += 2
        }
        assertEquals(11, steps.size)
        // Rejeux : refusés, sans tirage.
        for ((s, t) in sent) attendreErreur(Erreur.Rejoue) { s.decrypt(t, now, Recorder("x")) }
        // Notre propre premier message, renvoyé après la confirmation : le
        // préambule est oublié et HK_AB n'est plus une clé d'envoi, il n'est
        // donc plus reconnu (comme la référence) — « pas cette session ».
        attendreErreur(Erreur.SessionInconnue) { a.decrypt(t1, now, rngA) }
        // Les états relus par JSON continuent la conversation.
        val a2 = Session4.fromJson(a.toJson())
        val b2 = Session4.fromJson(b.toJson())
        assertEquals(a.toJson(), a2.toJson())
        egal("encore", texte(b2.decrypt(a2.encryptToken("encore"), now, rngB)), "après JSON", "v4")
        println("Session v4 « $name » des vecteurs retrouvée")
    }

    @Test
    fun derivationsV4() {
        // Les constantes d'info, telles que la spécification les écrit (§9.1).
        egal("Brocolis_v4_X25519_MLKEM768_SHA-256", Octets.fromUtf8(Kdf.INFO4_SK), "info SK", "v4")
        egal("Brocolis_v4_PSK_SHA-256", Octets.fromUtf8(Kdf.INFO4_PSK), "info PSK", "v4")
        egal("Brocolis_v4_PSK_Ratchet", Octets.fromUtf8(Kdf.INFO4_PSK_RATCHET), "info r_PSK", "v4")
        egal("Brocolis_v4_HeaderKeys", Octets.fromUtf8(Kdf.INFO4_HEADER_KEYS), "info clés d'en-tête", "v4")
        egal("Brocolis_v4_Ratchet", Octets.fromUtf8(Kdf.INFO4_RATCHET), "info KDF_RK4", "v4")
        egal("Brocolis_v4_Ratchet_MLKEM768", Octets.fromUtf8(Kdf.INFO4_RATCHET_PQ), "info KDF_RK4 ML-KEM", "v4")
        egal("Brocolis_v4_MessageKeys", Octets.fromUtf8(Kdf.INFO4_MESSAGE), "info ENCRYPT4", "v4")
        egal("Brocolis_v4_Preamble", Octets.fromUtf8(Kdf.INFO4_PREAMBLE), "info préambule", "v4")
        // KDF_RK4 et ENCRYPT4 sont bien des HKDF de la bonne longueur.
        val rk = h32("rk")
        val dh = h32("dh")
        val ss = h32("ss")
        val out = Kdf.hkdfSha256(rk, Octets.concat(dh, ss), Kdf.INFO4_RATCHET_PQ, 96)
        val (a, b, c) = Kdf.kdfRk4(rk, dh, ss)
        egal(hex(out), hex(Octets.concat(a, b, c)), "KDF_RK4 avec ss", "v4")
        val out2 = Kdf.hkdfSha256(rk, dh, Kdf.INFO4_RATCHET, 96)
        val (a2, b2, c2) = Kdf.kdfRk4(rk, dh, null)
        egal(hex(out2), hex(Octets.concat(a2, b2, c2)), "KDF_RK4 sans ss", "v4")
        val mk = Kdf.hkdfSha256(Kdf.SEL_NUL, h32("mk"), Kdf.INFO4_MESSAGE, 56)
        val (k, n, hn) = Kdf.messageKeys4(h32("mk"))
        egal(hex(mk), hex(Octets.concat(k, n, hn)), "ENCRYPT4", "v4")
    }

    companion object {
        @AfterClass
        @JvmStatic
        fun bilan() {
            println("Valeurs des vecteurs v4 retrouvées : ${Compteur.total("v4")}")
        }
    }
}
