package rs.brocolis.messagerie.proto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Le protocole v4 (§9) : les tests unitaires de la référence
 * (`proto/src/session4.rs`, `proto/src/jeton_v4.rs`) et sa robustesse
 * (`proto/tests/robustesse_v4.rs`) — entrées aléatoires, altération de
 * chaque octet d'un jeton, sauts trop grands, désordre sur de longues
 * conversations. Aucune entrée ne doit lever autre chose qu'une
 * [BrocolisException], aucune altération ne doit être acceptée, et un échec
 * laisse la session telle qu'elle était.
 */
class ProtocoleV4Test {
    private fun pair(seed: String = "session4"): Triple<Device, Session4, Pair<Device, Deterministic>> {
        val rng = Deterministic(seed)
        val alice = Device.generate(rng, 0, true)
        val bob = Device.generate(rng, 0, true)
        val a = alice.initiate4(bob.bundle(), rng)
        return Triple(alice, a, bob to rng)
    }

    /** Alice et Bob, session établie et confirmée (un aller-retour). */
    private class Duo(val a: Session4, val b: Session4, val bob: Device, val rng: Deterministic)

    private fun duo(seed: String): Duo {
        val rng = Deterministic(seed)
        val alice = Device.generate(rng, 0, true)
        val bob = Device.generate(rng, 0, true)
        val a = alice.initiate4(bob.bundle(), rng)
        val t = a.encryptToken("bonjour")
        val (b, _) = bob.accept4(t, 0, rng)
        val r = b.encryptToken("re")
        a.decrypt(r, 0, rng)
        return Duo(a, b, bob, rng)
    }

    /** Exécute `bloc` : il réussit ou lève une [BrocolisException], rien d'autre. */
    private fun <T> sansPanique(quoi: String = "", bloc: () -> T): T? = try {
        bloc()
    } catch (_: BrocolisException) {
        null
    } catch (e: Throwable) {
        fail("$quoi : exception inattendue $e")
        null
    }

    private fun body(ct: Boolean) = Body4(
        ByteArray(12) { 3 }, ByteArray((if (ct) Token4.HEADER_LEN_CT else Token4.HEADER_LEN) + 16) { 4 }, ByteArray(176) { 5 },
    )

    // ----- Jeton v4 (jeton_v4.rs) --------------------------------------------

    @Test
    fun jetonAllerRetour() {
        for (
            t in listOf(
                Token4.Message(body(false)),
                Token4.Message(body(true)),
                Token4.Initial(Preamble4(ByteArray(32) { 1 }, ByteArray(Token4.KEM_CT_LEN) { 2 }, ByteArray(Token4.PREAMBLE_LEN) { 6 }), body(false)),
            )
        ) {
            assertEquals(t, Token4.decode(t.encode()))
            assertEquals(t, Token4.fromBytes(t.toBytes()))
        }
        assertEquals(1, Token4.findAll("avant ${Token4.Message(body(false)).encode()} après [[BROCOLIS:v4:").size)
    }

    @Test
    fun jetonRefusStricts() {
        val ok = Token4.Message(body(false)).toBytes()
        // Type inconnu.
        attendreErreur(Erreur.Format) { Token4.fromBytes(ok.copyOf().also { it[0] = 0x03 }) }
        // Longueur d'en-tête non permise.
        attendreErreur(Erreur.Format) { Token4.fromBytes(ok.copyOf().also { it[13] = 0x00; it[14] = 0x10 }) }
        // Chiffré tronqué, ou d'une longueur qui n'est pas 160·k + 16.
        attendreErreur(Erreur.Format) { Token4.fromBytes(ok.copyOf(ok.size - 1)) }
        attendreErreur(Erreur.Format) { Token4.fromBytes(ok.copyOf(ok.size - 160)) }
        attendreErreur(Erreur.Format) { Token4.fromBytes(ByteArray(0)) }
        attendreErreur(Erreur.TropGrand) { Token4.fromBytes(ByteArray(Token4.MAX_TOKEN_BYTES + 1)) }
        attendreErreur(Erreur.JetonAbsent) { Token4.decode("[[BROCOLIS:v3:AA==]]") }
        attendreErreur(Erreur.JetonAbsent) { Token4.decode(" " + Token4.Message(body(false)).encode()) }
        attendreErreur(Erreur.Base64) { Token4.decode("[[BROCOLIS:v4:AA=]]") }
        attendreErreur(Erreur.Format) { Token4.decode("[[BROCOLIS:v4:]]") }
    }

    @Test
    fun enTeteStrict() {
        val h = Header4(ByteArray(32) { 7 }, 1, 2, ByteArray(Paquet.PQPK_LEN) { 8 }, ByteArray(Token4.KEM_CT_LEN) { 9 })
        val b = h.toBytes()
        assertEquals(Token4.HEADER_LEN_CT, b.size)
        assertEquals(h, Header4.fromBytes(b))
        attendreErreur(Erreur.Format) { Header4.fromBytes(b.copyOf().also { it[40] = 2 }) }
        attendreErreur(Erreur.Format) { Header4.fromBytes(b.copyOf(Token4.HEADER_LEN)) }
        attendreErreur(Erreur.Format) { Header4.fromBytes(b.copyOf(b.size + 1)) }
        val sans = Header4(ByteArray(32) { 7 }, 1, 2, ByteArray(Paquet.PQPK_LEN) { 8 }, null)
        assertEquals(Token4.HEADER_LEN, sans.toBytes().size)
        assertNull(Header4.fromBytes(sans.toBytes()).ct)
    }

    // ----- Session v4 (session4.rs) ------------------------------------------

    @Test
    fun premierEchangeEtTripleCliquet() {
        val (alice, a, rest) = pair()
        val (bob, rng) = rest
        val t = a.encryptToken("Salut 🥦")
        assertTrue(t is Token4.Initial)
        // L'identité d'Alice n'est pas dans le jeton.
        val ikA = alice.identity().dh
        assertFalse(hex(t.toBytes()).contains(hex(ikA)))
        val (b, c) = bob.accept4(t, 10, rng)
        assertEquals("Salut 🥦", texte(c))
        assertEquals(hex(ikA), hex(b.peerIdentity!!))
        assertEquals(hex(a.sessionId), hex(b.sessionId))
        attendreErreur(Erreur.Rejoue) { bob.accept4(t, 11, rng) }
        attendreErreur(Erreur.Rejoue) { b.decrypt(t, 11, rng) }
        // Plusieurs tours : chaque réponse porte une encapsulation.
        for (i in 0 until 4) {
            val r = b.encryptToken("b$i")
            assertTrue(r is Token4.Message)
            assertEquals(Token4.HEADER_LEN_CT + 16, r.body.header.size)
            assertEquals("b$i", texte(a.decrypt(r, 12, rng)))
            assertTrue(a.isConfirmed)
            val m = a.encryptToken("a$i")
            assertTrue(m is Token4.Message)
            assertEquals("a$i", texte(b.decrypt(m, 12, rng)))
        }
    }

    @Test
    fun desordreRejeuEtEcho() {
        val (_, a, rest) = pair()
        val (bob, rng) = rest
        val first = a.encryptToken("1")
        val (b, _) = bob.accept4(first, 0, rng)
        a.decrypt(b.encryptToken("r"), 0, rng)
        val m1 = a.encryptToken("m1")
        val m2 = a.encryptToken("m2")
        val m3 = a.encryptToken("m3")
        assertEquals("m3", texte(b.decrypt(m3, 0, rng)))
        assertEquals(2, b.skippedLen)
        assertEquals("m1", texte(b.decrypt(m1, 0, rng)))
        assertEquals("m2", texte(b.decrypt(m2, 0, rng)))
        attendreErreur(Erreur.Rejoue) { b.decrypt(m2, 0, rng) }
        // Notre propre message, renvoyé : rejeu, pas « inconnu ».
        attendreErreur(Erreur.Rejoue) { a.decrypt(m1, 0, rng) }
        // Un message d'une autre session : inconnu (même en 0x02, le type est authentifié).
        val (_, other, _) = pair("autre4")
        val foreign = other.encryptToken("x") as Token4.Initial
        attendreErreur(Erreur.SessionInconnue) { b.decrypt(Token4.Message(foreign.body), 0, rng) }
        attendreErreur(Erreur.SessionInconnue) { b.decrypt(foreign, 0, rng) }
        // Un premier message (0x01) d'une autre session, chez l'initiateur.
        attendreErreur(Erreur.SessionInconnue) { a.decrypt(foreign, 0, rng) }
        // Le premier message lui-même, rejoué au répondeur : rejeu.
        attendreErreur(Erreur.Rejoue) { b.decrypt(first, 0, rng) }
    }

    @Test
    fun alterationRefuseeEtEtatIntact() {
        val (_, a, rest) = pair()
        val (bob, rng) = rest
        val first = a.encryptToken("1")
        val (b, _) = bob.accept4(first, 0, rng)
        val r = b.encryptToken("r")
        val before = a.toJson()
        val bytes = r.toBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        attendreErreur(Erreur.Dechiffrement) { a.decrypt(Token4.fromBytes(bytes), 0, rng) }
        assertEquals("transactionnel", before, a.toJson())
        // L'en-tête altéré : aucune clé ne l'ouvre.
        val bytes2 = r.toBytes()
        bytes2[20] = (bytes2[20].toInt() xor 1).toByte()
        attendreErreur(Erreur.SessionInconnue) { a.decrypt(Token4.fromBytes(bytes2), 0, rng) }
        assertEquals("transactionnel", before, a.toJson())
        assertEquals("r", texte(a.decrypt(r, 0, rng)))
    }

    @Test
    fun pskV4() {
        val rng = Deterministic("psk4")
        val key = ByteArray(32) { 7 }
        val a = Session4.initiatePsk(key, rng)
        val t = a.encryptToken("par la clé")
        assertTrue(t is Token4.Message)
        val guard = ReplayGuard()
        attendreErreur(Erreur.SessionInconnue) { Session4.acceptPsk(listOf(ByteArray(32) { 1 }), t, guard, 0, rng) }
        val (b, c) = Session4.acceptPsk(listOf(ByteArray(32) { 1 }, key), t, guard, 0, rng)
        assertEquals("par la clé", texte(c))
        assertEquals(Mode4.Psk, b.mode())
        assertNull(b.peerIdentity)
        attendreErreur(Erreur.Rejoue) { Session4.acceptPsk(listOf(key), t, guard, 0, rng) }
        // Un 0x01 n'est pas un premier message à clé partagée.
        val (_, other, _) = pair()
        attendreErreur(Erreur.SessionInconnue) { Session4.acceptPsk(listOf(key), other.encryptToken("x"), ReplayGuard(), 0, rng) }
        val r = b.encrypt("réponse")
        assertEquals("réponse", texte(a.decryptText(r, 0, rng)))
        val m = a.encrypt("encore")
        assertEquals("encore", texte(b.decryptText(m, 0, rng)))
    }

    @Test
    fun jsonAllerRetour() {
        val (_, a, rest) = pair()
        val (bob, rng) = rest
        val t = a.encryptToken("x")
        val (b, _) = bob.accept4(t, 0, rng)
        val b2 = Session4.fromJson(b.toJson())
        val a2 = Session4.fromJson(a.toJson())
        assertEquals(b.toJson(), b2.toJson())
        assertEquals(a.toJson(), a2.toJson())
        assertEquals("y", texte(a2.decryptText(b2.encrypt("y"), 0, rng)))
        attendreErreur(Erreur.Etat) { Session4.fromJson("{}") }
        attendreErreur(Erreur.Etat) { Session4.fromJson("[]") }
        attendreErreur(Erreur.Etat) { Session4.fromJson(b.toJson().replace("\"v\":4", "\"v\":1")) }
        attendreErreur(Erreur.Etat) { Session4.fromJson(b.toJson().replace("\"confirmed\":true", "\"confirmed\":1")) }
        // `previous_hkr` absent (`#[serde(default)]`) : relu.
        val sans = b.toJson().replace(",\"previous_hkr\":[]", "")
        assertFalse(sans.contains("previous_hkr"))
        Session4.fromJson(sans)
        // Un état v3 n'est pas un état v4.
        val v3 = Session.initiatePsk(ByteArray(32), rng)
        attendreErreur(Erreur.Etat) { Session4.fromJson(v3.toJson()) }
    }

    @Test
    fun capaciteV4Signee() {
        val rng = Deterministic("caps")
        val a = Device.generate(rng, 0, true)
        val b = Device.generate(rng, 0, true)
        val caps = a.caps4()!!
        Paquet.verifyCaps4(a.identity(), caps)
        // Sur une autre identité, ou altérée : refusée.
        attendreErreur(Erreur.Signature) { Paquet.verifyCaps4(b.identity(), caps) }
        attendreEchec { Paquet.verifyCaps4(a.identity(), caps.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }) }
        attendreErreur(Erreur.Signature) { Paquet.verifyCaps4(a.identity(), caps.copyOf(63)) }
        // Sans ML-KEM, pas de capacité v4.
        assertNull(Device.generate(rng, 0, false).caps4())
    }

    @Test
    fun unPaquetSansMlKemEstRefuse() {
        val rng = Deterministic("classique")
        val alice = Device.generate(rng, 0, true)
        val bob = Device.generate(rng, 0, false)
        attendreErreur(Erreur.PqIndisponible) { alice.initiate4(bob.bundle(), rng) }
    }

    @Test
    fun distributionParSessionV4() {
        val (_, a, rest) = pair()
        val (bob, rng) = rest
        val (b, _) = bob.accept4(a.encryptToken("x"), 0, rng)
        val s = SenderKeyState.generate(ByteArray(16) { 9 }, rng)
        val d = s.distribution()
        val c = b.decryptText(a.encryptDistribution(d), 0, rng)
        assertEquals(hex(d.toBytes()), hex((c as Content.Distribution).distribution.toBytes()))
    }

    @Test
    fun cleePreSigneeRemplaceeEncoreAcceptee() {
        // Un premier message vers l'ancienne SPK/PQPK (mois de grâce) s'ouvre.
        val rng = Deterministic("grace4")
        val alice = Device.generate(rng, 0, true)
        val bob = Device.generate(rng, 0, true)
        val old = bob.bundle()
        bob.rotate(rng, 8 * Protocole.JOUR)
        val a = alice.initiate4(old, rng)
        val (b, c) = bob.accept4(a.encryptToken("en retard"), 9 * Protocole.JOUR, rng)
        assertEquals("en retard", texte(c))
        assertEquals(hex(alice.identity().dh), hex(b.peerIdentity!!))
    }

    // ----- Robustesse (robustesse_v4.rs) -------------------------------------

    @Test
    fun entreesAleatoires() {
        val d = duo("aleatoire4")
        val rng = d.rng
        for (i in 0 until 3_000) {
            val n = (rng.nextU32() % 3_000).toInt()
            val data = rng.bytes(n)
            if (data.isNotEmpty()) data[0] = (1 + i % 2).toByte()
            // Une longueur d'en-tête plausible pour atteindre le déchiffrement.
            if (data.size > 15 && i % 3 == 0) {
                val len = if (i % 2 == 0) Token4.HEADER_LEN + 16 else Token4.HEADER_LEN_CT + 16
                data[13] = (len ushr 8).toByte()
                data[14] = len.toByte()
            }
            val text = String(data, Charsets.UTF_8)
            sansPanique("decode") { Token4.decode(text) }
            sansPanique("decode b64") { Token4.decode(Token4.HEAD + Octets.b64(data) + "]]") }
            sansPanique("findAll") { Token4.findAll(text) }
            sansPanique("json") { Session4.fromJson(text) }
            sansPanique("en-tête") { Header4.fromBytes(data) }
            val t = sansPanique("fromBytes") { Token4.fromBytes(data) } ?: continue
            for (s0 in listOf(d.a, d.b)) {
                val s = Session4.fromJson(s0.toJson())
                val before = s.toJson()
                try {
                    s.decrypt(t, 0, rng)
                    fail("entrée aléatoire acceptée")
                } catch (_: BrocolisException) {
                }
                assertEquals(before, s.toJson())
            }
            sansPanique("accept4") { Device.fromJson(d.bob.toJson()).accept4(t, 0, rng) }
            sansPanique("acceptPsk") { Session4.acceptPsk(listOf(ByteArray(32) { 1 }), t, ReplayGuard(), 0, rng) }
        }
    }

    @Test
    fun chaqueOctetAltereEstRefuse() {
        val d = duo("alteration4")
        val rng = d.rng
        // Un message avec encapsulation (nouvelle chaîne d'Alice).
        val t = d.a.encryptToken("secret").toBytes()
        val before = d.b.toJson()
        var essais = 0
        // Tout l'en-tête et le chiffré, un octet sur 7 (sans 4 000 essais ML-KEM).
        for (i in t.indices step 7) {
            val m = t.copyOf()
            m[i] = (m[i].toInt() xor 0x01).toByte()
            val tok = try {
                Token4.fromBytes(m)
            } catch (_: BrocolisException) {
                continue
            }
            val s = Session4.fromJson(before)
            try {
                s.decrypt(tok, 0, rng)
                fail("octet $i altéré accepté")
            } catch (_: BrocolisException) {
            }
            assertEquals("octet $i : état modifié", before, s.toJson())
            essais++
        }
        assertTrue(essais > 300)
        assertEquals(before, d.b.toJson())
        assertEquals("secret", texte(d.b.decrypt(Token4.fromBytes(t), 0, rng)))
    }

    @Test
    fun premierMessageAltereOuRejoue() {
        val rng = Deterministic("premier4")
        val alice = Device.generate(rng, 0, true)
        val bob = Device.generate(rng, 0, true)
        val a = alice.initiate4(bob.bundle(), rng)
        val t = a.encryptToken("x").toBytes()
        val bobJson = bob.toJson()
        // EK, CT, préambule, en-tête, chiffré : un octet de chaque.
        for (i in listOf(1, 40, 1_200, 1_170, 1_190, 1_250, t.size - 1)) {
            val m = t.copyOf()
            m[i] = (m[i].toInt() xor 0x01).toByte()
            val tok = try {
                Token4.fromBytes(m)
            } catch (_: BrocolisException) {
                continue
            }
            val b = Device.fromJson(bobJson)
            attendreEchec("octet $i") { b.accept4(tok, 0, rng) }
            // Sans effet sur l'appareil.
            assertEquals(bobJson, b.toJson())
        }
        // Un appareil tiers : aucune clé n'ouvre le préambule.
        val carole = Device.generate(rng, 0, true)
        attendreErreur(Erreur.CleInconnue) { carole.accept4(Token4.fromBytes(t), 0, rng) }
        // Un 0x02 n'est pas un premier message.
        attendreErreur(Erreur.Format) { bob.accept4(Token4.Message(Token4.fromBytes(t).body), 0, rng) }
        // Le bon : accepté, puis rejoué → refusé.
        bob.accept4(Token4.fromBytes(t), 0, rng)
        attendreErreur(Erreur.Rejoue) { bob.accept4(Token4.fromBytes(t), 0, rng) }
    }

    @Test
    fun tropDeSauts() {
        val d = duo("sauts4")
        var last: Token4? = null
        for (i in 0 until 1_002) last = d.a.encryptToken("$i")
        val before = d.b.toJson()
        attendreErreur(Erreur.TropDeClesSautees) { d.b.decrypt(last!!, 0, d.rng) }
        assertEquals(before, d.b.toJson())
    }

    @Test
    fun sautsBornesEtPurge() {
        val d = duo("bornes4")
        // 1 000 sauts exactement : acceptés, et les clés gardées sont bornées.
        val tokens = (0..1_000).map { d.a.encryptToken("$it") }
        assertEquals("1000", texte(d.b.decrypt(tokens[1_000], 0, d.rng)))
        assertEquals(Protocole.MAX_SKIP.toInt(), d.b.skippedLen)
        assertEquals("0", texte(d.b.decrypt(tokens[0], 0, d.rng)))
        assertEquals(999, d.b.skippedLen)
        // 30 jours plus tard, les clés sautées sont effacées : le retardataire est perdu.
        d.b.purge(Protocole.MAX_SKIP_AGE)
        assertEquals(0, d.b.skippedLen)
        attendreErreur(Erreur.Rejoue) { d.b.decrypt(tokens[1], Protocole.MAX_SKIP_AGE, d.rng) }
    }

    @Test
    fun longueConversationDansLeDesordre() {
        val d = duo("desordre4")
        val rng = d.rng
        for (round in 0 until 12) {
            val (from, to) = if (round % 2 == 0) d.a to d.b else d.b to d.a
            val n = 1 + (rng.nextU32() % 5).toInt()
            val batch = (0 until n).map { i -> "r${round}m$i".let { it to from.encryptToken(it) } }.toMutableList()
            // Mélange (Fisher-Yates déterministe).
            for (i in batch.size - 1 downTo 1) {
                val j = (rng.nextU32() % (i + 1)).toInt()
                val x = batch[i]
                batch[i] = batch[j]
                batch[j] = x
            }
            for ((t, tok) in batch) {
                assertEquals(t, texte(to.decrypt(tok, 0, rng)))
                attendreErreur(Erreur.Rejoue) { to.decrypt(tok, 0, rng) }
            }
            assertEquals(0, to.skippedLen)
        }
    }

    @Test
    fun unRetardataireDUneChainePassee() {
        val d = duo("retard4")
        val (a, b, rng) = Triple(d.a, d.b, d.rng)
        val x1 = a.encryptToken("x1")
        val x2 = a.encryptToken("x2")
        assertEquals("x2", texte(b.decrypt(x2, 0, rng)))
        val y = b.encryptToken("y")
        assertEquals("y", texte(a.decrypt(y, 0, rng)))
        // Nouvelle chaîne d'Alice (encapsulation vers la clé ML-KEM de Bob).
        val x3 = a.encryptToken("x3")
        assertEquals("x3", texte(b.decrypt(x3, 0, rng)))
        // x1, de la chaîne d'avant, arrive enfin.
        assertEquals("x1", texte(b.decrypt(x1, 0, rng)))
        attendreErreur(Erreur.Rejoue) { b.decrypt(x1, 0, rng) }
        assertEquals(0, b.skippedLen)
        // Un message d'une chaîne passée, déjà lu : rejeu (16 dernières HKr).
        attendreErreur(Erreur.Rejoue) { b.decrypt(x2, 0, rng) }
    }

    @Test
    fun unTiersNeLitRien() {
        val d = duo("tiers4")
        val t = d.a.encryptToken("privé")
        // Une autre session entre d'autres appareils : rien ne s'ouvre.
        val autre = duo("tiers4-bis")
        for (s in listOf(autre.a, autre.b)) {
            val before = s.toJson()
            attendreErreur(Erreur.SessionInconnue) { s.decrypt(t, 0, d.rng) }
            assertEquals(before, s.toJson())
        }
        // Ni l'appareil d'un tiers, ni une clé partagée.
        attendreErreur(Erreur.Format) { Device.generate(d.rng, 0, true).accept4(t, 0, d.rng) }
        attendreErreur(Erreur.SessionInconnue) { Session4.acceptPsk(listOf(ByteArray(32)), t, ReplayGuard(), 0, d.rng) }
        assertEquals("privé", texte(d.b.decrypt(t, 0, d.rng)))
    }
}
