package rs.brocolis.messagerie.crypto

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import rs.brocolis.messagerie.proto.Erreur
import rs.brocolis.messagerie.proto.KeyBundle
import rs.brocolis.messagerie.proto.Mode
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.proto.Protocole
import rs.brocolis.messagerie.proto.Token
import java.security.SecureRandom

/**
 * Le moteur v3 de l'app (docs/SECURITE.md §8), sur la JVM : chaque opération
 * est une « transaction » qui relit l'appareil et l'état (JSON) et les
 * réécrit, comme le magasin.
 */
class BrocolisV3EngineTest {

    /** Un appareil et son état, gardés entre deux transactions. */
    class Party {
        var deviceJson: String? = null
        var stored: BrocolisV3Stored? = null

        fun <T> tx(now: Long, body: (BrocolisV3Engine) -> T): T {
            val e = BrocolisV3Engine(deviceJson, stored, now)
            val out = body(e)
            if (e.deviceDirty) deviceJson = e.device.toJson()
            // Aller-retour JSON : l'état gardé est bien ce qui se relit.
            if (e.stateDirty) stored = json.decodeFromString<BrocolisV3Stored>(json.encodeToString(e.stored))
            return out
        }

        fun bundle(now: Long = T0): KeyBundle = KeyBundle.fromBase64(tx(now) { it.bundleBase64!! })
    }

    companion object {
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        const val T0 = 1_800_000_000L
        const val JOUR = Protocole.JOUR

        fun raw() = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun keyFor(id: String, k: ByteArray, bundle: KeyBundle?, at: Long = T0, group: Boolean = false, psk: Boolean = false) =
            BrocolisV3Key(id, k, bundle, at, group, psk)

        fun text(o: BrocolisV3Opened?): String = (o as? BrocolisV3Opened.Text)?.text ?: error("pas un texte : $o")

        fun type(token: String) = Token.decode(token).type

        /** La clé de message d'un jeton : (session, clé de cliquet, n). */
        fun keyUse(token: String): String = when (val t = Token.decode(token)) {
            is Token.InitialMessage -> t.initial.envelope.let { Octets.hex(it.sessionId) + Octets.hex(it.header.dh) + ":" + it.header.n }
            is Token.Message -> t.envelope.let { Octets.hex(it.sessionId) + Octets.hex(it.header.dh) + ":" + it.header.n }
            else -> error("type inattendu")
        }
    }

    private val k = raw()
    private val alice = Party()
    private val bob = Party()
    private val aKey get() = keyFor("cle-bob", k, bob.bundle())
    private val bKey get() = keyFor("cle-alice", k, alice.bundle())

    @Test
    fun appairage_session_dansLesDeuxSens() {
        val forBob = aKey
        val forAlice = bKey
        assertEquals(BrocolisProtection.POST_QUANTUM, alice.tx(T0) { it.protection(forBob, T0) })
        // L'invitant ouvre la session dès l'appairage ; rien ne part.
        assertTrue(alice.tx(T0) { it.openSession(forBob, T0) })
        assertEquals(1, alice.tx(T0) { it.sessionCount(forBob) })

        val t1 = alice.tx(T0) { it.seal("Salut 🥦", forBob, T0) }!!
        assertEquals(Token.TYPE_INITIAL, type(t1))
        assertEquals("Salut 🥦", text(bob.tx(T0) { it.open(t1, listOf(forAlice), T0) }))
        assertEquals(BrocolisProtection.POST_QUANTUM, bob.tx(T0) { it.protection(forAlice, T0) })

        val r1 = bob.tx(T0) { it.seal("Bien reçu", forAlice, T0) }!!
        assertEquals(Token.TYPE_MESSAGE, type(r1))
        assertEquals("Bien reçu", text(alice.tx(T0) { it.open(r1, listOf(forBob), T0) }))
        // Confirmée : Alice passe aux messages 0x02.
        val t2 = alice.tx(T0) { it.seal("Deuxième", forBob, T0) }!!
        assertEquals(Token.TYPE_MESSAGE, type(t2))
        assertEquals("Deuxième", text(bob.tx(T0) { it.open(t2, listOf(forAlice), T0) }))
        // Mes propres envois se relisent (messages ouverts), sans déchiffrement.
        assertEquals("Deuxième", alice.tx(T0) { it.recall(t2) })
    }

    @Test
    fun premierMessage_seulementDUnContact() {
        val t1 = alice.tx(T0) { it.seal("Qui suis-je ?", aKey, T0) }!!
        val carol = Party()
        // Bob ne connaît Alice par aucune clé : expéditeur inconnu, refusé.
        val sansContact = keyFor("autre", k, null)
        val autreContact = keyFor("carol", raw(), carol.bundle())
        val r = bob.tx(T0) { it.open(t1, listOf(sansContact, autreContact), T0) }
        assertEquals(BrocolisV3Opened.Failed(Erreur.SessionInconnue), r)
        // Ni une clé de groupe qui porterait son paquet.
        val groupe = keyFor("groupe", k, alice.bundle(), group = true)
        assertEquals(BrocolisV3Opened.Failed(Erreur.SessionInconnue), bob.tx(T0) { it.open(t1, listOf(groupe), T0) })
        // Avec le contact : accepté.
        assertEquals("Qui suis-je ?", text(bob.tx(T0) { it.open(t1, listOf(bKey), T0) }))
    }

    @Test
    fun desordre_etPertes() {
        val forBob = aKey
        val forAlice = bKey
        bob.tx(T0) { it.open(alice.tx(T0) { a -> a.seal("ouverture", forBob, T0) }!!, listOf(forAlice), T0) }
        alice.tx(T0) { it.open(bob.tx(T0) { b -> b.seal("ok", forAlice, T0) }!!, listOf(forBob), T0) }
        val tokens = (1..6).map { i -> alice.tx(T0) { it.seal("m$i", forBob, T0) }!! }
        // Reçus à l'envers, un perdu (m3).
        for (i in listOf(6, 5, 4, 2, 1)) {
            assertEquals("m$i", text(bob.tx(T0) { it.open(tokens[i - 1], listOf(forAlice), T0) }))
        }
        // Réponse croisée, puis le retardataire.
        alice.tx(T0) { it.open(bob.tx(T0) { b -> b.seal("suite", forAlice, T0) }!!, listOf(forBob), T0) }
        assertEquals("m3", text(bob.tx(T0) { it.open(tokens[2], listOf(forAlice), T0) }))
    }

    @Test
    fun doublon_relitLeClair_puisDejaLu() {
        val forAlice = bKey
        val t1 = alice.tx(T0) { it.seal("une fois", aKey, T0) }!!
        assertEquals("une fois", text(bob.tx(T0) { it.open(t1, listOf(forAlice), T0) }))
        // Le même jeton (même coupé par une messagerie) : le clair gardé.
        val coupe = t1.substring(0, 30) + "\n  " + t1.substring(30)
        assertEquals("une fois", text(bob.tx(T0) { it.open(coupe, listOf(forAlice), T0) }))
        assertEquals(BrocolisV3Format.tokenHash(t1), BrocolisV3Format.tokenHash(coupe))
        // Le clair n'est plus gardé (bornes) : déjà lu, jamais redéchiffré.
        bob.tx(T0) { e -> repeat(BrocolisV3Format.OPENED_MAX) { e.remember("[[BROCOLIS:v3:x$it]]", "x", false, T0) } }
        assertEquals(BrocolisV3Format.OPENED_MAX, bob.tx(T0) { it.openedCount })
        assertEquals(BrocolisV3Opened.Replay, bob.tx(T0) { it.open(t1, listOf(forAlice), T0) })
    }

    @Test
    fun messagesOuverts_bornesEnOctets() {
        bob.tx(T0) { e ->
            val big = "x".repeat(300 * 1024)
            repeat(5) { e.remember("[[BROCOLIS:v3:gros$it]]", big, false, T0) }
            // 1 Mio au plus : les plus anciens sont partis.
            assertEquals(3, e.openedCount)
            assertNull(e.recall("[[BROCOLIS:v3:gros0]]"))
            assertNotNull(e.recall("[[BROCOLIS:v3:gros4]]"))
        }
    }

    @Test
    fun premiersMessagesCroises_chacunLitLAutre() {
        val forBob = aKey
        val forAlice = bKey
        val a1 = alice.tx(T0) { it.seal("de A", forBob, T0) }!!
        val b1 = bob.tx(T0) { it.seal("de B", forAlice, T0) }!!
        assertEquals("de A", text(bob.tx(T0) { it.open(a1, listOf(forAlice), T0) }))
        assertEquals("de B", text(alice.tx(T0) { it.open(b1, listOf(forBob), T0) }))
        assertEquals(2, alice.tx(T0) { it.sessionCount(forBob) })
        // La dernière qui a servi envoie ; l'autre lit.
        val a2 = alice.tx(T0) { it.seal("suite A", forBob, T0) }!!
        val b2 = bob.tx(T0) { it.seal("suite B", forAlice, T0) }!!
        assertEquals("suite A", text(bob.tx(T0) { it.open(a2, listOf(forAlice), T0) }))
        assertEquals("suite B", text(alice.tx(T0) { it.open(b2, listOf(forBob), T0) }))
    }

    @Test
    fun psk_jamaisAutomatique_puisSuivie() {
        val marked = keyFor("k-a", k, null, psk = true)
        val plain = keyFor("k-b", k, null)
        assertEquals(BrocolisProtection.PSK, alice.tx(T0) { it.protection(marked, T0) })
        // Sans signe que l'autre est à jour : pas de v3 (→ v1/v2).
        assertEquals(BrocolisProtection.LEGACY, bob.tx(T0) { it.protection(plain, T0) })
        assertNull(bob.tx(T0) { it.seal("v1 svp", plain, T0) })

        val t1 = alice.tx(T0) { it.seal("en PSK", marked, T0) }!!
        assertEquals(Mode.Psk, (Token.decode(t1) as Token.InitialMessage).initial.mode)
        assertEquals("en PSK", text(bob.tx(T0) { it.open(t1, listOf(keyFor("autre", raw(), null), plain), T0) }))
        // Un message PSK est arrivé sur la clé : Bob suit.
        assertEquals(BrocolisProtection.PSK, bob.tx(T0) { it.protection(plain, T0) })
        val r1 = bob.tx(T0) { it.seal("réponse PSK", plain, T0) }!!
        assertEquals(Token.TYPE_MESSAGE, type(r1))
        assertEquals("réponse PSK", text(alice.tx(T0) { it.open(r1, listOf(marked), T0) }))
        // Jamais pour une clé de groupe, même marquée.
        assertNull(alice.tx(T0) { it.seal("groupe", keyFor("g", k, null, group = true, psk = true), T0) })
        assertEquals(BrocolisProtection.LEGACY, alice.tx(T0) { it.protection(keyFor("g", k, null, group = true, psk = true), T0) })
    }

    @Test
    fun psk_premierMessageRejoue_refuse() {
        val marked = keyFor("k-a", k, null, psk = true)
        val plain = keyFor("k-b", k, null)
        val t1 = alice.tx(T0) { it.seal("une seule fois", marked, T0) }!!
        assertEquals("une seule fois", text(bob.tx(T0) { it.open(t1, listOf(plain), T0) }))
        // Bob oublie ses sessions PSK et ses messages ouverts, garde la mémoire
        // des clés éphémères : le même premier message est refusé.
        val s = bob.stored!!
        bob.stored = s.copy(psk = emptyMap(), opened = emptyList())
        assertEquals(BrocolisV3Opened.Replay, bob.tx(T0) { it.open(t1, listOf(plain), T0) })
    }

    @Test
    fun paquetTropVieux_PSK_etSessionExistanteContinue() {
        val vieux = keyFor("cle-bob", k, bob.bundle(), at = T0)
        val tard = T0 + 31 * JOUR
        // Plus de 30 jours, pas de session : l'autre est à jour, PSK.
        assertEquals(BrocolisProtection.PSK, alice.tx(tard) { it.protection(vieux, tard) })
        val t = alice.tx(tard) { it.seal("tard", vieux, tard) }!!
        assertEquals(Mode.Psk, (Token.decode(t) as Token.InitialMessage).initial.mode)
        assertEquals("tard", text(bob.tx(tard) { it.open(t, listOf(keyFor("cle-alice", k, alice.bundle(), at = T0)), tard) }))

        // Une session ouverte à temps continue au-delà.
        val a2 = Party()
        val frais = keyFor("cle-bob", k, bob.bundle(), at = T0)
        assertNotNull(a2.tx(T0) { it.seal("tôt", frais, T0) })
        assertEquals(BrocolisProtection.POST_QUANTUM, a2.tx(tard) { it.protection(frais, tard) })
        assertEquals(Token.TYPE_INITIAL, type(a2.tx(tard) { it.seal("encore", frais, tard) }!!))
    }

    @Test
    fun cleDeGroupe_ancienFormat() {
        val g = keyFor("g", k, bob.bundle(), group = true)
        assertEquals(BrocolisProtection.LEGACY, alice.tx(T0) { it.protection(g, T0) })
        assertNull(alice.tx(T0) { it.seal("groupe", g, T0) })
        assertFalse(alice.tx(T0) { it.openSession(g, T0) })
        // Trop grand pour un jeton v3 : v1/v2.
        assertNull(alice.tx(T0) { it.seal("x".repeat(200 * 1024 + 1), aKey, T0) })
    }

    @Test
    fun reparation_seulementDUneSessionPerdue() {
        val forBob = aKey
        val forAlice = bKey
        val t1 = alice.tx(T0) { it.seal("un", forBob, T0) }!!
        bob.tx(T0) { it.openMessage(t1, listOf(forAlice), forAlice, mine = false, now = T0) }
        assertEquals(1, bob.tx(T0) { it.sessionCount(forAlice) })

        // Un message altéré sur la session connue : rien n'est réparé.
        val t2 = alice.tx(T0) { it.seal("deux", forBob, T0) }!!
        val bytes = Octets.unb64(t2.removePrefix(Token.HEAD).removeSuffix("]]"))!!
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        val altere = Token.HEAD + Octets.b64(bytes) + "]]"
        val r = bob.tx(T0) { it.openMessage(altere, listOf(forAlice), forAlice, mine = false, now = T0) }
        assertTrue(r is BrocolisV3Opened.Failed)
        assertEquals(1, bob.tx(T0) { it.sessionCount(forAlice) })

        // Un message (0x02) d'une session que Bob ne connaît pas (comme après
        // une perte d'état) : réparé, le prochain envoi en rouvre une.
        val carol = Party()
        val dave = Party()
        val kc = raw()
        val versDave = keyFor("d", kc, dave.bundle())
        val versCarol = keyFor("c", kc, carol.bundle())
        dave.tx(T0) { it.open(carol.tx(T0) { c -> c.seal("salut", versDave, T0) }!!, listOf(versCarol), T0) }
        val enAvant = dave.tx(T0) { it.seal("0x02 inconnu", versCarol, T0) }!!
        assertEquals(Token.TYPE_MESSAGE, type(enAvant))
        val rep = bob.tx(T0) { it.openMessage(enAvant, listOf(forAlice), forAlice, mine = false, now = T0) }
        assertEquals(BrocolisV3Opened.Failed(Erreur.SessionInconnue), rep)
        assertEquals(0, bob.tx(T0) { it.sessionCount(forAlice) })

        // Mes propres messages ne réparent jamais rien.
        bob.tx(T0) { it.seal("neuve", forAlice, T0) }.also { assertEquals(Token.TYPE_INITIAL, type(it!!)) }
        assertEquals(BrocolisV3Opened.Replay, bob.tx(T0) { it.openMessage(enAvant, listOf(forAlice), forAlice, mine = true, now = T0) })
        assertEquals(1, bob.tx(T0) { it.sessionCount(forAlice) })
    }

    @Test
    fun etatPerdu_laSessionSeRouvre() {
        val forBob = aKey
        val forAlice = bKey
        bob.tx(T0) { it.open(alice.tx(T0) { a -> a.seal("avant", forBob, T0) }!!, listOf(forAlice), T0) }
        alice.tx(T0) { it.open(bob.tx(T0) { b -> b.seal("ok", forAlice, T0) }!!, listOf(forBob), T0) }
        // Bob perd son état (fichier illisible) ; Alice écrit sur l'ancienne session.
        bob.stored = null
        val perdu = alice.tx(T0) { it.seal("perdu", forBob, T0) }!!
        assertEquals(BrocolisV3Opened.Failed(Erreur.SessionInconnue),
            bob.tx(T0) { it.openMessage(perdu, listOf(forAlice), forAlice, false, T0) })
        // Bob écrit : session neuve (0x01) qu'Alice accepte ; la conversation reprend.
        val neuf = bob.tx(T0) { it.seal("me revoilà", forAlice, T0) }!!
        assertEquals(Token.TYPE_INITIAL, type(neuf))
        assertEquals("me revoilà", text(alice.tx(T0) { it.open(neuf, listOf(forBob), T0) }))
        val suite = alice.tx(T0) { it.seal("bienvenue", forBob, T0) }!!
        assertEquals("bienvenue", text(bob.tx(T0) { it.open(suite, listOf(forAlice), T0) }))
    }

    @Test
    fun rotationHebdomadaire_lesAnciensPaquetsServentEncore() {
        val ancien = bob.bundle(T0)
        val semaine = T0 + 8 * JOUR
        val neuf = bob.bundle(semaine)
        assertNotEquals(ancien.spkId, neuf.spkId)
        assertTrue(neuf.pq != null)
        // Un premier message vers l'ancien paquet (moins de 30 jours) s'ouvre.
        val t = alice.tx(semaine) { it.seal("vers l'ancien", keyFor("cle-bob", k, ancien, at = T0), semaine) }!!
        assertEquals("vers l'ancien", text(bob.tx(semaine) { it.open(t, listOf(keyFor("cle-alice", k, alice.bundle(semaine))), semaine) }))
    }

    @Test
    fun medias_enveloppe() {
        val forBob = aKey
        val forAlice = bKey
        val photo = "BRCM1:img:" + Octets.b64(ByteArray(40_000) { (it % 251).toByte() })
        val ct = alice.tx(T0) { it.sealMessage(photo, forBob, T0) }!!
        val heads = BrocolisV3Format.findTokens(ct)
        assertEquals(1, heads.size)
        assertTrue(ct.substring(heads[0].last + 1).startsWith(BrocolisCrypto.TOKEN_PREFIX))
        // Le v3 ne porte que la clé du média.
        assertTrue(alice.tx(T0) { it.recall(ct.substring(heads[0].first, heads[0].last + 1)) }!!.startsWith("BRCM3:"))
        assertEquals(photo, text(bob.tx(T0) { it.openMessage(ct, listOf(forAlice), forAlice, false, T0) }))
        // Relu de mon côté (mes envois), et relu de nouveau chez Bob.
        assertEquals(photo, text(alice.tx(T0) { it.openMessage(ct, listOf(forBob), forBob, true, T0) }))
        assertEquals(photo, text(bob.tx(T0) { it.openMessage(ct, listOf(forAlice), forAlice, false, T0) }))
        // Un long texte aussi ; un court non.
        val long = "é".repeat(9_000)
        val ct2 = bob.tx(T0) { it.sealMessage(long, forAlice, T0) }!!
        assertTrue(ct2.contains(BrocolisCrypto.TOKEN_PREFIX))
        assertEquals(long, text(alice.tx(T0) { it.openMessage(ct2, listOf(forBob), forBob, false, T0) }))
        val ct3 = bob.tx(T0) { it.sealMessage("court", forAlice, T0) }!!
        assertFalse(ct3.contains(BrocolisCrypto.TOKEN_PREFIX))
        // Média v1 abîmé : illisible, pas de réparation.
        val casse = ct.dropLast(6) + "AAAA]]"
        assertTrue(bob.tx(T0) { it.openMessage(casse, listOf(forAlice), forAlice, false, T0) } is BrocolisV3Opened.Failed)
        // Sans jeton v3 : `null` (l'appelant lit le v1).
        assertNull(bob.tx(T0) { it.openMessage(BrocolisCrypto.encryptToken("v1".toByteArray(), k), listOf(forAlice), forAlice, false, T0) })
    }

    @Test
    fun empreinteDAppairage_vecteur() {
        val key = ByteArray(32) { 0x07 }
        val a = ByteArray(64) { 0x01 }
        val b = ByteArray(64) { 0x02 }
        assertEquals("1D47-6221-06A0-8AC5", BrocolisV3Format.pairingFingerprint(key, a, b))
        assertEquals("1D47-6221-06A0-8AC5", BrocolisV3Format.pairingFingerprint(key, b, a))
        // Les deux appareils calculent la même, chacun avec la sienne d'abord.
        val ia = alice.tx(T0) { it.identity }
        val ib = bob.tx(T0) { it.identity }
        assertEquals(BrocolisV3Format.pairingFingerprint(k, ia, BrocolisV3Format.identity(bob.bundle())),
            BrocolisV3Format.pairingFingerprint(k, ib, BrocolisV3Format.identity(alice.bundle())))
    }

    @Test
    fun outils() {
        assertTrue(BrocolisV3Format.needsRepair(Erreur.SessionInconnue))
        assertTrue(BrocolisV3Format.needsRepair(Erreur.CleInconnue))
        for (e in Erreur.entries.filter { it != Erreur.SessionInconnue && it != Erreur.CleInconnue }) {
            assertFalse(e.name, BrocolisV3Format.needsRepair(e))
        }
        val txt = "a [[BROCOLIS:v3:AA\n BB]] b [[BROCOLIS:v1:x]] [[BROCOLIS:v3:CC]] [[BROCOLIS:v3:fin"
        val found = BrocolisV3Format.findTokens(txt).map { txt.substring(it.first, it.last + 1) }
        assertEquals(listOf("[[BROCOLIS:v3:AA\n BB]]", "[[BROCOLIS:v3:CC]]"), found)
        assertEquals("[[BROCOLIS:v3:AABB]]", BrocolisV3Format.normalize(found[0]))
        assertFalse(BrocolisProtection.LEGACY.isRatchet)
        assertTrue(BrocolisProtection.PSK.isRatchet)
    }

    @Test
    fun libelles_troisLangues() {
        val avant = java.util.Locale.getDefault()
        try {
            java.util.Locale.setDefault(java.util.Locale.FRENCH)
            assertEquals("🔐 double cliquet (post-quantique)", BrocolisProtection.POST_QUANTUM.label)
            assertEquals("🔐 double cliquet, clé partagée (PSK)", BrocolisProtection.PSK.label)
            java.util.Locale.setDefault(java.util.Locale.ENGLISH)
            assertEquals("🔐 double ratchet (classic)", BrocolisProtection.CLASSIC.label)
            java.util.Locale.setDefault(java.util.Locale("es"))
            assertEquals("formato antiguo", BrocolisProtection.LEGACY.label)
        } finally {
            java.util.Locale.setDefault(avant)
        }
    }

    @Test
    fun etatIllisible_repartDeZero() {
        val e = BrocolisV3Engine("{pas du json", null, T0)
        assertTrue(e.deviceDirty)
        assertNotNull(e.bundleBase64)
        val stored = BrocolisV3Stored(peers = mapOf("zz" to BrocolisV3StoredPeer("00", listOf("{abîmé}"))), pskReplay = "?")
        val e2 = BrocolisV3Engine(e.device.toJson(), stored, T0)
        assertFalse(e2.deviceDirty)
        assertEquals(0, e2.sessionCount(keyFor("x", k, null)))
    }
}
