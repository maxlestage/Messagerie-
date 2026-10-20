package rs.brocolis.messagerie.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests de propriétés du protocole v3 (port de `proto/tests/protocole.rs`) :
 * aller-retour, désordre, pertes, rejeu, sessions croisées, altérations d'un
 * bit, MAX_SKIP, persistance JSON. Les scénarios sont tirés par un générateur
 * déterministe (graines fixes) : un échec se rejoue à l'identique.
 */
class ProtocoleTest {
    private val t0 = 1_790_000_000L
    private val maxSkip = Protocole.MAX_SKIP.toInt()

    private class Etabli(val a: Session, val b: Session, val rng: Deterministic)

    /** Une session établie et confirmée (B a répondu), en mode `pq`. */
    private fun established(seed: ByteArray, pq: Boolean): Etabli {
        val rng = Deterministic(seed)
        val alice = Device.generate(rng, t0, pq)
        val bob = Device.generate(rng, t0, pq)
        val a = alice.initiate(bob.bundle(), pq, rng)
        val i = (a.encryptToken("bonjour") as Token.InitialMessage).initial
        val (b, c) = bob.accept(i, t0, rng)
        assertEquals("bonjour", texte(c))
        val r = b.encryptToken("re")
        assertEquals("re", texte(a.decrypt(r, t0, rng)))
        return Etabli(a, b, rng)
    }

    private fun established(seed: String, pq: Boolean) = established(Octets.utf8(seed), pq)

    /**
     * Un échange au hasard : envois des deux côtés, livraisons dans le
     * désordre, pertes, rejeux et sauvegardes JSON. Chaque message livré est
     * lu une fois, exactement ; un rejeu ne l'est jamais, et ne change rien.
     */
    @Test
    fun echangesAleatoires() {
        for (seed in 0 until 24) {
            val pq = seed % 2 == 0
            val e = established(Octets.u32be(seed.toLong()), pq)
            var a = e.a
            var b = e.b
            val rng = e.rng
            val inFlight = mutableListOf<Triple<Boolean, Token, String>>()
            val delivered = mutableListOf<Pair<Boolean, Token>>()
            var now = t0
            for (step in 0 until 300) {
                now += 7
                when (rng.below(10)) {
                    in 0..3 -> {
                        val fromA = rng.below(2) == 0
                        val msg = "$seed/$step " + "é".repeat(rng.below(200))
                        val s = if (fromA) a else b
                        inFlight.add(Triple(fromA, s.encryptToken(msg), msg))
                    }
                    in 4..7 -> if (inFlight.isNotEmpty()) {
                        val (fromA, token, msg) = inFlight.removeAt(rng.below(inFlight.size))
                        val r = if (fromA) b else a
                        assertEquals("graine $seed", msg, texte(r.decrypt(token, now, rng)))
                        delivered.add(fromA to token)
                    }
                    8 -> if (inFlight.isNotEmpty()) {
                        // Perdu.
                        inFlight.removeAt(rng.below(inFlight.size))
                    }
                    9 -> if (delivered.isNotEmpty()) {
                        val (fromA, token) = delivered[rng.below(delivered.size)]
                        val r = if (fromA) b else a
                        val before = r.toJson()
                        attendreErreur(Erreur.Rejoue, "graine $seed étape $step") { r.decrypt(token, now, rng) }
                        assertEquals(before, r.toJson())
                    }
                    else -> {
                        a = Session.fromJson(a.toJson())
                        b = Session.fromJson(b.toJson())
                    }
                }
                assertTrue(a.skippedLen <= maxSkip && b.skippedLen <= maxSkip)
            }
            // Tout ce qui reste en vol arrive encore.
            while (inFlight.isNotEmpty()) {
                val (fromA, token, msg) = inFlight.removeAt(inFlight.size - 1)
                val r = if (fromA) b else a
                assertEquals(msg, texte(r.decrypt(token, now, rng)))
            }
        }
    }

    /** Un bit modifié n'importe où dans un jeton : refusé, et la session est exactement celle d'avant. */
    @Test
    fun alterationsDUnBit() {
        val e = established("bits", true)
        val token = e.a.encryptToken("un message à ne pas modifier")
        val bytes = token.toBytes()
        val before = e.b.toJson()
        for (i in bytes.indices) {
            for (bit in 0 until 8) {
                val x = bytes.copyOf()
                x[i] = (x[i].toInt() xor (1 shl bit)).toByte()
                val t = runCatching { Token.fromBytes(x) }.getOrNull()
                if (t != null) attendreEchec("octet $i bit $bit") { e.b.decrypt(t, t0, e.rng) }
                assertEquals(before, e.b.toJson())
            }
        }
        assertEquals("un message à ne pas modifier", texte(e.b.decrypt(token, t0, e.rng)))
    }

    /** Un bit modifié dans un premier message (préambule, CT ML-KEM compris) : aucune session, l'appareil ne retient rien. */
    @Test
    fun alterationsDuPremierMessage() {
        val rng = Deterministic("premier")
        val alice = Device.generate(rng, t0, true)
        val bob = Device.generate(rng, t0, true)
        val a = alice.initiate(bob.bundle(), true, rng)
        val token = a.encryptToken("établir")
        val bytes = token.toBytes()
        val before = bob.toJson()
        // Un octet sur trois, tous les bits : couvre chaque champ.
        for (i in bytes.indices step 3) {
            for (bit in 0 until 8) {
                val x = bytes.copyOf()
                x[i] = (x[i].toInt() xor (1 shl bit)).toByte()
                val t = runCatching { Token.fromBytes(x) }.getOrNull()
                if (t is Token.InitialMessage) attendreEchec("octet $i bit $bit") { bob.accept(t.initial, t0, rng) }
            }
        }
        assertEquals(before, bob.toJson())
        assertEquals("établir", texte(bob.accept((token as Token.InitialMessage).initial, t0, rng).second))
    }

    @Test
    fun maxSkipEtAgeDesClesSautees() {
        val e = established("skip", false)
        val b = e.b
        val tokens = (0..maxSkip + 1).map { e.a.encryptToken(it.toString()) }
        // Le message n = MAX_SKIP + 1 demanderait 1 001 clés sautées : refusé.
        val before = b.toJson()
        attendreErreur(Erreur.TropDeClesSautees) { b.decrypt(tokens[maxSkip + 1], t0, e.rng) }
        assertEquals(before, b.toJson())
        // n = MAX_SKIP passe : 1 000 clés gardées.
        assertEquals("1000", texte(b.decrypt(tokens[maxSkip], t0, e.rng)))
        assertEquals(maxSkip, b.skippedLen)
        assertEquals("1001", texte(b.decrypt(tokens[maxSkip + 1], t0, e.rng)))
        // Un retardataire, encore dans les 30 jours.
        assertEquals("5", texte(b.decrypt(tokens[5], t0 + Protocole.MAX_SKIP_AGE - 1, e.rng)))
        attendreErreur(Erreur.Rejoue) { b.decrypt(tokens[5], t0, e.rng) }
        // Après 30 jours, les clés sautées sont effacées : le message est perdu.
        attendreEchec { b.decrypt(tokens[6], t0 + Protocole.MAX_SKIP_AGE, e.rng) }
        b.purge(t0 + Protocole.MAX_SKIP_AGE)
        assertEquals(0, b.skippedLen)
    }

    @Test
    fun lePlafondDeClesSauteesEffaceLesPlusVieilles() {
        val e = established("plafond", false)
        val first = (0 until 600).map { e.a.encryptToken(it.toString()) }
        val second = (600 until 1200).map { e.a.encryptToken(it.toString()) }
        e.b.decrypt(first[599], t0, e.rng)
        e.b.decrypt(second[599], t0, e.rng)
        assertEquals(maxSkip, e.b.skippedLen)
        // Les plus vieilles (0..198) sont parties ; 198 et suivantes restent.
        attendreEchec { e.b.decrypt(first[0], t0, e.rng) }
        assertEquals("198", texte(e.b.decrypt(first[198], t0, e.rng)))
    }

    @Test
    fun sessionsCroisees() {
        val e1 = established("croise-1", true)
        val e2 = established("croise-2", true)
        val rng = e1.rng
        val t1 = e1.a.encryptToken("pour b1")
        val t2 = e2.a.encryptToken("pour b2")
        val before = e2.b.toJson()
        attendreErreur(Erreur.SessionInconnue) { e2.b.decrypt(t1, t0, rng) }
        assertEquals(before, e2.b.toJson())
        // Même identifiant forcé : la clé ne correspond pas.
        val forged = Token.Message((t1 as Token.Message).envelope.withSessionId(e2.b.sessionId))
        attendreEchec { e2.b.decrypt(forged, t0, rng) }
        assertEquals(before, e2.b.toJson())
        assertEquals("pour b1", texte(e1.b.decrypt(t1, t0, rng)))
        assertEquals("pour b2", texte(e2.b.decrypt(t2, t0, rng)))
        // Ses propres messages renvoyés : ignorés.
        val own = e1.a.encryptToken("à moi")
        attendreErreur(Erreur.Rejoue) { e1.a.decrypt(own, t0, rng) }
    }

    @Test
    fun nouvelleSessionMemeIdentifiant() {
        val rng = Deterministic("nouvelle")
        val alice = Device.generate(rng, t0, true)
        val bob = Device.generate(rng, t0, true)
        val bundle = bob.bundle()
        val a1 = alice.initiate(bundle, true, rng)
        val i1 = (a1.encryptToken("un") as Token.InitialMessage).initial
        val (b1, _) = bob.accept(i1, t0, rng)
        // Alice a perdu sa session et en ouvre une autre : même AD, même id.
        val a2 = alice.initiate(bundle, true, rng)
        val t = a2.encryptToken("deux")
        assertArrayEquals(b1.sessionId, t.sessionId)
        attendreErreur(Erreur.NouvelleSession) { b1.decrypt(t, t0, rng) }
        val (b2, c) = bob.accept((t as Token.InitialMessage).initial, t0, rng)
        assertEquals("deux", texte(c))
        assertEquals("ok", texte(a2.decrypt(b2.encryptToken("ok"), t0, rng)))
    }

    @Test
    fun sansPqEtPaquetSansMlkem() {
        val rng = Deterministic("sans-pq")
        val alice = Device.generate(rng, t0, true)
        val bob = Device.generate(rng, t0, false)
        val bundle = bob.bundle()
        attendreErreur(Erreur.PqIndisponible) { alice.initiate(bundle, true, rng) }
        val a = alice.initiate(bundle, false, rng)
        assertFalse(a.isPostQuantum)
        val (b, _) = bob.accept((a.encryptToken("classique") as Token.InitialMessage).initial, t0, rng)
        assertFalse(b.isPostQuantum)
        assertArrayEquals(alice.identity().dh, b.peerIdentity)
    }

    @Test
    fun ancienneSpkGardeeUnMois() {
        val rng = Deterministic("spk")
        val alice = Device.generate(rng, t0, true)
        val bob = Device.generate(rng, t0, true)
        val old = bob.bundle()
        val a = alice.initiate(old, true, rng)
        val late = (a.encryptToken("en retard") as Token.InitialMessage).initial
        bob.rotate(rng, t0 + Paquet.PREKEY_ROTATION)
        assertNotEquals(old.spkId, bob.bundle().spkId)
        // Encore acceptée pendant le mois de grâce…
        val copy = Device.fromJson(bob.toJson())
        copy.accept(late, t0 + Paquet.PREKEY_ROTATION + 1, rng)
        // … puis effacée.
        bob.purge(t0 + Paquet.PREKEY_ROTATION + Paquet.PREKEY_GRACE)
        attendreErreur(Erreur.CleInconnue) { bob.accept(late, t0, rng) }
    }

    @Test
    fun pskAllerRetourEtConfidentialiteApresReponse() {
        val rng = Deterministic("psk")
        val key = ByteArray(32) { 9 }
        val a = Session.initiatePsk(key, rng)
        val guard = ReplayGuard()
        val t1 = a.encryptToken("un")
        val t2 = a.encryptToken("deux")
        val (b, c) = Session.acceptPsk(listOf(key), (t2 as Token.InitialMessage).initial, guard, t0, rng)
        assertEquals("deux", texte(c))
        assertEquals("un", texte(b.decrypt(t1, t0, rng)))
        assertEquals("trois", texte(a.decrypt(b.encryptToken("trois"), t0, rng)))
        assertTrue(a.isConfirmed)
        // Après la réponse, quelqu'un qui n'a que la clé partagée (et a tout vu
        // passer) ne lit plus rien.
        val next = a.encryptToken("quatre")
        val (spy, _) = Session.acceptPsk(listOf(key), (t1 as Token.InitialMessage).initial, ReplayGuard(), t0, Deterministic("espion"))
        attendreEchec { spy.decrypt(next, t0, rng) }
        assertEquals("quatre", texte(b.decrypt(next, t0, rng)))
        // Un premier message rejoué, ou une autre clé : refusés.
        attendreErreur(Erreur.Rejoue) { Session.acceptPsk(listOf(key), t2.initial, guard, t0, rng) }
        attendreErreur(Erreur.SessionInconnue) { Session.acceptPsk(listOf(ByteArray(32) { 1 }), t1.initial, ReplayGuard(), t0, rng) }
    }

    @Test
    fun groupeParSessionsADeux() {
        val e = established("groupe", true)
        val rng = e.rng
        val gid = Groupe.newGroupId(rng)
        val chain = SenderKeyState.generate(gid, rng)
        // Distribution par la session à deux (type 0x03).
        val dist = e.a.encryptDistribution(chain.distribution())
        assertTrue(Token.decode(dist) is Token.Distribution)
        val d = (e.b.decryptText(dist, t0, rng) as Content.Distribution).distribution
        val recv = ReceivedSenderKey.fromDistribution(d)
        // Un 0x02 relu comme 0x03 est refusé : le type est authentifié.
        val env = (e.a.encryptToken("texte") as Token.Message).envelope
        val before = e.b.toJson()
        attendreEchec { e.b.decrypt(Token.Distribution(env), t0, rng) }
        assertEquals(before, e.b.toJson())
        assertEquals("texte", texte(e.b.decrypt(Token.Message(env), t0, rng)))
        val msgs = (0 until 50).map { chain.encrypt("g$it") }
        val order = (0 until 50).toMutableList()
        for (i in order.size - 1 downTo 1) {
            val j = rng.below(i + 1)
            val x = order[i]
            order[i] = order[j]
            order[j] = x
        }
        for ((k, i) in order.withIndex()) {
            if (k % 7 == 3) continue // perdu
            val g = (Token.decode(msgs[i]) as Token.Group).message
            assertEquals("g$i", recv.decrypt(g, t0))
            attendreErreur(Erreur.Rejoue) { recv.decrypt(g, t0) }
        }
        // Un membre qui n'a que l'ancienne chaîne ne lit pas la nouvelle.
        val renewed = SenderKeyState.generate(gid, rng)
        val g = (renewed.encryptToken("après départ") as Token.Group).message
        attendreErreur(Erreur.ExpediteurInconnu) { recv.decrypt(g, t0) }
    }

    @Test
    fun groupeAlterationsEtSaut() {
        val rng = Deterministic("groupe-bits")
        val chain = SenderKeyState.generate(ByteArray(16) { 3 }, rng)
        val recv = ReceivedSenderKey.fromDistribution(chain.distribution())
        val t = chain.encryptToken("signé")
        val bytes = t.toBytes()
        val before = recv.toJson()
        for (i in bytes.indices) {
            val x = bytes.copyOf()
            x[i] = (x[i].toInt() xor 0x40).toByte()
            val g = runCatching { Token.fromBytes(x) }.getOrNull()
            if (g is Token.Group) attendreEchec("octet $i") { recv.decrypt(g.message, t0) }
        }
        assertEquals(before, recv.toJson())
        assertEquals("signé", recv.decrypt((t as Token.Group).message, t0))
        repeat(maxSkip + 1) { chain.encryptToken("x") }
        val far = (chain.encryptToken("trop loin") as Token.Group).message
        attendreErreur(Erreur.TropDeClesSautees) { recv.decrypt(far, t0) }
    }

    @Test
    fun texteTropLongRefuse() {
        val e = established("long", false)
        attendreErreur(Erreur.TropGrand) { e.a.encrypt("x".repeat(Session.MAX_PLAINTEXT + 1)) }
        val t = e.a.encrypt("x".repeat(Session.MAX_PLAINTEXT))
        Token.decode(t)
        // Le jeton reste du base64 standard strict.
        val inner = t.removePrefix(Token.HEAD).removeSuffix("]]")
        assertTrue(Octets.unb64(inner) != null)
    }

    @Test
    fun etatsJsonAllerRetour() {
        val e = established("json", true)
        val dev = Device.generate(Deterministic("appareil"), t0, true)
        memeForme(dev.toJson(), Device.fromJson(dev.toJson()).toJson(), "appareil")
        for (s in listOf(e.a, e.b)) assertEquals(s.toJson(), Session.fromJson(s.toJson()).toJson())
        attendreErreur(Erreur.Etat) { Session.fromJson("{}") }
        attendreErreur(Erreur.Etat) { Device.fromJson("{}") }
        attendreErreur(Erreur.Etat) { Session.fromJson("pas du json") }
        // Une incohérence (clé publique de cliquet qui ne va pas avec le secret) : refusée.
        val o = kotlinx.serialization.json.Json.parseToJsonElement(e.a.toJson()) as kotlinx.serialization.json.JsonObject
        val bad = kotlinx.serialization.json.JsonObject(o + ("dhs_public" to kotlinx.serialization.json.JsonPrimitive(Octets.b64(ByteArray(32) { 1 }))))
        attendreErreur(Erreur.Etat) { Session.fromJson(bad.toString()) }
        val v2 = kotlinx.serialization.json.JsonObject(o + ("v" to kotlinx.serialization.json.JsonPrimitive(2)))
        attendreErreur(Erreur.Etat) { Session.fromJson(v2.toString()) }
    }
}
