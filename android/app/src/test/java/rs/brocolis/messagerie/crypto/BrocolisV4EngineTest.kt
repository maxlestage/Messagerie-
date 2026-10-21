package rs.brocolis.messagerie.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.T0
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.keyFor
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.text
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Party
import rs.brocolis.messagerie.proto.Erreur
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.proto.Token
import rs.brocolis.messagerie.proto.Token4

/**
 * Le v4 dans le moteur de l'app (docs/SECURITE.md §9.6, §9.7), comme le site
 * (`site/src/v3.rs`) : une capacité v4 valide fait passer le contact au
 * triple cliquet, l'empreinte prend le contexte v4, un contact v4 ne
 * redescend jamais en v3, la PSK v4 suit une PSK v4 reçue.
 */
class BrocolisV4EngineTest {
    private val alice = Party()
    private val bob = Party()

    private fun caps(p: Party): ByteArray = Octets.unb64(p.tx(T0) { it.capsBase64!! })!!

    private fun withCaps(k: BrocolisV3Key, caps: ByteArray?) =
        BrocolisV3Key(k.id, k.raw, k.bundle, k.bundleAt, k.group, k.psk, caps)

    /** Oublie les messages ouverts gardés (pour voir le rejeu). */
    private fun Party.forgetOpened() {
        stored = stored!!.copy(opened = emptyList())
    }

    @Test
    fun laCapaciteFaitPasserAuTripleCliquet() {
        val key = ByteArray(32) { 11 }
        val ka = withCaps(keyFor("k", key, bob.bundle()), caps(bob))
        val kb = withCaps(keyFor("k", key, alice.bundle()), caps(alice))
        assertEquals(BrocolisProtection.TRIPLE, alice.tx(T0) { it.protection(ka, T0) })
        // Les deux voient la même empreinte, sous le contexte v4.
        val fp = alice.tx(T0) { it.fingerprint(ka) }!!
        assertEquals(fp, bob.tx(T0) { it.fingerprint(kb) })
        val ia = alice.tx(T0) { it.identity }
        val ib = bob.tx(T0) { it.identity }
        assertEquals(fp, BrocolisV3Format.pairingFingerprint4(key, ia, ib))
        assertNotEquals(fp, BrocolisV3Format.pairingFingerprint(key, ia, ib))
        assertTrue(alice.tx(T0) { it.openSession(ka, T0) })
        val m1 = alice.tx(T0) { it.seal("un", ka, T0) }!!
        val m2 = alice.tx(T0) { it.seal("deux", ka, T0) }!!
        assertTrue(m1.startsWith(Token4.HEAD))
        assertTrue(Token4.decode(m1) is Token4.Initial)
        assertEquals(1, BrocolisV3Format.findTokens("x $m1 y").size)
        assertEquals("deux", text(bob.tx(T0) { it.open(m2, listOf(kb), T0) }))
        assertEquals("un", text(bob.tx(T0) { it.open(m1, listOf(kb), T0) }))
        assertEquals(BrocolisProtection.TRIPLE, bob.tx(T0) { it.protection(kb, T0) })
        val r = bob.tx(T0) { it.seal("réponse", kb, T0) }!!
        assertTrue(r.startsWith(Token4.HEAD))
        assertEquals("réponse", text(alice.tx(T0) { it.open(r, listOf(ka), T0) }))
        // Déjà lu, sans le clair gardé.
        bob.forgetOpened()
        assertEquals(BrocolisV3Opened.Replay, bob.tx(T0) { it.open(m1, listOf(kb), T0) })
        // Un tiers : aucune de ses clés n'ouvre le préambule.
        val carole = Party()
        assertEquals(
            BrocolisV3Opened.Failed(Erreur.CleInconnue),
            carole.tx(T0) { it.open(m1, listOf(keyFor("k", key, null)), T0) },
        )
        // La suite, après relecture de l'état (Party relit tout à chaque transaction).
        val m3 = alice.tx(T0) { it.seal("relu", ka, T0) }!!
        assertEquals("relu", text(bob.tx(T0) { it.open(m3, listOf(kb), T0) }))
        assertEquals(1, alice.tx(T0) { it.sessionCount(ka) })
        // Un message v4 illisible ne déclenche pas de réparation (§9.6).
        val bytes = Octets.unb64(m3.removePrefix(Token4.HEAD).removeSuffix("]]"))!!
        bytes[20] = (bytes[20].toInt() xor 1).toByte()
        val inconnu = Token4.HEAD + Octets.b64(bytes) + "]]"
        val o = bob.tx(T0) { it.openMessage(inconnu, listOf(kb), kb, mine = false, now = T0) }
        assertEquals(BrocolisV3Opened.Failed(Erreur.SessionInconnue), o)
        assertEquals(1, bob.tx(T0) { it.sessionCount(kb) })
    }

    @Test
    fun uneCapaciteRetireeSeVoitEtNeFaitPasRedescendre() {
        val key = ByteArray(32) { 12 }
        // Le serveur retire la capacité d'Alice chez Bob seulement.
        val ka = withCaps(keyFor("k", key, bob.bundle()), caps(bob))
        val kb = keyFor("k", key, alice.bundle())
        assertNotEquals(alice.tx(T0) { it.fingerprint(ka) }, bob.tx(T0) { it.fingerprint(kb) })
        assertEquals(BrocolisProtection.POST_QUANTUM, bob.tx(T0) { it.protection(kb, T0) })
        // Une capacité d'une autre identité ne vaut rien.
        assertEquals(BrocolisProtection.POST_QUANTUM, bob.tx(T0) { it.protection(withCaps(kb, caps(bob)), T0) })
        // Alice écrit en v4 : Bob le lit, puis ne redescend plus en v3.
        val m = alice.tx(T0) { it.seal("v4", ka, T0) }!!
        assertEquals("v4", text(bob.tx(T0) { it.open(m, listOf(kb), T0) }))
        assertEquals(BrocolisProtection.TRIPLE, bob.tx(T0) { it.protection(kb, T0) })
        val r = bob.tx(T0) { it.seal("toujours v4", kb, T0) }!!
        assertTrue(r.startsWith(Token4.HEAD))
        assertEquals("toujours v4", text(alice.tx(T0) { it.open(r, listOf(ka), T0) }))
        // Paquet trop vieux, plus de session : la PSK, en v4.
        val later = T0 + BrocolisV3Format.BUNDLE_MAX_AGE + 1
        val bob2 = Party().also {
            it.deviceJson = bob.deviceJson
            it.stored = BrocolisV3Stored(v4Seen = bob.stored!!.v4Seen)
        }
        assertEquals(BrocolisProtection.TRIPLE_PSK, bob2.tx(later) { it.protection(kb, later) })
        val p = bob2.tx(later) { it.seal("par la clé", kb, later) }!!
        assertTrue(p.startsWith(Token4.HEAD))
        assertEquals("par la clé", text(alice.tx(later) { it.open(p, listOf(ka), later) }))
    }

    @Test
    fun laPskV4SuitUnePskV4Recue() {
        val key = ByteArray(32) { 13 }
        val ka = keyFor("ka", key, null)
        val kb = keyFor("kb", key, null)
        // Alice a reçu une PSK v4 sur la clé (un autre appareil à jour).
        alice.tx(T0) { it.bundleBase64 }
        alice.stored = (alice.stored ?: BrocolisV3Stored()).copy(pskSeen = listOf("ka"), psk4Seen = listOf("ka"))
        assertEquals(BrocolisProtection.TRIPLE_PSK, alice.tx(T0) { it.protection(ka, T0) })
        val m = alice.tx(T0) { it.seal("psk v4", ka, T0) }!!
        assertTrue(m.startsWith(Token4.HEAD))
        assertEquals("psk v4", text(bob.tx(T0) { it.open(m, listOf(kb), T0) }))
        assertEquals(BrocolisProtection.TRIPLE_PSK, bob.tx(T0) { it.protection(kb, T0) })
        val r = bob.tx(T0) { it.seal("suivi", kb, T0) }!!
        assertEquals("suivi", text(alice.tx(T0) { it.open(r, listOf(ka), T0) }))
        // Rejoué : déjà lu.
        bob.forgetOpened()
        assertEquals(BrocolisV3Opened.Replay, bob.tx(T0) { it.open(m, listOf(kb), T0) })
        // Sans ce signe, la PSK reste en v3.
        val carole = Party()
        val kc = keyFor("kc", key, null, psk = true)
        assertEquals(BrocolisProtection.PSK, carole.tx(T0) { it.protection(kc, T0) })
        assertTrue(carole.tx(T0) { it.seal("v3", kc, T0) }!!.startsWith(Token.HEAD))
    }

    @Test
    fun libellesV4() {
        assertTrue(BrocolisProtection.TRIPLE.isRatchet)
        assertTrue(BrocolisProtection.TRIPLE_PSK.isRatchet)
        val fr = BrocolisProtection.TRIPLE.label
        assertTrue(
            fr == "🔐 triple cliquet (post-quantique à chaque message)" ||
                fr == "🔐 triple ratchet (post-quantum on every message)" ||
                fr == "🔐 triple trinquete (poscuántico en cada mensaje)",
        )
    }
}
