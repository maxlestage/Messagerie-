package rs.brocolis.messagerie.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.T0
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.keyFor
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Party
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.proto.Token
import rs.brocolis.messagerie.proto.Token4

/**
 * Les groupes à cliquet dans le moteur (docs/SECURITE.md §9.9), comme
 * brocolis (`a_ratchet_group_hands_out_chains_and_renews_when_someone_leaves`) :
 * chaînes remises par les sessions à deux, chaînes des autres cachées,
 * auteur, chaîne neuve quand un membre sort, état relu, repli.
 */
class BrocolisGroupEngineTest {
    private val a = Party()
    private val b = Party()
    private val c = Party()
    private val gid = ByteArray(16) { 7 }

    private fun tokens(out: String): List<String> =
        BrocolisV3Format.findTokens(out).map { out.substring(it.first, it.last + 1) }

    /** Ouvre chaque jeton d'un envoi de groupe : le texte du message de groupe, et combien de chaînes étaient pour moi. */
    private fun readGroup(p: Party, out: String, keys: List<BrocolisV3Key>): Pair<String?, Int> = p.tx(T0) { e ->
        var text: String? = null
        var chains = 0
        for (t in tokens(out)) {
            when (val o = e.open(t, keys, T0)) {
                BrocolisV3Opened.Hidden -> chains++
                is BrocolisV3Opened.Text -> if (BrocolisV3Format.isGroupToken(t)) text = o.text
                else -> Unit
            }
        }
        text to chains
    }

    @Test
    fun unGroupeACliquetRemetSesChainesEtLesRenouvelleQuandQuelquUnSort() {
        val (ba, bb, bc) = Triple(a.bundle(), b.bundle(), c.bundle())
        val (kab, kac, kbc) = Triple(ByteArray(32) { 21 }, ByteArray(32) { 22 }, ByteArray(32) { 23 })
        // Chacun a une session à deux possible avec chaque autre membre.
        val aB = keyFor("ab", kab, bb)
        val aC = keyFor("ac", kac, bc)
        val bA = keyFor("ab", kab, ba)
        val bC = keyFor("bc", kbc, bc)
        val cA = keyFor("ac", kac, ba)
        val cB = keyFor("bc", kbc, bb)
        assertTrue(a.tx(T0) { it.groupRatchet(listOf(aB, aC), T0) })
        val m1 = a.tx(T0) { it.sealGroup(gid, listOf(aB, aC), "salut le groupe", T0) }!!
        // Pour chacun : un premier message vide (la session v3 n'est pas
        // encore confirmée), sa chaîne (0x03) ; puis le message de groupe (0x04).
        val t1 = tokens(m1)
        assertEquals(5, t1.size)
        assertEquals(listOf(Token.TYPE_INITIAL, Token.TYPE_DISTRIBUTION, Token.TYPE_INITIAL, Token.TYPE_DISTRIBUTION, Token.TYPE_GROUP),
            t1.map { Token.decode(it).type })
        assertEquals("salut le groupe" to 1, readGroup(b, m1, listOf(bA, bC)))
        assertEquals("salut le groupe" to 1, readGroup(c, m1, listOf(cA, cB)))
        // L'expéditeur est celui qui a remis la chaîne.
        assertEquals(0, b.tx(T0) { it.sender(t1.last(), listOf(bA, bC)) })
        assertEquals(0, c.tx(T0) { it.sender(t1.last(), listOf(cA, cB)) })
        // Mes envois sont à moi.
        assertTrue(a.tx(T0) { it.isMine(t1.last()) })
        // Ensuite, le message seul.
        val m2 = a.tx(T0) { it.sealGroup(gid, listOf(aB, aC), "deuxième", T0) }!!
        assertEquals(1, tokens(m2).size)
        assertEquals("deuxième", readGroup(c, m2, listOf(cA, cB)).first)
        // B répond au groupe avec sa propre chaîne ; son auteur est B.
        val r = b.tx(T0) { it.sealGroup(gid, listOf(bA, bC), "bien reçu", T0) }!!
        assertEquals("bien reçu", readGroup(a, r, listOf(aB, aC)).first)
        assertEquals("bien reçu", readGroup(c, r, listOf(cA, cB)).first)
        assertEquals(1, c.tx(T0) { it.sender(tokens(r).last(), listOf(cA, cB)) })
        // Rejoué : déjà lu.
        c.stored = c.stored!!.copy(opened = emptyList())
        assertEquals(BrocolisV3Opened.Replay, c.tx(T0) { it.open(m2, listOf(cA, cB), T0) })
        // C quitte le groupe : A tire une chaîne neuve, C ne lit plus rien.
        val m3 = a.tx(T0) { it.sealGroup(gid, listOf(aB), "sans C", T0) }!!
        assertEquals("B a répondu : session confirmée", 2, tokens(m3).size)
        assertEquals("sans C", readGroup(b, m3, listOf(bA, bC)).first)
        assertEquals(null to 0, readGroup(c, m3, listOf(cA, cB)))
        // L'état se relit (Party relit tout à chaque transaction) : la suite se lit.
        val m4 = a.tx(T0) { it.sealGroup(gid, listOf(aB), "relu", T0) }!!
        assertEquals(1, tokens(m4).size)
        assertEquals("relu", readGroup(b, m4, listOf(bA, bC)).first)
        // Un membre sans session possible : pas de groupe à cliquet.
        val d = keyFor("ad", ByteArray(32) { 24 }, null)
        assertEquals(false, a.tx(T0) { it.groupRatchet(listOf(aB, d), T0) })
        assertNull(a.tx(T0) { it.sealGroup(gid, listOf(aB, d), "x", T0) })
        // Un identifiant de groupe malformé : refusé.
        assertNull(a.tx(T0) { it.sealGroup(ByteArray(8), listOf(aB), "x", T0) })
    }

    @Test
    fun enV4LaChaineVoyageDansLeChiffre() {
        val caps = { p: Party -> Octets.unb64(p.tx(T0) { it.capsBase64!! })!! }
        val k = ByteArray(32) { 31 }
        val aB = BrocolisV3Key("ab", k, b.bundle(), T0, false, false, caps(b))
        val bA = BrocolisV3Key("ab", k, a.bundle(), T0, false, false, caps(a))
        val m = a.tx(T0) { it.sealGroup(gid, listOf(aB), "v4", T0) }!!
        val t = tokens(m)
        // Pas de premier message vide en v4 : la distribution (genre 0x01) suffit.
        assertEquals(2, t.size)
        assertTrue(t[0].startsWith(Token4.HEAD))
        assertTrue(BrocolisV3Format.isGroupToken(t[1]))
        assertEquals("v4" to 1, readGroup(b, m, listOf(bA)))
        assertEquals(0, b.tx(T0) { it.sender(t[1], listOf(bA)) })
    }

    @Test
    fun uneChaineDePskSuffit() {
        // Membres sans paquet, marqués PSK : la chaîne part par la clé partagée.
        val k = ByteArray(32) { 41 }
        val aB = keyFor("kab", k, null, psk = true)
        val bA = keyFor("kba", k, null, psk = true)
        val m = a.tx(T0) { it.sealGroup(gid, listOf(aB), "psk", T0) }!!
        assertEquals("psk" to 1, readGroup(b, m, listOf(bA)))
        assertEquals(0, b.tx(T0) { it.sender(tokens(m).last(), listOf(bA)) })
    }
}
