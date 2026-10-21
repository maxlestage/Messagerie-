package rs.brocolis.messagerie.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.proto.Token
import rs.brocolis.messagerie.store.BrocolisV3Store
import rs.brocolis.messagerie.store.NamedKey
import rs.brocolis.messagerie.store.PlainFileVault
import java.io.File

/**
 * L'alerte de changement d'identité (docs/SECURITE.md §9.8) et les groupes
 * à cliquet vus par la façade (§9.9) : ré-appairage, échec fermé de tout
 * envoi (v3/v4 et v1/v2), lecture intacte, confirmation ; chaînes des autres
 * cachées, auteur, repli en v2.
 */
class BrocolisIdentityTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun api(name: String): BrocolisV3Api {
        val dir = File(tmp.root, name)
        return BrocolisV3Api.of(BrocolisV3Store(dir, PlainFileVault(File(dir, "coffre"))))
    }

    private val alice by lazy { api("alice") }
    private val bob by lazy { api("bob") }
    private val k = BrocolisCrypto.generateKeyBase64()

    private fun contact(id: String, bundle: String?, key: String = k, psk: Boolean? = null) =
        NamedKey(id, id, key, v3Bundle = bundle, v3SinceSeconds = if (bundle == null) null else BrocolisV3Api.now(), duo = true, psk = psk)

    @Test
    fun reappairage_memeIdentite_rienNeChange() {
        val bb = bob.myBundle()!!
        val (k1, changed) = BrocolisIdentity.repaired(contact("bob", bb), BrocolisCrypto.generateKeyBase64(), bb, true, null, 10)
        assertFalse(changed)
        assertNull(k1.identityChanged)
        assertNull(k1.previousIdentity)
        assertEquals(10L, k1.v3SinceSeconds)
        // Un contact sans paquet d'avant (ancien client) : rien à comparer.
        assertFalse(BrocolisIdentity.repaired(contact("bob", null), k, bb, true, null, 10).second)
    }

    @Test
    fun reappairage_autreIdentite_alerte_puisConfirmation() {
        val bb = bob.myBundle()!!
        val mallory = api("mallory").myBundle()!!
        val autre = api("autre").myBundle()!!
        val nouvelle = BrocolisCrypto.generateKeyBase64()
        val avant = contact("bob", bb, psk = true)
        val (k1, changed) = BrocolisIdentity.repaired(avant, nouvelle, mallory, true, "caps", 20)
        assertTrue(changed)
        assertEquals(true, k1.identityChanged)
        assertEquals(Octets.b64(BrocolisIdentity.identityOf(bb)!!), k1.previousIdentity)
        assertEquals(nouvelle, k1.base64)
        assertEquals(mallory, k1.v3Bundle)
        assertEquals("caps", k1.v3Caps)
        assertNull(k1.psk)
        assertEquals(avant.id, k1.id)
        assertTrue(BrocolisIdentity.blocked(k1))
        // Une alerte encore en attente garde l'identité d'avant la première.
        val (k2, still) = BrocolisIdentity.repaired(k1, nouvelle, autre, true, null, 30)
        assertTrue(still)
        assertEquals(k1.previousIdentity, k2.previousIdentity)
        // Même revenu à la même identité, l'alerte attend la confirmation.
        assertTrue(BrocolisIdentity.repaired(k2, nouvelle, autre, true, null, 40).second)
        // « J'ai comparé l'empreinte » : l'alerte tombe.
        val ok = BrocolisIdentity.confirmed(k2)
        assertFalse(BrocolisIdentity.blocked(ok))
        assertNull(ok.previousIdentity)
        assertFalse(BrocolisIdentity.repaired(ok, nouvelle, autre, true, null, 50).second)
    }

    @Test
    fun identiteChangee_echecFerme_lectureIntacte() {
        val ba = alice.myBundle()!!
        val bb = bob.myBundle()!!
        val versBob = contact("bob", bb)
        val versAlice = contact("alice", ba)
        // Bob écrit à Alice avant l'alerte, et après : Alice lit toujours.
        val avant = bob.seal("avant", versAlice)!!
        val bloque = versBob.copy(identityChanged = true, previousIdentity = "x")
        assertTrue(alice.blocked(listOf(bloque)))
        assertTrue(alice.blocked(listOf(contact("autre", null), bloque)))
        assertEquals(BrocolisProtection.IDENTITY_CHANGED, alice.protection(bloque))
        assertEquals(BrocolisIdentity.warning, BrocolisProtection.IDENTITY_CHANGED.label)
        assertFalse(BrocolisProtection.IDENTITY_CHANGED.isRatchet)
        // Rien ne part : ni v3/v4, ni v1/v2.
        assertNull(alice.seal("x", bloque))
        assertNull(alice.sealMessage("x", bloque))
        assertNull(alice.codec(listOf(bloque), listOf(bloque)).seal("x"))
        assertNull(alice.codec(listOf(bloque, contact("autre", null)), listOf(bloque)).seal("x"))
        assertNull(alice.sealGroup(alice.newGroupId(), listOf(bloque), "x"))
        assertFalse(alice.groupRatchet(listOf(bloque)))
        // La lecture reste possible.
        assertEquals("avant", alice.openTokens(avant, listOf(bloque)).text)
        val apres = bob.seal("après", versAlice)!!
        assertEquals("après", alice.openTokens(apres, listOf(bloque)).text)
        // Confirmé : l'envoi reprend.
        val ok = BrocolisIdentity.confirmed(bloque)
        val t = alice.seal("reprise", ok)
        assertNotNull(t)
        assertEquals("reprise", bob.openTokens(t!!, listOf(versAlice)).text)
    }

    @Test
    fun groupe_facade_chainesCachees_auteur_repli() {
        val carol = api("carol")
        val (ba, bb, bc) = Triple(alice.myBundle()!!, bob.myBundle()!!, carol.myBundle()!!)
        val (kab, kac, kbc) = Triple(BrocolisCrypto.generateKeyBase64(), BrocolisCrypto.generateKeyBase64(), BrocolisCrypto.generateKeyBase64())
        val aB = contact("ab-bob", bb, kab)
        val aC = contact("ac-carol", bc, kac)
        val bA = contact("ab-alice", ba, kab)
        val bC = contact("bc-carol", bc, kbc)
        val cA = contact("ac-alice", ba, kac)
        val cB = contact("bc-bob", bb, kbc)
        val gid = alice.newGroupId()
        assertTrue(alice.groupRatchet(listOf(aB, aC)))
        val m = alice.sealGroup(gid, listOf(aB, aC), "bonjour à tous")!!
        assertTrue(BrocolisV3Format.findTokens(m).size >= 3)
        // Chacun lit le message ; les chaînes remises aux autres ne s'affichent pas.
        assertEquals("bonjour à tous", bob.openTokens(m, listOf(bA, bC)).text)
        assertEquals("bonjour à tous", carol.openTokens(m, listOf(cA, cB)).text)
        // Relu (clairs gardés) : pareil.
        assertEquals("bonjour à tous", bob.openTokens(m, listOf(bA, bC)).text)
        // L'auteur : Alice, celle qui a remis la chaîne.
        assertEquals(listOf("ab-alice"), bob.authors(m, listOf(bA, bC)).map { it.id })
        assertEquals(listOf("ac-alice"), carol.authors(m, listOf(cA, cB)).map { it.id })
        // Mon envoi relu chez moi : sans auteur.
        assertEquals(emptyList<NamedKey>(), alice.authors(m, listOf(aB, aC)))
        // Un message de groupe d'une chaîne inconnue reste affiché chiffré.
        val seulBob = alice.sealGroup(gid, listOf(aB), "sans Carol")!!
        val reste = carol.openTokens(seulBob, listOf(cA, cB)).text
        assertTrue(reste.contains(Token.HEAD))
        assertEquals("sans Carol", bob.openTokens(seulBob, listOf(bA, bC)).text)
        // Un membre sans session possible (ni paquet ni PSK) : v2 pour les clés des membres.
        val sansV3 = contact("vieux", null)
        assertFalse(alice.groupRatchet(listOf(aB, sansV3)))
        val v2 = alice.sealGroup(gid, listOf(aB, sansV3), "en v2")!!
        assertTrue(v2.startsWith(BrocolisCrypto.TOKEN_PREFIX_V2))
        assertEquals("en v2", bob.openTokens(v2, listOf(bA)).text)
    }
}
