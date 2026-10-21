package rs.brocolis.messagerie.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import rs.brocolis.messagerie.net.PairingPeer
import rs.brocolis.messagerie.net.WrapInbox
import rs.brocolis.messagerie.proto.CleProtegee
import rs.brocolis.messagerie.proto.Token
import rs.brocolis.messagerie.proto.Token4
import rs.brocolis.messagerie.store.BrocolisV3Store
import rs.brocolis.messagerie.store.NamedKey
import rs.brocolis.messagerie.store.PlainFileVault
import java.io.File

/**
 * La façade v3 de l'app avec des clés nommées : le codec (Partager,
 * Conversation), la messagerie, l'appairage (règles « à deux », empreinte),
 * la clé protégée (export v2, import v1 et v2).
 */
class BrocolisV3FacadeTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun api(name: String): BrocolisV3Api {
        val dir = File(tmp.root, name)
        return BrocolisV3Api.of(BrocolisV3Store(dir, PlainFileVault(File(dir, "coffre"))))
    }

    private val alice by lazy { api("alice") }
    private val bob by lazy { api("bob") }
    private val k = BrocolisCrypto.generateKeyBase64()

    private fun contact(id: String, bundle: String?, duo: Boolean? = true, psk: Boolean? = null) =
        NamedKey(id, id, k, v3Bundle = bundle, v3SinceSeconds = if (bundle == null) null else BrocolisV3Api.now(), duo = duo, psk = psk)

    @Test
    fun codec_v3PourUneCle_v2PourPlusieurs_lectureDeTout() {
        val versBob = contact("bob", bob.myBundle())
        val versAlice = contact("alice", alice.myBundle())
        val autre = NamedKey("autre", "autre", BrocolisCrypto.generateKeyBase64())

        val seul = alice.codec(listOf(versBob), listOf(versBob)).seal("pour Bob")!!
        assertTrue(seul.startsWith(Token.HEAD))
        assertEquals(BrocolisProtection.POST_QUANTUM, alice.protectionUsed(seul, listOf(versBob)))
        val deux = alice.codec(listOf(versBob, autre), listOf(versBob, autre)).seal("pour deux")!!
        assertTrue(deux.startsWith(BrocolisCrypto.TOKEN_PREFIX_V2))
        assertEquals(BrocolisProtection.LEGACY, alice.protectionUsed(deux, listOf(versBob, autre)))

        val colle = "Bob : $seul\nGroupe : $deux\nv1 : ${BrocolisCrypto.encryptToken("ancien".toByteArray(), BrocolisCrypto.keyBytes(k))}"
        val (clair, n) = bob.openTokens(colle, listOf(versAlice))
        assertEquals(3, n)
        assertEquals("Bob : pour Bob\nGroupe : pour deux\nv1 : ancien", clair)
        // Relu (messages ouverts, puis mémoire du processus) : même clair.
        assertEquals(clair, bob.openTokens(colle, listOf(versAlice)).text)

        // L'écran Conversation : ligne par ligne, v3 compris.
        val rendu = BrocolisConversation.render(colle + "\nen clair", bob.codec(emptyList(), listOf(versAlice)))
        assertEquals(3, rendu.decryptedCount)
        assertEquals(BrocolisConversation.Status.CLEAR, rendu.lines.last().status)

        // Chiffrement sélectif ((…)) avec le codec.
        val marque = BrocolisCrypto.encryptMarked("a ((b)) c ((d))", alice.codec(listOf(versBob), listOf(versBob)).seal)
        assertEquals(2, marque.count)
        assertEquals(2, BrocolisV3Format.findTokens(marque.text).size)
        assertEquals("a b c d", bob.openTokens(marque.text, listOf(versAlice)).text)
    }

    @Test
    fun ancienFormat_sansContactNiPsk() {
        val brute = NamedKey("x", "x", k)
        assertNull(alice.seal("v1", brute))
        assertTrue(alice.codec(listOf(brute), listOf(brute)).seal("v1")!!.startsWith(BrocolisCrypto.TOKEN_PREFIX))
        assertEquals(BrocolisProtection.LEGACY, alice.protection(brute))
        // v3 indisponible : tout en ancien format.
        val off = BrocolisV3Api.of(null)
        assertEquals(mapOf("x" to BrocolisProtection.LEGACY), off.protections(listOf(brute)))
        assertTrue(off.codec(listOf(brute), listOf(brute)).seal("v1")!!.startsWith(BrocolisCrypto.TOKEN_PREFIX))
    }

    @Test
    fun messagerie_v3_etMedias() {
        val versBob = contact("bob", bob.myBundle())
        val versAlice = contact("alice", alice.myBundle())
        val m1 = alice.sealMessage("bonjour", versBob)!!
        val photo = "BRCM1:img:" + BrocolisCrypto.b64encode(ByteArray(30_000) { it.toByte() })
        val m2 = alice.sealMessage(photo, versBob)!!
        val v1 = BrocolisCrypto.encryptToken("ancien client".toByteArray(), BrocolisCrypto.keyBytes(k))
        val incoming = listOf(m1, m2, v1, m1).map { BrocolisV3Api.Incoming(it, mine = false) }
        val r = bob.openMessages(incoming, versAlice, listOf(versAlice))
        assertEquals(BrocolisV3Opened.Text("bonjour"), r[0])
        assertEquals(BrocolisV3Opened.Text(photo), r[1])
        assertNull(r[2]) // v1 : l'appelant le lit
        assertEquals(BrocolisV3Opened.Text("bonjour"), r[3]) // republié : le clair gardé
        // Mes envois relus chez moi (jamais déchiffrés).
        val mine = alice.openMessages(listOf(m1, m2).map { BrocolisV3Api.Incoming(it, mine = true) }, versBob, listOf(versBob))
        assertEquals(listOf(BrocolisV3Opened.Text("bonjour"), BrocolisV3Opened.Text(photo)), mine)
        // Un autre appareil d'Alice (sans ses messages ouverts) : « envoyé depuis cet appareil ».
        val ailleurs = api("alice-2").openMessages(listOf(BrocolisV3Api.Incoming(m1, true)), versBob, listOf(versBob))
        assertEquals(listOf(BrocolisV3Opened.Replay), ailleurs)
    }

    @Test
    fun appairage_empreinte_etRegles() {
        val ba = alice.myBundle()!!
        val bb = bob.myBundle()!!
        val peerB = PairingPeer("b", "pubB", bb)
        val peerA = PairingPeer("a", "pubA", ba)
        // Mode compatible : toujours à deux, paquet pris seulement si j'ai publié le mien.
        assertEquals(BrocolisV3Contact(bb, true), BrocolisV3Contact.compatible(peerB, ba))
        assertEquals(BrocolisV3Contact(null, true), BrocolisV3Contact.compatible(peerB, null))
        assertEquals(BrocolisV3Contact(null, true), BrocolisV3Contact.compatible(PairingPeer("b", "pubB"), ba))
        // L'invitant : à deux tant qu'une seule personne a reçu la clé.
        assertEquals(BrocolisV3Contact(bb, true), BrocolisV3Contact.inviting(listOf(peerB), ba))
        assertFalse(BrocolisV3Contact.inviting(listOf(peerB, PairingPeer("c", "pubC")), ba).duo)
        // Celui qui rejoint : l'invitant est wrap.from / wrap.fromPub ; à deux
        // si le salon (lui exclu) compte exactement un participant.
        val wrap = WrapInbox("a", "pubA", "blob")
        assertEquals(BrocolisV3Contact(ba, true), BrocolisV3Contact.joining(listOf(peerA), wrap, bb))
        assertFalse(BrocolisV3Contact.joining(listOf(peerA, PairingPeer("c", "pubC")), wrap, bb).duo)
        assertNull(BrocolisV3Contact.joining(listOf(PairingPeer("a", "autrePub", ba)), wrap, bb).bundle)

        // L'empreinte v3 : la même des deux côtés, différente de l'ancienne.
        val fa = BrocolisV3Contact(bb, true).fingerprint(k, "LEGACY", alice)
        val fb = BrocolisV3Contact(ba, true).fingerprint(k, "LEGACY", bob)
        assertEquals(fa, fb)
        assertTrue(Regex("[0-9A-F]{4}(-[0-9A-F]{4}){3}").matches(fa))
        // Un paquet substitué (Mallory) : les deux empreintes diffèrent.
        val mallory = api("mallory").myBundle()!!
        assertNotEquals(fb, BrocolisV3Contact(mallory, true).fingerprint(k, "LEGACY", alice))
        // Groupe, ou sans paquet : l'empreinte d'avant.
        assertEquals("LEGACY", BrocolisV3Contact(bb, false).fingerprint(k, "LEGACY", alice))
        assertEquals("LEGACY", BrocolisV3Contact(null, true).fingerprint(k, "LEGACY", alice))

        // L'invitant ouvre la session aussitôt ; le premier message la porte.
        val versBob = contact("bob", bb)
        alice.openSession(versBob)
        assertEquals(BrocolisProtection.POST_QUANTUM, alice.protection(versBob))
        val t = alice.seal("premier", versBob)!!
        assertEquals(Token.TYPE_INITIAL, Token.decode(t).type)
        assertEquals("premier", bob.openTokens(t, listOf(contact("alice", ba))).text)
        // Un contact passé en groupe : plus de v3.
        assertNull(alice.seal("groupe", versBob.copy(duo = false)))
    }

    @Test
    fun appairageV4_capacite_empreinte_tripleCliquet() {
        val (ba, ca) = alice.myBundleAndCaps()
        val (bb, cb) = bob.myBundleAndCaps()
        assertNotNull(ca)
        assertNotNull(cb)
        // La capacité voyage avec le paquet, et n'est prise qu'avec lui.
        val peerB = PairingPeer("b", "pubB", bb, cb)
        val peerA = PairingPeer("a", "pubA", ba, ca)
        assertEquals(BrocolisV3Contact(bb, true, cb), BrocolisV3Contact.compatible(peerB, ba))
        assertEquals(BrocolisV3Contact(null, true), BrocolisV3Contact.compatible(peerB, null))
        assertEquals(BrocolisV3Contact(bb, true, cb), BrocolisV3Contact.inviting(listOf(peerB), ba))
        assertEquals(BrocolisV3Contact(ba, true, ca), BrocolisV3Contact.joining(listOf(peerA), WrapInbox("a", "pubA", "blob"), bb))
        // L'empreinte v4 : la même des deux côtés, différente de la v3 (§9.7).
        val fa = BrocolisV3Contact(bb, true, cb).fingerprint(k, "LEGACY", alice)
        val fb = BrocolisV3Contact(ba, true, ca).fingerprint(k, "LEGACY", bob)
        assertEquals(fa, fb)
        assertNotEquals(fa, BrocolisV3Contact(bb, true).fingerprint(k, "LEGACY", alice))
        // Une capacité retirée d'un seul côté : deux empreintes différentes.
        assertNotEquals(fa, BrocolisV3Contact(ba, true).fingerprint(k, "LEGACY", bob))
        // Une capacité d'une autre identité : l'empreinte v3.
        assertEquals(
            BrocolisV3Contact(bb, true).fingerprint(k, "LEGACY", alice),
            BrocolisV3Contact(bb, true, ca).fingerprint(k, "LEGACY", alice),
        )

        val versBob = contact("bob", bb).copy(v3Caps = cb)
        val versAlice = contact("alice", ba).copy(v3Caps = ca)
        alice.openSession(versBob)
        assertEquals(BrocolisProtection.TRIPLE, alice.protection(versBob))
        val t = alice.seal("premier v4", versBob)!!
        assertTrue(t.startsWith(Token4.HEAD))
        assertEquals(BrocolisProtection.TRIPLE, alice.protectionUsed(t, listOf(versBob)))
        assertEquals("premier v4", bob.openTokens("reçu : $t", listOf(versAlice)).text.removePrefix("reçu : "))
        val r = bob.sealMessage("réponse", versAlice)!!
        assertTrue(r.startsWith(Token4.HEAD))
        assertEquals(
            listOf<BrocolisV3Opened?>(BrocolisV3Opened.Text("réponse")),
            alice.openMessages(listOf(BrocolisV3Api.Incoming(r, false)), versBob, listOf(versBob)),
        )
    }

    @Test
    fun psk_marquee_etOubliee() {
        val marquee = contact("k", null, duo = null, psk = true)
        val chezBob = contact("k", null, duo = null)
        val t = alice.seal("psk", marquee)!!
        assertEquals("psk", bob.openTokens(t, listOf(chezBob)).text)
        assertEquals(BrocolisProtection.PSK, bob.protection(chezBob))
        bob.forget("k")
        assertEquals(BrocolisProtection.LEGACY, bob.protection(chezBob))
    }

    @Test
    fun cleProtegee_exportV2_importV1EtV2() {
        val raw = ByteArray(32) { (it * 3).toByte() }
        val v2 = BrocolisKeyProtection.seal(raw, "une phrase assez longue")
        assertTrue(v2.startsWith(BrocolisKeyProtection.TOKEN_PREFIX_V2))
        assertEquals(65_536L, CleProtegee.v2Params(v2).mKib)
        // Collé avec un retour à la ligne : relu.
        assertArrayEquals(raw, BrocolisKeyProtection.open("clé :\n" + v2.substring(0, 40) + "\n" + v2.substring(40), "une phrase assez longue"))
        assertNull(BrocolisKeyProtection.openOrNull(v2, "une autre phrase"))
        // Une v1 (le vecteur commun) se lit toujours.
        val v1 = "[[BROCOLIS-CLE:v1:ERERERERERERERERERERESIiIiIiIiIiIiIiIsq57j18BXkqq/4VdIw82nQqzrax9Cfn2mfUJjWH8l327NAf2rWaSYCJh3BfGH4eWA==]]"
        assertArrayEquals(ByteArray(32) { it.toByte() }, BrocolisKeyProtection.open(v1, "brocoli vert 2026"))
        assertTrue(BrocolisKeyProtection.containsToken(v2) && BrocolisKeyProtection.containsToken(v1))
        // Une v2 qui demanderait 1 Gio : refusée avant tout calcul.
        val lourde = ByteArray(83).also {
            it[0] = 0x02; it[1] = 0x00; it[2] = 0x10; it[3] = 0x00; it[4] = 0x00; it[5] = 3; it[6] = 1
        }
        val jeton = BrocolisKeyProtection.TOKEN_PREFIX_V2 + java.util.Base64.getEncoder().encodeToString(lourde) + "]]"
        assertEquals(1_048_576L, CleProtegee.v2Params(jeton).mKib)
        val msg = try { BrocolisKeyProtection.open(jeton, "une phrase assez longue"); null } catch (e: BrocolisKeyProtection.ProtectionException) { e.message }
        assertNotNull(msg)
        assertTrue(msg!!.contains("coûteuse"))
    }
}
