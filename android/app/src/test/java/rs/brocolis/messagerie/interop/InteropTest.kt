package rs.brocolis.messagerie.interop

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.crypto.BrocolisKeyAgreement
import rs.brocolis.messagerie.crypto.BrocolisProtection
import rs.brocolis.messagerie.crypto.BrocolisV3Api
import rs.brocolis.messagerie.crypto.BrocolisV3Contact
import rs.brocolis.messagerie.crypto.BrocolisV3Opened
import rs.brocolis.messagerie.net.BrocolisMessagingClient
import rs.brocolis.messagerie.net.PairingClient
import rs.brocolis.messagerie.net.PairingFlow
import rs.brocolis.messagerie.net.WrapItem
import rs.brocolis.messagerie.store.BrocolisV3Store
import rs.brocolis.messagerie.store.NamedKey
import rs.brocolis.messagerie.store.PlainFileVault
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Essais d'interopérabilité de l'app Android (sa logique, sur la JVM) contre le
 * VRAI serveur (`server-rust`) et contre la logique de l'iPhone
 * (`broc-v3-client`, Shared/ de l'app compilé sous Linux) — docs/SECURITE.md
 * §8.11 :
 *
 *     BROCOLIS_INTEROP_SERVER=http://127.0.0.1:8799 \
 *     BROCOLIS_SWIFT_CLIENT=…/broc-v3-client gradle :app:testDebugUnitTest --tests '*InteropTest*'
 *
 * Sans ces variables, les essais sont sautés. Le coffre des appareils
 * Kotlin est ici en clair (`PlainFileVault`, fichiers temporaires) : tout le
 * reste est le code de l'app (appairage, façade v3, magasin, clients HTTP).
 */
class InteropTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val server: String? = System.getenv("BROCOLIS_INTEROP_SERVER")
    private val swift: String? = System.getenv("BROCOLIS_SWIFT_CLIENT")

    private fun say(s: String) = println("[interop] $s")

    /** Un appareil Android : son magasin v3, sa paire X25519, ses clients. */
    inner class Android(val name: String, val legacy: Boolean = false) {
        val v3: BrocolisV3Api = if (legacy) BrocolisV3Api.of(null) else File(tmp.root, name).let {
            BrocolisV3Api.of(BrocolisV3Store(it, PlainFileVault(File(it, "coffre"))))
        }
        val priv = X25519PrivateKeyParameters(SecureRandom())
        val pub = BrocolisKeyAgreement.publicKeyBase64(priv)
        val peerId = UUID.randomUUID().toString()
        val pairing = PairingClient(server!!)
        val messaging = BrocolisMessagingClient(server!!, "android-$name-" + peerId.take(8))
        lateinit var named: NamedKey
        lateinit var fingerprint: String
        val myBundle: String? by lazy { v3.myBundle() }
        private val seen = HashSet<String>()

        /** Range la clé et son contact v3, comme `PairingScreen`. */
        fun install(key: String, contact: BrocolisV3Contact, legacyFingerprint: String) {
            fingerprint = contact.fingerprint(key, legacyFingerprint, v3)
            named = NamedKey(
                "k-$name", "pair", key,
                v3Bundle = if (contact.duo) contact.bundle else null,
                v3SinceSeconds = if (contact.duo && contact.bundle != null) BrocolisV3Api.now() else null,
                duo = contact.duo,
            )
        }

        val conv get() = BrocolisMessagingClient.conversationId(named.base64)!!

        /** Envoie comme `ChatController.sendClear` : v3 si possible, sinon v1. */
        suspend fun send(clear: String): String {
            val v3token = withContext(Dispatchers.IO) { v3.sealMessage(clear, named) }
            return if (v3token != null) {
                messaging.send(v3token, conv); "v3"
            } else {
                messaging.send(clear, conv, BrocolisCrypto.keyBytes(named.base64)); "v1"
            }
        }

        /** Les messages reçus depuis la dernière fois, lus comme `ChatController.render`. */
        suspend fun receive(): List<Pair<String, String?>> {
            val page = messaging.fetch(conv, 0)
            val fresh = page.messages.filter { seen.add(it.id) }.filter { !it.senderId.startsWith("android-$name-") }
            if (fresh.isEmpty()) return emptyList()
            val opened = withContext(Dispatchers.IO) {
                v3.openMessages(fresh.map { BrocolisV3Api.Incoming(it.ciphertext, false) }, named, listOf(named))
            }
            return fresh.zip(opened).map { (m, o) ->
                val kind = if (m.ciphertext.contains("[[BROCOLIS:v3:")) "v3" else "v1"
                kind to when (o) {
                    is BrocolisV3Opened.Text -> o.text
                    BrocolisV3Opened.Replay -> BrocolisV3Api.alreadyRead
                    is BrocolisV3Opened.Failed -> null
                    null -> BrocolisCrypto.decryptTokens(m.ciphertext, listOf(BrocolisCrypto.keyBytes(named.base64)))
                        .takeIf { it.count > 0 }?.text
                }
            }
        }

        suspend fun expect(n: Int = 1, timeoutMs: Long = 30_000): List<Pair<String, String?>> {
            val out = ArrayList<Pair<String, String?>>()
            val end = System.currentTimeMillis() + timeoutMs
            while (out.size < n && System.currentTimeMillis() < end) {
                out += receive()
                if (out.size < n) delay(300)
            }
            assertTrue("$name : ${out.size}/$n messages", out.size >= n)
            out.forEach { say("$name REÇU ${it.first} ${it.second?.take(50)} [${it.second?.length}]") }
            return out
        }
    }

    /** Le client iPhone (`broc-v3-client`) : ses lignes de sortie, son entrée. */
    inner class Iphone(vararg args: String) {
        private val process = ProcessBuilder(swift!!, *args).redirectErrorStream(true).start()
        private val lines = LinkedBlockingQueue<String>()
        private val writer = process.outputStream.bufferedWriter()

        init {
            Thread {
                process.inputStream.bufferedReader().forEachLine { say("iPhone> $it"); lines.add(it) }
            }.apply { isDaemon = true }.start()
        }

        fun expect(prefix: String, timeoutMs: Long = 60_000): String {
            val end = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < end) {
                val l = lines.poll(200, TimeUnit.MILLISECONDS) ?: continue
                if (l.startsWith(prefix)) return l
                if (l.startsWith("ÉCHEC")) error("iPhone : $l")
            }
            error("iPhone : « $prefix » attendu")
        }

        fun command(c: String) {
            writer.write(c + "\n"); writer.flush()
        }

        fun stop() {
            runCatching { command("FIN") }
            if (!process.waitFor(10, TimeUnit.SECONDS)) process.destroyForcibly()
        }
    }

    private fun photo(n: Int) = "BRCM1:img:" + BrocolisCrypto.b64encode(ByteArray(n) { (it % 251).toByte() })

    // MARK: Android ↔ Android (mode compatible, « Appairer à deux »)

    @Test
    fun android_android_appairageCompatible_v3() = runBlocking {
        assumeTrue("BROCOLIS_INTEROP_SERVER absent", server != null)
        val a = Android("a")
        val b = Android("b")
        val code = "KT" + UUID.randomUUID().toString().replace("-", "").take(8).uppercase()
        val pa = async(Dispatchers.IO) { PairingFlow.pairTwo(a.pairing, code, a.peerId, a.priv, a.myBundle, 40, 300) }
        val pb = async(Dispatchers.IO) { PairingFlow.pairTwo(b.pairing, code, b.peerId, b.priv, b.myBundle, 40, 300) }
        val ra = pa.await()!!
        val rb = pb.await()!!
        assertEquals(ra.keyBase64, rb.keyBase64)
        a.install(ra.keyBase64, ra.contact, ra.legacyFingerprint)
        b.install(rb.keyBase64, rb.contact, rb.legacyFingerprint)
        say("empreintes ${a.fingerprint} / ${b.fingerprint} (avant : ${ra.legacyFingerprint})")
        assertEquals(a.fingerprint, b.fingerprint)
        assertTrue(a.fingerprint != ra.legacyFingerprint)
        assertEquals(BrocolisProtection.POST_QUANTUM, a.v3.protection(a.named))

        // Les deux écrivent en même temps leur premier message : chacun lit l'autre.
        assertEquals("v3", a.send("bonjour de A"))
        assertEquals("v3", b.send("bonjour de B"))
        assertEquals(listOf("v3" to "bonjour de B"), a.expect())
        assertEquals(listOf("v3" to "bonjour de A"), b.expect())
        repeat(3) { assertEquals("v3", a.send("A$it")) }
        assertEquals((0..2).map { "v3" to "A$it" }, b.expect(3))
        assertEquals("v3", b.send(photo(30_000)))
        assertEquals(listOf("v3" to photo(30_000)), a.expect())
    }

    @Test
    fun android_ancienAndroid_resteEnV1() = runBlocking {
        assumeTrue("BROCOLIS_INTEROP_SERVER absent", server != null)
        val a = Android("neuf")
        val old = Android("ancien", legacy = true)
        val code = "KT" + UUID.randomUUID().toString().replace("-", "").take(8).uppercase()
        val pa = async(Dispatchers.IO) { PairingFlow.pairTwo(a.pairing, code, a.peerId, a.priv, a.myBundle, 40, 300) }
        val po = async(Dispatchers.IO) { PairingFlow.pairTwo(old.pairing, code, old.peerId, old.priv, null, 40, 300) }
        val ra = pa.await()!!
        val ro = po.await()!!
        a.install(ra.keyBase64, ra.contact, ra.legacyFingerprint)
        old.install(ro.keyBase64, ro.contact, ro.legacyFingerprint)
        // L'autre n'a pas de paquet : ancien format, affiché comme tel, même empreinte d'avant.
        assertEquals(null, ra.contact.bundle)
        assertEquals(ra.legacyFingerprint, a.fingerprint)
        assertEquals(a.fingerprint, old.fingerprint)
        assertEquals(BrocolisProtection.LEGACY, a.v3.protection(a.named))
        assertEquals("v1", a.send("pour l'ancien"))
        assertEquals("v1", old.send("de l'ancien"))
        assertEquals(listOf("v1" to "pour l'ancien"), old.expect())
        assertEquals(listOf("v1" to "de l'ancien"), a.expect())
    }

    // MARK: Android ↔ iPhone (invitation / rejoindre, par le vrai serveur)

    /** Celui qui rejoint (Android), comme l'iPhone : clé remise par l'invitant. */
    private suspend fun join(a: Android, code: String) {
        a.pairing.publish(code, a.peerId, a.pub, bundle = a.myBundle)
        var wrap = a.pairing.fetchWrap(code, a.peerId)
        val end = System.currentTimeMillis() + 60_000
        while (wrap == null && System.currentTimeMillis() < end) {
            delay(300); wrap = a.pairing.fetchWrap(code, a.peerId)
        }
        assertNotNull("clé non remise", wrap)
        val key = BrocolisKeyAgreement.unwrapGroupKey(wrap!!.blob, wrap.fromPub, a.priv)
        val room = a.pairing.fetch(code, a.peerId)
        a.install(key, BrocolisV3Contact.joining(room, wrap, a.myBundle), BrocolisKeyAgreement.groupFingerprint(key))
    }

    @Test
    fun iphoneInvite_androidRejoint_v3DansLesDeuxSens() = runBlocking {
        assumeTrue("BROCOLIS_INTEROP_SERVER / BROCOLIS_SWIFT_CLIENT absents", server != null && swift != null)
        val iphone = Iphone("invite", server!!, File(tmp.root, "iphone-invite").path)
        try {
            val code = iphone.expect("CODE ").removePrefix("CODE ")
            val a = Android("rejoint")
            join(a, code)
            val fp = iphone.expect("EMPREINTE ").removePrefix("EMPREINTE ")
            say("empreinte iPhone $fp / Android ${a.fingerprint}")
            assertEquals(fp, a.fingerprint)
            assertEquals(BrocolisProtection.POST_QUANTUM, a.v3.protection(a.named))
            exchange(iphone, a, iphoneFirst = true)
        } finally {
            iphone.stop()
        }
    }

    @Test
    fun androidInvite_iphoneRejoint_v3DansLesDeuxSens() = runBlocking {
        assumeTrue("BROCOLIS_INTEROP_SERVER / BROCOLIS_SWIFT_CLIENT absents", server != null && swift != null)
        val a = Android("invite")
        val (_, iphone) = invite(a) { code -> Iphone("join", server!!, code, File(tmp.root, "iphone-join").path) }
        try {
            val fp = iphone.expect("EMPREINTE ").removePrefix("EMPREINTE ")
            say("empreinte iPhone $fp / Android ${a.fingerprint}")
            assertEquals(fp, a.fingerprint)
            assertTrue(iphone.expect("PROTECTION ").let { it.contains("post") || it.contains("pos") })
            exchange(iphone, a, iphoneFirst = false)
        } finally {
            iphone.stop()
        }
    }

    @Test
    fun androidInvite_ancienIphone_resteEnV1() = runBlocking {
        assumeTrue("BROCOLIS_INTEROP_SERVER / BROCOLIS_SWIFT_CLIENT absents", server != null && swift != null)
        val a = Android("invite-ancien")
        val (_, iphone) = invite(a) { code -> Iphone("join", server!!, code, File(tmp.root, "iphone-ancien").path, "--ancien") }
        try {
            iphone.expect("PAQUET aucun")
            assertEquals(iphone.expect("EMPREINTE ").removePrefix("EMPREINTE "), a.fingerprint)
            assertEquals(BrocolisKeyAgreement.groupFingerprint(a.named.base64), a.fingerprint)
            assertEquals(BrocolisProtection.LEGACY, a.v3.protection(a.named))
            assertEquals("v1", a.send("pour l'ancien iPhone"))
            assertTrue(iphone.expect("REÇU ").startsWith("REÇU v1 pour l'ancien iPhone"))
            iphone.command("ENVOI de l'ancien iPhone")
            assertEquals(listOf("v1" to "de l'ancien iPhone"), a.expect())
        } finally {
            iphone.stop()
        }
    }

    /**
     * L'invitant (Android) : publie (`host`), attend une personne, lui remet
     * la clé, ouvre la session (§8.4).
     */
    private suspend fun invite(a: Android, start: (String) -> Iphone): Pair<String, Iphone> {
        val code = UUID.randomUUID().toString().replace("-", "").take(8).uppercase()
        val key = BrocolisKeyAgreement.generateGroupKeyBase64()
        a.pairing.publish(code, a.peerId, a.pub, host = true, bundle = a.myBundle)
        val iphone = start(code)
        var peers = a.pairing.fetch(code, a.peerId)
        val end = System.currentTimeMillis() + 60_000
        while (peers.isEmpty() && System.currentTimeMillis() < end) {
            delay(300); peers = a.pairing.fetch(code, a.peerId)
        }
        val peer = peers.first()
        val blob = BrocolisKeyAgreement.wrapGroupKey(key, peer.pub, a.priv)
        a.pairing.postWraps(code, a.peerId, a.pub, listOf(WrapItem(peer.peerId, blob)))
        a.install(key, BrocolisV3Contact.inviting(listOf(peer), a.myBundle), BrocolisKeyAgreement.groupFingerprint(key))
        a.v3.openSession(a.named)
        return code to iphone
    }

    private suspend fun exchange(iphone: Iphone, a: Android, iphoneFirst: Boolean) {
        if (iphoneFirst) {
            iphone.command("ENVOI Bonjour de l'iPhone 🥦")
            assertEquals(listOf("v3" to "Bonjour de l'iPhone 🥦"), a.expect())
        }
        assertEquals("v3", a.send("Bonjour de l'Android 🥦"))
        assertTrue(iphone.expect("REÇU ").startsWith("REÇU v3 Bonjour de l'Android 🥦"))
        if (!iphoneFirst) {
            iphone.command("ENVOI Bonjour de l'iPhone 🥦")
            assertEquals(listOf("v3" to "Bonjour de l'iPhone 🥦"), a.expect())
        }
        // Plusieurs d'affilée, dans les deux sens (le cliquet avance).
        repeat(3) { assertEquals("v3", a.send("Android $it")) }
        repeat(3) { assertTrue(iphone.expect("REÇU ").startsWith("REÇU v3 Android $it")) }
        iphone.command("ENVOI iPhone 1")
        iphone.command("ENVOI iPhone 2")
        assertEquals(listOf("v3" to "iPhone 1", "v3" to "iPhone 2"), a.expect(2))
        // Médias : l'enveloppe BRCM3 dans les deux sens.
        iphone.command("PHOTO 30000")
        assertEquals(listOf("v3" to photo(30_000)), a.expect())
        val p = photo(25_000)
        assertEquals("v3", a.send(p))
        val recu = iphone.expect("REÇU ")
        assertTrue(recu, recu.startsWith("REÇU v3 BRCM1:img:") && recu.endsWith("[${p.length} car.]"))
        iphone.command("PROTECTION")
        val label = iphone.expect("PROTECTION ")
        assertTrue(label, label.contains("post") || label.contains("pos"))
    }
}
