package rs.brocolis.messagerie.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import rs.brocolis.messagerie.crypto.BrocolisV3Api
import rs.brocolis.messagerie.crypto.BrocolisV3Engine
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.keyFor
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.keyUse
import rs.brocolis.messagerie.crypto.BrocolisV3EngineTest.Companion.raw
import rs.brocolis.messagerie.crypto.BrocolisV3Key
import rs.brocolis.messagerie.crypto.BrocolisV3Opened
import rs.brocolis.messagerie.proto.KeyBundle
import java.io.File
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * Le magasin v3 (docs/SECURITE.md §8.1–8.3) : persistance chiffrée, état
 * illisible, et surtout la TRANSACTION — plusieurs fils et plusieurs
 * processus n'utilisent jamais deux fois la même clé de message ; sans le
 * verrou (contre-essai), si.
 */
class BrocolisV3StoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun store(name: String, locking: Boolean = true, pause: Long = 0): BrocolisV3Store {
        val dir = File(tmp.root, name)
        return BrocolisV3Store(dir, PlainFileVault(File(dir, "coffre")), locking, pause)
    }

    private fun bundleOf(s: BrocolisV3Store): KeyBundle =
        KeyBundle.fromBase64(s.transaction(BrocolisV3Api.now()) { it.bundleBase64!! })

    @Test
    fun persistance_entreDeuxMagasins_etChiffrementAuRepos() {
        val a = store("a")
        val b = store("b")
        val k = raw()
        val versB = keyFor("kb", k, bundleOf(b), at = BrocolisV3Api.now())
        val versA = keyFor("ka", k, bundleOf(a), at = BrocolisV3Api.now())
        val now = BrocolisV3Api.now()
        val secret = "un secret bien gardé 🥦"
        val t = a.transaction(now) { it.seal(secret, versB, now) }!!
        // Un autre magasin sur le même dossier (un autre processus) relit tout.
        val a2 = BrocolisV3Store(a.directory, PlainFileVault(File(a.directory, "coffre")))
        assertEquals(secret, a2.transaction(now) { it.recall(t) })
        assertEquals(BrocolisV3Opened.Text(secret), b.transaction(now) { it.open(t, listOf(versA), now) })
        // Rien du clair, ni des sessions, en clair sur le disque.
        val disque = a.stateFile.readBytes()
        assertFalse(String(disque, Charsets.ISO_8859_1).contains("secret"))
        assertFalse(String(disque, Charsets.ISO_8859_1).contains("sessions"))
    }

    @Test
    fun etatAbime_repartDeZero_appareilGarde() {
        val a = store("a")
        val now = BrocolisV3Api.now()
        val k = raw()
        val versB = keyFor("kb", k, bundleOf(store("b")), at = now)
        val avant = a.transaction(now) { it.bundleBase64 }
        val t = a.transaction(now) { it.seal("x", versB, now) }!!
        val bytes = a.stateFile.readBytes()
        bytes[20] = (bytes[20].toInt() xor 1).toByte()
        a.stateFile.writeBytes(bytes)
        // L'état ne s'ouvre plus : vide (les sessions se rouvriront), l'appareil reste.
        assertNull(a.transaction(now) { it.recall(t) })
        assertEquals(0, a.transaction(now) { it.sessionCount(versB) })
        assertEquals(avant, a.transaction(now) { it.bundleBase64 })
    }

    @Test
    fun coffreIndisponible_v3Indisponible() {
        val dir = File(tmp.root, "muet")
        val muet = object : BrocolisSecretVault {
            override fun read(name: String) = BrocolisVaultRead.Failed
            override fun write(name: String, data: ByteArray) = false
        }
        val s = BrocolisV3Store(dir, muet)
        val refused = try { s.transaction(1L) { it.bundleBase64 }; false } catch (_: BrocolisV3StoreException) { true }
        assertTrue(refused)
        // La façade passe alors à l'ancien format.
        assertNull(BrocolisV3Api.of(s).myBundle())
        assertNull(BrocolisV3Api.of(null).myBundle())
        // Un coffre qui lit mais n'écrit pas : aucun jeton rendu sans état écrit.
        val lecture = object : BrocolisSecretVault {
            override fun read(name: String) = BrocolisVaultRead.NotFound
            override fun write(name: String, data: ByteArray) = false
        }
        assertNull(BrocolisV3Api.of(BrocolisV3Store(File(tmp.root, "lecture"), lecture)).myBundle())
    }

    @Test
    fun transactionImbriquee_refusee() {
        val s = store("a")
        val refused = try {
            s.transaction(1L) { s.transaction(1L) { } }
            false
        } catch (_: IllegalStateException) {
            true
        }
        assertTrue(refused)
    }

    /** `threads` fils chiffrent chacun `each` messages pour Bob, en même temps. */
    private fun sealConcurrently(a: BrocolisV3Store, versB: BrocolisV3Key, threads: Int, each: Int): List<String> {
        val out = Collections.synchronizedList(ArrayList<String>())
        val pool = Executors.newFixedThreadPool(threads)
        val start = CountDownLatch(1)
        repeat(threads) { t ->
            pool.execute {
                start.await()
                repeat(each) { i ->
                    val now = BrocolisV3Api.now()
                    runCatching { a.transaction(now) { e -> e.seal("f$t-$i", versB, now) } }.getOrNull()?.let(out::add)
                }
            }
        }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.MINUTES))
        return out
    }

    @Test
    fun concurrence_fils_aucuneCleDeMessageReutilisee() {
        val a = store("a")
        val b = store("b")
        val k = raw()
        val now = BrocolisV3Api.now()
        val versB = keyFor("kb", k, bundleOf(b), at = now)
        val versA = keyFor("ka", k, bundleOf(a), at = now)
        val tokens = sealConcurrently(a, versB, threads = 8, each = 15)
        assertEquals(120, tokens.size)
        val uses = tokens.map(::keyUse)
        assertEquals("clés de message réutilisées", uses.size, uses.toSet().size)
        // Bob les lit tous, dans le désordre.
        val opened = b.transaction(now) { e -> tokens.shuffled().map { e.open(it, listOf(versA), now) } }
        assertTrue(opened.all { it is BrocolisV3Opened.Text })
        assertEquals(tokens.size, opened.map { (it as BrocolisV3Opened.Text).text }.toSet().size)
    }

    @Test
    fun contreEssai_sansVerrou_clesReutilisees() {
        val a = store("a", locking = false, pause = 5)
        val b = store("b")
        val k = raw()
        val now = BrocolisV3Api.now()
        val versB = keyFor("kb", k, bundleOf(b), at = now)
        a.transaction(now) { it.openSession(versB, now) }
        val tokens = sealConcurrently(a, versB, threads = 8, each = 10)
        val uses = tokens.map(::keyUse)
        // Deux fils lisent le même état : même clé de message pour deux messages.
        assertTrue("sans verrou, la course devait réutiliser des clés (${uses.size} jetons)", uses.toSet().size < uses.size)
    }

    @Test
    fun concurrence_processus_aucuneCleDeMessageReutilisee() {
        val a = store("a")
        val b = store("b")
        val k = raw()
        val now = BrocolisV3Api.now()
        val bBundle = bundleOf(b)
        // L'appareil d'Alice n'existe pas encore : les processus se le disputent.
        val javaBin = File(System.getProperty("java.home"), "bin/java").path
        val cp = System.getProperty("java.class.path")
        val procs = (0 until 3).map { p ->
            ProcessBuilder(javaBin, "-cp", cp, "rs.brocolis.messagerie.store.V3Worker",
                a.directory.path, bBundle.toBase64(), now.toString(),
                java.util.Base64.getEncoder().encodeToString(k), "p$p", "15")
                .redirectErrorStream(false)
                .start()
        }
        val tokens = procs.flatMap { p ->
            val lines = p.inputStream.bufferedReader().readLines()
            val err = p.errorStream.bufferedReader().readText()
            assertTrue(p.waitFor(5, TimeUnit.MINUTES))
            assertEquals("processus : $err", 0, p.exitValue())
            lines.filter { it.startsWith("[[BROCOLIS:v3:") }
        }
        assertEquals(45, tokens.size)
        val uses = tokens.map(::keyUse)
        assertEquals("clés de message réutilisées entre processus", uses.size, uses.toSet().size)
        val versA = keyFor("ka", k, bundleOf(a), at = now)
        val opened = b.transaction(now) { e -> tokens.shuffled().map { e.open(it, listOf(versA), now) } }
        assertTrue(opened.toString(), opened.all { it is BrocolisV3Opened.Text })
        assertNotNull(a.transaction(now) { e: BrocolisV3Engine -> e.bundleBase64 })
    }
}

/**
 * Un « autre processus » (le test de concurrence) : chiffre `n` messages pour
 * le paquet donné, une transaction chacun, et les écrit sur la sortie.
 *
 *     V3Worker <dossier> <paquet> <heure> <clé base64> <préfixe> <n>
 */
object V3Worker {
    @JvmStatic
    fun main(args: Array<String>) {
        val dir = File(args[0])
        val s = BrocolisV3Store(dir, PlainFileVault(File(dir, "coffre")))
        val key = BrocolisV3Key("kb", java.util.Base64.getDecoder().decode(args[3]), KeyBundle.fromBase64(args[1]),
            args[2].toLong(), group = false, psk = false)
        repeat(args[5].toInt()) { i ->
            val now = BrocolisV3Api.now()
            println(s.transaction(now) { it.seal("${args[4]}-$i", key, now) } ?: "ÉCHEC")
        }
    }
}
