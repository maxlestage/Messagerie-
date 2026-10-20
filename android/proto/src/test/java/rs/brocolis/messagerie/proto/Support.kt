package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Ce que partagent les tests : les fichiers du dépôt lus sur place (une seule
 * source, jamais de copie périmée : `proto/vectors.json`,
 * `proto/tests/wycheproof/`, `proto-swift/Tests/…/Fixtures/`), les
 * comparaisons comptées, le générateur qui note ses tirages.
 */
object Depot {
    /** La racine du dépôt : le premier parent qui contient `proto/vectors.json`. */
    val racine: File by lazy {
        var d: File? = File(System.getProperty("user.dir")).absoluteFile
        while (d != null && !File(d, "proto/vectors.json").isFile) d = d.parentFile
        d ?: error("proto/vectors.json introuvable au-dessus de ${System.getProperty("user.dir")}")
    }

    fun json(chemin: String): JsonObject = Json.parseToJsonElement(File(racine, chemin).readText()).jsonObject

    val vecteurs: JsonObject by lazy { json("proto/vectors.json") }
}

/** Les valeurs comparées, par catégorie (affichées à la fin des tests). */
object Compteur {
    private val totaux = ConcurrentHashMap<String, AtomicInteger>()
    fun ajouter(categorie: String, n: Int = 1) {
        totaux.computeIfAbsent(categorie) { AtomicInteger() }.addAndGet(n)
    }
    fun total(categorie: String): Int = totaux[categorie]?.get() ?: 0
}

fun hex(b: ByteArray): String = Octets.hex(b)
fun unhex(s: String): ByteArray = Octets.unhex(s)
fun h32(label: String): ByteArray = Kdf.sha256(Octets.utf8(label))

fun JsonObject.o(k: String): JsonObject = this[k]!!.jsonObject
fun JsonObject.a(k: String): JsonArray = this[k]!!.jsonArray
fun JsonObject.s(k: String): String = this[k]!!.jsonPrimitive.content
fun JsonObject.n(k: String): Long = this[k]!!.jsonPrimitive.long
fun JsonObject.b(k: String): ByteArray = unhex(s(k))
fun JsonObject.isNull(k: String): Boolean = this[k] is JsonNull
fun JsonElement.s(): String = jsonPrimitive.content

/** Égalité comptée (catégorie « vecteurs » par défaut). */
fun egal(attendu: String?, obtenu: String?, quoi: String, categorie: String = "vecteurs") {
    assertEquals(quoi, attendu, obtenu)
    Compteur.ajouter(categorie)
}

fun egal(attendu: ByteArray, obtenu: ByteArray, quoi: String, categorie: String = "vecteurs") {
    assertArrayEquals(quoi, attendu, obtenu)
    Compteur.ajouter(categorie)
}

fun egal(attendu: Long?, obtenu: Long?, quoi: String, categorie: String = "vecteurs") {
    assertEquals(quoi, attendu, obtenu)
    Compteur.ajouter(categorie)
}

/** L'erreur attendue, et aucune autre. */
fun attendreErreur(e: Erreur, quoi: String = "", bloc: () -> Any?) {
    try {
        val r = bloc()
        fail("$quoi : $e attendue, obtenu $r")
    } catch (x: BrocolisException) {
        assertEquals(quoi, e, x.erreur)
    }
}

/** Une erreur du protocole, quelle qu'elle soit. */
fun attendreEchec(quoi: String = "", bloc: () -> Any?) {
    try {
        val r = bloc()
        fail("$quoi : échec attendu, obtenu $r")
    } catch (_: BrocolisException) {
    }
}

fun erreurDe(bloc: () -> Any?): Erreur? = try {
    bloc()
    null
} catch (x: BrocolisException) {
    x.erreur
}

fun texte(c: Content): String = (c as? Content.Text)?.text ?: error("texte attendu, obtenu $c")

/** Un générateur qui note tout ce qu'il donne (les secrets tirés pendant le cliquet). */
class Recorder(seed: String) : CryptoRng {
    private val inner = Deterministic(seed)
    private var drawn = ByteArray(0)
    override fun fill(dst: ByteArray) {
        inner.fill(dst)
        drawn = Octets.concat(drawn, dst)
    }
    fun take(): ByteArray = drawn.also { drawn = ByteArray(0) }
}

/** `n` tiré dans `0 until n` (comme `below` des tests Rust : `next_u32 % n`). */
fun CryptoRng.below(n: Int): Int = (nextU32() % n).toInt()

/** Deux textes JSON de même forme (mêmes objets, ordre des clés indifférent). */
fun memeForme(a: String, b: String, quoi: String) {
    assertEquals(quoi, Json.parseToJsonElement(a), Json.parseToJsonElement(b))
    Compteur.ajouter("rust")
}

fun JsonElement.texteJson(): String = toString()

fun jsonNum(v: Long) = JsonPrimitive(v)
