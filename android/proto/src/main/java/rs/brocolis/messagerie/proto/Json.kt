package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.put

/**
 * Les états en JSON, **de la même forme que la référence Rust** (serde_json) :
 * mêmes noms de champs, dans le même ordre, octets en base64 standard,
 * `null` écrits, entiers nus. Un état écrit par Rust (ou Swift) se relit ici,
 * et inversement. Toute entorse (champ manquant, longueur ou type faux,
 * entier hors bornes) donne [Erreur.Etat].
 */
internal object EtatJson {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(text: String): JsonObject = try {
        json.parseToJsonElement(text) as? JsonObject ?: echec(Erreur.Etat)
    } catch (e: BrocolisException) {
        throw e
    } catch (_: Exception) {
        echec(Erreur.Etat)
    }

    fun write(o: JsonObject): String = o.toString()

    // ----- Lecture -----------------------------------------------------------

    fun JsonObject.field(name: String): JsonElement = this[name] ?: echec(Erreur.Etat)

    fun JsonObject.obj(name: String): JsonObject = field(name) as? JsonObject ?: echec(Erreur.Etat)

    fun JsonObject.arr(name: String): JsonArray = field(name) as? JsonArray ?: echec(Erreur.Etat)

    fun JsonElement.asObj(): JsonObject = this as? JsonObject ?: echec(Erreur.Etat)

    /** Un entier non signé, 0 ≤ v ≤ max (u8, u32 ; u64 borné à `Long.MAX_VALUE`). */
    fun JsonElement.uint(max: Long): Long {
        val p = this as? JsonPrimitive ?: echec(Erreur.Etat)
        if (p.isString) echec(Erreur.Etat)
        val c = p.content
        if (c.isEmpty() || !c.all { it in '0'..'9' }) echec(Erreur.Etat)
        val v = c.toLongOrNull() ?: echec(Erreur.Etat)
        if (v > max) echec(Erreur.Etat)
        return v
    }

    fun JsonObject.u8(name: String): Long = field(name).uint(0xff)
    fun JsonObject.u32(name: String): Long = field(name).uint(Octets.U32_MAX)
    fun JsonObject.u64(name: String): Long = field(name).uint(Long.MAX_VALUE)

    fun JsonObject.optU64(name: String): Long? {
        val e = field(name)
        return if (e is JsonNull) null else e.uint(Long.MAX_VALUE)
    }

    fun JsonElement.str(): String {
        val p = this as? JsonPrimitive ?: echec(Erreur.Etat)
        if (!p.isString) echec(Erreur.Etat)
        return p.content
    }

    fun JsonObject.str(name: String): String = field(name).str()

    /** Des octets en base64 ; `len` impose leur nombre (un `[u8; N]` de Rust). */
    fun JsonElement.bytes(len: Int? = null): ByteArray {
        val b = Octets.unb64(str()) ?: echec(Erreur.Etat)
        if (len != null && b.size != len) echec(Erreur.Etat)
        return b
    }

    fun JsonObject.bytes(name: String, len: Int? = null): ByteArray = field(name).bytes(len)

    /** Des octets ou `null` ; un champ absent n'est accepté qu'avec `optional` (`#[serde(default)]`). */
    fun JsonObject.optBytes(name: String, len: Int? = null, optional: Boolean = false): ByteArray? {
        val e = this[name] ?: if (optional) return null else echec(Erreur.Etat)
        return if (e is JsonNull) null else e.bytes(len)
    }

    // ----- Écriture ----------------------------------------------------------

    fun JsonObjectBuilder.putBytes(name: String, b: ByteArray?) {
        put(name, if (b == null) JsonNull else JsonPrimitive(Octets.b64(b)))
    }

    fun JsonObjectBuilder.putNum(name: String, v: Long?) {
        put(name, if (v == null) JsonNull else JsonPrimitive(v))
    }

    fun JsonObjectBuilder.putStr(name: String, v: String) {
        put(name, v)
    }
}
