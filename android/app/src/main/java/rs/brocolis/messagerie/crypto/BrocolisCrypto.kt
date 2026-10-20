package rs.brocolis.messagerie.crypto

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Chiffrement sélectif AES-256-GCM, INTEROPÉRABLE au format de jeton près avec
 * l'app iOS (CryptoKit) et le proxy Rust brocolis.
 *
 * - Tout segment `((texte secret))` est chiffré et remplacé par un jeton
 *   `[[BROCOLIS:v1:<base64>]]`.
 * - Tout jeton `[[BROCOLIS:v1:<base64>]]` (ou `v2` multi-destinataire) est
 *   déchiffré en clair.
 *
 * Le jeton v1 encode `nonce (12) || ciphertext || tag (16)`, exactement la
 * représentation `combined` de CryptoKit (`AES.GCM.SealedBox`) : sous Java,
 * `Cipher("AES/GCM/NoPadding")` renvoie déjà `ciphertext || tag`, on préfixe le
 * nonce.
 *
 * Port fidèle de Shared/BrocolisCrypto.swift. Les clés sont des `ByteArray` de
 * 32 octets ; on les passe/retourne en base64 standard (sans retour à la ligne).
 *
 * Sans `android.*` (java.util.Base64, javax.crypto) : se teste tel quel sur la
 * JVM, avec le v3 (`BrocolisV3`), qui s'en sert pour l'enveloppe des médias.
 */
object BrocolisCrypto {

    const val TOKEN_HEAD = "[[BROCOLIS:"
    const val TOKEN_PREFIX = "[[BROCOLIS:v1:"
    const val TOKEN_PREFIX_V2 = "[[BROCOLIS:v2:"
    const val TOKEN_SUFFIX = "]]"
    const val PLAIN_OPEN = "(("
    const val PLAIN_CLOSE = "))"

    const val KEY_LENGTH = 32
    private const val NONCE_LENGTH = 12
    private const val TAG_LENGTH = 16
    private const val TAG_BITS = 128
    /** Clé de message emballée : nonce(12) + clé(32) + tag(16). */
    private const val WRAPPED_KEY_LENGTH = 12 + 32 + 16

    class CryptoException(message: String) : Exception(message)

    // MARK: Base64 (standard, sans wrap — comme base64EncodedString d'iOS)

    fun b64encode(data: ByteArray): String = Base64.getEncoder().encodeToString(data)

    /**
     * Décodage tolérant, comme `android.util.Base64` avant lui : tout caractère
     * hors de l'alphabet (blancs, retours à la ligne collés) est ignoré.
     */
    fun b64decode(s: String): ByteArray? =
        try { Base64.getMimeDecoder().decode(s.trim()) } catch (_: Exception) { null }

    // MARK: Clé

    fun generateKeyBase64(): String {
        val raw = ByteArray(KEY_LENGTH)
        SecureRandom().nextBytes(raw)
        return b64encode(raw)
    }

    /** Valide + décode une clé base64 en 32 octets, ou lève une exception. */
    @Throws(CryptoException::class)
    fun keyBytes(fromBase64: String): ByteArray {
        val raw = b64decode(fromBase64) ?: throw CryptoException("Clé base64 invalide.")
        if (raw.size != KEY_LENGTH) throw CryptoException("Clé de ${raw.size} octets, ${KEY_LENGTH} attendus.")
        return raw
    }

    fun isValidKey(base64: String): Boolean =
        try { keyBytes(base64); true } catch (_: Exception) { false }

    // MARK: AES-GCM bas niveau (format « combined »)

    private fun sealCombined(plaintext: ByteArray, key: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_LENGTH)
        SecureRandom().nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        val ctAndTag = cipher.doFinal(plaintext)
        return nonce + ctAndTag
    }

    private fun openCombined(combined: ByteArray, key: ByteArray): ByteArray {
        require(combined.size >= NONCE_LENGTH + TAG_LENGTH)
        val nonce = combined.copyOfRange(0, NONCE_LENGTH)
        val ctAndTag = combined.copyOfRange(NONCE_LENGTH, combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        return cipher.doFinal(ctAndTag)
    }

    // MARK: Jeton unitaire (v1)

    @Throws(CryptoException::class)
    fun encryptToken(plaintext: ByteArray, key: ByteArray): String {
        val combined = try { sealCombined(plaintext, key) } catch (e: Exception) {
            throw CryptoException("Échec du chiffrement AES-256-GCM.")
        }
        return TOKEN_PREFIX + b64encode(combined) + TOKEN_SUFFIX
    }

    /** Déchiffre le base64 d'un jeton v1, ou renvoie null si la clé ne convient pas. */
    fun decryptTokenOrNull(base64: String, key: ByteArray): ByteArray? {
        val packed = b64decode(base64) ?: return null
        if (packed.size < NONCE_LENGTH + TAG_LENGTH) return null
        return try { openCombined(packed, key) } catch (_: Exception) { null }
    }

    // MARK: Jeton multi-destinataire (v2, chiffrement d'enveloppe)
    //
    // Disposition du payload (puis base64) :
    //   [0]                     format = 0x01
    //   [1]                     N = nombre de destinataires (1…255)
    //   [2 .. 2+60N)            N clés de message emballées (60 octets chacune)
    //   [2+60N .. fin)          corps = AES-GCM(texte, cléDeMessage) « combined »

    @Throws(CryptoException::class)
    fun encryptTokenMulti(plaintext: ByteArray, keys: List<ByteArray>): String {
        if (keys.isEmpty() || keys.size > 255) throw CryptoException("Nombre de destinataires invalide.")

        val messageKey = ByteArray(KEY_LENGTH)
        SecureRandom().nextBytes(messageKey)

        val body = try { sealCombined(plaintext, messageKey) } catch (e: Exception) {
            throw CryptoException("Échec du chiffrement AES-256-GCM.")
        }

        val out = ArrayList<Byte>()
        out.add(0x01)
        out.add(keys.size.toByte())
        for (key in keys) {
            val wrapped = try { sealCombined(messageKey, key) } catch (e: Exception) {
                throw CryptoException("Échec de l'emballage de clé.")
            }
            if (wrapped.size != WRAPPED_KEY_LENGTH) throw CryptoException("Taille d'emballage inattendue.")
            for (b in wrapped) out.add(b)
        }
        for (b in body) out.add(b)

        return TOKEN_PREFIX_V2 + b64encode(out.toByteArray()) + TOKEN_SUFFIX
    }

    /** Ouvre un jeton v2 avec un jeu de clés, ou null si aucune ne correspond. */
    fun decryptTokenV2OrNull(base64: String, keys: List<ByteArray>): ByteArray? {
        val payload = b64decode(base64) ?: return null
        if (payload.size < 2) return null
        if (payload[0].toInt() != 0x01) return null

        val n = payload[1].toInt() and 0xFF
        val wrapsStart = 2
        val bodyStart = wrapsStart + n * WRAPPED_KEY_LENGTH
        if (payload.size < bodyStart + NONCE_LENGTH + TAG_LENGTH) return null

        val body = payload.copyOfRange(bodyStart, payload.size)

        for (i in 0 until n) {
            val s = wrapsStart + i * WRAPPED_KEY_LENGTH
            val wrapped = payload.copyOfRange(s, s + WRAPPED_KEY_LENGTH)
            for (key in keys) {
                val messageKey = try { openCombined(wrapped, key) } catch (_: Exception) { continue }
                val plain = try { openCombined(body, messageKey) } catch (_: Exception) { continue }
                return plain
            }
        }
        return null
    }

    /** Scelle un texte : v1 pour une seule clé (compatible brocolis), v2 sinon. */
    fun sealTokenOrNull(plaintext: ByteArray, keys: List<ByteArray>): String? {
        val first = keys.firstOrNull() ?: return null
        return try {
            if (keys.size == 1) encryptToken(plaintext, first)
            else encryptTokenMulti(plaintext, keys)
        } catch (_: Exception) { null }
    }

    // MARK: Sélectif (best effort)

    data class Marked(val text: String, val count: Int)

    /** Chiffre chaque `((segment))` pour TOUTES les clés (v2 si plusieurs, v1 sinon). */
    fun encryptMarked(input: String, keys: List<ByteArray>): Marked =
        encryptMarked(input) { sealTokenOrNull(it.toByteArray(Charsets.UTF_8), keys) }

    /**
     * Chiffre chaque `((segment))` avec `seal` (le codec : v3 pour une clé qui
     * le permet, sinon v1/v2) ; un segment que `seal` refuse reste tel quel.
     */
    fun encryptMarked(input: String, seal: (String) -> String?): Marked {
        val out = StringBuilder()
        var count = 0
        var rest = input

        while (true) {
            val open = rest.indexOf(PLAIN_OPEN)
            if (open < 0) break
            val afterOpen = rest.substring(open + PLAIN_OPEN.length)
            val close = afterOpen.indexOf(PLAIN_CLOSE)
            if (close < 0) break
            val secret = afterOpen.substring(0, close)

            out.append(rest, 0, open)
            val token = seal(secret)
            if (token != null) {
                out.append(token); count++
            } else {
                out.append(PLAIN_OPEN).append(secret).append(PLAIN_CLOSE)
            }
            rest = afterOpen.substring(close + PLAIN_CLOSE.length)
        }
        out.append(rest)
        return Marked(out.toString(), count)
    }

    data class Decrypted(val text: String, val count: Int)

    /**
     * Déchiffre chaque jeton en essayant plusieurs clés : pour chaque jeton, la
     * 1re clé qui réussit gagne. Un jeton qu'aucune clé n'ouvre est laissé tel
     * quel (message « pour les autres »).
     *
     * `other` lit les jetons d'une autre version (le v3 : `BrocolisV3`), le
     * jeton entier en argument : son clair, ou `null` pour le laisser tel quel.
     */
    fun decryptTokens(input: String, keys: List<ByteArray>, other: ((String) -> String?)? = null): Decrypted {
        val out = StringBuilder()
        var count = 0
        var rest = input

        while (true) {
            val start = rest.indexOf(TOKEN_HEAD)
            if (start < 0) break
            val afterHead = rest.substring(start + TOKEN_HEAD.length)
            val end = afterHead.indexOf(TOKEN_SUFFIX)
            if (end < 0) break
            val inner = afterHead.substring(0, end) // "v1:…" / "v2:…"

            out.append(rest, 0, start)

            var decrypted: String? = null
            if (inner.startsWith("v1:")) {
                val b64 = inner.substring(3)
                for (key in keys) {
                    val plain = decryptTokenOrNull(b64, key)
                    if (plain != null) { decrypted = String(plain, Charsets.UTF_8); break }
                }
            } else if (inner.startsWith("v2:")) {
                val b64 = inner.substring(3)
                val plain = decryptTokenV2OrNull(b64, keys)
                if (plain != null) decrypted = String(plain, Charsets.UTF_8)
            } else if (other != null) {
                decrypted = other(TOKEN_HEAD + inner + TOKEN_SUFFIX)
            }

            if (decrypted != null) {
                out.append(decrypted); count++
            } else {
                out.append(TOKEN_HEAD).append(inner).append(TOKEN_SUFFIX)
            }
            rest = afterHead.substring(end + TOKEN_SUFFIX.length)
        }
        out.append(rest)
        return Decrypted(out.toString(), count)
    }

    fun containsToken(text: String): Boolean = text.contains(TOKEN_HEAD)

    /** Compte les jetons bien formés (v1 et v2). */
    fun countTokens(input: String): Int {
        var count = 0
        var rest = input
        while (true) {
            val start = rest.indexOf(TOKEN_HEAD)
            if (start < 0) break
            val afterHead = rest.substring(start + TOKEN_HEAD.length)
            val end = afterHead.indexOf(TOKEN_SUFFIX)
            if (end < 0) break
            count++
            rest = afterHead.substring(end + TOKEN_SUFFIX.length)
        }
        return count
    }
}

/**
 * Ce qui chiffre et ce qui lit un texte (port de `BrocolisCodec`, iOS) :
 * `BrocolisV3Api.codec` (v3 pour UNE clé qui le permet, docs/SECURITE.md §8.5)
 * ou `legacy` (v1 pour une clé, v2 pour plusieurs).
 */
class BrocolisCodec(
    val seal: (String) -> String?,
    val open: (String) -> BrocolisCrypto.Decrypted
) {
    companion object {
        fun legacy(keys: List<ByteArray>) = BrocolisCodec(
            seal = { BrocolisCrypto.sealTokenOrNull(it.toByteArray(Charsets.UTF_8), keys) },
            open = { BrocolisCrypto.decryptTokens(it, keys) }
        )
    }
}
