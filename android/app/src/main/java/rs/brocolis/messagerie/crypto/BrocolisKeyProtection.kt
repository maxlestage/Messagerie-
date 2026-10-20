package rs.brocolis.messagerie.crypto

import rs.brocolis.messagerie.proto.BrocolisException
import rs.brocolis.messagerie.proto.CleProtegee
import rs.brocolis.messagerie.proto.Erreur
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Clé Brocolis protégée par une phrase secrète : le format COMMUN (Talka,
 * Brocolis iOS / Android / site) pour sortir une clé de l'appareil sans jamais
 * la copier en clair. La phrase se donne à part (de vive voix).
 *
 * L'export écrit la **v2** (docs/SECURITE.md §3.2, §7.1, §8.9) :
 *
 *     [[BROCOLIS-CLE:v2:<base64>]]   Argon2id (m = 64 Mio, t = 3, p = 1)
 *
 * (module `:proto`, `CleProtegee`). L'import lit la v2 et l'ancienne v1 :
 *
 *     [[BROCOLIS-CLE:v1:<base64 standard, avec =>]]
 *
 * payload v1 décodé (76 octets) = sel (16) ‖ nonce (12) ‖ AES-256-GCM(clé brute 32 octets) ‖ tag (16)
 *
 * - clé de chiffrement = PBKDF2-HMAC-SHA256(phrase en UTF-8 telle quelle, sel, 600 000 itérations, 32 octets)
 * - données associées (AAD) = les 15 octets ASCII `brocolis-cle-v1`
 *
 * Volontairement sans `android.*` : se teste tel quel sur la JVM.
 *
 * Attention : Argon2id (64 Mio) comme PBKDF2 (600 000 tours) prennent du
 * temps (≈ 0,5 à 2 s sur téléphone) — appeler `seal`/`open` hors du fil
 * principal. À l'import, une v2 qui demanderait plus de mémoire que l'app
 * n'en a (au plus 256 Mio, comme l'iPhone) est refusée avant tout calcul.
 */
object BrocolisKeyProtection {

    const val TOKEN_PREFIX = "[[BROCOLIS-CLE:v1:"
    const val TOKEN_PREFIX_V2 = "[[BROCOLIS-CLE:v2:"
    const val TOKEN_SUFFIX = "]]"

    /** Mémoire Argon2id acceptée à l'import (Kio) : 256 Mio au plus, et la moitié du tas de l'app. */
    val maxImportMemoryKib: Long
        get() = minOf(256L * 1024, Runtime.getRuntime().maxMemory() / 1024 / 2)

    /** Longueur minimale de la phrase à l'export (à l'import, toute phrase est essayée). */
    const val MIN_PASSPHRASE_LENGTH = 8

    const val ITERATIONS = 600_000
    private const val SALT_LENGTH = 16
    private const val NONCE_LENGTH = 12
    private const val TAG_BITS = 128
    private const val PAYLOAD_LENGTH = SALT_LENGTH + NONCE_LENGTH + BrocolisCrypto.KEY_LENGTH + 16 // 76
    private val AAD = "brocolis-cle-v1".toByteArray(Charsets.US_ASCII)

    class ProtectionException(message: String) : Exception(message)

    /** La phrase est-elle assez longue pour exporter ? (en caractères, comme iOS/site) */
    fun isPassphraseAcceptable(passphrase: String): Boolean =
        passphrase.codePointCount(0, passphrase.length) >= MIN_PASSPHRASE_LENGTH

    /** Le texte contient-il un jeton de clé protégée (v1 ou v2) ? */
    fun containsToken(text: String): Boolean = text.contains(TOKEN_PREFIX) || text.contains(TOKEN_PREFIX_V2)

    /**
     * Scelle une clé brute (32 octets) avec une phrase secrète → jeton
     * `[[BROCOLIS-CLE:v2:…]]` (Argon2id). Refuse une phrase de moins de 8
     * caractères.
     */
    @Throws(ProtectionException::class)
    fun seal(rawKey: ByteArray, passphrase: String): String {
        if (!isPassphraseAcceptable(passphrase)) {
            throw ProtectionException("Phrase secrète trop courte ($MIN_PASSPHRASE_LENGTH caractères au moins).")
        }
        if (rawKey.size != BrocolisCrypto.KEY_LENGTH) {
            throw ProtectionException("Clé de ${rawKey.size} octets, ${BrocolisCrypto.KEY_LENGTH} attendus.")
        }
        return try { CleProtegee.protectKey(rawKey, passphrase) } catch (_: BrocolisException) {
            throw ProtectionException("Échec du chiffrement de la clé.")
        }
    }

    /**
     * Scelle en **v1** avec un sel et un nonce DONNÉS. Réservé au vecteur de
     * test (l'export écrit la v2) : la v1 n'est plus que lue.
     */
    @Throws(ProtectionException::class)
    internal fun sealWith(rawKey: ByteArray, passphrase: String, salt: ByteArray, nonce: ByteArray): String {
        if (rawKey.size != BrocolisCrypto.KEY_LENGTH) {
            throw ProtectionException("Clé de ${rawKey.size} octets, ${BrocolisCrypto.KEY_LENGTH} attendus.")
        }
        require(salt.size == SALT_LENGTH && nonce.size == NONCE_LENGTH)
        val sealed = try {
            val kek = derive(passphrase, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kek, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(AAD)
            cipher.doFinal(rawKey) // chiffré (32) ‖ tag (16)
        } catch (e: Exception) {
            throw ProtectionException("Échec du chiffrement de la clé.")
        }
        val payload = salt + nonce + sealed
        return TOKEN_PREFIX + Base64.getEncoder().encodeToString(payload) + TOKEN_SUFFIX
    }

    /**
     * Ouvre un jeton (le texte collé peut contenir autre chose autour) avec la
     * phrase → clé brute de 32 octets. Phrase fausse ou jeton abîmé → exception,
     * rien n'est renvoyé.
     */
    @Throws(ProtectionException::class)
    fun open(text: String, passphrase: String): ByteArray {
        if (text.contains(TOKEN_PREFIX_V2)) return openV2(text, passphrase)
        val b64 = extractBase64(text) ?: throw ProtectionException("Jeton de clé introuvable ou incomplet.")
        val payload = try { Base64.getDecoder().decode(b64) } catch (_: IllegalArgumentException) {
            throw ProtectionException("Jeton de clé abîmé.")
        }
        if (payload.size != PAYLOAD_LENGTH) throw ProtectionException("Jeton de clé abîmé.")
        val salt = payload.copyOfRange(0, SALT_LENGTH)
        val nonce = payload.copyOfRange(SALT_LENGTH, SALT_LENGTH + NONCE_LENGTH)
        val sealed = payload.copyOfRange(SALT_LENGTH + NONCE_LENGTH, payload.size)
        val raw = try {
            val kek = derive(passphrase, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(kek, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(AAD)
            cipher.doFinal(sealed)
        } catch (_: Exception) {
            // AEADBadTagException : phrase fausse OU jeton modifié — indiscernables, et c'est voulu.
            throw ProtectionException("Phrase secrète incorrecte ou jeton abîmé.")
        }
        if (raw.size != BrocolisCrypto.KEY_LENGTH) throw ProtectionException("Jeton de clé abîmé.")
        return raw
    }

    /** Une v2 (blancs collés retirés), paramètres Argon2id vérifiés avant tout calcul. */
    private fun openV2(text: String, passphrase: String): ByteArray {
        val start = text.indexOf(TOKEN_PREFIX_V2)
        val end = text.indexOf(TOKEN_SUFFIX, start + TOKEN_PREFIX_V2.length)
        if (end < 0) throw ProtectionException("Jeton de clé introuvable ou incomplet.")
        val token = TOKEN_PREFIX_V2 +
            text.substring(start + TOKEN_PREFIX_V2.length, end).filterNot { it.isWhitespace() } + TOKEN_SUFFIX
        try {
            if (CleProtegee.v2Params(token).mKib > maxImportMemoryKib) {
                throw ProtectionException("Clé protégée trop coûteuse à ouvrir sur cet appareil.")
            }
            return CleProtegee.unprotectKey(token, passphrase)
        } catch (e: BrocolisException) {
            throw ProtectionException(
                if (e.erreur == Erreur.Dechiffrement) "Phrase secrète incorrecte ou jeton abîmé." else "Jeton de clé abîmé."
            )
        }
    }

    /** Comme `open`, mais renvoie null en cas d'échec. */
    fun openOrNull(text: String, passphrase: String): ByteArray? =
        try { open(text, passphrase) } catch (_: ProtectionException) { null }

    /** Le base64 du premier jeton du texte (espaces / retours à la ligne collés retirés). */
    internal fun extractBase64(text: String): String? {
        val start = text.indexOf(TOKEN_PREFIX)
        if (start < 0) return null
        val afterHead = text.substring(start + TOKEN_PREFIX.length)
        val end = afterHead.indexOf(TOKEN_SUFFIX)
        if (end < 0) return null
        return afterHead.substring(0, end).filterNot { it.isWhitespace() }
    }

    /** PBKDF2-HMAC-SHA256(phrase UTF-8, sel, 600 000, 32 octets). */
    private fun derive(passphrase: String, salt: ByteArray): ByteArray {
        val chars = passphrase.toCharArray()
        val spec = PBEKeySpec(chars, salt, ITERATIONS, BrocolisCrypto.KEY_LENGTH * 8)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
        }
    }
}
