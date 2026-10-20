package rs.brocolis.messagerie.crypto

import java.security.SecureRandom
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
 *     [[BROCOLIS-CLE:v1:<base64 standard, avec =>]]
 *
 * payload décodé (76 octets) = sel (16) ‖ nonce (12) ‖ AES-256-GCM(clé brute 32 octets) ‖ tag (16)
 *
 * - clé de chiffrement = PBKDF2-HMAC-SHA256(phrase en UTF-8 telle quelle, sel, 600 000 itérations, 32 octets)
 * - données associées (AAD) = les 15 octets ASCII `brocolis-cle-v1`
 * - sel et nonce aléatoires (CSPRNG) à chaque export
 *
 * Volontairement sans `android.*` (java.util.Base64, javax.crypto) : le module
 * se teste tel quel sur la JVM (tests unitaires) et reste identique sur Android
 * (minSdk 26 : java.util.Base64 et PBKDF2WithHmacSHA256 y sont disponibles ;
 * sur Android comme sur la JVM, PBEKeySpec encode la phrase en UTF-8).
 *
 * Attention : 600 000 itérations prennent du temps (≈ 0,5 à 2 s sur téléphone) —
 * appeler `seal`/`open` hors du fil principal.
 */
object BrocolisKeyProtection {

    const val TOKEN_PREFIX = "[[BROCOLIS-CLE:v1:"
    const val TOKEN_SUFFIX = "]]"

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

    /** Le texte contient-il un jeton de clé protégée ? */
    fun containsToken(text: String): Boolean = text.contains(TOKEN_PREFIX)

    /**
     * Scelle une clé brute (32 octets) avec une phrase secrète → jeton
     * `[[BROCOLIS-CLE:v1:…]]`. Refuse une phrase de moins de 8 caractères.
     */
    @Throws(ProtectionException::class)
    fun seal(rawKey: ByteArray, passphrase: String): String {
        if (!isPassphraseAcceptable(passphrase)) {
            throw ProtectionException("Phrase secrète trop courte ($MIN_PASSPHRASE_LENGTH caractères au moins).")
        }
        val random = SecureRandom()
        val salt = ByteArray(SALT_LENGTH).also { random.nextBytes(it) }
        val nonce = ByteArray(NONCE_LENGTH).also { random.nextBytes(it) }
        return sealWith(rawKey, passphrase, salt, nonce)
    }

    /**
     * Scelle avec un sel et un nonce DONNÉS. Réservé au vecteur de test : en
     * vrai, toujours passer par `seal` (sel et nonce neufs à chaque export).
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
