package rs.brocolis.messagerie.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Tests JVM (sans appareil) de la clé protégée par une phrase secrète — format
 * commun Talka / Brocolis iOS / Android / site. Le vecteur fixe (v1, encore
 * lue) garantit l'interopérabilité octet pour octet avec les autres
 * plateformes ; l'export écrit la v2 (vecteurs dans le module `:proto`).
 */
class BrocolisKeyProtectionTest {

    private val rawKey = ByteArray(32) { it.toByte() } // 0x00 … 0x1f
    private val salt = ByteArray(16) { 0x11 }
    private val nonce = ByteArray(12) { 0x22 }
    private val phrase = "brocoli vert 2026"
    private val expected =
        "[[BROCOLIS-CLE:v1:ERERERERERERERERERERESIiIiIiIiIiIiIiIsq57j18BXkqq/4VdIw82nQqzrax9Cfn2mfUJjWH8l327NAf2rWaSYCJh3BfGH4eWA==]]"

    @Test
    fun vecteurDeTest_exact() {
        assertEquals("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", Base64.getEncoder().encodeToString(rawKey))
        assertEquals(expected, BrocolisKeyProtection.sealWith(rawKey, phrase, salt, nonce))
    }

    @Test
    fun vecteurDeTest_ouverture() {
        assertArrayEquals(rawKey, BrocolisKeyProtection.open(expected, phrase))
        // Collé au milieu d'un message, avec un retour à la ligne dans le base64.
        val pasted = "Voici ma clé :\n" + expected.replace("NAf2", "NAf\n2") + "\nà bientôt"
        assertArrayEquals(rawKey, BrocolisKeyProtection.open(pasted, phrase))
    }

    @Test
    fun mauvaisePhrase_echoue() {
        assertNull(BrocolisKeyProtection.openOrNull(expected, "brocoli vert 2025"))
        assertNull(BrocolisKeyProtection.openOrNull(expected, ""))
    }

    @Test
    fun allerRetour() {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val a = BrocolisKeyProtection.seal(key, "une phrase assez longue")
        val b = BrocolisKeyProtection.seal(key, "une phrase assez longue")
        // L'export écrit la v2 (Argon2id, docs/SECURITE.md §8.9).
        assertTrue(a.startsWith(BrocolisKeyProtection.TOKEN_PREFIX_V2) && a.endsWith(BrocolisKeyProtection.TOKEN_SUFFIX))
        assertNotEquals(a, b) // sel et nonce neufs à chaque export
        assertArrayEquals(key, BrocolisKeyProtection.open(a, "une phrase assez longue"))
        assertArrayEquals(key, BrocolisKeyProtection.open(b, "une phrase assez longue"))
    }

    @Test
    fun jetonAbime_refuse() {
        val b64 = BrocolisKeyProtection.extractBase64(expected)!!
        val payload = Base64.getDecoder().decode(b64)
        // Un bit changé dans chaque zone : sel, nonce, chiffré, tag.
        for (i in listOf(0, 16, 30, payload.size - 1)) {
            val bad = payload.clone().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            val token = BrocolisKeyProtection.TOKEN_PREFIX + Base64.getEncoder().encodeToString(bad) + BrocolisKeyProtection.TOKEN_SUFFIX
            assertNull("octet $i modifié", BrocolisKeyProtection.openOrNull(token, phrase))
        }
        // Tronqué, base64 invalide, sans fin.
        val short = BrocolisKeyProtection.TOKEN_PREFIX + Base64.getEncoder().encodeToString(payload.copyOf(75)) + "]]"
        assertNull(BrocolisKeyProtection.openOrNull(short, phrase))
        assertNull(BrocolisKeyProtection.openOrNull("[[BROCOLIS-CLE:v1:%%%pas du base64%%%]]", phrase))
        assertNull(BrocolisKeyProtection.openOrNull(expected.removeSuffix("]]"), phrase))
    }

    @Test
    fun phraseTropCourte_refuseeALExport() {
        assertFalse(BrocolisKeyProtection.isPassphraseAcceptable("1234567"))
        assertTrue(BrocolisKeyProtection.isPassphraseAcceptable("12345678"))
        val refused = try { BrocolisKeyProtection.seal(rawKey, "court"); false }
            catch (_: BrocolisKeyProtection.ProtectionException) { true }
        assertTrue(refused)
    }

    @Test
    fun detection() {
        assertTrue(BrocolisKeyProtection.containsToken("bla $expected bla"))
        assertFalse(BrocolisKeyProtection.containsToken("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="))
    }
}
