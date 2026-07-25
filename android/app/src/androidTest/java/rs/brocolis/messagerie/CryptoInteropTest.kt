package rs.brocolis.messagerie

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import rs.brocolis.messagerie.crypto.BrocolisConversation
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.crypto.BrocolisKeyAgreement
import rs.brocolis.messagerie.net.BrocolisMessagingClient

/**
 * Tests instrumentés du cœur crypto : ils vérifient les invariants qui
 * GARANTISSENT l'interopérabilité avec l'app iOS et le serveur Rust (format des
 * jetons, dérivation X25519, `conversationId`). À lancer sur appareil/émulateur
 * (android.util.Base64 exige le runtime Android).
 */
@RunWith(AndroidJUnit4::class)
class CryptoInteropTest {

    @Test
    fun v1_roundTrip() {
        val key = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val token = BrocolisCrypto.encryptToken("Bonjour 🥦".toByteArray(), key)
        assertTrue(token.startsWith(BrocolisCrypto.TOKEN_PREFIX))
        assertTrue(token.endsWith(BrocolisCrypto.TOKEN_SUFFIX))
        val (clear, count) = BrocolisCrypto.decryptTokens(token, listOf(key))
        assertEquals(1, count)
        assertEquals("Bonjour 🥦", clear)
    }

    @Test
    fun v1_wrongKeyStaysLocked() {
        val a = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val b = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val token = BrocolisCrypto.encryptToken("secret".toByteArray(), a)
        val (out, count) = BrocolisCrypto.decryptTokens(token, listOf(b))
        assertEquals(0, count)
        assertEquals(token, out) // laissé tel quel : « message pour les autres »
    }

    @Test
    fun v2_multiRecipient() {
        val k1 = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val k2 = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val token = BrocolisCrypto.encryptTokenMulti("groupe".toByteArray(), listOf(k1, k2))
        assertTrue(token.startsWith(BrocolisCrypto.TOKEN_PREFIX_V2))
        // Chaque destinataire ouvre le même jeton.
        assertEquals("groupe", BrocolisCrypto.decryptTokens(token, listOf(k1)).text)
        assertEquals("groupe", BrocolisCrypto.decryptTokens(token, listOf(k2)).text)
        // Une clé étrangère n'ouvre rien.
        val other = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        assertEquals(0, BrocolisCrypto.decryptTokens(token, listOf(other)).count)
    }

    @Test
    fun marked_encryptDecrypt() {
        val key = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val marked = BrocolisCrypto.encryptMarked("avant ((secret)) après", listOf(key))
        assertEquals(1, marked.count)
        assertTrue(marked.text.contains(BrocolisCrypto.TOKEN_HEAD))
        val back = BrocolisCrypto.decryptTokens(marked.text, listOf(key))
        assertEquals("avant secret après", back.text)
    }

    @Test
    fun conversationId_isStableAndUrlSafe() {
        val b64 = BrocolisCrypto.generateKeyBase64()
        val id1 = BrocolisMessagingClient.conversationId(b64)
        val id2 = BrocolisMessagingClient.conversationId(b64)
        assertNotNull(id1)
        assertEquals(id1, id2) // déterministe
        assertTrue(id1!!.none { it == '+' || it == '/' || it == '=' }) // base64url sans padding
    }

    @Test
    fun x25519_bothSidesDeriveSameKey() {
        val alice = org.bouncycastle.crypto.params.X25519PrivateKeyParameters(java.security.SecureRandom())
        val bob = org.bouncycastle.crypto.params.X25519PrivateKeyParameters(java.security.SecureRandom())
        val alicePub = BrocolisCrypto.b64encode(alice.generatePublicKey().encoded)
        val bobPub = BrocolisCrypto.b64encode(bob.generatePublicKey().encoded)

        val dAlice = BrocolisKeyAgreement.derive(alice, bobPub)
        val dBob = BrocolisKeyAgreement.derive(bob, alicePub)

        // Même clé dérivée + même empreinte des deux côtés.
        assertEquals(dAlice.symmetricKeyBase64, dBob.symmetricKeyBase64)
        assertEquals(dAlice.fingerprint, dBob.fingerprint)

        // Et cette clé chiffre/déchiffre bien un jeton.
        val key = BrocolisCrypto.keyBytes(dAlice.symmetricKeyBase64)
        val token = BrocolisCrypto.encryptToken("appairé".toByteArray(), key)
        assertEquals("appairé", BrocolisCrypto.decryptTokens(token, listOf(key)).text)
    }

    @Test
    fun conversation_render_mixedLines() {
        val key = BrocolisCrypto.keyBytes(BrocolisCrypto.generateKeyBase64())
        val token = BrocolisCrypto.encryptToken("caché".toByteArray(), key)
        val input = "clair\n$token\n[[BROCOLIS:v1:AAAA]]"
        val r = BrocolisConversation.render(input, listOf(key))
        assertEquals(3, r.lines.size)
        assertEquals(BrocolisConversation.Status.CLEAR, r.lines[0].status)
        assertEquals(BrocolisConversation.Status.DECRYPTED, r.lines[1].status)
        assertEquals(BrocolisConversation.Status.LOCKED, r.lines[2].status)
        assertEquals(1, r.decryptedCount)
        assertEquals(1, r.lockedCount)
    }
}
