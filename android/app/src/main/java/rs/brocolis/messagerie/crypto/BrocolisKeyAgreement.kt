package rs.brocolis.messagerie.crypto

import rs.brocolis.messagerie.store.BrocolisKeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

/**
 * Accord de clé X25519 (ECDH) + HKDF-SHA256, INTEROPÉRABLE avec l'app iOS
 * (CryptoKit `Curve25519.KeyAgreement`). On échange les clés PUBLIQUES via le
 * serveur de rendez-vous, puis chacun dérive de son côté la MÊME clé AES-256.
 *
 * Détails devant matcher iOS bit à bit :
 *  - secret partagé = sortie brute X25519 (32 octets) ;
 *  - info = concat lexicographique(pubA, pubB) — identique des deux côtés ;
 *  - clé = HKDF(SHA256, ikm=secret, salt="brocolis-x25519", info, L=32) ;
 *  - empreinte = SHA256(info), 8 premiers octets, hex groupé par 4.
 */
object BrocolisKeyAgreement {

    private val salt = "brocolis-x25519".toByteArray(Charsets.UTF_8)
    private val wrapSalt = "brocolis-x25519-wrap".toByteArray(Charsets.UTF_8)

    class AgreementException(message: String) : Exception(message)

    data class Derived(val symmetricKeyBase64: String, val fingerprint: String)

    // MARK: Clé privée locale (persistée dans le store, comme iOS)

    fun loadOrCreatePrivateKey(): X25519PrivateKeyParameters {
        BrocolisKeyStore.privateKeyBase64?.let { b64 ->
            BrocolisCrypto.b64decode(b64)?.let { raw ->
                if (raw.size == 32) return X25519PrivateKeyParameters(raw, 0)
            }
        }
        val priv = X25519PrivateKeyParameters(SecureRandom())
        BrocolisKeyStore.privateKeyBase64 = BrocolisCrypto.b64encode(priv.encoded)
        return priv
    }

    fun publicKeyBase64(priv: X25519PrivateKeyParameters): String =
        BrocolisCrypto.b64encode(priv.generatePublicKey().encoded)

    // MARK: Dérivation (appairage à deux)

    @Throws(AgreementException::class)
    fun derive(myPrivate: X25519PrivateKeyParameters, peerPublicBase64: String): Derived {
        val peerData = BrocolisCrypto.b64decode(peerPublicBase64.trim())
            ?: throw AgreementException("Clé publique du correspondant invalide.")
        if (peerData.size != 32) throw AgreementException("Clé publique du correspondant invalide.")

        val shared = sharedSecret(myPrivate, peerData)
        val myPub = myPrivate.generatePublicKey().encoded
        val info = sortedConcat(myPub, peerData)
        val derivedKey = hkdf(shared, salt, info, 32)
        return Derived(BrocolisCrypto.b64encode(derivedKey), fingerprint(info))
    }

    // MARK: Clé de groupe (key-wrapping X25519)

    fun generateGroupKeyBase64(): String = BrocolisCrypto.generateKeyBase64()

    @Throws(AgreementException::class)
    fun wrapGroupKey(
        groupKeyBase64: String,
        forPeerPublicBase64: String,
        myPrivate: X25519PrivateKeyParameters
    ): String {
        val groupKey = BrocolisCrypto.b64decode(groupKeyBase64)
            ?: throw AgreementException("Clé de groupe invalide.")
        val peerPub = peerPublicData(forPeerPublicBase64)
        val wrapKey = pairwiseWrapKey(myPrivate, peerPub)
        val combined = try {
            // AES-GCM combined, via le chemin bas niveau de BrocolisCrypto.
            aesGcmSeal(groupKey, wrapKey)
        } catch (e: Exception) { throw AgreementException("Échec de l'emballage.") }
        return BrocolisCrypto.b64encode(combined)
    }

    @Throws(AgreementException::class)
    fun unwrapGroupKey(
        blobBase64: String,
        fromPeerPublicBase64: String,
        myPrivate: X25519PrivateKeyParameters
    ): String {
        val packed = BrocolisCrypto.b64decode(blobBase64)
            ?: throw AgreementException("Blob invalide.")
        val fromPub = peerPublicData(fromPeerPublicBase64)
        val wrapKey = pairwiseWrapKey(myPrivate, fromPub)
        val groupKey = try { aesGcmOpen(packed, wrapKey) }
            catch (e: Exception) { throw AgreementException("Échec du déballage.") }
        return BrocolisCrypto.b64encode(groupKey)
    }

    fun groupFingerprint(groupKeyBase64: String): String {
        val data = BrocolisCrypto.b64decode(groupKeyBase64) ?: ByteArray(0)
        return fingerprint(data)
    }

    // MARK: Interne

    private fun pairwiseWrapKey(myPrivate: X25519PrivateKeyParameters, peerPub: ByteArray): ByteArray {
        val shared = sharedSecret(myPrivate, peerPub)
        val info = sortedConcat(myPrivate.generatePublicKey().encoded, peerPub)
        return hkdf(shared, wrapSalt, info, 32)
    }

    private fun peerPublicData(b64: String): ByteArray {
        val d = BrocolisCrypto.b64decode(b64.trim())
            ?: throw AgreementException("Clé publique invalide.")
        if (d.size != 32) throw AgreementException("Clé publique invalide.")
        return d
    }

    private fun sharedSecret(priv: X25519PrivateKeyParameters, peerPub: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(priv)
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(peerPub, 0), out, 0)
        return out
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val gen = HKDFBytesGenerator(SHA256Digest())
        gen.init(HKDFParameters(ikm, salt, info))
        val out = ByteArray(length)
        gen.generateBytes(out, 0, length)
        return out
    }

    // AES-GCM « combined » — réutilise le même format que BrocolisCrypto.
    private fun aesGcmSeal(plaintext: ByteArray, key: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, nonce)
        )
        return nonce + cipher.doFinal(plaintext)
    }

    private fun aesGcmOpen(combined: ByteArray, key: ByteArray): ByteArray {
        val nonce = combined.copyOfRange(0, 12)
        val ct = combined.copyOfRange(12, combined.size)
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            javax.crypto.Cipher.DECRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, nonce)
        )
        return cipher.doFinal(ct)
    }

    private fun sortedConcat(a: ByteArray, b: ByteArray): ByteArray =
        if (lexLessOrEqual(a, b)) a + b else b + a

    private fun lexLessOrEqual(a: ByteArray, b: ByteArray): Boolean {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val x = a[i].toInt() and 0xFF
            val y = b[i].toInt() and 0xFF
            if (x != y) return x < y
        }
        return a.size <= b.size
    }

    /** Empreinte lisible (8 octets hex, groupés par 4) à comparer de vive voix. */
    fun fingerprint(info: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(info)
        val hex = digest.take(8).joinToString("") { "%02X".format(it) }
        val out = StringBuilder()
        for ((i, ch) in hex.withIndex()) {
            if (i != 0 && i % 4 == 0) out.append("-")
            out.append(ch)
        }
        return out.toString()
    }
}
