package rs.brocolis.messagerie.proto

import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters

/**
 * ML-KEM-768 (FIPS 203), par BouncyCastle (`brocolis_proto::paquet::mlkem_*`).
 *
 * - le secret est gardé sous sa forme FIPS 203 « graine » `d ‖ z` (64
 *   octets, §7.3) ;
 * - l'aléa d'encapsulation `m` (32 octets) est tiré par l'appelant :
 *   BouncyCastle accepte un `m` imposé, les vecteurs se retrouvent donc aussi
 *   par l'encapsulation (pas seulement par la décapsulation) ;
 * - une clé d'encapsulation reçue passe le contrôle du module de FIPS 203
 *   (§7.6.2) : sinon [Erreur.CleInvalide].
 */
object MlKem {
    /** La longueur d'une clé d'encapsulation ML-KEM-768. */
    const val PUBLIC_LEN = 1_184
    /** La longueur d'un chiffré ML-KEM-768. */
    const val CIPHERTEXT_LEN = 1_088
    /** La longueur d'une graine `d ‖ z`. */
    const val SEED_LEN = 64

    private val params: MLKEMParameters = MLKEMParameters.ml_kem_768

    private fun privateKey(seed: ByteArray): MLKEMPrivateKeyParameters {
        if (seed.size != SEED_LEN) echec(Erreur.Format)
        return MLKEMPrivateKeyParameters(params, seed)
    }

    /** La clé d'encapsulation ML-KEM-768 (1 184 octets) d'une graine `d ‖ z`. */
    fun publicKey(seed: ByteArray): ByteArray {
        val sk = privateKey(seed)
        try {
            return sk.publicKey
        } finally {
            sk.destroy()
        }
    }

    /** Vrai si `pqpk` est une clé d'encapsulation ML-KEM-768 valide (longueur, module). */
    fun isValidPublicKey(pqpk: ByteArray): Boolean = try {
        parsePublic(pqpk)
        true
    } catch (_: BrocolisException) {
        false
    }

    private fun parsePublic(pqpk: ByteArray): MLKEMPublicKeyParameters {
        if (pqpk.size != PUBLIC_LEN) echec(Erreur.CleInvalide)
        return try {
            MLKEMPublicKeyParameters(params, pqpk)
        } catch (_: IllegalArgumentException) {
            echec(Erreur.CleInvalide)
        }
    }

    /**
     * ML-KEM-768.Encaps avec le message `m` donné (32 octets aléatoires) :
     * `(CT, SS)`. Refuse une clé d'encapsulation invalide.
     */
    fun encapsulate(pqpk: ByteArray, m: ByteArray): Pair<ByteArray, ByteArray> {
        require(m.size == 32) { "m de 32 octets" }
        val pk = parsePublic(pqpk)
        val sw = MLKEMGenerator.internalGenerateEncapsulated(pk, m)
        try {
            return Pair(sw.encapsulation, sw.secret)
        } finally {
            sw.destroy()
        }
    }

    /**
     * ML-KEM-768.Decaps (rejet implicite : un chiffré altéré donne un secret
     * faux, sans erreur, et le message est ensuite refusé). Un chiffré de
     * mauvaise longueur : [Erreur.Format].
     */
    fun decapsulate(seed: ByteArray, ct: ByteArray): ByteArray {
        if (ct.size != CIPHERTEXT_LEN) echec(Erreur.Format)
        val sk = privateKey(seed)
        try {
            return MLKEMExtractor(sk).extractSecret(ct)
        } finally {
            sk.destroy()
        }
    }
}
