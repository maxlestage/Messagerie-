package rs.brocolis.messagerie.proto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter

/**
 * Les paramètres Argon2id d'une clé protégée v2 (§3.2, §7.1).
 *
 * @property mKib m : mémoire, en Kio (u32).
 * @property t t : nombre de passes (u8).
 * @property p p : parallélisme (u8).
 */
data class Argon2Params(val mKib: Long, val t: Int, val p: Int) {
    /**
     * Vérifie les bornes de §3.2 (m ≥ 19 456, t ≥ 2, m ≤ 1 048 576), plus
     * p ≥ 1, t ≤ 16 et m ≥ 8p (§7.1) : sinon [Erreur.Parametres].
     */
    fun check() {
        val ok = mKib >= MINIMUM.mKib && mKib <= MAX_M_KIB &&
            t >= 2 && t <= MAX_T && p >= 1 && p <= 255 && mKib >= 8L * p
        if (!ok) echec(Erreur.Parametres)
    }

    companion object {
        /** Le défaut : 64 Mio, 3 passes, 1 voie (§3.2). */
        val DEFAULT = Argon2Params(65_536, 3, 1)
        /** Les plus petits paramètres acceptés à l'import (19 Mio, 2 passes, 1 voie : le minimum de l'OWASP). */
        val MINIMUM = Argon2Params(19_456, 2, 1)
        /** La plus grande mémoire acceptée (1 Gio). */
        const val MAX_M_KIB: Long = 1_048_576
        /** Le plus grand nombre de passes accepté (§7.1). */
        const val MAX_T: Int = 16
    }
}

/**
 * Une clé Brocolis (32 octets) protégée par une phrase secrète (§3.2), pour
 * la sortir de l'appareil sans la montrer (`brocolis_proto::cle_protegee`).
 *
 * - `[[BROCOLIS-CLE:v1:<base64>]]` (lecture seulement) : sel (16) ‖ nonce
 *   (12) ‖ AES-256-GCM(clé) ‖ tag, sous PBKDF2-HMAC-SHA256(phrase, sel,
 *   600 000 tours), données associées `brocolis-cle-v1` ;
 * - `[[BROCOLIS-CLE:v2:<base64>]]` (par défaut) : Argon2id, format exact de
 *   §3.2 (83 octets), l'en-tête et les paramètres authentifiés.
 *
 * Argon2id (64 Mio) et PBKDF2 (600 000 tours) prennent du temps : à appeler
 * hors du fil principal.
 */
object CleProtegee {
    /** Le début d'une clé protégée v1. */
    const val HEAD_V1 = "[[BROCOLIS-CLE:v1:"
    /** Le début d'une clé protégée v2. */
    const val HEAD_V2 = "[[BROCOLIS-CLE:v2:"
    private const val END = "]]"
    private val AD_V1 = Octets.utf8("brocolis-cle-v1")
    /** Les tours de PBKDF2 de la v1. */
    const val PBKDF2_ROUNDS = 600_000
    /** La phrase la plus courte acceptée (en caractères) pour protéger une clé ; à l'import, toute phrase est essayée. */
    const val PHRASE_MIN = 8
    private const val V1_LEN = 16 + 12 + 32 + 16
    private const val V2_LEN = 83
    private const val V2_HEADER = 35

    private fun pbkdf2Key(phrase: String, salt: ByteArray): ByteArray {
        val g = PKCS5S2ParametersGenerator(SHA256Digest())
        val pw = Octets.utf8(phrase)
        try {
            g.init(pw, salt, PBKDF2_ROUNDS)
            return (g.generateDerivedParameters(256) as KeyParameter).key
        } finally {
            Octets.wipe(pw)
        }
    }

    /**
     * La clé de chiffrement v2 : `Argon2id(phrase UTF-8, sel, m, t, p, 32)`
     * (version 0x13, sans secret ni données associées Argon2). Vérifie les
     * paramètres d'abord.
     */
    fun argon2idKey(phrase: String, salt: ByteArray, params: Argon2Params): ByteArray {
        params.check()
        return argon2id(Octets.utf8(phrase), salt, params.mKib.toInt(), params.t, params.p, 32)
    }

    /** Argon2id brut (version 0x13), sans contrôle des bornes : les tests le comparent à la crate `argon2`. */
    internal fun argon2id(password: ByteArray, salt: ByteArray, mKib: Int, t: Int, p: Int, len: Int): ByteArray {
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(mKib)
            .withIterations(t)
            .withParallelism(p)
            .withSalt(salt)
            .build()
        val g = Argon2BytesGenerator()
        g.init(params)
        val out = ByteArray(len)
        try {
            g.generateBytes(password, out)
        } finally {
            Octets.wipe(password)
        }
        return out
    }

    /** Le contenu entre `head` et `]]` dans un texte collé. */
    private fun inner(text: String, head: String): String? {
        val i = text.indexOf(head)
        if (i < 0) return null
        val start = i + head.length
        val end = text.indexOf(END, start)
        if (end < 0) return null
        return text.substring(start, end)
    }

    /** Vrai si le texte contient une clé protégée (v1 ou v2). */
    fun hasProtectedKey(text: String): Boolean = text.contains(HEAD_V1) || text.contains(HEAD_V2)

    /**
     * Écrit une clé protégée v1 avec un sel et un nonce donnés. **Héritage** :
     * sert aux vecteurs et à l'interopérabilité ; on n'écrit plus que la v2.
     */
    fun protectKeyV1With(key: ByteArray, phrase: String, salt: ByteArray, nonce: ByteArray): String {
        require(key.size == 32 && salt.size == 16 && nonce.size == 12)
        val k = pbkdf2Key(phrase, salt)
        try {
            val ct = Kdf.aesGcmSeal(k, nonce, AD_V1, key)
            return HEAD_V1 + Octets.b64(Octets.concat(salt, nonce, ct)) + END
        } finally {
            Octets.wipe(k)
        }
    }

    /**
     * Écrit une clé protégée v2 avec des paramètres, un sel et un nonce donnés
     * (les vecteurs ; [protectKey] tire sel et nonce au hasard).
     */
    fun protectKeyV2With(key: ByteArray, phrase: String, params: Argon2Params, salt: ByteArray, nonce: ByteArray): String {
        require(key.size == 32 && salt.size == 16 && nonce.size == 12)
        if (phrase.codePointCount(0, phrase.length) < PHRASE_MIN) echec(Erreur.PhraseTropCourte)
        val header = Octets.concat(
            byteArrayOf(0x02), Octets.u32be(params.mKib), byteArrayOf(params.t.toByte(), params.p.toByte()), salt, nonce,
        )
        val k = argon2idKey(phrase, salt, params)
        try {
            val ct = Kdf.aesGcmSeal(k, nonce, header, key)
            return HEAD_V2 + Octets.b64(Octets.concat(header, ct)) + END
        } finally {
            Octets.wipe(k)
        }
    }

    /**
     * Protège une clé par une phrase secrète (v2, paramètres par défaut, sel
     * et nonce aléatoires). Refuse une phrase de moins de [PHRASE_MIN]
     * caractères.
     */
    fun protectKey(key: ByteArray, phrase: String, rng: CryptoRng = Hasard.system()): String =
        protectKeyV2With(key, phrase, Argon2Params.DEFAULT, rng.bytes(16), rng.bytes(12))

    /**
     * Retrouve la clé d'un jeton `[[BROCOLIS-CLE:v1:…]]` ou `v2` collé (seul
     * ou dans un texte ; la v2 est cherchée d'abord). Phrase fausse ou jeton
     * abîmé : [Erreur.Dechiffrement] ; paramètres v2 hors bornes :
     * [Erreur.Parametres] (avant tout calcul).
     */
    fun unprotectKey(text: String, phrase: String): ByteArray {
        inner(text, HEAD_V2)?.let { return unprotectV2(it, phrase) }
        inner(text, HEAD_V1)?.let { return unprotectV1(it, phrase) }
        echec(Erreur.JetonAbsent)
    }

    private fun decode(b: String, len: Int): ByteArray {
        // Une clé protégée fait moins de 120 caractères : rien à décoder au-delà.
        if (Octets.utf8Len(b) > 4L * ((len + 2) / 3)) echec(Erreur.Format)
        val data = Octets.unb64OrThrow(b)
        if (data.size != len) {
            Octets.wipe(data)
            echec(Erreur.Format)
        }
        return data
    }

    private fun toKey(plain: ByteArray): ByteArray {
        if (plain.size != 32) {
            Octets.wipe(plain)
            echec(Erreur.Format)
        }
        return plain
    }

    private fun unprotectV1(b: String, phrase: String): ByteArray {
        val data = decode(b, V1_LEN)
        val k = pbkdf2Key(phrase, data.sub(0, 16))
        try {
            return toKey(Kdf.aesGcmOpen(k, data.sub(16, 28), AD_V1, data.sub(28, data.size)))
        } finally {
            Octets.wipe(k, data)
        }
    }

    /** Les paramètres d'une clé protégée v2 (sans la phrase), pour prévenir l'utilisateur avant un calcul long. */
    fun v2Params(text: String): Argon2Params {
        val data = decode(inner(text, HEAD_V2) ?: echec(Erreur.JetonAbsent), V2_LEN)
        return parseV2Params(data)
    }

    internal fun parseV2Params(data: ByteArray): Argon2Params {
        if (data[0].toInt() != 0x02) echec(Erreur.Format)
        val params = Argon2Params(Octets.readU32(data, 1), data[5].toInt() and 0xff, data[6].toInt() and 0xff)
        params.check()
        return params
    }

    private fun unprotectV2(b: String, phrase: String): ByteArray {
        val data = decode(b, V2_LEN)
        try {
            val params = parseV2Params(data)
            val k = argon2idKey(phrase, data.sub(7, 23), params)
            try {
                return toKey(Kdf.aesGcmOpen(k, data.sub(23, 35), data.sub(0, V2_HEADER), data.sub(V2_HEADER, V2_LEN)))
            } finally {
                Octets.wipe(k)
            }
        } finally {
            Octets.wipe(data)
        }
    }
}
