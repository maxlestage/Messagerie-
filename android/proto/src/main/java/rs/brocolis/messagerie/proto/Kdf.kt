package rs.brocolis.messagerie.proto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Les primitives et chaque dérivation du protocole (`brocolis_proto::kdf`),
 * exposées telles quelles pour que les vecteurs vérifient chaque étape
 * intermédiaire.
 *
 * | Fonction | Spécification |
 * |---|---|
 * | [skX3dh] | §4.2 : `HKDF(0³², FF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ SS], info)` |
 * | [skPsk] | §4.2 : clé partagée |
 * | [kdfRk] | §4.3 `KDF_RK` |
 * | [kdfCk] | §4.3 `KDF_CK` |
 * | [messageKey] | §4.3 `ENCRYPT(mk)` → clé AES ‖ nonce |
 * | [sessionId] | §4.4 `SHA-256(AD)[0..8]` |
 *
 * Primitives : BouncyCastle (SHA-256, HMAC, HKDF, X25519, Ed25519) et
 * javax.crypto (AES-256-GCM : Conscrypt, donc l'AES matériel, sur Android).
 */
object Kdf {
    /** `"Brocolis_v3_X25519_MLKEM768_SHA-256"` : l'info de SK avec ML-KEM. */
    val INFO_PQ: ByteArray = Octets.utf8("Brocolis_v3_X25519_MLKEM768_SHA-256")
    /** `"Brocolis_v3_X25519_SHA-256"` : l'info de SK sans ML-KEM (`pq = 0`). */
    val INFO_CLASSIQUE: ByteArray = Octets.utf8("Brocolis_v3_X25519_SHA-256")
    /** `"Brocolis_v3_PSK_SHA-256"` : l'info de SK pour une clé partagée. */
    val INFO_PSK: ByteArray = Octets.utf8("Brocolis_v3_PSK_SHA-256")
    /** `"Brocolis_v3_PSK_Ratchet"` : la clé de cliquet initiale du répondeur d'une session à clé partagée (§7.4). */
    val INFO_PSK_RATCHET: ByteArray = Octets.utf8("Brocolis_v3_PSK_Ratchet")
    /** `"Brocolis_v3_Ratchet"` : l'info de `KDF_RK`. */
    val INFO_RATCHET: ByteArray = Octets.utf8("Brocolis_v3_Ratchet")
    /** `"Brocolis_v3_MessageKeys"` : l'info de `ENCRYPT(mk)`. */
    val INFO_MESSAGE: ByteArray = Octets.utf8("Brocolis_v3_MessageKeys")

    /** 32 octets nuls : le sel des HKDF « sans sel » de la spécification. */
    val SEL_NUL: ByteArray get() = ByteArray(32)

    // ----- Primitives --------------------------------------------------------

    /** SHA-256. */
    fun sha256(data: ByteArray): ByteArray {
        val d = SHA256Digest()
        d.update(data, 0, data.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    /** HMAC-SHA256 (clé de toute longueur, vide comprise). */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        return ByteArray(32).also { mac.doFinal(it, 0) }
    }

    /**
     * HKDF-SHA256 (RFC 5869) de longueur quelconque ; refuse
     * ([Erreur.TropGrand]) une longueur au-delà de 255 × 32 octets.
     */
    fun hkdfSha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, len: Int): ByteArray {
        if (len < 0 || len > 255 * 32) echec(Erreur.TropGrand)
        val out = ByteArray(len)
        if (len == 0) return out
        val g = HKDFBytesGenerator(SHA256Digest())
        g.init(HKDFParameters(ikm, salt, info))
        g.generateBytes(out, 0, len)
        return out
    }

    /**
     * AES-256-GCM, nonce de 12 octets : chiffré ‖ tag (16).
     */
    fun aesGcmSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, msg: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "AES-256-GCM : clé de 32 octets, nonce de 12" }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) c.updateAAD(aad)
        return c.doFinal(msg)
    }

    /**
     * Ouvre un AES-256-GCM (chiffré ‖ tag) ; le tag est vérifié en temps
     * constant par le fournisseur. Échec : [Erreur.Dechiffrement].
     */
    fun aesGcmOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12) { "AES-256-GCM : clé de 32 octets, nonce de 12" }
        if (ct.size < 16) echec(Erreur.Dechiffrement)
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            if (aad.isNotEmpty()) c.updateAAD(aad)
            c.doFinal(ct)
        } catch (_: AEADBadTagException) {
            echec(Erreur.Dechiffrement)
        }
    }

    // ----- X25519 ------------------------------------------------------------

    /**
     * La clé publique X25519 d'un secret de 32 octets (bruts, réduits par
     * RFC 7748 au moment du calcul, comme dalek et CryptoKit).
     */
    fun x25519Public(secret: ByteArray): ByteArray {
        require(secret.size == 32) { "secret X25519 de 32 octets" }
        return ByteArray(32).also { X25519.scalarMultBase(secret, 0, it, 0) }
    }

    /**
     * Vrai si une clé publique X25519 est **canonique** : bit 255 nul et
     * u < 2²⁵⁵ − 19 (§7.3). RFC 7748 ignore le bit 255 et réduit u modulo p :
     * sans ce contrôle, une même clé aurait plusieurs écritures.
     */
    fun x25519IsCanonical(public: ByteArray): Boolean {
        if (public.size != 32) return false
        if (public[31].toInt() and 0x80 != 0) return false
        // u ≥ p ⇔ u = 2²⁵⁵ − 19 + k, k < 19 : 0x7f, 30 × 0xff, puis ≥ 0xed.
        if (public[31].toInt() and 0xff != 0x7f) return true
        for (i in 1..30) if (public[i].toInt() and 0xff != 0xff) return true
        return (public[0].toInt() and 0xff) < 0xed
    }

    /**
     * X25519(secret, public). Refuse ([Erreur.CleInvalide]) une clé publique
     * non canonique ([x25519IsCanonical]) et un résultat nul (clé publique de
     * petit ordre).
     */
    fun x25519(secret: ByteArray, public: ByteArray): ByteArray {
        require(secret.size == 32) { "secret X25519 de 32 octets" }
        if (!x25519IsCanonical(public)) echec(Erreur.CleInvalide)
        val out = ByteArray(32)
        X25519.scalarMult(secret, 0, public, 0, out, 0)
        if (Octets.isZero(out)) echec(Erreur.CleInvalide)
        return out
    }

    // ----- Ed25519 -----------------------------------------------------------

    /** La clé publique Ed25519 d'une graine de 32 octets (RFC 8032). */
    fun ed25519Public(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "graine Ed25519 de 32 octets" }
        return ByteArray(32).also { Ed25519.generatePublicKey(seed, 0, it, 0) }
    }

    /** Signe (Ed25519 déterministe, RFC 8032 : mêmes octets que dalek). */
    fun ed25519Sign(seed: ByteArray, msg: ByteArray): ByteArray {
        require(seed.size == 32) { "graine Ed25519 de 32 octets" }
        return ByteArray(64).also { Ed25519.sign(seed, 0, msg, 0, msg.size, it, 0) }
    }

    /**
     * Vrai si `public` est une clé Ed25519 utilisable, comme ed25519-dalek la
     * juge (`VerifyingKey::from_bytes` puis `!is_weak()`) : un point de la
     * courbe qui n'est pas de petit ordre. Comme dalek, une écriture de y non
     * réduite (y ≥ p) est lue modulo p.
     */
    fun ed25519IsValidPublic(public: ByteArray): Boolean {
        if (public.size != 32) return false
        var enc = public
        if (yNonCanonique(public)) {
            // y = p + k (k < 19) : la même chose que y = k, signe gardé.
            enc = ByteArray(32)
            enc[0] = ((public[0].toInt() and 0xff) - 0xed).toByte()
            enc[31] = (public[31].toInt() and 0x80).toByte()
        }
        return Ed25519.validatePublicKeyPartial(enc, 0)
    }

    private fun yNonCanonique(e: ByteArray): Boolean {
        if (e[31].toInt() and 0x7f != 0x7f) return false
        for (i in 1..30) if (e[i].toInt() and 0xff != 0xff) return false
        return (e[0].toInt() and 0xff) >= 0xed
    }

    /**
     * Vérifie une signature Ed25519 (vérification **stricte**, §7.3, comme
     * `verify_strict` d'ed25519-dalek : R et A de petit ordre et S non
     * canonique refusés). Clé publique inutilisable : [Erreur.CleInvalide] ;
     * signature fausse : [Erreur.Signature].
     *
     * BouncyCastle refuse déjà S ≥ L, A de petit ordre et toute écriture non
     * canonique ; on exige en plus que A et R soient d'ordre L (sans
     * composante de torsion). L'équation de BouncyCastle devient alors
     * exactement celle, sans cofacteur, de `verify_strict` ; une signature
     * valide pour dalek n'est refusée ici que si A elle-même a une composante
     * de torsion (une clé qu'aucun appareil honnête ne produit).
     */
    fun ed25519Verify(public: ByteArray, msg: ByteArray, sig: ByteArray) {
        if (!ed25519IsValidPublic(public)) echec(Erreur.CleInvalide)
        if (sig.size != 64) echec(Erreur.Signature)
        val ok = Ed25519.validatePublicKeyFull(public, 0) &&
            Ed25519.validatePublicKeyFull(sig, 0) &&
            Ed25519.verify(sig, 0, public, 0, msg, 0, msg.size)
        if (!ok) echec(Erreur.Signature)
    }

    // ----- Dérivations du protocole -------------------------------------------

    /**
     * SK de l'établissement (§4.2) : `HKDF-SHA256(sel = 32 × 0x00, ikm = 32 ×
     * 0xFF ‖ DH1 ‖ DH2 ‖ DH3 [‖ SS], info)`. Avec `ss`, l'info est [INFO_PQ] ;
     * sans, [INFO_CLASSIQUE].
     */
    fun skX3dh(dh1: ByteArray, dh2: ByteArray, dh3: ByteArray, ss: ByteArray?): ByteArray {
        val ff = ByteArray(32) { 0xFF.toByte() }
        val ikm = if (ss != null) Octets.concat(ff, dh1, dh2, dh3, ss) else Octets.concat(ff, dh1, dh2, dh3)
        try {
            return hkdfSha256(SEL_NUL, ikm, if (ss != null) INFO_PQ else INFO_CLASSIQUE, 32)
        } finally {
            Octets.wipe(ikm)
        }
    }

    /** SK d'une session à clé partagée (§4.2) : `HKDF(0³², clé, "Brocolis_v3_PSK_SHA-256", 32)`. */
    fun skPsk(key: ByteArray): ByteArray = hkdfSha256(SEL_NUL, key, INFO_PSK, 32)

    /**
     * Le secret X25519 (32 octets bruts) de la clé de cliquet initiale du
     * répondeur d'une session à clé partagée :
     * `HKDF(0³², SK, "Brocolis_v3_PSK_Ratchet", 32)`.
     */
    fun pskRatchetSecret(sk: ByteArray): ByteArray = hkdfSha256(SEL_NUL, sk, INFO_PSK_RATCHET, 32)

    /** `KDF_RK(rk, dh) = HKDF-SHA256(sel = rk, ikm = dh, "Brocolis_v3_Ratchet", 64)` → `(rk', ck)`. */
    fun kdfRk(rk: ByteArray, dh: ByteArray): Pair<ByteArray, ByteArray> {
        val out = hkdfSha256(rk, dh, INFO_RATCHET, 64)
        try {
            return Pair(out.sub(0, 32), out.sub(32, 64))
        } finally {
            Octets.wipe(out)
        }
    }

    /** `KDF_CK(ck)` → `(ck', mk)` avec `mk = HMAC-SHA256(ck, 0x01)` et `ck' = HMAC-SHA256(ck, 0x02)`. */
    fun kdfCk(ck: ByteArray): Pair<ByteArray, ByteArray> {
        val mk = hmacSha256(ck, byteArrayOf(0x01))
        val next = hmacSha256(ck, byteArrayOf(0x02))
        return Pair(next, mk)
    }

    /** `ENCRYPT(mk)` : `HKDF-SHA256(sel = 32 × 0x00, ikm = mk, "Brocolis_v3_MessageKeys", 44)` → clé AES (32) et nonce (12). */
    fun messageKey(mk: ByteArray): Pair<ByteArray, ByteArray> {
        val out = hkdfSha256(SEL_NUL, mk, INFO_MESSAGE, 44)
        try {
            return Pair(out.sub(0, 32), out.sub(32, 44))
        } finally {
            Octets.wipe(out)
        }
    }

    /** L'identifiant de session : `SHA-256(AD)[0..8]` (§4.4). */
    fun sessionId(ad: ByteArray): ByteArray = sha256(ad).sub(0, 8)

    /**
     * L'empreinte à comparer de vive voix (`AB12-CD34-EF56-7890`) : les 8
     * premiers octets du SHA-256 des données, en hexadécimal majuscule.
     */
    fun fingerprint(data: ByteArray): String {
        val h = Octets.hex(sha256(data).sub(0, 8)).uppercase()
        return h.chunked(4).joinToString("-")
    }
}
