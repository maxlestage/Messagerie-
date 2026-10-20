package rs.brocolis.messagerie.proto

/**
 * Les jetons de Brocolis v1 et v2, et les passages `((…))`
 * (`brocolis_proto::jetons`) : exactement le comportement de
 * `talka-web::jetons` (Talka) et de `BrocolisCrypto` (iOS, Android), qui
 * restent lisibles pour toujours (§4.6).
 *
 * - une clé : 32 octets (AES-256), en base64 standard ;
 * - `[[BROCOLIS:v1:<base64>]]` : AES-256-GCM « combined » (nonce 12 octets ‖
 *   chiffré ‖ tag 16 octets), pour une seule clé ;
 * - `[[BROCOLIS:v2:<base64>]]` : une enveloppe pour plusieurs clés : `0x01`,
 *   N, puis N clés de message emballées (60 octets chacune), puis le corps
 *   chiffré sous la clé de message ;
 * - `((…))` : seuls ces passages sont chiffrés, le reste part en clair.
 *
 * Pas de remplissage ni de données associées : ce sont les formats
 * historiques, tels quels. Les jetons v3 sont ceux de [Token] ; ici, ils
 * restent « verrouillés ».
 */
object Jetons {
    /** Le début de tout jeton Brocolis. */
    const val HEAD = "[[BROCOLIS:"
    private const val V1 = "v1:"
    private const val V2 = "v2:"
    private const val END = "]]"
    private const val MARK_OPEN = "(("
    private const val MARK_CLOSE = "))"
    private const val WRAPPED = 12 + 32 + 16
    private const val SEPARATEURS = "«»\"'“”()[]<>"

    /** Une clé Brocolis en base64 (32 octets), ou `null`. */
    fun keyFromB64(text: String): ByteArray? = Octets.unb64(Octets.rustTrim(text))?.takeIf { it.size == 32 }

    /**
     * Retrouve une clé dans un texte collé (l'invitation de l'app Brocolis
     * entière, par exemple) : le premier mot qui est une clé.
     */
    fun findKey(text: String): String? {
        var start = 0
        var i = 0
        while (true) {
            val atEnd = i >= text.length
            val cp = if (atEnd) 0 else text.codePointAt(i)
            if (atEnd || Octets.isRustWhitespace(cp) || (cp < 0x10000 && SEPARATEURS.indexOf(cp.toChar()) >= 0)) {
                val w = text.substring(start, i)
                if (keyFromB64(w) != null) return Octets.rustTrim(w)
                if (atEnd) return null
                i += Character.charCount(cp)
                start = i
            } else {
                i += Character.charCount(cp)
            }
        }
    }

    /**
     * L'empreinte d'une clé, à comparer de vive voix (`AB12-CD34-EF56-7890`) :
     * les 8 premiers octets de son SHA-256.
     */
    fun fingerprint(keyB64: String): String? = keyFromB64(keyB64)?.let { Kdf.fingerprint(it) }

    /** Une nouvelle clé, en base64. */
    fun generateKey(rng: CryptoRng = Hasard.system()): String {
        val k = rng.bytes(32)
        try {
            return Octets.b64(k)
        } finally {
            Octets.wipe(k)
        }
    }

    /** Vrai si le texte contient un jeton Brocolis (toute version). */
    fun hasToken(text: String): Boolean = text.contains(HEAD)

    private fun sealRaw(key: ByteArray, plain: ByteArray, rng: CryptoRng): ByteArray {
        val nonce = rng.bytes(12)
        return Octets.concat(nonce, Kdf.aesGcmSeal(key, nonce, ByteArray(0), plain))
    }

    private fun openRaw(key: ByteArray, combined: ByteArray): ByteArray? {
        if (combined.size < 12 + 16 || key.size != 32) return null
        return try {
            Kdf.aesGcmOpen(key, combined.sub(0, 12), ByteArray(0), combined.sub(12, combined.size))
        } catch (_: BrocolisException) {
            null
        }
    }

    /**
     * Un jeton pour `text` : `v1` pour une clé (lisible par toutes les
     * versions de Brocolis), `v2` pour plusieurs (255 au plus).
     */
    fun sealToken(text: String, keys: List<ByteArray>, rng: CryptoRng): String? {
        return when {
            keys.isEmpty() -> null
            keys.size == 1 -> HEAD + V1 + Octets.b64(sealRaw(keys[0], Octets.utf8(text), rng)) + END
            keys.size > 255 -> null
            else -> {
                val messageKey = rng.bytes(32)
                try {
                    val parts = mutableListOf(byteArrayOf(1, keys.size.toByte()))
                    for (k in keys) parts.add(sealRaw(k, messageKey, rng))
                    parts.add(sealRaw(messageKey, Octets.utf8(text), rng))
                    HEAD + V2 + Octets.b64(Octets.concat(*parts.toTypedArray())) + END
                } finally {
                    Octets.wipe(messageKey)
                }
            }
        }
    }

    /**
     * Chiffre un message : les passages `((…))` s'il y en a, sinon tout le
     * texte. Un texte qui porte déjà un jeton part tel quel.
     */
    fun sealWith(text: String, keys: List<ByteArray>, rng: CryptoRng): String {
        if (text.isEmpty() || keys.isEmpty() || hasToken(text)) return text
        val out = StringBuilder()
        var rest = text
        var marked = false
        while (true) {
            val start = rest.indexOf(MARK_OPEN)
            if (start < 0) break
            val after = rest.substring(start + MARK_OPEN.length)
            val end = after.indexOf(MARK_CLOSE)
            if (end < 0) break
            out.append(rest, 0, start)
            out.append(sealToken(after.substring(0, end), keys, rng) ?: rest.substring(start, start + MARK_OPEN.length + end + MARK_CLOSE.length))
            marked = true
            rest = after.substring(end + MARK_CLOSE.length)
        }
        if (!marked) return sealToken(text, keys, rng) ?: text
        out.append(rest)
        return out.toString()
    }

    /** [sealWith] avec le hasard du système. */
    fun seal(text: String, keys: List<ByteArray>): String = sealWith(text, keys, Hasard.system())

    private fun openV2(payload: ByteArray, keys: List<ByteArray>): ByteArray? {
        if (payload.size < 2) return null
        val format = payload[0].toInt() and 0xff
        val n = payload[1].toInt() and 0xff
        if (format != 1 || payload.size - 2 < n * WRAPPED + 12 + 16) return null
        val body = payload.sub(2 + n * WRAPPED, payload.size)
        for (i in 0 until n) {
            val wrapped = payload.sub(2 + i * WRAPPED, 2 + (i + 1) * WRAPPED)
            for (key in keys) {
                val messageKey = openRaw(key, wrapped) ?: continue
                val plain = openRaw(messageKey, body)
                Octets.wipe(messageKey)
                if (plain != null) return plain
            }
        }
        return null
    }

    private fun openToken(inner: String, keys: List<ByteArray>): String? {
        val plain = when {
            inner.startsWith(V1) -> {
                val combined = Octets.unb64(inner.substring(V1.length)) ?: return null
                keys.firstNotNullOfOrNull { openRaw(it, combined) }
            }
            inner.startsWith(V2) -> openV2(Octets.unb64(inner.substring(V2.length)) ?: return null, keys)
            else -> null
        } ?: return null
        return try {
            Octets.fromUtf8(plain)
        } catch (_: BrocolisException) {
            null
        } finally {
            Octets.wipe(plain)
        }
    }

    /**
     * Ce que donne un texte une fois ses jetons ouverts.
     *
     * @property text le texte, jetons ouverts remplacés par leur contenu ;
     * @property opened les jetons ouverts ;
     * @property locked ceux qu'aucune des clés n'ouvre (laissés tels quels).
     */
    data class Opened(val text: String, val opened: Int, val locked: Int)

    /** Ouvre les jetons v1/v2 de `text` avec toutes les clés. */
    fun open(text: String, keys: List<ByteArray>): Opened {
        val out = StringBuilder()
        var opened = 0
        var locked = 0
        var rest = text
        while (true) {
            val start = rest.indexOf(HEAD)
            if (start < 0) break
            val after = rest.substring(start + HEAD.length)
            val end = after.indexOf(END)
            if (end < 0) break
            out.append(rest, 0, start)
            val plain = openToken(after.substring(0, end), keys)
            if (plain != null) {
                out.append(plain)
                opened++
            } else {
                out.append(rest, start, start + HEAD.length + end + END.length)
                locked++
            }
            rest = after.substring(end + END.length)
        }
        out.append(rest)
        return Opened(out.toString(), opened, locked)
    }

    /** Un texte prêt à afficher : un jeton qu'aucune clé n'ouvre devient « 🔒🥦 ». */
    fun masked(text: String): String {
        if (!hasToken(text)) return text
        val out = StringBuilder()
        var rest = text
        while (true) {
            val start = rest.indexOf(HEAD)
            if (start < 0) break
            val end = rest.indexOf(END, start)
            if (end < 0) break
            out.append(rest, 0, start)
            out.append("🔒🥦")
            rest = rest.substring(end + END.length)
        }
        out.append(rest)
        return out.toString()
    }
}
