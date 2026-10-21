package rs.brocolis.messagerie.proto

/**
 * L'en-tête du cliquet v4 (§9.3), en clair — il voyage chiffré :
 * `DH (32) ‖ PN (u32 BE) ‖ N (u32 BE) ‖ drapeaux (1) ‖ ek (1 184) ‖ [ct (1 088)]`.
 *
 * @property dh la clé publique de cliquet X25519 de l'expéditeur ;
 * @property pn la longueur de sa chaîne d'envoi précédente ;
 * @property n le numéro du message dans sa chaîne ;
 * @property ek sa clé d'encapsulation ML-KEM-768 de cliquet courante (1 184 octets) ;
 * @property ct l'encapsulation qui a ouvert cette chaîne (absente de la
 *   première chaîne de l'initiateur).
 */
class Header4(dh: ByteArray, val pn: Long, val n: Long, ek: ByteArray, ct: ByteArray?) {
    val dh: ByteArray = dh.copyOf()
    val ek: ByteArray = ek.copyOf()
    val ct: ByteArray? = ct?.copyOf()

    init {
        require(dh.size == 32 && pn in 0..Octets.U32_MAX && n in 0..Octets.U32_MAX)
    }

    /** Les octets de l'en-tête en clair. */
    fun toBytes(): ByteArray = Octets.concat(
        dh, Octets.u32be(pn), Octets.u32be(n), byteArrayOf(if (ct != null) 0x01 else 0x00), ek, ct ?: ByteArray(0),
    )

    override fun equals(other: Any?): Boolean = other is Header4 && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()

    companion object {
        /** Relit un en-tête en clair (strict : longueur, drapeaux). */
        fun fromBytes(b: ByteArray): Header4 {
            val r = Lecteur4(b)
            val dh = r.take(32)
            val pn = r.u32()
            val n = r.u32()
            val flags = r.u8()
            val ek = r.take(Paquet.PQPK_LEN)
            val ct = when (flags) {
                0x00 -> null
                0x01 -> r.take(Token4.KEM_CT_LEN)
                else -> echec(Erreur.Format)
            }
            if (r.remaining() != 0) echec(Erreur.Format)
            return Header4(dh, pn, n, ek, ct)
        }
    }
}

/**
 * La partie chiffrée commune à tous les messages v4.
 *
 * @property headerNonce le nonce de l'en-tête (dérivé de la clé de message, §9.1) ;
 * @property header l'en-tête chiffré (AES-256-GCM ‖ tag) ;
 * @property ciphertext le chiffré du message (AES-256-GCM ‖ tag).
 */
class Body4(headerNonce: ByteArray, header: ByteArray, ciphertext: ByteArray) {
    val headerNonce: ByteArray = headerNonce.copyOf()
    val header: ByteArray = header.copyOf()
    val ciphertext: ByteArray = ciphertext.copyOf()

    init {
        require(headerNonce.size == 12 && header.size <= 0xFFFF)
    }

    internal fun toBytes(): ByteArray = Octets.concat(
        headerNonce, byteArrayOf((header.size ushr 8).toByte(), header.size.toByte()), header, ciphertext,
    )

    override fun equals(other: Any?): Boolean = other is Body4 && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()
}

/**
 * Le préambule d'un premier message v4 (type 0x01).
 *
 * @property ephemeral la clé éphémère EK_A ;
 * @property kemCiphertext l'encapsulation ML-KEM-768 vers la PQPK du répondeur ;
 * @property sealedIdentity IK_A chiffrée (§9.4, 48 octets).
 */
class Preamble4(ephemeral: ByteArray, kemCiphertext: ByteArray, sealedIdentity: ByteArray) {
    val ephemeral: ByteArray = ephemeral.copyOf()
    val kemCiphertext: ByteArray = kemCiphertext.copyOf()
    val sealedIdentity: ByteArray = sealedIdentity.copyOf()

    init {
        require(ephemeral.size == 32 && kemCiphertext.size == Token4.KEM_CT_LEN && sealedIdentity.size == Token4.PREAMBLE_LEN)
    }

    /** Les données associées du préambule chiffré : `0x01 ‖ EK_A ‖ CT`. */
    fun aad(): ByteArray = Octets.concat(byteArrayOf(Token4.TYPE_INITIAL.toByte()), ephemeral, kemCiphertext)
}

/** Lecture stricte d'octets (fin de données : [Erreur.Format]). */
private class Lecteur4(val data: ByteArray) {
    var pos = 0
    fun take(n: Int): ByteArray {
        if (data.size - pos < n) echec(Erreur.Format)
        return data.copyOfRange(pos, pos + n).also { pos += n }
    }
    fun u8(): Int = take(1)[0].toInt() and 0xff
    fun u16(): Int {
        val b = take(2)
        return ((b[0].toInt() and 0xff) shl 8) or (b[1].toInt() and 0xff)
    }
    fun u32(): Long = Octets.readU32(take(4), 0)
    fun remaining(): Int = data.size - pos
    fun rest(): ByteArray = data.copyOfRange(pos, data.size).also { pos = data.size }
}

/**
 * Un jeton v4 décodé (§9.4, `brocolis_proto::jeton_v4`) :
 * `[[BROCOLIS:v4:<base64>]]`, encodage et décodage **stricts**.
 *
 * ```text
 * octet 0 : type
 *   0x01 premier message : EK_A (32) ‖ CT ML-KEM (1 088) ‖ préambule chiffré (48)
 *                          ‖ nonce d'en-tête (12) ‖ longueur (u16 BE) ‖ en-tête chiffré ‖ chiffré
 *   0x02 message         : nonce d'en-tête (12) ‖ longueur (u16 BE) ‖ en-tête chiffré ‖ chiffré
 * en-tête chiffré : 1 241 ou 2 329 octets ; chiffré : 160·k + 16 octets, k ≥ 1
 * ```
 *
 * Aucun identifiant n'est en clair : sans la clé d'en-tête, un 0x02 ne se
 * distingue pas d'octets aléatoires de même longueur.
 */
sealed class Token4 {
    /** Type 0x01. */
    class Initial(val preamble: Preamble4, override val body: Body4) : Token4()
    /** Type 0x02. */
    class Message(override val body: Body4) : Token4()

    /** La partie chiffrée. */
    abstract val body: Body4

    /** L'octet de type. */
    val kind: Int
        get() = when (this) {
            is Initial -> TYPE_INITIAL
            is Message -> TYPE_MESSAGE
        }

    /** Les octets du jeton. */
    fun toBytes(): ByteArray = when (this) {
        is Initial -> Octets.concat(
            byteArrayOf(TYPE_INITIAL.toByte()), preamble.ephemeral, preamble.kemCiphertext, preamble.sealedIdentity, body.toBytes(),
        )
        is Message -> Octets.concat(byteArrayOf(TYPE_MESSAGE.toByte()), body.toBytes())
    }

    /** Le jeton `[[BROCOLIS:v4:<base64>]]`. */
    fun encode(): String = HEAD + Octets.b64(toBytes()) + END

    override fun equals(other: Any?): Boolean = other is Token4 && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()

    companion object {
        /** Le début d'un jeton v4. */
        const val HEAD = "[[BROCOLIS:v4:"
        private const val END = "]]"
        /** Type 0x01 : premier message d'une session établie par paquet. */
        const val TYPE_INITIAL = 0x01
        /** Type 0x02 : tout autre message (premier message à clé partagée compris). */
        const val TYPE_MESSAGE = 0x02
        /** La longueur d'un chiffré ML-KEM-768. */
        const val KEM_CT_LEN = 1_088
        /** La longueur du préambule chiffré : IK_A (32) ‖ tag (16). */
        const val PREAMBLE_LEN = 48
        /** L'en-tête en clair, sans `ct` : DH, PN, N, drapeaux, ek. */
        const val HEADER_LEN = 32 + 4 + 4 + 1 + Paquet.PQPK_LEN
        /** L'en-tête en clair, avec `ct`. */
        const val HEADER_LEN_CT = HEADER_LEN + KEM_CT_LEN
        /** La taille maximale d'un jeton v4 décodé : 256 Kio. */
        const val MAX_TOKEN_BYTES = 256 * 1024
        /** Le genre de ce que porte un message (premier octet du clair, §9.3) : un texte. */
        const val GENRE_TEXTE = 0x00
        /** Une distribution de chaîne de groupe (§4.5). */
        const val GENRE_DISTRIBUTION = 0x01

        private fun parseBody(r: Lecteur4): Body4 {
            val headerNonce = r.take(12)
            val len = r.u16()
            if (len != HEADER_LEN + 16 && len != HEADER_LEN_CT + 16) echec(Erreur.Format)
            val header = r.take(len)
            val ciphertext = r.rest()
            if (ciphertext.size < Remplissage.BLOC + 16 || (ciphertext.size - 16) % Remplissage.BLOC != 0) echec(Erreur.Format)
            return Body4(headerNonce, header, ciphertext)
        }

        /** Décode les octets d'un jeton v4. */
        fun fromBytes(data: ByteArray): Token4 {
            if (data.size > MAX_TOKEN_BYTES) echec(Erreur.TropGrand)
            val r = Lecteur4(data)
            return when (r.u8()) {
                TYPE_INITIAL -> {
                    val ephemeral = r.take(32)
                    val kemCiphertext = r.take(KEM_CT_LEN)
                    val sealedIdentity = r.take(PREAMBLE_LEN)
                    Initial(Preamble4(ephemeral, kemCiphertext, sealedIdentity), parseBody(r))
                }
                TYPE_MESSAGE -> Message(parseBody(r))
                else -> echec(Erreur.Format)
            }
        }

        /**
         * Décode un jeton `[[BROCOLIS:v4:<base64>]]`, exactement (sans espace
         * autour ; voir [findAll] pour un texte collé).
         */
        fun decode(text: String): Token4 {
            if (!text.startsWith(HEAD) || !text.endsWith(END) || text.length < HEAD.length + END.length) {
                echec(Erreur.JetonAbsent)
            }
            val b = text.substring(HEAD.length, text.length - END.length)
            if (Octets.utf8Len(b) > 4L * ((MAX_TOKEN_BYTES + 2) / 3)) echec(Erreur.TropGrand)
            return fromBytes(Octets.unb64OrThrow(b))
        }

        /**
         * Les jetons v4 d'un texte collé, dans l'ordre (chaque
         * `[[BROCOLIS:v4:…]]` complet), avec leur décodage (ou l'erreur).
         */
        fun findAll(text: String): List<Pair<String, Result<Token4>>> {
            val out = mutableListOf<Pair<String, Result<Token4>>>()
            var rest = text
            while (true) {
                val start = rest.indexOf(HEAD)
                if (start < 0) break
                val end = rest.indexOf(END, start)
                if (end < 0) break
                val token = rest.substring(start, end + END.length)
                out.add(Pair(token, runCatching { decode(token) }))
                rest = rest.substring(end + END.length)
            }
            return out
        }
    }
}
