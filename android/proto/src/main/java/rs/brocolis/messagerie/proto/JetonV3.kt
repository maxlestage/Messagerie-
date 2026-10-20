package rs.brocolis.messagerie.proto

/**
 * Le mode d'établissement d'une session (le drapeau `pq` de la
 * spécification, §4.4). `jsonName` est son nom dans les états JSON (serde).
 */
enum class Mode(val byte: Int, internal val jsonName: String) {
    /** X25519 seul (`pq = 0`) : « session non post-quantique ». */
    Classic(0x00, "Classic"),
    /** X25519 + ML-KEM-768 (`pq = 1`). */
    Hybrid(0x01, "Hybrid"),
    /** Clé Brocolis partagée (octet `0x02`, §7.4). */
    Psk(0x02, "Psk");

    internal companion object {
        fun fromByte(b: Int): Mode = entries.firstOrNull { it.byte == b } ?: echec(Erreur.Format)
        fun fromJson(name: String): Mode = entries.firstOrNull { it.jsonName == name } ?: echec(Erreur.Etat)
    }
}

/**
 * L'en-tête d'un message du Double Ratchet : `DH_pub (32) ‖ PN (u32 BE) ‖ N (u32 BE)`.
 *
 * @property dh la clé publique de cliquet de l'expéditeur ;
 * @property pn la longueur de sa chaîne d'envoi précédente ;
 * @property n le numéro du message dans sa chaîne d'envoi.
 */
class Header(dh: ByteArray, val pn: Long, val n: Long) {
    val dh: ByteArray = dh.copyOf()

    init {
        require(dh.size == 32 && pn in 0..Octets.U32_MAX && n in 0..Octets.U32_MAX)
    }

    /** Les 40 octets de l'en-tête. */
    fun toBytes(): ByteArray = Octets.concat(dh, Octets.u32be(pn), Octets.u32be(n))

    override fun equals(other: Any?): Boolean = other is Header && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()
}

/**
 * Un message chiffré par le ratchet d'une session (types 0x02 et 0x03, et la
 * fin d'un 0x01).
 *
 * @property sessionId l'identifiant de session : `SHA-256(AD)[0..8]` ;
 * @property header l'en-tête du ratchet ;
 * @property ciphertext le chiffré AES-256-GCM ‖ tag.
 */
class Envelope(sessionId: ByteArray, val header: Header, ciphertext: ByteArray) {
    val sessionId: ByteArray = sessionId.copyOf()
    val ciphertext: ByteArray = ciphertext.copyOf()

    init {
        require(sessionId.size == 8)
    }

    /** Une copie, avec un autre identifiant de session (tests d'altération). */
    fun withSessionId(id: ByteArray) = Envelope(id, header, ciphertext)
}

/**
 * Le premier message d'une session (type 0x01).
 *
 * @property identity la clé d'identité X25519 de l'initiateur (nulle en mode clé partagée) ;
 * @property ephemeral la clé éphémère EK de l'initiateur ;
 * @property mode le mode d'établissement ;
 * @property kemCiphertext le chiffré ML-KEM-768 (mode hybride seulement) ;
 * @property spkId l'identifiant de la clé pré-signée du répondeur utilisée ;
 * @property pqId l'identifiant de sa clé ML-KEM utilisée (0 sans ML-KEM) ;
 * @property envelope le message lui-même.
 */
class Initial(
    identity: ByteArray,
    ephemeral: ByteArray,
    val mode: Mode,
    kemCiphertext: ByteArray?,
    val spkId: Long,
    val pqId: Long,
    val envelope: Envelope,
) {
    val identity: ByteArray = identity.copyOf()
    val ephemeral: ByteArray = ephemeral.copyOf()
    val kemCiphertext: ByteArray? = kemCiphertext?.copyOf()

    init {
        require(identity.size == 32 && ephemeral.size == 32)
    }
}

/**
 * Un message de groupe (type 0x04) :
 * `0x04 ‖ id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)`.
 */
class GroupMessage(groupId: ByteArray, senderId: ByteArray, val iteration: Long, ciphertext: ByteArray, signature: ByteArray) {
    val groupId: ByteArray = groupId.copyOf()
    val senderId: ByteArray = senderId.copyOf()
    val ciphertext: ByteArray = ciphertext.copyOf()
    val signature: ByteArray = signature.copyOf()

    init {
        require(groupId.size == 16 && senderId.size == 8 && signature.size == 64 && iteration in 0..Octets.U32_MAX)
    }

    /** Les 29 premiers octets : type ‖ id groupe ‖ id expéditeur ‖ itération (les données associées du chiffrement). */
    fun prefix(): ByteArray = Octets.concat(byteArrayOf(Token.TYPE_GROUP.toByte()), groupId, senderId, Octets.u32be(iteration))

    /** Ce que couvre la signature : préfixe ‖ chiffré. */
    fun signedBytes(): ByteArray = Octets.concat(prefix(), ciphertext)

    internal fun withSignature(sig: ByteArray) = GroupMessage(groupId, senderId, iteration, ciphertext, sig)
}

/**
 * Un jeton v3 décodé (§4.4, `brocolis_proto::jeton_v3`) :
 * `[[BROCOLIS:v3:<base64>]]`, encodage et décodage **stricts** (toute
 * longueur, tout octet de type ou de mode inattendu, tout champ réservé non
 * nul est refusé).
 *
 * ```text
 * octet 0 : type
 *   0x01 premier message   : id session (8) ‖ IK_A (32) ‖ EK_A (32) ‖ mode (1)
 *                            ‖ [CT ML-KEM (1 088) si mode = 0x01]
 *                            ‖ id SPK (u32 BE) ‖ id PQPK (u32 BE)
 *                            ‖ en-tête (40) ‖ chiffré
 *   0x02 message           : id session (8) ‖ en-tête (40) ‖ chiffré
 *   0x03 distribution      : id session (8) ‖ en-tête (40) ‖ chiffré
 *   0x04 message de groupe : id groupe (16) ‖ id expéditeur (8)
 *                            ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)
 * chiffré = AES-256-GCM(remplissage §3.3) ‖ tag : 160·k + 16 octets, k ≥ 1
 * ```
 */
sealed class Token {
    /** Type 0x01. */
    class InitialMessage(val initial: Initial) : Token()
    /** Type 0x02. */
    class Message(val envelope: Envelope) : Token()
    /** Type 0x03. */
    class Distribution(val envelope: Envelope) : Token()
    /** Type 0x04. */
    class Group(val message: GroupMessage) : Token()

    /** L'octet de type. */
    val type: Int
        get() = when (this) {
            is InitialMessage -> TYPE_INITIAL
            is Message -> TYPE_MESSAGE
            is Distribution -> TYPE_DISTRIBUTION
            is Group -> TYPE_GROUP
        }

    /** L'identifiant de session (types 0x01 à 0x03). */
    val sessionId: ByteArray?
        get() = when (this) {
            is InitialMessage -> initial.envelope.sessionId.copyOf()
            is Message -> envelope.sessionId.copyOf()
            is Distribution -> envelope.sessionId.copyOf()
            is Group -> null
        }

    /** Les octets du jeton. */
    fun toBytes(): ByteArray = when (this) {
        is InitialMessage -> {
            val i = initial
            Octets.concat(
                byteArrayOf(TYPE_INITIAL.toByte()), i.envelope.sessionId, i.identity, i.ephemeral,
                byteArrayOf(i.mode.byte.toByte()), i.kemCiphertext ?: ByteArray(0),
                Octets.u32be(i.spkId), Octets.u32be(i.pqId), i.envelope.header.toBytes(), i.envelope.ciphertext,
            )
        }
        is Message -> envelopeBytes(TYPE_MESSAGE, envelope)
        is Distribution -> envelopeBytes(TYPE_DISTRIBUTION, envelope)
        is Group -> Octets.concat(message.signedBytes(), message.signature)
    }

    /** Le jeton `[[BROCOLIS:v3:<base64>]]`. */
    fun encode(): String = HEAD + Octets.b64(toBytes()) + END

    override fun equals(other: Any?): Boolean = other is Token && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()

    companion object {
        /** Le début d'un jeton v3. */
        const val HEAD = "[[BROCOLIS:v3:"
        private const val END = "]]"
        /** Type 0x01 : premier message, qui établit la session. */
        const val TYPE_INITIAL = 0x01
        /** Type 0x02 : message d'une session établie. */
        const val TYPE_MESSAGE = 0x02
        /** Type 0x03 : distribution d'une chaîne de groupe. */
        const val TYPE_DISTRIBUTION = 0x03
        /** Type 0x04 : message de groupe signé. */
        const val TYPE_GROUP = 0x04
        /** La longueur d'un chiffré ML-KEM-768. */
        const val KEM_CT_LEN = 1_088
        /** La longueur d'un en-tête de ratchet. */
        const val HEADER_LEN = 40
        /** La taille maximale d'un jeton v3 décodé : 256 Kio. */
        const val MAX_TOKEN_BYTES = 256 * 1024

        private fun envelopeBytes(type: Int, e: Envelope) =
            Octets.concat(byteArrayOf(type.toByte()), e.sessionId, e.header.toBytes(), e.ciphertext)

        /** Vérifie la longueur d'un chiffré : 160·k + 16 octets, k ≥ 1. */
        private fun checkCiphertext(len: Int) {
            if (len < Remplissage.BLOC + 16 || (len - 16) % Remplissage.BLOC != 0) echec(Erreur.Format)
        }

        private class Reader(val data: ByteArray) {
            var pos = 0
            fun take(n: Int): ByteArray {
                if (data.size - pos < n) echec(Erreur.Format)
                return data.copyOfRange(pos, pos + n).also { pos += n }
            }
            fun u8(): Int = take(1)[0].toInt() and 0xff
            fun u32(): Long = Octets.readU32(take(4), 0)
            fun rest(): ByteArray = data.copyOfRange(pos, data.size).also { pos = data.size }
            fun header() = Header(take(32), u32(), u32())
        }

        /** Décode les octets d'un jeton v3. */
        fun fromBytes(data: ByteArray): Token {
            if (data.size > MAX_TOKEN_BYTES) echec(Erreur.TropGrand)
            val r = Reader(data)
            return when (val kind = r.u8()) {
                TYPE_INITIAL -> {
                    val sessionId = r.take(8)
                    val identity = r.take(32)
                    val ephemeral = r.take(32)
                    val mode = Mode.fromByte(r.u8())
                    val ct = if (mode == Mode.Hybrid) r.take(KEM_CT_LEN) else null
                    val spkId = r.u32()
                    val pqId = r.u32()
                    when (mode) {
                        Mode.Classic -> if (pqId != 0L) echec(Erreur.Format)
                        Mode.Psk -> if (!Octets.isZero(identity) || spkId != 0L || pqId != 0L) echec(Erreur.Format)
                        Mode.Hybrid -> {}
                    }
                    val header = r.header()
                    val ciphertext = r.rest()
                    checkCiphertext(ciphertext.size)
                    InitialMessage(Initial(identity, ephemeral, mode, ct, spkId, pqId, Envelope(sessionId, header, ciphertext)))
                }
                TYPE_MESSAGE, TYPE_DISTRIBUTION -> {
                    val sessionId = r.take(8)
                    val header = r.header()
                    val ciphertext = r.rest()
                    checkCiphertext(ciphertext.size)
                    val env = Envelope(sessionId, header, ciphertext)
                    if (kind == TYPE_MESSAGE) Message(env) else Distribution(env)
                }
                TYPE_GROUP -> {
                    val groupId = r.take(16)
                    val senderId = r.take(8)
                    val iteration = r.u32()
                    val rest = r.rest()
                    if (rest.size < 64) echec(Erreur.Format)
                    val ct = rest.copyOfRange(0, rest.size - 64)
                    checkCiphertext(ct.size)
                    Group(GroupMessage(groupId, senderId, iteration, ct, rest.copyOfRange(rest.size - 64, rest.size)))
                }
                else -> echec(Erreur.Format)
            }
        }

        /**
         * Décode un jeton `[[BROCOLIS:v3:<base64>]]`, exactement (sans espace
         * autour ; voir [findAll] pour un texte collé).
         */
        fun decode(text: String): Token {
            if (!text.startsWith(HEAD) || !text.endsWith(END) || text.length < HEAD.length + END.length) {
                echec(Erreur.JetonAbsent)
            }
            val b = text.substring(HEAD.length, text.length - END.length)
            if (Octets.utf8Len(b) > 4L * ((MAX_TOKEN_BYTES + 2) / 3)) echec(Erreur.TropGrand)
            return fromBytes(Octets.unb64OrThrow(b))
        }

        /**
         * Les jetons v3 d'un texte collé, dans l'ordre (chaque
         * `[[BROCOLIS:v3:…]]` complet), avec leur décodage (ou l'erreur).
         */
        fun findAll(text: String): List<Pair<String, Result<Token>>> {
            val out = mutableListOf<Pair<String, Result<Token>>>()
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
