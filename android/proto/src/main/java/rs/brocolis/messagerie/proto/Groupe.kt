package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import rs.brocolis.messagerie.proto.EtatJson.arr
import rs.brocolis.messagerie.proto.EtatJson.asObj
import rs.brocolis.messagerie.proto.EtatJson.bytes
import rs.brocolis.messagerie.proto.EtatJson.putBytes
import rs.brocolis.messagerie.proto.EtatJson.putNum
import rs.brocolis.messagerie.proto.EtatJson.u32
import rs.brocolis.messagerie.proto.EtatJson.u64
import rs.brocolis.messagerie.proto.EtatJson.u8

/**
 * Les groupes : Sender Keys (§4.5, §7.6, §7.7), le modèle de Signal
 * (`brocolis_proto::groupe`).
 *
 * Chaque membre tire une **chaîne d'envoi** (clé de chaîne 32 octets + clé de
 * signature Ed25519) et la distribue à chaque membre par sa session v3 à deux
 * (jeton de type 0x03, [Session.encryptDistribution]). Ses messages de
 * groupe (type 0x04) :
 *
 * ```text
 * 0x04 ‖ id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)
 * ```
 *
 * - la chaîne avance par `KDF_CK` ; la clé du message d'itération `i` est
 *   `mk_i`, chiffrée comme au §4.3 (`ENCRYPT(mk)`, remplissage §3.3) ;
 * - données associées AES-GCM : les 29 premiers octets ;
 * - signature Ed25519 (stricte) de tout ce qui précède (type compris),
 *   vérifiée **avant** toute autre chose ;
 * - id expéditeur = `SHA-256(clé publique de signature)[0..8]`.
 *
 * Un membre qui part : chacun tire une chaîne neuve ([SenderKeyState.generate])
 * et la distribue aux membres restants.
 */
object Groupe {
    /** La longueur d'une distribution (avant remplissage). */
    const val DISTRIBUTION_LEN = 92

    /** Un identifiant de groupe aléatoire (16 octets). */
    fun newGroupId(rng: CryptoRng = Hasard.system()): ByteArray = rng.bytes(16)

    /** L'identifiant d'expéditeur d'une chaîne : `SHA-256(clé publique)[0..8]`. */
    fun senderIdOf(signingPublic: ByteArray): ByteArray = Kdf.sha256(signingPublic).sub(0, 8)
}

/**
 * Une chaîne de groupe telle qu'on la distribue (92 octets) :
 * `id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ clé de chaîne (32) ‖ clé publique Ed25519 (32)`.
 */
class SenderKeyDistribution(groupId: ByteArray, senderId: ByteArray, val iteration: Long, chainKey: ByteArray, signingPublic: ByteArray) {
    val groupId: ByteArray = groupId.copyOf()
    val senderId: ByteArray = senderId.copyOf()
    val chainKey: ByteArray = chainKey.copyOf()
    val signingPublic: ByteArray = signingPublic.copyOf()

    init {
        require(groupId.size == 16 && senderId.size == 8 && chainKey.size == 32 && signingPublic.size == 32)
        require(iteration in 0..Octets.U32_MAX)
    }

    /** Les 92 octets. */
    fun toBytes(): ByteArray = Octets.concat(groupId, senderId, Octets.u32be(iteration), chainKey, signingPublic)

    internal fun check() {
        if (!Groupe.senderIdOf(signingPublic).contentEquals(senderId)) echec(Erreur.Format)
        if (!Kdf.ed25519IsValidPublic(signingPublic)) echec(Erreur.CleInvalide)
    }

    override fun equals(other: Any?): Boolean = other is SenderKeyDistribution && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()
    override fun toString(): String = "SenderKeyDistribution(${Octets.hex(groupId)}, ${Octets.hex(senderId)}, $iteration)"

    companion object {
        /** Lit 92 octets ; vérifie l'identifiant d'expéditeur et la clé publique. */
        fun fromBytes(b: ByteArray): SenderKeyDistribution {
            if (b.size != Groupe.DISTRIBUTION_LEN) echec(Erreur.Format)
            val d = SenderKeyDistribution(b.sub(0, 16), b.sub(16, 24), Octets.readU32(b, 24), b.sub(28, 60), b.sub(60, 92))
            d.check()
            return d
        }
    }
}

/** Sa propre chaîne d'envoi dans un groupe. */
class SenderKeyState private constructor(
    private val groupIdBytes: ByteArray,
    private var chainKey: ByteArray,
    private var iterationValue: Long,
    private val signingSeed: ByteArray,
) {
    private val v: Int = 1

    /** La clé publique Ed25519 de la chaîne. */
    val signingPublic: ByteArray get() = Kdf.ed25519Public(signingSeed)

    /** L'identifiant d'expéditeur. */
    val senderId: ByteArray get() = Groupe.senderIdOf(signingPublic)

    /** L'identifiant du groupe. */
    val groupId: ByteArray get() = groupIdBytes.copyOf()

    /** L'itération courante (celle du prochain message). */
    val iteration: Long get() = iterationValue

    /** La distribution de la chaîne à son itération courante. */
    fun distribution(): SenderKeyDistribution {
        val pub = signingPublic
        return SenderKeyDistribution(groupIdBytes, Groupe.senderIdOf(pub), iterationValue, chainKey, pub)
    }

    /** Chiffre et signe un message de groupe (jeton décodé). */
    fun encryptToken(text: String): Token {
        val plain = Octets.utf8(text)
        if (plain.size > Session.MAX_PLAINTEXT) echec(Erreur.TropGrand)
        val nextIteration = iterationValue + 1
        if (nextIteration > Octets.U32_MAX) echec(Erreur.Epuise)
        val (next, mk) = Kdf.kdfCk(chainKey)
        val (key, nonce) = Kdf.messageKey(mk)
        val unsigned = GroupMessage(groupIdBytes, senderId, iterationValue, ByteArray(0), ByteArray(64))
        val padded = Remplissage.pad(plain)
        val ct = try {
            Kdf.aesGcmSeal(key, nonce, unsigned.prefix(), padded)
        } finally {
            Octets.wipe(mk, key, padded)
        }
        val msg = GroupMessage(groupIdBytes, unsigned.senderId, iterationValue, ct, ByteArray(64))
        val signed = msg.withSignature(Kdf.ed25519Sign(signingSeed, msg.signedBytes()))
        Octets.wipe(chainKey)
        chainKey = next
        iterationValue = nextIteration
        return Token.Group(signed)
    }

    /** Chiffre et signe un message de groupe : `[[BROCOLIS:v3:…]]`. */
    fun encrypt(text: String): String = encryptToken(text).encode()

    /** Efface les secrets de la chaîne. */
    fun wipe() = Octets.wipe(chainKey, signingSeed)

    /** L'état en JSON (même forme que la référence Rust). */
    fun toJson(): String = EtatJson.write(
        buildJsonObject {
            putNum("v", v.toLong())
            putBytes("group_id", groupIdBytes)
            putBytes("chain_key", chainKey)
            putNum("iteration", iterationValue)
            putBytes("signing_seed", signingSeed)
        },
    )

    companion object {
        /** Une chaîne neuve. Ordre de tirage : clé de chaîne (32), graine Ed25519 (32). */
        fun generate(groupId: ByteArray, rng: CryptoRng = Hasard.system()): SenderKeyState {
            val chainKey = rng.bytes(32)
            val seed = rng.bytes(32)
            return SenderKeyState(groupId.copyOf().also { require(it.size == 16) }, chainKey, 0, seed)
        }

        /** Une chaîne à partir des secrets donnés (les vecteurs). */
        fun generateWith(groupId: ByteArray, chainKey: ByteArray, signingSeed: ByteArray): SenderKeyState {
            require(groupId.size == 16 && chainKey.size == 32 && signingSeed.size == 32)
            return SenderKeyState(groupId.copyOf(), chainKey.copyOf(), 0, signingSeed.copyOf())
        }

        /** Relit un état JSON. */
        fun fromJson(text: String): SenderKeyState {
            val o = EtatJson.parse(text)
            if (o.u8("v") != 1L) echec(Erreur.Etat)
            return SenderKeyState(o.bytes("group_id", 16), o.bytes("chain_key", 32), o.u32("iteration"), o.bytes("signing_seed", 32))
        }
    }
}

private class GroupSkippedKey(val iteration: Long, val mk: ByteArray, val storedAt: Long) {
    fun toJson() = buildJsonObject {
        putNum("iteration", iteration)
        putBytes("mk", mk)
        putNum("stored_at", storedAt)
    }

    companion object {
        fun fromJson(o: JsonObject) = GroupSkippedKey(o.u32("iteration"), o.bytes("mk", 32), o.u64("stored_at"))
    }
}

/** La chaîne d'un autre membre, reçue par une distribution. */
class ReceivedSenderKey private constructor(
    private val groupIdBytes: ByteArray,
    private val senderIdBytes: ByteArray,
    private var chainKey: ByteArray,
    private var iteration: Long,
    private val signingPublic: ByteArray,
    private var skipped: MutableList<GroupSkippedKey>,
) {
    private val v: Int = 1

    /** L'identifiant du groupe. */
    val groupId: ByteArray get() = groupIdBytes.copyOf()

    /** L'identifiant d'expéditeur. */
    val senderId: ByteArray get() = senderIdBytes.copyOf()

    /** Vrai si ce message de groupe est de cette chaîne. */
    fun matches(msg: GroupMessage): Boolean =
        msg.groupId.contentEquals(groupIdBytes) && msg.senderId.contentEquals(senderIdBytes)

    /** Le nombre de clés sautées gardées. */
    val skippedLen: Int get() = skipped.size

    /** Vérifie la signature puis déchiffre. Transactionnel ; un message déjà lu donne [Erreur.Rejoue]. */
    fun decrypt(msg: GroupMessage, now: Long): String {
        if (!matches(msg)) echec(Erreur.ExpediteurInconnu)
        Kdf.ed25519Verify(signingPublic, msg.signedBytes(), msg.signature)
        // La transaction : une copie des clés sautées et de la chaîne.
        val nextSkipped = skipped
            .filter { Octets.satAdd(it.storedAt, Protocole.MAX_SKIP_AGE) > now }
            .map { GroupSkippedKey(it.iteration, it.mk.copyOf(), it.storedAt) }
            .toMutableList()
        var nextChain = chainKey.copyOf()
        var nextIteration = iteration
        val mk: ByteArray
        try {
            if (msg.iteration < nextIteration) {
                val pos = nextSkipped.indexOfFirst { it.iteration == msg.iteration }
                if (pos < 0) echec(Erreur.Rejoue)
                mk = nextSkipped.removeAt(pos).mk
            } else {
                if (msg.iteration - nextIteration > Protocole.MAX_SKIP) echec(Erreur.TropDeClesSautees)
                while (nextIteration < msg.iteration) {
                    val (n, k) = Kdf.kdfCk(nextChain)
                    nextSkipped.add(GroupSkippedKey(nextIteration, k, now))
                    Octets.wipe(nextChain)
                    nextChain = n
                    nextIteration++
                }
                val (n, k) = Kdf.kdfCk(nextChain)
                Octets.wipe(nextChain)
                nextChain = n
                if (nextIteration + 1 > Octets.U32_MAX) echec(Erreur.Epuise)
                nextIteration++
                mk = k
                while (nextSkipped.size > Protocole.MAX_SKIP) Octets.wipe(nextSkipped.removeAt(0).mk)
            }
            val (key, nonce) = Kdf.messageKey(mk)
            Octets.wipe(mk)
            val padded = try {
                Kdf.aesGcmOpen(key, nonce, msg.prefix(), msg.ciphertext)
            } finally {
                Octets.wipe(key)
            }
            val text = try {
                Octets.fromUtf8(Remplissage.unpad(padded))
            } finally {
                Octets.wipe(padded)
            }
            // Réussi : la copie devient l'état.
            Octets.wipe(chainKey)
            skipped.forEach { Octets.wipe(it.mk) }
            chainKey = nextChain
            iteration = nextIteration
            skipped = nextSkipped
            return text
        } catch (e: BrocolisException) {
            Octets.wipe(nextChain)
            nextSkipped.forEach { Octets.wipe(it.mk) }
            throw e
        }
    }

    /** L'état en JSON (même forme que la référence Rust). */
    fun toJson(): String = EtatJson.write(
        buildJsonObject {
            putNum("v", v.toLong())
            putBytes("group_id", groupIdBytes)
            putBytes("sender_id", senderIdBytes)
            putBytes("chain_key", chainKey)
            putNum("iteration", iteration)
            putBytes("signing_public", signingPublic)
            put("skipped", JsonArray(skipped.map { it.toJson() }))
        },
    )

    companion object {
        /** La chaîne d'une distribution (vérifiée). */
        fun fromDistribution(d: SenderKeyDistribution): ReceivedSenderKey {
            d.check()
            return ReceivedSenderKey(d.groupId, d.senderId, d.chainKey, d.iteration, d.signingPublic, mutableListOf())
        }

        /** Relit un état JSON. */
        fun fromJson(text: String): ReceivedSenderKey {
            val o = EtatJson.parse(text)
            if (o.u8("v") != 1L) echec(Erreur.Etat)
            val r = ReceivedSenderKey(
                o.bytes("group_id", 16), o.bytes("sender_id", 8), o.bytes("chain_key", 32), o.u32("iteration"),
                o.bytes("signing_public", 32), o.arr("skipped").map { GroupSkippedKey.fromJson(it.asObj()) }.toMutableList(),
            )
            if (r.skipped.size > Protocole.MAX_SKIP || !Groupe.senderIdOf(r.signingPublic).contentEquals(r.senderIdBytes)) {
                echec(Erreur.Etat)
            }
            return r
        }
    }
}
