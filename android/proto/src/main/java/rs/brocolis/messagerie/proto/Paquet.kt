package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import rs.brocolis.messagerie.proto.EtatJson.arr
import rs.brocolis.messagerie.proto.EtatJson.asObj
import rs.brocolis.messagerie.proto.EtatJson.bytes
import rs.brocolis.messagerie.proto.EtatJson.obj
import rs.brocolis.messagerie.proto.EtatJson.optU64
import rs.brocolis.messagerie.proto.EtatJson.putBytes
import rs.brocolis.messagerie.proto.EtatJson.putNum
import rs.brocolis.messagerie.proto.EtatJson.u32
import rs.brocolis.messagerie.proto.EtatJson.u64
import rs.brocolis.messagerie.proto.EtatJson.u8

/**
 * Le paquet de clés publiques (§4.1, format binaire v1 du §7.3) et ses
 * constantes (`brocolis_proto::paquet`).
 *
 * ```text
 * octet 0          : 0x01 (version du paquet)
 * octets 1–32      : IK X25519
 * octets 33–64     : IK Ed25519 (clé de vérification)
 * octets 65–68     : id SPK (u32 BE)
 * octets 69–100    : SPK (X25519)
 * octets 101–164   : signature Ed25519 de "Brocolis_v3_SPK" ‖ IK X25519 ‖ id SPK ‖ SPK
 * octet 165        : 0x00 sans ML-KEM, 0x01 avec
 * si 0x01 :
 *   octets 166–169   : id PQPK (u32 BE)
 *   octets 170–1353  : PQPK (clé d'encapsulation ML-KEM-768, 1 184 octets)
 *   octets 1354–1417 : signature Ed25519 de "Brocolis_v3_PQPK" ‖ IK X25519 ‖ id PQPK ‖ PQPK
 * ```
 */
object Paquet {
    /** La version du format binaire du paquet. */
    const val BUNDLE_VERSION = 0x01
    /** La longueur d'une clé d'encapsulation ML-KEM-768. */
    const val PQPK_LEN = MlKem.PUBLIC_LEN
    /** La longueur d'un paquet sans ML-KEM. */
    const val BUNDLE_LEN_CLASSIC = 166
    /** La longueur d'un paquet avec ML-KEM. */
    const val BUNDLE_LEN_PQ = 1_418
    /** Le contexte signé avec la SPK. */
    val SIG_CONTEXT_SPK: ByteArray = Octets.utf8("Brocolis_v3_SPK")
    /** Le contexte signé avec la PQPK. */
    val SIG_CONTEXT_PQPK: ByteArray = Octets.utf8("Brocolis_v3_PQPK")
    /** Le renouvellement des clés pré-signées : chaque semaine. */
    const val PREKEY_ROTATION: Long = 7 * Protocole.JOUR
    /** Une clé pré-signée remplacée est gardée un mois (30 jours). */
    const val PREKEY_GRACE: Long = 30 * Protocole.JOUR

    /** Le contexte de la capacité v4 signée (§9.6). */
    val SIG_CONTEXT_CAPS4: ByteArray = Octets.utf8("Brocolis_v4_Caps")

    internal fun caps4Message(ik: ByteArray) = Octets.concat(SIG_CONTEXT_CAPS4, ik, byteArrayOf(0x04))

    /**
     * Vérifie la capacité v4 d'un correspondant (§9.6) : signature stricte
     * par son IK Ed25519, sur son IK X25519. Fausse : [Erreur.Signature] ;
     * clé inutilisable : [Erreur.CleInvalide].
     */
    fun verifyCaps4(identity: IdentityPublic, signature: ByteArray) =
        Kdf.ed25519Verify(identity.sign, caps4Message(identity.dh), signature)

    internal fun spkSignedMessage(ik: ByteArray, id: Long, spk: ByteArray) =
        Octets.concat(SIG_CONTEXT_SPK, ik, Octets.u32be(id), spk)

    internal fun pqpkSignedMessage(ik: ByteArray, id: Long, pqpk: ByteArray) =
        Octets.concat(SIG_CONTEXT_PQPK, ik, Octets.u32be(id), pqpk)
}

/**
 * Ce que l'appareil doit garder secret de son identité.
 *
 * @property dh le secret X25519 (32 octets bruts) ;
 * @property sign la graine Ed25519 (32 octets).
 */
class IdentitySecret(dh: ByteArray, sign: ByteArray) {
    val dh: ByteArray = dh.copyOf()
    val sign: ByteArray = sign.copyOf()

    init {
        require(dh.size == 32 && sign.size == 32)
    }

    /** L'identité publique. */
    fun public(): IdentityPublic = IdentityPublic(Kdf.x25519Public(dh), Kdf.ed25519Public(sign))

    /** Efface les secrets. */
    fun wipe() = Octets.wipe(dh, sign)

    internal fun toJson(): JsonObject = buildJsonObject {
        putBytes("dh", dh)
        putBytes("sign", sign)
    }

    internal companion object {
        fun fromJson(o: JsonObject) = IdentitySecret(o.bytes("dh", 32), o.bytes("sign", 32))
    }
}

/**
 * L'identité publique d'un appareil : IK X25519 et IK Ed25519.
 */
class IdentityPublic(dh: ByteArray, sign: ByteArray) {
    /** IK X25519. */
    val dh: ByteArray = dh.copyOf()
    /** IK Ed25519 (clé de vérification). */
    val sign: ByteArray = sign.copyOf()

    init {
        require(dh.size == 32 && sign.size == 32)
    }

    /**
     * L'empreinte de l'identité, à comparer de vive voix :
     * `SHA-256(IK X25519 ‖ IK Ed25519)[0..8]` en `XXXX-XXXX-XXXX-XXXX`.
     */
    fun fingerprint(): String = Kdf.fingerprint(Octets.concat(dh, sign))

    override fun equals(other: Any?): Boolean =
        other is IdentityPublic && dh.contentEquals(other.dh) && sign.contentEquals(other.sign)

    override fun hashCode(): Int = dh.contentHashCode() * 31 + sign.contentHashCode()
}

/**
 * La partie ML-KEM d'un paquet.
 *
 * @property id l'identifiant de la PQPK ;
 * @property key la clé d'encapsulation ML-KEM-768 (1 184 octets) ;
 * @property signature sa signature par IK Ed25519.
 */
class PqBundle(val id: Long, key: ByteArray, signature: ByteArray) {
    val key: ByteArray = key.copyOf()
    val signature: ByteArray = signature.copyOf()
}

/**
 * Un paquet de clés publiques. [KeyBundle.fromBytes] vérifie tout.
 *
 * @property identity l'identité ;
 * @property spkId l'identifiant de la SPK ;
 * @property spk la SPK ;
 * @property spkSignature sa signature par IK Ed25519 ;
 * @property pq la PQPK, si l'appareil sait faire ML-KEM.
 */
class KeyBundle(val identity: IdentityPublic, val spkId: Long, spk: ByteArray, spkSignature: ByteArray, val pq: PqBundle?) {
    val spk: ByteArray = spk.copyOf()
    val spkSignature: ByteArray = spkSignature.copyOf()

    /** Les octets du paquet (format v1). */
    fun toBytes(): ByteArray {
        val head = Octets.concat(
            byteArrayOf(Paquet.BUNDLE_VERSION.toByte()), identity.dh, identity.sign, Octets.u32be(spkId), spk, spkSignature,
        )
        return if (pq == null) {
            Octets.concat(head, byteArrayOf(0x00))
        } else {
            Octets.concat(head, byteArrayOf(0x01), Octets.u32be(pq.id), pq.key, pq.signature)
        }
    }

    /**
     * Vérifie les clés (X25519 canoniques et non nulles, Ed25519 non faible,
     * ML-KEM bien formée) et les signatures (Ed25519 stricte).
     */
    fun verify() {
        for (key in listOf(identity.dh, spk)) {
            if (!Kdf.x25519IsCanonical(key) || Octets.isZero(key)) echec(Erreur.CleInvalide)
        }
        Kdf.ed25519Verify(identity.sign, Paquet.spkSignedMessage(identity.dh, spkId, spk), spkSignature)
        if (pq != null) {
            if (pq.key.size != Paquet.PQPK_LEN || pq.id == 0L) echec(Erreur.Format)
            Kdf.ed25519Verify(identity.sign, Paquet.pqpkSignedMessage(identity.dh, pq.id, pq.key), pq.signature)
            // La clé doit être une clé ML-KEM valide (FIPS 203, contrôle du module).
            if (!MlKem.isValidPublicKey(pq.key)) echec(Erreur.CleInvalide)
        }
    }

    /** Le paquet en base64 standard. */
    fun toBase64(): String = Octets.b64(toBytes())

    override fun equals(other: Any?): Boolean = other is KeyBundle && toBytes().contentEquals(other.toBytes())
    override fun hashCode(): Int = toBytes().contentHashCode()

    companion object {
        /**
         * Lit un paquet et **vérifie** tout : version, longueur exacte, clés et
         * signatures.
         */
        fun fromBytes(data: ByteArray): KeyBundle {
            if (data.size != Paquet.BUNDLE_LEN_CLASSIC && data.size != Paquet.BUNDLE_LEN_PQ) echec(Erreur.Format)
            if (data[0].toInt() != Paquet.BUNDLE_VERSION) echec(Erreur.Format)
            val identity = IdentityPublic(data.sub(1, 33), data.sub(33, 65))
            val pq = when {
                data[165].toInt() == 0x00 && data.size == Paquet.BUNDLE_LEN_CLASSIC -> null
                data[165].toInt() == 0x01 && data.size == Paquet.BUNDLE_LEN_PQ ->
                    PqBundle(Octets.readU32(data, 166), data.sub(170, 170 + Paquet.PQPK_LEN), data.sub(1354, 1418))
                else -> echec(Erreur.Format)
            }
            val bundle = KeyBundle(identity, Octets.readU32(data, 65), data.sub(69, 101), data.sub(101, 165), pq)
            bundle.verify()
            return bundle
        }

        /** Lit (et vérifie) un paquet en base64 standard. */
        fun fromBase64(text: String): KeyBundle {
            if (Octets.utf8Len(text) > 2L * Paquet.BUNDLE_LEN_PQ) echec(Erreur.TropGrand)
            return fromBytes(Octets.unb64OrThrow(Octets.rustTrim(text)))
        }
    }
}

/**
 * Les clés éphémères déjà vues dans un premier message (type 0x01) : rejouer
 * un premier message ne rouvre pas de session (§7.3). Bornée : [MAX]
 * entrées, [MAX_AGE].
 */
class ReplayGuard {
    private class Seen(val ek: ByteArray, val at: Long)

    private val seen = ArrayList<Seen>()

    /** Vrai si cette clé éphémère a déjà ouvert une session. */
    fun seen(ek: ByteArray): Boolean = seen.any { it.ek.contentEquals(ek) }

    /** Retient une clé éphémère. */
    fun insert(ek: ByteArray, now: Long) {
        purge(now)
        seen.add(Seen(ek.copyOf(), now))
        while (seen.size > MAX) seen.removeAt(0)
    }

    /** Oublie les entrées trop vieilles. */
    fun purge(now: Long) {
        seen.removeAll { Octets.satAdd(it.at, MAX_AGE) <= now }
    }

    /** Le nombre d'entrées. */
    val size: Int get() = seen.size

    /** Vrai si aucune entrée. */
    fun isEmpty(): Boolean = seen.isEmpty()

    internal fun copy(): ReplayGuard = ReplayGuard().also { g -> seen.forEach { g.seen.add(Seen(it.ek, it.at)) } }

    internal fun toJsonObject(): JsonObject = buildJsonObject {
        put("seen", JsonArray(seen.map { s -> buildJsonObject { putBytes("ek", s.ek); putNum("at", s.at) } }))
    }

    /** L'état en JSON (`{"seen":[{"ek":…,"at":…}]}`, comme serde). */
    fun toJson(): String = EtatJson.write(toJsonObject())

    companion object {
        /** Le nombre maximal de clés retenues (les plus anciennes partent). */
        const val MAX = 4_096
        /** L'âge maximal d'une entrée : la vie d'une clé pré-signée (7 + 30 jours). */
        const val MAX_AGE: Long = Paquet.PREKEY_ROTATION + Paquet.PREKEY_GRACE

        internal fun fromJsonObject(o: JsonObject): ReplayGuard {
            val g = ReplayGuard()
            for (e in o.arr("seen")) {
                val s = e.asObj()
                g.seen.add(Seen(s.bytes("ek", 32), s.u64("at")))
            }
            return g
        }

        /** Relit un état JSON. */
        fun fromJson(text: String): ReplayGuard = fromJsonObject(EtatJson.parse(text))
    }
}

/** Une clé pré-signée X25519 (secrète). */
internal class SignedPreKey(val id: Long, val secret: ByteArray, val createdAt: Long, var replacedAt: Long?) {
    fun toJson() = buildJsonObject {
        putNum("id", id)
        putBytes("secret", secret)
        putNum("created_at", createdAt)
        putNum("replaced_at", replacedAt)
    }

    companion object {
        fun fromJson(o: JsonObject) = SignedPreKey(o.u32("id"), o.bytes("secret", 32), o.u64("created_at"), o.optU64("replaced_at"))
    }
}

/** Une clé ML-KEM-768 (secrète : sa graine FIPS 203 `d ‖ z`, 64 octets). */
internal class PqPreKey(val id: Long, val seed: ByteArray, val createdAt: Long, var replacedAt: Long?) {
    fun toJson() = buildJsonObject {
        putNum("id", id)
        putBytes("seed", seed)
        putNum("created_at", createdAt)
        putNum("replaced_at", replacedAt)
    }

    companion object {
        fun fromJson(o: JsonObject) = PqPreKey(o.u32("id"), o.bytes("seed", 64), o.u64("created_at"), o.optU64("replaced_at"))
    }
}

/**
 * Un appareil : son identité, ses clés pré-signées (la courante et celles
 * gardées pour les retardataires) et la mémoire des premiers messages.
 * Sérialisable ([toJson], même forme que la référence) ; à garder chiffré par
 * la clé matérielle (§3.1).
 */
class Device private constructor(
    private val identity: IdentitySecret,
    private val signedPrekeys: MutableList<SignedPreKey>,
    private val pqPrekeys: MutableList<PqPreKey>,
    private var replay: ReplayGuard,
) {
    /** La version du format de l'état. */
    val v: Int = 1

    private fun addPrekeys(rng: CryptoRng, now: Long, pq: Boolean) {
        val spkId = nextId(rng, signedPrekeys.lastOrNull()?.id)
        val secret = rng.bytes(32)
        for (k in signedPrekeys) if (k.replacedAt == null) k.replacedAt = now
        signedPrekeys.add(SignedPreKey(spkId, secret, now, null))
        if (pq) {
            val pqId = nextId(rng, pqPrekeys.lastOrNull()?.id)
            val seed = rng.bytes(64)
            for (k in pqPrekeys) if (k.replacedAt == null) k.replacedAt = now
            pqPrekeys.add(PqPreKey(pqId, seed, now, null))
        }
    }

    /**
     * Renouvelle la SPK (et la PQPK si l'appareil en a une) ; les anciennes
     * restent utilisables [Paquet.PREKEY_GRACE], puis [purge] les efface.
     *
     * Ordre de tirage : id SPK (4 octets, seulement la première fois), secret
     * SPK (32), id PQPK (4, la première fois), graine ML-KEM (64).
     */
    fun rotate(rng: CryptoRng, now: Long) {
        addPrekeys(rng, now, pqPrekeys.isNotEmpty())
        purge(now)
    }

    /** Ajoute ML-KEM à un appareil qui n'en avait pas, en renouvelant la SPK. */
    fun enablePq(rng: CryptoRng, now: Long) = addPrekeys(rng, now, true)

    /** Vrai si la SPK courante a une semaine ou plus. */
    fun needsRotation(now: Long): Boolean {
        val last = signedPrekeys.lastOrNull() ?: return true
        return Octets.satAdd(last.createdAt, Paquet.PREKEY_ROTATION) <= now
    }

    /** Efface les clés remplacées depuis plus d'un mois et les vieilles entrées de la mémoire des premiers messages. */
    fun purge(now: Long) {
        fun keep(r: Long?) = r == null || Octets.satAdd(r, Paquet.PREKEY_GRACE) > now
        signedPrekeys.filterNot { keep(it.replacedAt) }.forEach { Octets.wipe(it.secret) }
        pqPrekeys.filterNot { keep(it.replacedAt) }.forEach { Octets.wipe(it.seed) }
        signedPrekeys.retainAll { keep(it.replacedAt) }
        pqPrekeys.retainAll { keep(it.replacedAt) }
        replay.purge(now)
    }

    /** L'identité publique. */
    fun identity(): IdentityPublic = identity.public()

    /** L'identité secrète (pour l'établissement). */
    val identitySecret: IdentitySecret get() = identity

    /** Vrai si l'appareil a une clé ML-KEM courante. */
    fun supportsPq(): Boolean = pqPrekeys.any { it.replacedAt == null }

    /** Le paquet de clés publiques courant, signé. */
    fun bundle(): KeyBundle {
        val ik = identity.public()
        val spkKey = signedPrekeys.lastOrNull { it.replacedAt == null } ?: echec(Erreur.Etat)
        val spk = Kdf.x25519Public(spkKey.secret)
        val spkSignature = Kdf.ed25519Sign(identity.sign, Paquet.spkSignedMessage(ik.dh, spkKey.id, spk))
        val pq = pqPrekeys.lastOrNull { it.replacedAt == null }?.let { k ->
            val key = MlKem.publicKey(k.seed)
            PqBundle(k.id, key, Kdf.ed25519Sign(identity.sign, Paquet.pqpkSignedMessage(ik.dh, k.id, key)))
        }
        return KeyBundle(ik, spkKey.id, spk, spkSignature, pq)
    }

    internal fun spkSecret(id: Long): ByteArray =
        signedPrekeys.firstOrNull { it.id == id }?.secret?.copyOf() ?: echec(Erreur.CleInconnue)

    internal fun pqSeed(id: Long): ByteArray =
        pqPrekeys.firstOrNull { it.id == id }?.seed?.copyOf() ?: echec(Erreur.CleInconnue)

    internal val replayGuard: ReplayGuard get() = replay

    /** Les secrets de toutes les SPK gardées (la courante d'abord) : un premier message v4 ne dit pas laquelle a servi. */
    internal fun spkSecrets(): List<ByteArray> = signedPrekeys.reversed().map { it.secret.copyOf() }

    /** Les graines ML-KEM de toutes les PQPK gardées (la courante d'abord). */
    internal fun pqSeeds(): List<ByteArray> = pqPrekeys.reversed().map { it.seed.copyOf() }

    /**
     * La capacité v4 signée (§9.6) : `Ed25519(IK, "Brocolis_v4_Caps" ‖ IK
     * X25519 ‖ 0x04)`. Seul un appareil qui a ML-KEM la publie (`null` sinon).
     */
    fun caps4(): ByteArray? {
        if (!supportsPq()) return null
        return Kdf.ed25519Sign(identity.sign, Paquet.caps4Message(identity.public().dh))
    }

    /** Ouvre une session v4 vers un paquet ([Session4.initiate]). */
    fun initiate4(bundle: KeyBundle, rng: CryptoRng = Hasard.system()): Session4 =
        Session4.initiate(identity, bundle, rng)

    /**
     * Accepte le premier message (0x01) d'une session v4 : essaie chaque SPK
     * et PQPK gardée jusqu'à ouvrir le préambule (IK_A), puis établit la
     * session et déchiffre. Aucune ne l'ouvre : [Erreur.CleInconnue]. Une EK
     * déjà vue : [Erreur.Rejoue]. L'appelant vérifie ensuite que
     * [Session4.peerIdentity] est celle d'un contact. Sans effet sur
     * l'appareil en cas d'échec.
     */
    fun accept4(token: Token4, now: Long, rng: CryptoRng = Hasard.system()): Pair<Session4, Content> =
        Session4.accept(this, token, now, rng)

    /** Ouvre une session vers un paquet ([Session.initiate]). */
    fun initiate(bundle: KeyBundle, pq: Boolean, rng: CryptoRng = Hasard.system()): Session =
        Session.initiate(identity, bundle, pq, rng)

    /**
     * Accepte le premier message (type 0x01) d'une nouvelle session, en mode
     * X25519 ou hybride : retrouve la SPK (et la PQPK) désignées, calcule SK,
     * déchiffre. Un premier message dont la clé éphémère a déjà servi est
     * refusé ([Erreur.Rejoue]). Sans effet sur l'appareil en cas d'échec.
     */
    fun accept(msg: Initial, now: Long, rng: CryptoRng = Hasard.system()): Pair<Session, Content> =
        Session.accept(this, msg, now, rng)

    /** L'état en JSON (même forme que la référence Rust). */
    fun toJson(): String = EtatJson.write(toJsonObject())

    internal fun toJsonObject(): JsonObject = buildJsonObject {
        putNum("v", v.toLong())
        put("identity", identity.toJson())
        put("signed_prekeys", JsonArray(signedPrekeys.map { it.toJson() }))
        put("pq_prekeys", JsonArray(pqPrekeys.map { it.toJson() }))
        put("replay", replay.toJsonObject())
    }

    companion object {
        private fun nextId(rng: CryptoRng, last: Long?): Long = if (last != null) {
            maxOf((last + 1) and Octets.U32_MAX, 1L)
        } else {
            maxOf(rng.nextU32() ushr 1, 1L)
        }

        /**
         * Un nouvel appareil : identité, SPK et, avec `pq`, PQPK.
         *
         * Ordre de tirage (vecteurs) : secret X25519 d'IK (32), graine Ed25519
         * (32), puis comme [rotate].
         */
        fun generate(rng: CryptoRng, now: Long, pq: Boolean): Device {
            val identity = IdentitySecret(rng.bytes(32), rng.bytes(32))
            return fromIdentity(identity, rng, now, pq)
        }

        /** Un appareil à partir d'une identité existante (nouvelles SPK et PQPK). */
        fun fromIdentity(identity: IdentitySecret, rng: CryptoRng, now: Long, pq: Boolean): Device {
            val d = Device(IdentitySecret(identity.dh, identity.sign), mutableListOf(), mutableListOf(), ReplayGuard())
            d.addPrekeys(rng, now, pq)
            return d
        }

        /**
         * Un appareil à partir de secrets donnés (vecteurs, import) : identité,
         * SPK (id, secret) et, optionnellement, PQPK (id, graine `d ‖ z`).
         */
        fun fromSecrets(identity: IdentitySecret, spk: Pair<Long, ByteArray>, pq: Pair<Long, ByteArray>?, now: Long): Device {
            require(spk.second.size == 32 && (pq == null || pq.second.size == 64))
            return Device(
                IdentitySecret(identity.dh, identity.sign),
                mutableListOf(SignedPreKey(spk.first, spk.second.copyOf(), now, null)),
                if (pq == null) mutableListOf() else mutableListOf(PqPreKey(pq.first, pq.second.copyOf(), now, null)),
                ReplayGuard(),
            )
        }

        /** Relit un état JSON (version 1). */
        fun fromJson(text: String): Device {
            val o = EtatJson.parse(text)
            if (o.u8("v") != 1L) echec(Erreur.Etat)
            return Device(
                IdentitySecret.fromJson(o.obj("identity")),
                o.arr("signed_prekeys").map { SignedPreKey.fromJson(it.asObj()) }.toMutableList(),
                o.arr("pq_prekeys").map { PqPreKey.fromJson(it.asObj()) }.toMutableList(),
                // `#[serde(default)]` : un état sans mémoire des premiers messages se relit.
                o["replay"]?.let { ReplayGuard.fromJsonObject(it.asObj()) } ?: ReplayGuard(),
            )
        }
    }
}
