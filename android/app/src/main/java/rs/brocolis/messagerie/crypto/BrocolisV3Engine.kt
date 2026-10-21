package rs.brocolis.messagerie.crypto

import kotlinx.serialization.Serializable
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.proto.BrocolisException
import rs.brocolis.messagerie.proto.Content
import rs.brocolis.messagerie.proto.CryptoRng
import rs.brocolis.messagerie.proto.Device
import rs.brocolis.messagerie.proto.GroupMessage
import rs.brocolis.messagerie.proto.Erreur
import rs.brocolis.messagerie.proto.Hasard
import rs.brocolis.messagerie.proto.Kdf
import rs.brocolis.messagerie.proto.KeyBundle
import rs.brocolis.messagerie.proto.Mode
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.proto.Paquet
import rs.brocolis.messagerie.proto.Protocole
import rs.brocolis.messagerie.proto.ReceivedSenderKey
import rs.brocolis.messagerie.proto.ReplayGuard
import rs.brocolis.messagerie.proto.SenderKeyDistribution
import rs.brocolis.messagerie.proto.SenderKeyState
import rs.brocolis.messagerie.proto.Session
import rs.brocolis.messagerie.proto.Session4
import rs.brocolis.messagerie.proto.Token
import rs.brocolis.messagerie.proto.Token4
import java.security.SecureRandom

/*
 * Le protocole v3 dans Brocolis (docs/SECURITE.md §8) : sessions à double
 * cliquet, établies en hybride X25519 + ML-KEM-768 (toujours disponible ici :
 * BouncyCastle), avec le module `:proto`.
 *
 * Ce fichier est la logique PURE (ni Keystore, ni fichier, ni interface),
 * testée sur la JVM ; c'est la même que l'iPhone (`Shared/BrocolisV3.swift`)
 * et le site (`site/src/v3.rs`) :
 *
 * - un appareil v3 (`Device`) par installation, entretenu à chaque
 *   transaction (§8.1) ;
 * - deux sessions au plus par contact (la dernière qui a servi envoie), et
 *   des sessions PSK par clé (§8.2) ;
 * - les messages ouverts : un message v3 ne se déchiffre qu'une fois, son
 *   clair est gardé sous l'empreinte du jeton (§8.2) ;
 * - le choix du format d'un envoi (§8.5), la réception et la réparation
 *   (seulement d'une session perdue, §8.6) ;
 * - l'empreinte d'appairage (§8.4) et l'enveloppe des médias (§8.7) ;
 * - le v4 (§9) par le même moteur : un contact dont la capacité v4 signée
 *   est valide (ou dont un message v4 est déjà arrivé) reçoit des jetons
 *   `[[BROCOLIS:v4:…]]` à triple cliquet et en-têtes chiffrés, et ne
 *   redescend plus en v3 ; son empreinte d'appairage prend le contexte v4
 *   (§9.7).
 *
 * La persistance et le verrou entre processus sont dans
 * `store/BrocolisV3Store.kt` ; la façade dont se servent les écrans, dans
 * `BrocolisV3.kt`.
 */

// MARK: - Protection affichée (§8.8)

/** La protection d'une clé, telle que le prochain envoi la donnera. */
enum class BrocolisProtection {
    /** v4 : ML-KEM à chaque tour, en-têtes chiffrés (§9). */
    TRIPLE,
    /** v4, à partir de la clé partagée. */
    TRIPLE_PSK,
    POST_QUANTUM, CLASSIC, PSK, LEGACY,
    /** L'identité du contact a changé sans confirmation (§9.8) : rien ne part vers lui. */
    IDENTITY_CHANGED;

    /** Libellé affiché partout où s'affiche une clé ou un contact. */
    val label: String
        get() = when (this) {
            TRIPLE -> loc(
                "🔐 triple cliquet (post-quantique à chaque message)",
                "🔐 triple ratchet (post-quantum on every message)",
                "🔐 triple trinquete (poscuántico en cada mensaje)",
            )
            TRIPLE_PSK -> loc("🔐 triple cliquet, clé partagée (PSK)", "🔐 triple ratchet, shared key (PSK)", "🔐 triple trinquete, clave compartida (PSK)")
            POST_QUANTUM -> loc("🔐 double cliquet (post-quantique)", "🔐 double ratchet (post-quantum)", "🔐 doble trinquete (poscuántico)")
            CLASSIC -> loc("🔐 double cliquet (classique)", "🔐 double ratchet (classic)", "🔐 doble trinquete (clásico)")
            PSK -> loc("🔐 double cliquet, clé partagée (PSK)", "🔐 double ratchet, shared key (PSK)", "🔐 doble trinquete, clave compartida (PSK)")
            LEGACY -> loc("ancien format", "old format", "formato antiguo")
            IDENTITY_CHANGED -> BrocolisIdentity.warning
        }

    /** Un envoi à cliquet (v3 ou v4). */
    val isRatchet: Boolean get() = this != LEGACY && this != IDENTITY_CHANGED
}

// MARK: - Une clé vue par le moteur

/**
 * Une clé nommée, telle que le moteur v3 la voit (§8.5).
 *
 * @property id l'identifiant de la clé nommée (où ranger ses sessions PSK) ;
 * @property raw la clé partagée (32 octets) ;
 * @property bundle le paquet du correspondant reçu à l'appairage, vérifié ;
 * @property bundleAt quand ce paquet est arrivé (secondes Unix) ;
 * @property group une clé de groupe (3 personnes ou plus) : jamais de v3 ;
 * @property psk marquée « à deux, double cliquet » par l'utilisateur (PSK) ;
 * @property caps sa capacité v4 signée, reçue avec le paquet (§9.6), vérifiée
 *   par le moteur.
 */
class BrocolisV3Key(
    val id: String,
    val raw: ByteArray,
    val bundle: KeyBundle?,
    val bundleAt: Long,
    val group: Boolean,
    val psk: Boolean,
    val caps: ByteArray? = null,
)

/** Le résultat d'une réception. */
sealed class BrocolisV3Opened {
    /** Le clair (déchiffré à l'instant, ou gardé). */
    data class Text(val text: String) : BrocolisV3Opened()
    /** Déjà lu, et le clair n'est plus gardé. */
    object Replay : BrocolisV3Opened()
    /** Une chaîne de groupe reçue (§9.9) : gardée, rien à afficher. */
    object Hidden : BrocolisV3Opened()
    /** Illisible (pas pour nous, session perdue, altéré…). */
    data class Failed(val erreur: Erreur) : BrocolisV3Opened()
}

// MARK: - Constantes et outils (§8)

object BrocolisV3Format {
    /** Le début du clair v3 qui porte une clé de média (§8.7). */
    const val MEDIA_PREFIX = "BRCM3:"
    /** Le début d'un média (photo, vocal) dans un clair. */
    const val MEDIA_V1_PREFIX = "BRCM1:"
    /** Au-delà (ou pour un média `BRCM1:`), l'enveloppe des médias. */
    const val MEDIA_THRESHOLD = 16 * 1024
    /** Un paquet d'appairage ouvre une session pendant 30 jours (§8.5). */
    const val BUNDLE_MAX_AGE: Long = 30 * Protocole.JOUR
    /** Celui qui rejoint relit le salon pendant 8 jours (§8.4). */
    const val GROUP_WATCH: Long = 8 * Protocole.JOUR
    /** Ce qui précède les identités dans l'empreinte d'appairage (§8.4). */
    val FINGERPRINT_CONTEXT: ByteArray = "Brocolis_v3_Appairage".toByteArray(Charsets.UTF_8)
    /** …quand les deux côtés ont une capacité v4 valide (§9.7). */
    val FINGERPRINT_CONTEXT_V4: ByteArray = "Brocolis_v4_Appairage".toByteArray(Charsets.UTF_8)
    /** Messages ouverts gardés : 2 000 au plus et 1 Mio de clair (§8.2). */
    const val OPENED_MAX = 2_000
    const val OPENED_MAX_BYTES = 1 shl 20
    /** Deux sessions au plus par contact. */
    const val SESSIONS_PER_PEER = 2

    /** Faut-il réparer ? Seulement une session PERDUE (§8.6). */
    fun needsRepair(e: Erreur): Boolean = e == Erreur.SessionInconnue || e == Erreur.CleInconnue

    /**
     * L'empreinte d'appairage à deux (§8.4) :
     * SHA-256("Brocolis_v3_Appairage" ‖ K ‖ min(P_A, P_B) ‖ max(P_A, P_B))[0..8],
     * P = IK X25519 ‖ IK Ed25519, en XXXX-XXXX-XXXX-XXXX.
     */
    fun pairingFingerprint(key: ByteArray, a: ByteArray, b: ByteArray): String =
        fingerprintWith(FINGERPRINT_CONTEXT, key, a, b)

    /** L'empreinte d'appairage v4 (§9.7) : la même, sous `"Brocolis_v4_Appairage"`. */
    fun pairingFingerprint4(key: ByteArray, a: ByteArray, b: ByteArray): String =
        fingerprintWith(FINGERPRINT_CONTEXT_V4, key, a, b)

    private fun fingerprintWith(context: ByteArray, key: ByteArray, a: ByteArray, b: ByteArray): String {
        val (lo, hi) = if (compare(a, b) <= 0) a to b else b to a
        val digest = Kdf.sha256(context + key + lo + hi)
        val hex = digest.copyOf(8).joinToString("") { "%02X".format(it.toInt() and 0xff) }
        return hex.chunked(4).joinToString("-")
    }

    /** Ordre lexicographique des octets (non signés). */
    private fun compare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val x = a[i].toInt() and 0xff
            val y = b[i].toInt() and 0xff
            if (x != y) return x - y
        }
        return a.size - b.size
    }

    /**
     * La capacité v4 du paquet est-elle valide (§9.6) : 64 octets signés par
     * son identité, et un paquet qui propose ML-KEM.
     */
    fun capsValid(bundle: KeyBundle, caps: ByteArray?): Boolean =
        bundle.pq != null && caps != null && runCatching { Paquet.verifyCaps4(bundle.identity, caps) }.isSuccess

    /** Un message de groupe signé (0x04, §4.5) ? */
    fun isGroupToken(token: String): Boolean =
        runCatching { Token.decode(normalize(token)) }.getOrNull() is Token.Group

    /** Un jeton v4 (§9.4) ? */
    fun isV4(token: String): Boolean = token.trimStart().startsWith(Token4.HEAD)

    /** L'identité d'un paquet : IK X25519 ‖ IK Ed25519 (64 octets). */
    fun identity(bundle: KeyBundle): ByteArray = bundle.identity.dh + bundle.identity.sign

    /** Le jeton sans aucun blanc (une messagerie peut couper une ligne). */
    fun normalize(token: String): String {
        val sb = StringBuilder(token.length)
        var i = 0
        while (i < token.length) {
            val cp = token.codePointAt(i)
            if (!Character.isWhitespace(cp) && !Character.isSpaceChar(cp)) sb.appendCodePoint(cp)
            i += Character.charCount(cp)
        }
        return sb.toString()
    }

    /** L'empreinte d'un jeton, sous laquelle son clair est gardé (§8.2). */
    fun tokenHash(token: String): String = Octets.hex(Kdf.sha256(normalize(token).toByteArray(Charsets.UTF_8)))

    /**
     * Les jetons v3 et v4 d'un texte, dans l'ordre (début inclus, fin
     * exclue ; les jetons v1 de l'enveloppe des médias n'en sont pas).
     */
    fun findTokens(text: String): List<IntRange> {
        val out = ArrayList<IntRange>()
        var from = 0
        while (true) {
            val start = text.indexOf("[[BROCOLIS:v", from)
            if (start < 0) break
            if (!text.startsWith(Token.HEAD, start) && !text.startsWith(Token4.HEAD, start)) {
                from = start + 2
                continue
            }
            val end = text.indexOf("]]", start + Token.HEAD.length)
            if (end < 0) break
            out.add(start until end + 2)
            from = end + 2
        }
        return out
    }
}

// MARK: - L'état gardé (§8.2)

/** Les sessions d'un contact (ou d'une clé PSK), telles qu'elles sont gardées. */
@Serializable
data class BrocolisV3StoredPeer(
    val current: String = "",
    /** Chaque session, dans le JSON de la référence. */
    val sessions: List<String> = emptyList(),
)

/** Un message ouvert (§8.2). */
@Serializable
data class BrocolisV3StoredOpened(
    val h: String,
    val text: String,
    val at: Long,
    val mine: Boolean,
    /** Qui l'a écrit : `c:` + IK du contact, `k:` + id de la clé (PSK), vide si inconnu. */
    val from: String = "",
)

/** Ma chaîne d'un groupe (§9.9), et les membres (`c:`/`k:`) qui l'ont reçue. */
@Serializable
data class BrocolisV3StoredChain(val chain: String, val given: List<String> = emptyList())

/** La chaîne d'un autre membre, et de qui elle vient (`c:`/`k:`). */
@Serializable
data class BrocolisV3StoredReceived(val from: String, val key: String)

/** L'état chiffré au repos : sessions et messages ouverts. */
@Serializable
data class BrocolisV3Stored(
    val v: Int = 1,
    val peers: Map<String, BrocolisV3StoredPeer> = emptyMap(),
    val psk: Map<String, BrocolisV3StoredPeer> = emptyMap(),
    val pskSeen: List<String> = emptyList(),
    val pskReplay: String? = null,
    val opened: List<BrocolisV3StoredOpened> = emptyList(),
    /** Les sessions v4 (§9), rangées comme les v3. */
    val peers4: Map<String, BrocolisV3StoredPeer> = emptyMap(),
    val psk4: Map<String, BrocolisV3StoredPeer> = emptyMap(),
    /** Les contacts (IK X25519, hex) dont un message v4 est arrivé : on ne leur écrit plus qu'en v4 (§9.6). */
    val v4Seen: List<String> = emptyList(),
    /** Les clés sur lesquelles une PSK v4 est arrivée. */
    val psk4Seen: List<String> = emptyList(),
    /** Mes chaînes de groupe (§9.9), par identifiant de groupe (hex). */
    val groups: Map<String, BrocolisV3StoredChain> = emptyMap(),
    /** Les chaînes reçues des autres membres. */
    val received: List<BrocolisV3StoredReceived> = emptyList(),
)

/** Ce qu'une session à deux transporte : un texte, ou une chaîne de groupe (§9.9). */
private sealed class BrocolisPayload {
    class Text(val text: String) : BrocolisPayload()
    class Chain(val d: SenderKeyDistribution) : BrocolisPayload()

    fun seal3(s: Session): String = when (this) {
        is Text -> s.encrypt(text)
        // Une distribution v3 (0x03) ne voyage que sur une session que l'autre
        // a déjà : tant que la nôtre n'est pas confirmée, un premier message
        // vide (0x01) la lui ouvre d'abord.
        is Chain -> (if (s.isConfirmed) "" else s.encrypt("")) + s.encryptDistribution(d)
    }

    fun seal4(s: Session4): String = when (this) {
        is Text -> s.encrypt(text)
        is Chain -> s.encryptDistribution(d)
    }
}

/** Ma chaîne d'un groupe. */
private class MyChain(val chain: SenderKeyState, val given: MutableList<String>)

/** Une chaîne reçue. */
private class Received(val from: String, val key: ReceivedSenderKey)

/** Les chaînes reçues gardées, au plus. */
private const val RECEIVED_MAX = 512

/** Ce que le rangement attend d'une session v3 ou v4. */
private interface Rangement<S> {
    fun id(s: S): ByteArray
    fun json(s: S): String
    fun parse(json: String): S?
}

private object RangementV3 : Rangement<Session> {
    override fun id(s: Session) = s.sessionId
    override fun json(s: Session) = s.toJson()
    override fun parse(json: String) = runCatching { Session.fromJson(json) }.getOrNull()
}

private object RangementV4 : Rangement<Session4> {
    override fun id(s: Session4) = s.sessionId
    override fun json(s: Session4) = s.toJson()
    override fun parse(json: String) = runCatching { Session4.fromJson(json) }.getOrNull()
}

/** Les sessions (v3 ou v4) d'un contact (ou d'une clé PSK). */
class BrocolisPeer<S> private constructor(private val r: Rangement<S>) {
    val sessions: MutableList<S> = ArrayList()
    var current: ByteArray? = null

    private constructor(r: Rangement<S>, stored: BrocolisV3StoredPeer?) : this(r) {
        if (stored != null) {
            stored.sessions.mapNotNull { r.parse(it) }
                .take(BrocolisV3Format.SESSIONS_PER_PEER)
                .forEach { sessions.add(it) }
            current = sessions.map { r.id(it) }.firstOrNull { Octets.hex(it) == stored.current }
        }
    }

    val stored: BrocolisV3StoredPeer
        get() = BrocolisV3StoredPeer(current?.let(Octets::hex) ?: "", sessions.map { r.json(it) })

    fun get(id: ByteArray): S? = sessions.firstOrNull { r.id(it).contentEquals(id) }

    val sendingId: ByteArray?
        get() {
            val c = current
            if (c != null && sessions.any { r.id(it).contentEquals(c) }) return c
            return sessions.lastOrNull()?.let { r.id(it) }
        }

    val sending: S? get() = sendingId?.let(::get)

    /**
     * Range une session (remplace celle de même identifiant, la plus ancienne
     * part au-delà de deux) et en fait la session d'envoi.
     */
    fun put(s: S) {
        val id = r.id(s)
        sessions.removeAll { r.id(it).contentEquals(id) }
        sessions.add(s)
        while (sessions.size > BrocolisV3Format.SESSIONS_PER_PEER) sessions.removeAt(0)
        current = id
    }

    companion object {
        /** Les sessions v3 d'un contact. */
        fun v3(stored: BrocolisV3StoredPeer? = null): BrocolisPeer<Session> = BrocolisPeer(RangementV3, stored)

        /** Les sessions v4 d'un contact (§9). */
        fun v4(stored: BrocolisV3StoredPeer? = null): BrocolisPeer<Session4> = BrocolisPeer(RangementV4, stored)
    }
}

// MARK: - Le moteur (le temps d'une transaction, §8.3)

/**
 * L'appareil v3 et ses sessions. Ce qui a changé se lit avec [deviceDirty] /
 * [stateDirty] : l'appelant l'écrit (l'appareil d'abord) avant de rendre le
 * jeton.
 *
 * Charge l'appareil et l'état (ou les crée), puis entretient l'appareil
 * (§8.1). Un état illisible repart de zéro.
 */
class BrocolisV3Engine(
    deviceJson: String?,
    stored: BrocolisV3Stored?,
    now: Long,
    private val rng: CryptoRng = Hasard.system(),
) {
    val device: Device
    private val peers: MutableMap<String, BrocolisPeer<Session>>
    private val psk: MutableMap<String, BrocolisPeer<Session>>
    private val pskSeen: MutableList<String>
    private val pskReplay: ReplayGuard
    private val opened: ArrayDeque<BrocolisV3StoredOpened>
    private val peers4: MutableMap<String, BrocolisPeer<Session4>>
    private val psk4: MutableMap<String, BrocolisPeer<Session4>>
    private val v4Seen: MutableList<String>
    private val psk4Seen: MutableList<String>
    private val groups: MutableMap<String, MyChain>
    private val received: MutableList<Received>
    /** L'expéditeur du dernier jeton déchiffré (voir [sender]). */
    private var lastFrom: String = ""
    var deviceDirty: Boolean
        private set
    var stateDirty: Boolean = false
        private set

    init {
        val existing = deviceJson?.let { runCatching { Device.fromJson(it) }.getOrNull() }
        // ML-KEM-768 est toujours là (BouncyCastle) : appareil hybride d'emblée.
        device = existing ?: Device.generate(rng, now, pq = true)
        deviceDirty = existing == null
        val s = stored ?: BrocolisV3Stored()
        peers = s.peers.mapValuesTo(LinkedHashMap()) { BrocolisPeer.v3(it.value) }
        psk = s.psk.mapValuesTo(LinkedHashMap()) { BrocolisPeer.v3(it.value) }
        peers4 = s.peers4.mapValuesTo(LinkedHashMap()) { BrocolisPeer.v4(it.value) }
        psk4 = s.psk4.mapValuesTo(LinkedHashMap()) { BrocolisPeer.v4(it.value) }
        v4Seen = s.v4Seen.toMutableList()
        psk4Seen = s.psk4Seen.toMutableList()
        groups = LinkedHashMap()
        for ((gid, c) in s.groups) {
            val chain = runCatching { SenderKeyState.fromJson(c.chain) }.getOrNull() ?: continue
            groups[gid] = MyChain(chain, c.given.toMutableList())
        }
        received = s.received.mapNotNull { r ->
            runCatching { ReceivedSenderKey.fromJson(r.key) }.getOrNull()?.let { Received(r.from, it) }
        }.toMutableList()
        pskSeen = s.pskSeen.toMutableList()
        pskReplay = s.pskReplay?.let { runCatching { ReplayGuard.fromJson(it) }.getOrNull() } ?: ReplayGuard()
        opened = ArrayDeque(s.opened)
        maintain(now)
    }

    /**
     * SPK et PQPK neuves chaque semaine, ML-KEM s'il manquait, purge des clés
     * remplacées depuis un mois.
     */
    private fun maintain(now: Long) {
        if (device.needsRotation(now)) {
            device.rotate(rng, now)
            deviceDirty = true
        }
        if (!device.supportsPq()) {
            if (runCatching { device.enablePq(rng, now) }.isSuccess) deviceDirty = true
        }
        device.purge(now)
        for (peer in peers.values + psk.values) {
            for (s in peer.sessions) s.purge(now)
        }
        for (peer in peers4.values + psk4.values) {
            for (s in peer.sessions) s.purge(now)
        }
    }

    /** L'état à garder. */
    val stored: BrocolisV3Stored
        get() = BrocolisV3Stored(
            v = 1,
            peers = peers.mapValues { it.value.stored },
            psk = psk.mapValues { it.value.stored },
            pskSeen = pskSeen.toList(),
            pskReplay = pskReplay.toJson(),
            opened = opened.toList(),
            peers4 = peers4.mapValues { it.value.stored },
            psk4 = psk4.mapValues { it.value.stored },
            v4Seen = v4Seen.toList(),
            psk4Seen = psk4Seen.toList(),
            groups = groups.mapValues { BrocolisV3StoredChain(it.value.chain.toJson(), it.value.given.toList()) },
            received = received.map { BrocolisV3StoredReceived(it.from, it.key.toJson()) },
        )

    /** Le paquet de clés à publier dans le salon (base64). */
    val bundleBase64: String? get() = runCatching { device.bundle().toBase64() }.getOrNull()

    /** Ma capacité v4 signée, à publier avec le paquet (§9.6, base64). */
    val capsBase64: String? get() = device.caps4()?.let(Octets::b64)

    /** Mon identité : IK X25519 ‖ IK Ed25519. */
    val identity: ByteArray get() = device.identity().dh + device.identity().sign

    /**
     * L'empreinte d'appairage à comparer pour `k` (§8.4, §9.7) : sous le
     * contexte v4 si le contact a une capacité valide (la mienne est
     * toujours publiée), sinon v3. `null` sans paquet.
     */
    fun fingerprint(k: BrocolisV3Key): String? {
        val b = contact(k) ?: return null
        val theirs = BrocolisV3Format.identity(b)
        return if (BrocolisV3Format.capsValid(b, k.caps) && device.supportsPq()) {
            BrocolisV3Format.pairingFingerprint4(k.raw, identity, theirs)
        } else {
            BrocolisV3Format.pairingFingerprint(k.raw, identity, theirs)
        }
    }

    // MARK: Choix (§8.5)

    private fun contact(k: BrocolisV3Key): KeyBundle? = if (k.group) null else k.bundle

    private fun fresh(k: BrocolisV3Key, now: Long): Boolean = Octets.satAdd(k.bundleAt, BrocolisV3Format.BUNDLE_MAX_AGE) > now

    /**
     * Le paquet du contact s'il parle v4 (§9.6) : ML-KEM, et une capacité
     * valide ou un message v4 déjà reçu de lui (on ne redescend pas).
     */
    private fun contact4(k: BrocolisV3Key): KeyBundle? {
        val b = contact(k) ?: return null
        if (b.pq == null || !device.supportsPq()) return null
        val sticky = v4Seen.contains(Octets.hex(b.identity.dh))
        return if (sticky || BrocolisV3Format.capsValid(b, k.caps)) b else null
    }

    /** La PSK part-elle en v4 : une PSK v4 est arrivée sur la clé, ou le contact parle v4. */
    private fun psk4Allowed(k: BrocolisV3Key, now: Long): Boolean =
        pskAllowed(k, now) && (psk4Seen.contains(k.id) || contact4(k) != null)

    private fun pskAllowed(k: BrocolisV3Key, now: Long): Boolean {
        if (k.group) return false
        // Un contact v3 au paquet trop vieux est à jour : la PSK est sûre.
        return k.psk || pskSeen.contains(k.id) || (k.bundle != null && !fresh(k, now))
    }

    /** La protection de la clé, telle que le prochain envoi la donnera (§8.8). */
    fun protection(k: BrocolisV3Key, now: Long): BrocolisProtection {
        val b4 = contact4(k)
        if (b4 != null) {
            val live = peers4[Octets.hex(b4.identity.dh)]?.sendingId != null
            if (live || fresh(k, now)) return BrocolisProtection.TRIPLE
        } else contact(k)?.let { b ->
            peers[Octets.hex(b.identity.dh)]?.sending?.let { s ->
                return if (s.isPostQuantum) BrocolisProtection.POST_QUANTUM else BrocolisProtection.CLASSIC
            }
            if (fresh(k, now)) {
                return if (b.pq != null) BrocolisProtection.POST_QUANTUM else BrocolisProtection.CLASSIC
            }
        }
        return when {
            psk4Allowed(k, now) -> BrocolisProtection.TRIPLE_PSK
            pskAllowed(k, now) -> BrocolisProtection.PSK
            else -> BrocolisProtection.LEGACY
        }
    }

    /**
     * Ouvre la session vers le contact s'il n'y en a pas (l'invitant, à la fin
     * de l'appairage : §8.4). Rien ne part : le premier message la porte.
     */
    fun openSession(k: BrocolisV3Key, now: Long): Boolean {
        contact4(k)?.let { b4 ->
            val peer = peer4For(b4)
            if (peer.sendingId != null) return true
            if (!fresh(k, now)) return false
            val s = runCatching { device.initiate4(b4, rng) }.getOrNull() ?: return false
            peer.put(s)
            stateDirty = true
            return true
        }
        val b = contact(k) ?: return false
        if (!fresh(k, now)) return false
        val peer = peerFor(b)
        if (peer.sendingId != null) return true
        val s = initiateBest(b) ?: return false
        peer.put(s)
        stateDirty = true
        return true
    }

    /** Hybride si le paquet propose ML-KEM (cet appareil le sait toujours). */
    private fun initiateBest(b: KeyBundle): Session? =
        runCatching { device.initiate(b, pq = b.pq != null, rng = rng) }.getOrNull()

    private fun peerFor(b: KeyBundle): BrocolisPeer<Session> =
        peers.getOrPut(Octets.hex(b.identity.dh)) { BrocolisPeer.v3() }

    private fun pskPeer(id: String): BrocolisPeer<Session> = psk.getOrPut(id) { BrocolisPeer.v3() }

    private fun peer4For(b: KeyBundle): BrocolisPeer<Session4> =
        peers4.getOrPut(Octets.hex(b.identity.dh)) { BrocolisPeer.v4() }

    private fun psk4Peer(id: String): BrocolisPeer<Session4> = psk4.getOrPut(id) { BrocolisPeer.v4() }

    // MARK: Envoi

    /**
     * Chiffre `text` pour `k` en v3 (§8.5) : session de contact, session neuve
     * vers son paquet, ou PSK. `null` : l'appelant chiffre en v1/v2.
     */
    fun seal(text: String, k: BrocolisV3Key, now: Long): String? {
        if (text.toByteArray(Charsets.UTF_8).size > Session.MAX_PLAINTEXT) return null
        val token = sealPayload(k, BrocolisPayload.Text(text), now) ?: return null
        remember(token, text, mine = true, now = now)
        return token
    }

    /**
     * Ce qu'emporte une session à deux, quelle qu'elle soit. Un contact v4 ne
     * reçoit plus que du v4 (§9.6) : sans session ni paquet frais, la PSK
     * (v4) prend le relais, jamais le v3.
     */
    private fun sealPayload(k: BrocolisV3Key, payload: BrocolisPayload, now: Long): String? {
        val contact = if (contact4(k) != null) sealContact4(payload, k, now) else sealContact(payload, k, now)
        return contact ?: if (psk4Allowed(k, now)) sealPsk4(payload, k) else sealPsk(payload, k, now)
    }

    private fun sealContact(payload: BrocolisPayload, k: BrocolisV3Key, now: Long): String? {
        val b = contact(k) ?: return null
        val peer = peerFor(b)
        peer.sending?.let { s ->
            runCatching { payload.seal3(s) }.getOrNull()?.let { token ->
                stateDirty = true
                return token
            }
            // Chaîne épuisée ou état abîmé : une session neuve.
            peer.sessions.clear()
        }
        if (!fresh(k, now)) return null
        val s = initiateBest(b) ?: return null
        val token = runCatching { payload.seal3(s) }.getOrNull() ?: return null
        peer.put(s)
        stateDirty = true
        return token
    }

    private fun sealContact4(payload: BrocolisPayload, k: BrocolisV3Key, now: Long): String? {
        val b = contact4(k) ?: return null
        val peer = peer4For(b)
        peer.sending?.let { s ->
            runCatching { payload.seal4(s) }.getOrNull()?.let { token ->
                stateDirty = true
                return token
            }
            peer.sessions.clear()
        }
        if (!fresh(k, now)) return null
        val s = runCatching { device.initiate4(b, rng) }.getOrNull() ?: return null
        val token = runCatching { payload.seal4(s) }.getOrNull() ?: return null
        peer.put(s)
        stateDirty = true
        return token
    }

    private fun sealPsk4(payload: BrocolisPayload, k: BrocolisV3Key): String? {
        if (k.raw.size != 32) return null
        val peer = psk4Peer(k.id)
        peer.sending?.let { s ->
            runCatching { payload.seal4(s) }.getOrNull()?.let { token ->
                stateDirty = true
                return token
            }
            peer.sessions.clear()
        }
        val s = runCatching { Session4.initiatePsk(k.raw, rng) }.getOrNull() ?: return null
        val token = runCatching { payload.seal4(s) }.getOrNull() ?: return null
        peer.put(s)
        stateDirty = true
        return token
    }

    private fun sealPsk(payload: BrocolisPayload, k: BrocolisV3Key, now: Long): String? {
        if (!pskAllowed(k, now) || k.raw.size != 32) return null
        val peer = pskPeer(k.id)
        peer.sending?.let { s ->
            runCatching { payload.seal3(s) }.getOrNull()?.let { token ->
                stateDirty = true
                return token
            }
            peer.sessions.clear()
        }
        val s = runCatching { Session.initiatePsk(k.raw, rng) }.getOrNull() ?: return null
        val token = runCatching { payload.seal3(s) }.getOrNull() ?: return null
        peer.put(s)
        stateDirty = true
        return token
    }

    // MARK: Groupes à cliquet (§9.9)

    /** Qui est ce membre d'un groupe : `c:` + son IK (contact), ou `k:` + sa clé (PSK). */
    private fun memberTag(k: BrocolisV3Key): String =
        contact(k)?.let { "c:" + Octets.hex(it.identity.dh) } ?: "k:${k.id}"

    /**
     * Le groupe peut-il partir à cliquet : chaque membre a une session à deux
     * possible (contact v3/v4 ou PSK).
     */
    fun groupRatchet(members: List<BrocolisV3Key>, now: Long): Boolean =
        members.isNotEmpty() && members.all { protection(it, now).isRatchet }

    /**
     * Chiffre `text` pour un groupe à cliquet (§9.9) : ma chaîne du groupe
     * (neuve si un membre l'a quitté), remise d'abord par sa session à deux à
     * chaque membre qui ne l'a pas encore, puis le message de groupe (0x04),
     * le tout dans le même texte. `null` si un membre n'a pas de session
     * possible : l'appelant reste en v2.
     */
    fun sealGroup(groupId: ByteArray, members: List<BrocolisV3Key>, text: String, now: Long): String? {
        if (groupId.size != 16 || text.toByteArray(Charsets.UTF_8).size > Session.MAX_PLAINTEXT ||
            !groupRatchet(members, now)
        ) {
            return null
        }
        val tags = members.map(::memberTag)
        val gid = Octets.hex(groupId)
        val current = groups[gid]
        // Un membre est sorti : la chaîne qui lui avait été remise est abandonnée.
        if (current == null || current.given.any { it !in tags }) {
            groups[gid] = MyChain(SenderKeyState.generate(groupId, rng), mutableListOf())
            stateDirty = true
        }
        val c = groups[gid] ?: return null
        val d = c.chain.distribution()
        val out = StringBuilder()
        val newly = mutableListOf<String>()
        for ((k, tag) in members.zip(tags)) {
            if (tag in c.given || tag in newly) continue
            val token = sealPayload(k, BrocolisPayload.Chain(d), now) ?: return null
            remember(token, "", mine = true, now = now)
            out.append(token)
            newly.add(tag)
        }
        val msg = runCatching { c.chain.encrypt(text) }.getOrNull() ?: return null
        c.given.addAll(newly)
        stateDirty = true
        remember(msg, text, mine = true, now = now)
        out.append(msg)
        return out.toString()
    }

    /** Garde la chaîne d'un membre (elle remplace celle de même groupe et même expéditeur). */
    private fun keepChain(d: SenderKeyDistribution, from: String) {
        val key = ReceivedSenderKey.fromDistribution(d)
        received.removeAll { it.key.groupId.contentEquals(d.groupId) && it.key.senderId.contentEquals(d.senderId) }
        received.add(Received(from, key))
        while (received.size > RECEIVED_MAX) received.removeAt(0)
        stateDirty = true
    }

    /** Un message de groupe (0x04) : la chaîne reçue de son expéditeur. */
    private fun decryptGroup(m: GroupMessage, now: Long): Content {
        val r = received.firstOrNull { it.key.matches(m) } ?: fail(Erreur.ExpediteurInconnu)
        val text = r.key.decrypt(m, now)
        lastFrom = r.from
        stateDirty = true
        return Content.Text(text)
    }

    // MARK: Messages ouverts

    /** Le clair gardé d'un jeton, s'il l'est. */
    fun recall(token: String): String? {
        val h = BrocolisV3Format.tokenHash(token)
        return opened.firstOrNull { it.h == h }?.text
    }

    /** Garde le clair d'un jeton (§8.2). */
    fun remember(token: String, text: String, mine: Boolean, now: Long, from: String = "") {
        val h = BrocolisV3Format.tokenHash(token)
        if (opened.any { it.h == h }) return
        opened.addLast(BrocolisV3StoredOpened(h, text, now, mine, from))
        var total = opened.sumOf { it.text.toByteArray(Charsets.UTF_8).size.toLong() }
        while (opened.size > BrocolisV3Format.OPENED_MAX ||
            (total > BrocolisV3Format.OPENED_MAX_BYTES && opened.size > 1)
        ) {
            total -= opened.removeFirst().text.toByteArray(Charsets.UTF_8).size
        }
        stateDirty = true
    }

    /** Nombre de messages ouverts gardés (tests). */
    val openedCount: Int get() = opened.size

    /** Ce jeton est-il un de mes envois (gardé au chiffrement) ? */
    fun isMine(token: String): Boolean {
        val h = BrocolisV3Format.tokenHash(token)
        return opened.any { it.h == h && it.mine }
    }

    /**
     * La clé de `keys` dont la session a porté ce jeton (son contact ou sa
     * clé partagée) : de qui vient un message. Pour un message de groupe,
     * celui qui a remis la chaîne (§9.9).
     */
    fun sender(token: String, keys: List<BrocolisV3Key>): Int? {
        val h = BrocolisV3Format.tokenHash(token)
        val from = opened.firstOrNull { it.h == h && it.from.isNotEmpty() }?.from ?: return null
        val kind = from.substringBefore(':')
        val who = from.substringAfter(':')
        val i = when (kind) {
            "c" -> keys.indexOfFirst { k -> contact(k)?.let { Octets.hex(it.identity.dh) == who } == true }
            "k" -> keys.indexOfFirst { it.id == who }
            else -> -1
        }
        return if (i >= 0) i else null
    }

    // MARK: Réception (§8.6)

    /**
     * Ouvre un jeton v3/v4 reçu : clair gardé, sinon session, sinon premier
     * message d'un contact (ou PSK d'une de `keys`). Une chaîne de groupe
     * reçue est gardée : [BrocolisV3Opened.Hidden].
     */
    fun open(token: String, keys: List<BrocolisV3Key>, now: Long): BrocolisV3Opened {
        recall(token)?.let { return BrocolisV3Opened.Text(it) }
        val clean = BrocolisV3Format.normalize(token)
        lastFrom = ""
        return try {
            val content = if (BrocolisV3Format.isV4(clean)) {
                decrypt4(Token4.decode(clean), keys, now)
            } else {
                decrypt(Token.decode(clean), keys, now)
            }
            val from = lastFrom
            when (content) {
                is Content.Text -> {
                    remember(token, content.text, mine = false, now = now, from = from)
                    BrocolisV3Opened.Text(content.text)
                }
                is Content.Distribution -> {
                    keepChain(content.distribution, from)
                    remember(token, "", mine = false, now = now, from = from)
                    BrocolisV3Opened.Hidden
                }
            }
        } catch (e: BrocolisException) {
            if (e.erreur == Erreur.Rejoue) BrocolisV3Opened.Replay else BrocolisV3Opened.Failed(e.erreur)
        }
    }

    private fun decrypt(token: Token, keys: List<BrocolisV3Key>, now: Long): Content {
        if (token is Token.Group) return decryptGroup(token.message, now)
        val id = token.sessionId ?: fail(Erreur.SessionInconnue)
        search@ for ((kind, table) in listOf("c" to peers, "k" to psk)) {
            for ((owner, peer) in table) {
                val s = peer.get(id) ?: continue
                try {
                    val content = s.decrypt(token, now, rng)
                    peer.current = id
                    lastFrom = "$kind:$owner"
                    stateDirty = true
                    return content
                } catch (e: BrocolisException) {
                    // L'autre a ouvert une session neuve (il avait perdu la sienne).
                    if (e.erreur == Erreur.NouvelleSession) break@search
                    throw e
                }
            }
        }
        val first = (token as? Token.InitialMessage)?.initial ?: fail(Erreur.SessionInconnue)
        if (first.mode == Mode.Psk) {
            for (k in keys) {
                if (k.group || k.raw.size != 32) continue
                try {
                    val (s, content) = Session.acceptPsk(listOf(k.raw), first, pskReplay, now, rng)
                    pskPeer(k.id).put(s)
                    if (!pskSeen.contains(k.id)) pskSeen.add(k.id)
                    lastFrom = "k:${k.id}"
                    stateDirty = true
                    return content
                } catch (e: BrocolisException) {
                    if (e.erreur == Erreur.SessionInconnue) continue
                    throw e
                }
            }
            fail(Erreur.SessionInconnue)
        }
        // X25519 ou hybride : seulement d'un contact (paquet de l'appairage).
        val b = keys.asSequence().mapNotNull { contact(it) }
            .firstOrNull { it.identity.dh.contentEquals(first.identity) }
            ?: fail(Erreur.SessionInconnue)
        val (s, content) = device.accept(first, now, rng)
        deviceDirty = true
        peerFor(b).put(s)
        lastFrom = "c:" + Octets.hex(first.identity)
        stateDirty = true
        return content
    }

    /**
     * Reçoit un jeton v4 (§9) : chaque session v4 l'essaie (une
     * [Erreur.SessionInconnue] veut dire « pas celle-ci ») ; sinon un premier
     * message d'un contact, ou une PSK v4 d'une de `keys`.
     */
    private fun decrypt4(token: Token4, keys: List<BrocolisV3Key>, now: Long): Content {
        for ((isPsk, table) in listOf(false to peers4, true to psk4)) {
            for ((owner, peer) in table) {
                for (s in peer.sessions) {
                    val content = try {
                        s.decrypt(token, now, rng)
                    } catch (e: BrocolisException) {
                        if (e.erreur == Erreur.SessionInconnue) continue
                        throw e
                    }
                    peer.current = s.sessionId
                    if (!isPsk && !v4Seen.contains(owner)) v4Seen.add(owner)
                    lastFrom = (if (isPsk) "k:" else "c:") + owner
                    stateDirty = true
                    return content
                }
            }
        }
        when (token) {
            is Token4.Initial -> {
                // Seulement d'un contact (paquet reçu à l'appairage) : l'identité
                // n'est connue qu'une fois le préambule ouvert.
                val (s, content) = device.accept4(token, now, rng)
                deviceDirty = true
                val ik = s.peerIdentity ?: fail(Erreur.SessionInconnue)
                val known = keys.any { k -> contact(k)?.identity?.dh?.contentEquals(ik) == true }
                if (!known) fail(Erreur.SessionInconnue)
                val owner = Octets.hex(ik)
                if (!v4Seen.contains(owner)) v4Seen.add(owner)
                peers4.getOrPut(owner) { BrocolisPeer.v4() }.put(s)
                lastFrom = "c:$owner"
                stateDirty = true
                return content
            }
            is Token4.Message -> {
                for (k in keys) {
                    if (k.group || k.raw.size != 32) continue
                    try {
                        val (s, content) = Session4.acceptPsk(listOf(k.raw), token, pskReplay, now, rng)
                        psk4Peer(k.id).put(s)
                        if (!pskSeen.contains(k.id)) pskSeen.add(k.id)
                        if (!psk4Seen.contains(k.id)) psk4Seen.add(k.id)
                        lastFrom = "k:${k.id}"
                        stateDirty = true
                        return content
                    } catch (e: BrocolisException) {
                        if (e.erreur == Erreur.SessionInconnue) continue
                        throw e
                    }
                }
                fail(Erreur.SessionInconnue)
            }
        }
    }

    private fun fail(e: Erreur): Nothing = throw BrocolisException(e)

    /**
     * Oublie les sessions du contact de `k` : le prochain envoi en ouvre une
     * neuve (§8.6, réparation).
     */
    fun repair(k: BrocolisV3Key) {
        val b = k.bundle ?: return
        val owner = Octets.hex(b.identity.dh)
        val v3 = peers.remove(owner) != null
        if (peers4.remove(owner) != null || v3) stateDirty = true
    }

    /**
     * Oublie tout ce qui touche à une clé supprimée (sessions PSK) ; les
     * sessions du contact restent si une autre clé le désigne.
     */
    fun forget(keyId: String) {
        if (psk.remove(keyId) != null) stateDirty = true
        if (pskSeen.remove(keyId)) stateDirty = true
        if (psk4.remove(keyId) != null) stateDirty = true
        if (psk4Seen.remove(keyId)) stateDirty = true
    }

    /** Nombre de sessions avec le contact de `k` (tests, affichage). */
    fun sessionCount(k: BrocolisV3Key): Int {
        val owner = k.bundle?.let { Octets.hex(it.identity.dh) }
        return (owner?.let { peers[it]?.sessions?.size } ?: 0) + (owner?.let { peers4[it]?.sessions?.size } ?: 0) +
            (psk[k.id]?.sessions?.size ?: 0) + (psk4[k.id]?.sessions?.size ?: 0)
    }

    // MARK: Messagerie (§8.7)

    /**
     * Le champ `ciphertext` d'un message de la messagerie, en v3 si la clé le
     * permet ; un média (ou un long texte) part dans l'enveloppe :
     * `[[BROCOLIS:v3:…]]` (clair `BRCM3:` ‖ base64(K_m)) suivi du jeton v1
     * sous K_m.
     */
    fun sealMessage(clear: String, k: BrocolisV3Key, now: Long): String? {
        if (clear.startsWith(BrocolisV3Format.MEDIA_V1_PREFIX) ||
            clear.toByteArray(Charsets.UTF_8).size > BrocolisV3Format.MEDIA_THRESHOLD
        ) {
            val mediaKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
            try {
                val media = runCatching { BrocolisCrypto.encryptToken(clear.toByteArray(Charsets.UTF_8), mediaKey) }
                    .getOrNull() ?: return null
                val head = seal(BrocolisV3Format.MEDIA_PREFIX + Octets.b64(mediaKey), k, now) ?: return null
                return head + media
            } finally {
                mediaKey.fill(0)
            }
        }
        return seal(clear, k, now)
    }

    /**
     * Le clair d'un message de la messagerie qui porte un jeton v3 (`null`
     * s'il n'en porte pas : l'appelant essaie v1). `mine` : un de mes envois,
     * relu seulement dans les messages ouverts (jamais déchiffré ni réparé).
     * `conversation` : la clé de la conversation (réparation).
     */
    fun openMessage(
        ciphertext: String,
        keys: List<BrocolisV3Key>,
        conversation: BrocolisV3Key,
        mine: Boolean,
        now: Long,
    ): BrocolisV3Opened? {
        val range = BrocolisV3Format.findTokens(ciphertext).firstOrNull() ?: return null
        val token = ciphertext.substring(range.first, range.last + 1)
        val result = if (mine) {
            recall(token)?.let { BrocolisV3Opened.Text(it) } ?: BrocolisV3Opened.Replay
        } else {
            open(token, keys, now).also {
                // En v4, un jeton qu'aucune session n'ouvre ne dit pas laquelle
                // est perdue (pas d'identifiant en clair) : pas de réparation,
                // l'envoi suivant ouvre une session s'il n'y en a plus (§9.6).
                if (it is BrocolisV3Opened.Failed && BrocolisV3Format.needsRepair(it.erreur) && !BrocolisV3Format.isV4(token)) {
                    repair(conversation)
                }
            }
        }
        val t = (result as? BrocolisV3Opened.Text)?.text ?: return result
        if (!t.startsWith(BrocolisV3Format.MEDIA_PREFIX)) return result
        val rest = ciphertext.substring(range.last + 1)
        val raw = Octets.unb64(t.removePrefix(BrocolisV3Format.MEDIA_PREFIX))
        if (raw == null || raw.size != 32) return BrocolisV3Opened.Failed(Erreur.Dechiffrement)
        val (media, n) = BrocolisCrypto.decryptTokens(rest, listOf(raw))
        raw.fill(0)
        return if (n > 0) BrocolisV3Opened.Text(media) else BrocolisV3Opened.Failed(Erreur.Dechiffrement)
    }
}
