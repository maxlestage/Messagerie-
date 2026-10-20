package rs.brocolis.messagerie.crypto

import kotlinx.serialization.Serializable
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.proto.BrocolisException
import rs.brocolis.messagerie.proto.Content
import rs.brocolis.messagerie.proto.CryptoRng
import rs.brocolis.messagerie.proto.Device
import rs.brocolis.messagerie.proto.Erreur
import rs.brocolis.messagerie.proto.Hasard
import rs.brocolis.messagerie.proto.Kdf
import rs.brocolis.messagerie.proto.KeyBundle
import rs.brocolis.messagerie.proto.Mode
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.proto.Protocole
import rs.brocolis.messagerie.proto.ReplayGuard
import rs.brocolis.messagerie.proto.Session
import rs.brocolis.messagerie.proto.Token
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
 * - l'empreinte d'appairage (§8.4) et l'enveloppe des médias (§8.7).
 *
 * La persistance et le verrou entre processus sont dans
 * `store/BrocolisV3Store.kt` ; la façade dont se servent les écrans, dans
 * `BrocolisV3.kt`.
 */

// MARK: - Protection affichée (§8.8)

/** La protection d'une clé, telle que le prochain envoi la donnera. */
enum class BrocolisProtection {
    POST_QUANTUM, CLASSIC, PSK, LEGACY;

    /** Libellé affiché partout où s'affiche une clé ou un contact. */
    val label: String
        get() = when (this) {
            POST_QUANTUM -> loc("🔐 double cliquet (post-quantique)", "🔐 double ratchet (post-quantum)", "🔐 doble trinquete (poscuántico)")
            CLASSIC -> loc("🔐 double cliquet (classique)", "🔐 double ratchet (classic)", "🔐 doble trinquete (clásico)")
            PSK -> loc("🔐 double cliquet, clé partagée (PSK)", "🔐 double ratchet, shared key (PSK)", "🔐 doble trinquete, clave compartida (PSK)")
            LEGACY -> loc("ancien format", "old format", "formato antiguo")
        }

    val isRatchet: Boolean get() = this != LEGACY
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
 * @property psk marquée « à deux, double cliquet » par l'utilisateur (PSK).
 */
class BrocolisV3Key(
    val id: String,
    val raw: ByteArray,
    val bundle: KeyBundle?,
    val bundleAt: Long,
    val group: Boolean,
    val psk: Boolean,
)

/** Le résultat d'une réception. */
sealed class BrocolisV3Opened {
    /** Le clair (déchiffré à l'instant, ou gardé). */
    data class Text(val text: String) : BrocolisV3Opened()
    /** Déjà lu, et le clair n'est plus gardé. */
    object Replay : BrocolisV3Opened()
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
    fun pairingFingerprint(key: ByteArray, a: ByteArray, b: ByteArray): String {
        val (lo, hi) = if (compare(a, b) <= 0) a to b else b to a
        val digest = Kdf.sha256(FINGERPRINT_CONTEXT + key + lo + hi)
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

    /** Les jetons v3 d'un texte, dans l'ordre (début inclus, fin exclue). */
    fun findTokens(text: String): List<IntRange> {
        val out = ArrayList<IntRange>()
        var from = 0
        while (true) {
            val start = text.indexOf(Token.HEAD, from)
            if (start < 0) break
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
data class BrocolisV3StoredOpened(val h: String, val text: String, val at: Long, val mine: Boolean)

/** L'état chiffré au repos : sessions et messages ouverts. */
@Serializable
data class BrocolisV3Stored(
    val v: Int = 1,
    val peers: Map<String, BrocolisV3StoredPeer> = emptyMap(),
    val psk: Map<String, BrocolisV3StoredPeer> = emptyMap(),
    val pskSeen: List<String> = emptyList(),
    val pskReplay: String? = null,
    val opened: List<BrocolisV3StoredOpened> = emptyList(),
)

/** Les sessions d'un contact (ou d'une clé PSK). */
class BrocolisV3Peer() {
    val sessions: MutableList<Session> = ArrayList()
    var current: ByteArray? = null

    constructor(stored: BrocolisV3StoredPeer) : this() {
        stored.sessions.mapNotNull { runCatching { Session.fromJson(it) }.getOrNull() }
            .take(BrocolisV3Format.SESSIONS_PER_PEER)
            .forEach { sessions.add(it) }
        current = sessions.map { it.sessionId }.firstOrNull { Octets.hex(it) == stored.current }
    }

    val stored: BrocolisV3StoredPeer
        get() = BrocolisV3StoredPeer(current?.let(Octets::hex) ?: "", sessions.map { it.toJson() })

    fun get(id: ByteArray): Session? = sessions.firstOrNull { it.sessionId.contentEquals(id) }

    val sendingId: ByteArray?
        get() {
            val c = current
            if (c != null && sessions.any { it.sessionId.contentEquals(c) }) return c
            return sessions.lastOrNull()?.sessionId
        }

    val sending: Session? get() = sendingId?.let(::get)

    /**
     * Range une session (remplace celle de même identifiant, la plus ancienne
     * part au-delà de deux) et en fait la session d'envoi.
     */
    fun put(s: Session) {
        val id = s.sessionId
        sessions.removeAll { it.sessionId.contentEquals(id) }
        sessions.add(s)
        while (sessions.size > BrocolisV3Format.SESSIONS_PER_PEER) sessions.removeAt(0)
        current = id
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
    private val peers: MutableMap<String, BrocolisV3Peer>
    private val psk: MutableMap<String, BrocolisV3Peer>
    private val pskSeen: MutableList<String>
    private val pskReplay: ReplayGuard
    private val opened: ArrayDeque<BrocolisV3StoredOpened>
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
        peers = s.peers.mapValuesTo(LinkedHashMap()) { BrocolisV3Peer(it.value) }
        psk = s.psk.mapValuesTo(LinkedHashMap()) { BrocolisV3Peer(it.value) }
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
        )

    /** Le paquet de clés à publier dans le salon (base64). */
    val bundleBase64: String? get() = runCatching { device.bundle().toBase64() }.getOrNull()

    /** Mon identité : IK X25519 ‖ IK Ed25519. */
    val identity: ByteArray get() = device.identity().dh + device.identity().sign

    // MARK: Choix (§8.5)

    private fun contact(k: BrocolisV3Key): KeyBundle? = if (k.group) null else k.bundle

    private fun fresh(k: BrocolisV3Key, now: Long): Boolean = Octets.satAdd(k.bundleAt, BrocolisV3Format.BUNDLE_MAX_AGE) > now

    private fun pskAllowed(k: BrocolisV3Key, now: Long): Boolean {
        if (k.group) return false
        // Un contact v3 au paquet trop vieux est à jour : la PSK est sûre.
        return k.psk || pskSeen.contains(k.id) || (k.bundle != null && !fresh(k, now))
    }

    /** La protection de la clé, telle que le prochain envoi la donnera (§8.8). */
    fun protection(k: BrocolisV3Key, now: Long): BrocolisProtection {
        contact(k)?.let { b ->
            peers[Octets.hex(b.identity.dh)]?.sending?.let { s ->
                return if (s.isPostQuantum) BrocolisProtection.POST_QUANTUM else BrocolisProtection.CLASSIC
            }
            if (fresh(k, now)) {
                return if (b.pq != null) BrocolisProtection.POST_QUANTUM else BrocolisProtection.CLASSIC
            }
        }
        return if (pskAllowed(k, now)) BrocolisProtection.PSK else BrocolisProtection.LEGACY
    }

    /**
     * Ouvre la session vers le contact s'il n'y en a pas (l'invitant, à la fin
     * de l'appairage : §8.4). Rien ne part : le premier message la porte.
     */
    fun openSession(k: BrocolisV3Key, now: Long): Boolean {
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

    private fun peerFor(b: KeyBundle): BrocolisV3Peer =
        peers.getOrPut(Octets.hex(b.identity.dh)) { BrocolisV3Peer() }

    private fun pskPeer(id: String): BrocolisV3Peer = psk.getOrPut(id) { BrocolisV3Peer() }

    // MARK: Envoi

    /**
     * Chiffre `text` pour `k` en v3 (§8.5) : session de contact, session neuve
     * vers son paquet, ou PSK. `null` : l'appelant chiffre en v1/v2.
     */
    fun seal(text: String, k: BrocolisV3Key, now: Long): String? {
        if (text.toByteArray(Charsets.UTF_8).size > Session.MAX_PLAINTEXT) return null
        val token = sealContact(text, k, now) ?: sealPsk(text, k, now) ?: return null
        remember(token, text, mine = true, now = now)
        return token
    }

    private fun sealContact(text: String, k: BrocolisV3Key, now: Long): String? {
        val b = contact(k) ?: return null
        val peer = peerFor(b)
        peer.sending?.let { s ->
            runCatching { s.encrypt(text) }.getOrNull()?.let { token ->
                stateDirty = true
                return token
            }
            // Chaîne épuisée ou état abîmé : une session neuve.
            peer.sessions.clear()
        }
        if (!fresh(k, now)) return null
        val s = initiateBest(b) ?: return null
        val token = runCatching { s.encrypt(text) }.getOrNull() ?: return null
        peer.put(s)
        stateDirty = true
        return token
    }

    private fun sealPsk(text: String, k: BrocolisV3Key, now: Long): String? {
        if (!pskAllowed(k, now) || k.raw.size != 32) return null
        val peer = pskPeer(k.id)
        peer.sending?.let { s ->
            runCatching { s.encrypt(text) }.getOrNull()?.let { token ->
                stateDirty = true
                return token
            }
            peer.sessions.clear()
        }
        val s = runCatching { Session.initiatePsk(k.raw, rng) }.getOrNull() ?: return null
        val token = runCatching { s.encrypt(text) }.getOrNull() ?: return null
        peer.put(s)
        stateDirty = true
        return token
    }

    // MARK: Messages ouverts

    /** Le clair gardé d'un jeton, s'il l'est. */
    fun recall(token: String): String? {
        val h = BrocolisV3Format.tokenHash(token)
        return opened.firstOrNull { it.h == h }?.text
    }

    /** Garde le clair d'un jeton (§8.2). */
    fun remember(token: String, text: String, mine: Boolean, now: Long) {
        val h = BrocolisV3Format.tokenHash(token)
        if (opened.any { it.h == h }) return
        opened.addLast(BrocolisV3StoredOpened(h, text, now, mine))
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

    // MARK: Réception (§8.6)

    /**
     * Ouvre un jeton v3 reçu : clair gardé, sinon session, sinon premier
     * message d'un contact (ou PSK d'une de `keys`).
     */
    fun open(token: String, keys: List<BrocolisV3Key>, now: Long): BrocolisV3Opened {
        recall(token)?.let { return BrocolisV3Opened.Text(it) }
        val decoded = try {
            Token.decode(BrocolisV3Format.normalize(token))
        } catch (e: BrocolisException) {
            return BrocolisV3Opened.Failed(e.erreur)
        }
        return try {
            val text = decrypt(decoded, keys, now)
            remember(token, text, mine = false, now = now)
            BrocolisV3Opened.Text(text)
        } catch (e: BrocolisException) {
            if (e.erreur == Erreur.Rejoue) BrocolisV3Opened.Replay else BrocolisV3Opened.Failed(e.erreur)
        }
    }

    private fun decrypt(token: Token, keys: List<BrocolisV3Key>, now: Long): String {
        val id = token.sessionId ?: fail(Erreur.SessionInconnue)
        search@ for (peer in peers.values + psk.values) {
            val s = peer.get(id) ?: continue
            try {
                val content = s.decrypt(token, now, rng)
                peer.current = id
                stateDirty = true
                return text(content)
            } catch (e: BrocolisException) {
                // L'autre a ouvert une session neuve (il avait perdu la sienne).
                if (e.erreur == Erreur.NouvelleSession) break@search
                throw e
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
                    stateDirty = true
                    return text(content)
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
        stateDirty = true
        return text(content)
    }

    private fun text(content: Content): String = (content as? Content.Text)?.text ?: fail(Erreur.Format)

    private fun fail(e: Erreur): Nothing = throw BrocolisException(e)

    /**
     * Oublie les sessions du contact de `k` : le prochain envoi en ouvre une
     * neuve (§8.6, réparation).
     */
    fun repair(k: BrocolisV3Key) {
        val b = k.bundle ?: return
        if (peers.remove(Octets.hex(b.identity.dh)) != null) stateDirty = true
    }

    /**
     * Oublie tout ce qui touche à une clé supprimée (sessions PSK) ; les
     * sessions du contact restent si une autre clé le désigne.
     */
    fun forget(keyId: String) {
        if (psk.remove(keyId) != null) stateDirty = true
        if (pskSeen.remove(keyId)) stateDirty = true
    }

    /** Nombre de sessions avec le contact de `k` (tests, affichage). */
    fun sessionCount(k: BrocolisV3Key): Int =
        (k.bundle?.let { peers[Octets.hex(it.identity.dh)]?.sessions?.size } ?: 0) + (psk[k.id]?.sessions?.size ?: 0)

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
                if (it is BrocolisV3Opened.Failed && BrocolisV3Format.needsRepair(it.erreur)) repair(conversation)
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
