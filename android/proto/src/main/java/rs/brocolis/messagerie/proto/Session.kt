package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import rs.brocolis.messagerie.proto.EtatJson.arr
import rs.brocolis.messagerie.proto.EtatJson.asObj
import rs.brocolis.messagerie.proto.EtatJson.bytes
import rs.brocolis.messagerie.proto.EtatJson.optBytes
import rs.brocolis.messagerie.proto.EtatJson.putBytes
import rs.brocolis.messagerie.proto.EtatJson.putNum
import rs.brocolis.messagerie.proto.EtatJson.str
import rs.brocolis.messagerie.proto.EtatJson.u32
import rs.brocolis.messagerie.proto.EtatJson.u64
import rs.brocolis.messagerie.proto.EtatJson.u8

/** Ce que porte un message déchiffré. */
sealed class Content {
    /** Un texte (types 0x01 et 0x02). */
    data class Text(val text: String) : Content()

    /** Une chaîne de groupe (type 0x03). */
    data class Distribution(val distribution: SenderKeyDistribution) : Content()
}

/** Ce que l'initiateur répète dans chaque message de type 0x01 tant qu'il n'a pas reçu de réponse. */
private class Preamble(
    val identity: ByteArray,
    val ephemeral: ByteArray,
    val mode: Mode,
    val kemCiphertext: ByteArray?,
    val spkId: Long,
    val pqId: Long,
) {
    fun toJson() = buildJsonObject {
        putBytes("identity", identity)
        putBytes("ephemeral", ephemeral)
        put("mode", mode.jsonName)
        putBytes("kem_ciphertext", kemCiphertext)
        putNum("spk_id", spkId)
        putNum("pq_id", pqId)
    }

    companion object {
        fun fromJson(o: JsonObject) = Preamble(
            o.bytes("identity", 32), o.bytes("ephemeral", 32), Mode.fromJson(o.str("mode")),
            // `#[serde(default)]` : absent = None.
            o.optBytes("kem_ciphertext", optional = true), o.u32("spk_id"), o.u32("pq_id"),
        )
    }
}

/** Une clé de message sautée (message pas encore arrivé). */
private class SkippedKey(val dh: ByteArray, val n: Long, val mk: ByteArray, val storedAt: Long) {
    fun toJson() = buildJsonObject {
        putBytes("dh", dh)
        putNum("n", n)
        putBytes("mk", mk)
        putNum("stored_at", storedAt)
    }

    companion object {
        fun fromJson(o: JsonObject) = SkippedKey(o.bytes("dh", 32), o.u32("n"), o.bytes("mk", 32), o.u64("stored_at"))
    }
}

/**
 * Une session à cliquet entre deux appareils : l'établissement (§4.2, §7.3,
 * §7.4) et le Double Ratchet (§4.3, §7.5), une clé neuve par message
 * (`brocolis_proto::session`).
 *
 * Chaque déchiffrement est **transactionnel** : s'il échoue (message altéré,
 * rejeu, trop de sauts), l'état de la session est exactement celui d'avant.
 *
 * Pour recevoir un jeton v3 de type 0x01 à 0x03 :
 *
 * 1. décoder ([Token.decode]) et chercher la session par [Token.sessionId] ;
 * 2. si elle existe : [decrypt]. Une erreur [Erreur.NouvelleSession] sur un
 *    0x01 veut dire « nouvelle session » : passer à l'étape 3 ;
 * 3. sinon, pour un 0x01 : [Device.accept] (mode X25519 ou hybride) ou
 *    [Session.acceptPsk] (clé partagée).
 *
 * [Erreur.Rejoue] : message déjà lu, à ignorer sans bruit.
 *
 * Sérialisable ([toJson], même forme que la référence Rust) ; à garder
 * chiffrée par la clé matérielle (§3.1). Pas faite pour être partagée entre
 * fils sans verrou.
 */
class Session private constructor(
    private var mode: Mode,
    private var ad: ByteArray,
    private var sessionIdBytes: ByteArray,
    private var rk: ByteArray,
    private var dhsSecret: ByteArray,
    private var dhsPublic: ByteArray,
    private var dhr: ByteArray?,
    private var cks: ByteArray?,
    private var ckr: ByteArray?,
    private var ns: Long,
    private var nr: Long,
    private var pn: Long,
    private var skipped: MutableList<SkippedKey>,
    private var previousDhr: MutableList<ByteArray>,
    private var preamble: Preamble?,
    private var initialEphemeral: ByteArray?,
    private var peerIdentityBytes: ByteArray?,
) {
    private val v: Int = 1

    /** Une copie profonde (pour la transaction d'un déchiffrement). */
    private fun copy(): Session = Session(
        mode, ad.copyOf(), sessionIdBytes.copyOf(), rk.copyOf(), dhsSecret.copyOf(), dhsPublic.copyOf(),
        dhr?.copyOf(), cks?.copyOf(), ckr?.copyOf(), ns, nr, pn,
        skipped.map { SkippedKey(it.dh.copyOf(), it.n, it.mk.copyOf(), it.storedAt) }.toMutableList(),
        previousDhr.map { it.copyOf() }.toMutableList(), preamble, initialEphemeral?.copyOf(), peerIdentityBytes?.copyOf(),
    )

    /** Remplace l'état par `o` (fin d'une transaction réussie), en effaçant l'ancien. */
    private fun commit(o: Session) {
        wipeSecrets()
        mode = o.mode; ad = o.ad; sessionIdBytes = o.sessionIdBytes; rk = o.rk
        dhsSecret = o.dhsSecret; dhsPublic = o.dhsPublic; dhr = o.dhr; cks = o.cks; ckr = o.ckr
        ns = o.ns; nr = o.nr; pn = o.pn; skipped = o.skipped; previousDhr = o.previousDhr
        preamble = o.preamble; initialEphemeral = o.initialEphemeral; peerIdentityBytes = o.peerIdentityBytes
    }

    private fun wipeSecrets() {
        Octets.wipe(rk, dhsSecret, cks, ckr)
        skipped.forEach { Octets.wipe(it.mk) }
    }

    /** Efface les secrets de la session (elle devient inutilisable). */
    fun wipe() {
        wipeSecrets()
        cks = null
        ckr = null
        skipped.clear()
    }

    // ----- Envoi -------------------------------------------------------------

    private fun seal(plain: ByteArray, kind: Int): Token {
        if (plain.size > MAX_PLAINTEXT) echec(Erreur.TropGrand)
        val ck = cks ?: echec(Erreur.Etat)
        val nextNs = ns + 1
        if (nextNs > Octets.U32_MAX) echec(Erreur.Epuise)
        val (next, mk) = Kdf.kdfCk(ck)
        val header = Header(dhsPublic, pn, ns)
        val (key, nonce) = Kdf.messageKey(mk)
        val padded = Remplissage.pad(plain)
        val ciphertext = try {
            Kdf.aesGcmSeal(key, nonce, aad(header, kind), padded)
        } finally {
            Octets.wipe(mk, key, padded)
        }
        Octets.wipe(ck)
        cks = next
        ns = nextNs
        val envelope = Envelope(sessionIdBytes, header, ciphertext)
        val p = preamble
        return when {
            kind == Token.TYPE_DISTRIBUTION -> Token.Distribution(envelope)
            p != null -> Token.InitialMessage(Initial(p.identity, p.ephemeral, p.mode, p.kemCiphertext, p.spkId, p.pqId, envelope))
            else -> Token.Message(envelope)
        }
    }

    /**
     * Les données associées : `AD ‖ en-tête`, et `‖ 0x03` pour une
     * distribution (§7.6 : le type est ainsi authentifié).
     */
    private fun aad(header: Header, kind: Int): ByteArray =
        if (kind == Token.TYPE_DISTRIBUTION) {
            Octets.concat(ad, header.toBytes(), byteArrayOf(Token.TYPE_DISTRIBUTION.toByte()))
        } else {
            Octets.concat(ad, header.toBytes())
        }

    /**
     * Chiffre un texte : le jeton décodé (type 0x01 tant que l'initiateur n'a
     * pas reçu de réponse, 0x02 ensuite).
     */
    fun encryptToken(text: String): Token = seal(Octets.utf8(text), Token.TYPE_MESSAGE)

    /** Chiffre un texte : `[[BROCOLIS:v3:…]]`. */
    fun encrypt(text: String): String = encryptToken(text).encode()

    /** Envoie une chaîne de groupe (type 0x03) par cette session. */
    fun encryptDistribution(d: SenderKeyDistribution): String {
        val b = d.toBytes()
        try {
            return seal(b, Token.TYPE_DISTRIBUTION).encode()
        } finally {
            Octets.wipe(b)
        }
    }

    // ----- Réception ---------------------------------------------------------

    /**
     * Déchiffre un jeton décodé de cette session. Transactionnel : en cas
     * d'erreur, la session n'a pas changé. Peut tirer une nouvelle clé de
     * cliquet (32 octets) si le message fait tourner le cliquet.
     */
    fun decrypt(token: Token, now: Long, rng: CryptoRng = Hasard.system()): Content {
        val env: Envelope
        val kind: Int
        when (token) {
            is Token.InitialMessage -> {
                val i = token.initial
                if (!i.envelope.sessionId.contentEquals(sessionIdBytes)) echec(Erreur.SessionInconnue)
                val ek = initialEphemeral
                val p = preamble
                when {
                    ek != null && ek.contentEquals(i.ephemeral) -> {
                        env = i.envelope
                        kind = Token.TYPE_MESSAGE
                    }
                    // Notre propre premier message, renvoyé : ignoré.
                    p != null && p.ephemeral.contentEquals(i.ephemeral) -> echec(Erreur.Rejoue)
                    else -> echec(Erreur.NouvelleSession)
                }
            }
            is Token.Message -> {
                env = token.envelope
                kind = Token.TYPE_MESSAGE
            }
            is Token.Distribution -> {
                env = token.envelope
                kind = Token.TYPE_DISTRIBUTION
            }
            is Token.Group -> echec(Erreur.SessionInconnue)
        }
        if (!env.sessionId.contentEquals(sessionIdBytes)) echec(Erreur.SessionInconnue)
        val next = copy()
        val plain = next.ratchetDecrypt(env.header, env.ciphertext, kind, now, rng)
        val content = try {
            if (kind == Token.TYPE_DISTRIBUTION) {
                Content.Distribution(SenderKeyDistribution.fromBytes(plain))
            } else {
                Content.Text(Octets.fromUtf8(plain))
            }
        } catch (e: BrocolisException) {
            next.wipeSecrets()
            throw e
        } finally {
            Octets.wipe(plain)
        }
        // Une réponse est arrivée : l'initiateur passe aux messages 0x02.
        next.preamble = null
        commit(next)
        return content
    }

    /** [decrypt] d'un jeton texte `[[BROCOLIS:v3:…]]`. */
    fun decryptText(token: String, now: Long, rng: CryptoRng = Hasard.system()): Content =
        decrypt(Token.decode(token), now, rng)

    private fun open(mk: ByteArray, header: Header, ct: ByteArray, kind: Int): ByteArray {
        val (key, nonce) = Kdf.messageKey(mk)
        try {
            val padded = Kdf.aesGcmOpen(key, nonce, aad(header, kind), ct)
            try {
                return Remplissage.unpad(padded)
            } finally {
                Octets.wipe(padded)
            }
        } finally {
            Octets.wipe(key)
        }
    }

    /** Le déchiffrement, sur une copie (voir [decrypt]) : en cas d'erreur, la copie est jetée. */
    private fun ratchetDecrypt(header: Header, ct: ByteArray, kind: Int, now: Long, rng: CryptoRng): ByteArray {
        try {
            purge(now)
            // Un de nos messages, renvoyé.
            if (header.dh.contentEquals(dhsPublic)) echec(Erreur.Rejoue)
            val pos = skipped.indexOfFirst { it.dh.contentEquals(header.dh) && it.n == header.n }
            if (pos >= 0) {
                val plain = open(skipped[pos].mk, header, ct, kind)
                Octets.wipe(skipped.removeAt(pos).mk)
                return plain
            }
            val current = dhr?.contentEquals(header.dh) == true
            if (current && header.n < nr) echec(Erreur.Rejoue)
            if (!current && previousDhr.any { it.contentEquals(header.dh) }) echec(Erreur.Rejoue)
            if (!current) {
                skip(header.pn, now)
                dhRatchet(header, rng)
            }
            skip(header.n, now)
            val ck = ckr ?: echec(Erreur.Etat)
            val (next, mk) = Kdf.kdfCk(ck)
            ckr = next
            Octets.wipe(ck)
            if (nr + 1 > Octets.U32_MAX) echec(Erreur.Epuise)
            nr += 1
            try {
                return open(mk, header, ct, kind)
            } finally {
                Octets.wipe(mk)
            }
        } catch (e: BrocolisException) {
            wipeSecrets()
            throw e
        }
    }

    private fun skip(until: Long, now: Long) {
        if (nr + Protocole.MAX_SKIP < until) echec(Erreur.TropDeClesSautees)
        val c = ckr
        val d = dhr
        if (c != null && d != null) {
            var ck: ByteArray = c
            while (nr < until) {
                val (next, mk) = Kdf.kdfCk(ck)
                skipped.add(SkippedKey(d.copyOf(), nr, mk, now))
                Octets.wipe(ck)
                ck = next
                nr += 1
            }
            ckr = ck
            while (skipped.size > Protocole.MAX_SKIP) Octets.wipe(skipped.removeAt(0).mk)
        }
    }

    private fun dhRatchet(header: Header, rng: CryptoRng) {
        pn = ns
        ns = 0
        nr = 0
        dhr?.let { old ->
            previousDhr.add(old)
            if (previousDhr.size > PREVIOUS_DHR) previousDhr.removeAt(0)
        }
        dhr = header.dh.copyOf()
        val dh1 = Kdf.x25519(dhsSecret, header.dh)
        val (rk1, ckr1) = Kdf.kdfRk(rk, dh1)
        Octets.wipe(rk, dh1, ckr)
        rk = rk1
        ckr = ckr1
        val secret = rng.bytes(32)
        Octets.wipe(dhsSecret)
        dhsSecret = secret
        dhsPublic = Kdf.x25519Public(secret)
        val dh2 = Kdf.x25519(dhsSecret, header.dh)
        val (rk2, cks2) = Kdf.kdfRk(rk, dh2)
        Octets.wipe(rk, dh2, cks)
        rk = rk2
        cks = cks2
    }

    // ----- État --------------------------------------------------------------

    /** Efface les clés sautées de plus de 30 jours. */
    fun purge(now: Long) {
        val old = skipped.filter { Octets.satAdd(it.storedAt, Protocole.MAX_SKIP_AGE) <= now }
        old.forEach { Octets.wipe(it.mk) }
        skipped.removeAll(old)
    }

    /** L'identifiant de session (8 octets). */
    val sessionId: ByteArray get() = sessionIdBytes.copyOf()

    /** AD = IK_A ‖ IK_B (ou EK_A ‖ R en clé partagée). */
    val associatedData: ByteArray get() = ad.copyOf()

    /** Le mode d'établissement. */
    fun mode(): Mode = mode

    /** Vrai si la session est post-quantique (hybride X25519 + ML-KEM). Sinon, l'appli l'affiche (« session non post-quantique »). */
    val isPostQuantum: Boolean get() = mode == Mode.Hybrid

    /** Vrai si l'autre côté a répondu (l'initiateur envoie des messages 0x01 jusque-là). */
    val isConfirmed: Boolean get() = preamble == null

    /**
     * IK X25519 du correspondant (absent en clé partagée) : l'appli le compare
     * à celui du contact (alerte si une clé d'identité change).
     */
    val peerIdentity: ByteArray? get() = peerIdentityBytes?.copyOf()

    /** Le nombre de clés sautées gardées. */
    val skippedLen: Int get() = skipped.size

    /** La clé publique de cliquet courante (pour les vecteurs). */
    val ratchetPublic: ByteArray get() = dhsPublic.copyOf()

    /** La clé racine courante (pour les vecteurs : un secret !). */
    internal val debugRootKey: ByteArray get() = rk.copyOf()

    /** Les clés de chaîne courantes (envoi, réception) — vecteurs seulement. */
    internal val debugChainKeys: Pair<ByteArray?, ByteArray?> get() = Pair(cks?.copyOf(), ckr?.copyOf())

    /** L'état en JSON (même forme que la référence Rust). */
    fun toJson(): String = EtatJson.write(
        buildJsonObject {
            putNum("v", v.toLong())
            put("mode", mode.jsonName)
            putBytes("ad", ad)
            putBytes("session_id", sessionIdBytes)
            putBytes("rk", rk)
            putBytes("dhs_secret", dhsSecret)
            putBytes("dhs_public", dhsPublic)
            putBytes("dhr", dhr)
            putBytes("cks", cks)
            putBytes("ckr", ckr)
            putNum("ns", ns)
            putNum("nr", nr)
            putNum("pn", pn)
            put("skipped", JsonArray(skipped.map { it.toJson() }))
            put("previous_dhr", JsonArray(previousDhr.map { kotlinx.serialization.json.JsonPrimitive(Octets.b64(it)) }))
            put("preamble", preamble?.toJson() ?: JsonNull)
            putBytes("initial_ephemeral", initialEphemeral)
            putBytes("peer_identity", peerIdentityBytes)
        },
    )

    companion object {
        /** Le plus long texte (en octets UTF-8) qu'un message v3 peut porter (§7.5). */
        const val MAX_PLAINTEXT = 200 * 1024

        /** Le nombre de clés de cliquet distantes passées dont on se souvient pour reconnaître un rejeu. */
        private const val PREVIOUS_DHR = 16

        private fun newInitiator(
            mode: Mode,
            sk: ByteArray,
            ad: ByteArray,
            ratchetSecret: ByteArray,
            remoteRatchet: ByteArray,
            preamble: Preamble,
            peerIdentity: ByteArray?,
        ): Session {
            val dh = Kdf.x25519(ratchetSecret, remoteRatchet)
            val (rk, cks) = Kdf.kdfRk(sk, dh)
            Octets.wipe(dh)
            return Session(
                mode, ad, Kdf.sessionId(ad), rk, ratchetSecret.copyOf(), Kdf.x25519Public(ratchetSecret),
                remoteRatchet.copyOf(), cks, null, 0, 0, 0, mutableListOf(), mutableListOf(), preamble, null, peerIdentity?.copyOf(),
            )
        }

        internal fun newResponder(
            mode: Mode,
            sk: ByteArray,
            ad: ByteArray,
            ratchetSecret: ByteArray,
            initialEphemeral: ByteArray,
            peerIdentity: ByteArray?,
        ): Session = Session(
            mode, ad.copyOf(), Kdf.sessionId(ad), sk.copyOf(), ratchetSecret.copyOf(), Kdf.x25519Public(ratchetSecret),
            null, null, null, 0, 0, 0, mutableListOf(), mutableListOf(), null, initialEphemeral.copyOf(), peerIdentity?.copyOf(),
        )

        /**
         * Ouvre une session vers l'appareil du paquet (§4.2), avec ML-KEM si
         * `pq` (le paquet doit alors en proposer : sinon
         * [Erreur.PqIndisponible]).
         *
         * Ordre de tirage : secret EK (32), secret de cliquet (32), puis, avec
         * `pq`, le message ML-KEM `m` (32).
         */
        fun initiate(identity: IdentitySecret, bundle: KeyBundle, pq: Boolean, rng: CryptoRng = Hasard.system()): Session {
            bundle.verify()
            val ek = rng.bytes(32)
            val ratchet = rng.bytes(32)
            val m = if (pq) rng.bytes(32) else null
            try {
                return initiateWith(identity, bundle, ek, ratchet, m)
            } finally {
                Octets.wipe(ek, ratchet, m)
            }
        }

        /**
         * [initiate] avec le hasard donné (les vecteurs). Le paquet doit avoir
         * été vérifié ([KeyBundle.fromBytes] le fait).
         */
        fun initiateWith(
            identity: IdentitySecret,
            bundle: KeyBundle,
            ekSecret: ByteArray,
            ratchetSecret: ByteArray,
            kemM: ByteArray?,
        ): Session {
            val ikA = identity.public().dh
            val ikB = bundle.identity.dh
            val dh1 = Kdf.x25519(identity.dh, bundle.spk)
            val dh2 = Kdf.x25519(ekSecret, ikB)
            val dh3 = Kdf.x25519(ekSecret, bundle.spk)
            var mode = Mode.Classic
            var ct: ByteArray? = null
            var ss: ByteArray? = null
            var pqId = 0L
            if (kemM != null) {
                val pq = bundle.pq ?: echec(Erreur.PqIndisponible)
                val (c, s) = MlKem.encapsulate(pq.key, kemM)
                mode = Mode.Hybrid
                ct = c
                ss = s
                pqId = pq.id
            }
            val sk = Kdf.skX3dh(dh1, dh2, dh3, ss)
            Octets.wipe(dh1, dh2, dh3, ss)
            try {
                val preamble = Preamble(ikA, Kdf.x25519Public(ekSecret), mode, ct, bundle.spkId, pqId)
                return newInitiator(mode, sk, Octets.concat(ikA, ikB), ratchetSecret, bundle.spk, preamble, ikB)
            } finally {
                Octets.wipe(sk)
            }
        }

        /**
         * Ouvre une session à partir d'une clé Brocolis partagée (§4.2, §7.4,
         * sans appairage). Tire le secret EK (32), qui sert aussi de première
         * clé de cliquet.
         */
        fun initiatePsk(key: ByteArray, rng: CryptoRng = Hasard.system()): Session {
            val ek = rng.bytes(32)
            try {
                return initiatePskWith(key, ek)
            } finally {
                Octets.wipe(ek)
            }
        }

        /**
         * [initiatePsk] avec le hasard donné.
         *
         * SK = `HKDF(0³², clé, "Brocolis_v3_PSK_SHA-256")` ; la clé de cliquet
         * initiale du répondeur R est le secret X25519
         * `HKDF(0³², SK, "Brocolis_v3_PSK_Ratchet")` (connu des deux) ;
         * AD = EK_A ‖ R ; la première clé de cliquet de A est EK_A.
         */
        fun initiatePskWith(key: ByteArray, ekSecret: ByteArray): Session {
            require(key.size == 32)
            val sk = Kdf.skPsk(key)
            val rSecret = Kdf.pskRatchetSecret(sk)
            val r = Kdf.x25519Public(rSecret)
            Octets.wipe(rSecret)
            val ek = Kdf.x25519Public(ekSecret)
            val preamble = Preamble(ByteArray(32), ek, Mode.Psk, null, 0, 0)
            try {
                return newInitiator(Mode.Psk, sk, Octets.concat(ek, r), ekSecret, r, preamble, null)
            } finally {
                Octets.wipe(sk)
            }
        }

        /**
         * Accepte le premier message d'une session à clé partagée : essaie
         * chaque clé (l'identifiant de session dit laquelle). `guard` retient
         * les clés éphémères déjà vues (un premier message rejoué est refusé :
         * [Erreur.Rejoue]).
         */
        fun acceptPsk(
            keys: List<ByteArray>,
            msg: Initial,
            guard: ReplayGuard,
            now: Long,
            rng: CryptoRng = Hasard.system(),
        ): Pair<Session, Content> {
            if (msg.mode != Mode.Psk || !msg.envelope.header.dh.contentEquals(msg.ephemeral)) echec(Erreur.Format)
            if (guard.seen(msg.ephemeral)) echec(Erreur.Rejoue)
            for (key in keys) {
                val sk = Kdf.skPsk(key)
                val rSecret = Kdf.pskRatchetSecret(sk)
                val ad = Octets.concat(msg.ephemeral, Kdf.x25519Public(rSecret))
                try {
                    if (Octets.ctEq(Kdf.sessionId(ad), msg.envelope.sessionId)) {
                        val s = newResponder(Mode.Psk, sk, ad, rSecret, msg.ephemeral, null)
                        val content = s.decrypt(Token.InitialMessage(msg), now, rng)
                        guard.insert(msg.ephemeral, now)
                        return Pair(s, content)
                    }
                } finally {
                    Octets.wipe(sk, rSecret)
                }
            }
            echec(Erreur.SessionInconnue)
        }

        /** [Device.accept] : voir sa documentation. */
        internal fun accept(device: Device, msg: Initial, now: Long, rng: CryptoRng): Pair<Session, Content> {
            if (msg.mode == Mode.Psk) echec(Erreur.Format)
            if (device.replayGuard.seen(msg.ephemeral)) echec(Erreur.Rejoue)
            val spk = device.spkSecret(msg.spkId)
            val own = device.identitySecret
            try {
                val dh1 = Kdf.x25519(spk, msg.identity)
                val dh2 = Kdf.x25519(own.dh, msg.ephemeral)
                val dh3 = Kdf.x25519(spk, msg.ephemeral)
                val ct = msg.kemCiphertext
                val ss = when {
                    msg.mode == Mode.Hybrid && ct != null -> {
                        val seed = device.pqSeed(msg.pqId)
                        try {
                            MlKem.decapsulate(seed, ct)
                        } finally {
                            Octets.wipe(seed)
                        }
                    }
                    msg.mode == Mode.Classic && ct == null -> null
                    else -> echec(Erreur.Format)
                }
                val sk = Kdf.skX3dh(dh1, dh2, dh3, ss)
                Octets.wipe(dh1, dh2, dh3, ss)
                try {
                    val ad = Octets.concat(msg.identity, Kdf.x25519Public(own.dh))
                    if (!Kdf.sessionId(ad).contentEquals(msg.envelope.sessionId)) echec(Erreur.SessionInconnue)
                    val s = newResponder(msg.mode, sk, ad, spk, msg.ephemeral, msg.identity)
                    val content = s.decrypt(Token.InitialMessage(msg), now, rng)
                    device.replayGuard.insert(msg.ephemeral, now)
                    return Pair(s, content)
                } finally {
                    Octets.wipe(sk)
                }
            } finally {
                Octets.wipe(spk)
            }
        }

        /** Relit un état JSON (vérifie sa cohérence). */
        fun fromJson(text: String): Session {
            val o = EtatJson.parse(text)
            if (o.u8("v") != 1L) echec(Erreur.Etat)
            val preambleEl = o["preamble"]
            val s = Session(
                Mode.fromJson(o.str("mode")),
                o.bytes("ad"),
                o.bytes("session_id", 8),
                o.bytes("rk", 32),
                o.bytes("dhs_secret", 32),
                o.bytes("dhs_public", 32),
                o.optBytes("dhr", 32),
                o.optBytes("cks", 32),
                o.optBytes("ckr", 32),
                o.u32("ns"),
                o.u32("nr"),
                o.u32("pn"),
                o.arr("skipped").map { SkippedKey.fromJson(it.asObj()) }.toMutableList(),
                o.arr("previous_dhr").map { it.bytes(32) }.toMutableList(),
                if (preambleEl == null || preambleEl is JsonNull) null else Preamble.fromJson(preambleEl.asObj()),
                o.optBytes("initial_ephemeral", 32),
                o.optBytes("peer_identity", 32),
            )
            val adOk = s.ad.size == 64 && Kdf.sessionId(s.ad).contentEquals(s.sessionIdBytes)
            if (!adOk || s.skipped.size > Protocole.MAX_SKIP ||
                !Kdf.x25519Public(s.dhsSecret).contentEquals(s.dhsPublic)
            ) {
                echec(Erreur.Etat)
            }
            return s
        }
    }
}
