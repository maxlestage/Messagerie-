package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import rs.brocolis.messagerie.proto.EtatJson.arr
import rs.brocolis.messagerie.proto.EtatJson.asObj
import rs.brocolis.messagerie.proto.EtatJson.bool
import rs.brocolis.messagerie.proto.EtatJson.bytes
import rs.brocolis.messagerie.proto.EtatJson.optBytes
import rs.brocolis.messagerie.proto.EtatJson.putBytes
import rs.brocolis.messagerie.proto.EtatJson.putNum
import rs.brocolis.messagerie.proto.EtatJson.str
import rs.brocolis.messagerie.proto.EtatJson.u32
import rs.brocolis.messagerie.proto.EtatJson.u64
import rs.brocolis.messagerie.proto.EtatJson.u8

/** Comment la session v4 a été établie. `jsonName` est son nom dans les états JSON (serde). */
enum class Mode4(internal val jsonName: String) {
    /** Par paquet de clés : X25519 + ML-KEM-768, identité de l'initiateur cachée. */
    Bundle("Bundle"),
    /** Par une clé Brocolis partagée. */
    Psk("Psk");

    internal companion object {
        fun fromJson(name: String): Mode4 = entries.firstOrNull { it.jsonName == name } ?: echec(Erreur.Etat)
    }
}

/** Une clé de message sautée : `(clé d'en-tête, N) → mk`. */
private class Skipped4(val hk: ByteArray, val n: Long, val mk: ByteArray, val storedAt: Long) {
    fun copy() = Skipped4(hk.copyOf(), n, mk.copyOf(), storedAt)

    fun toJson() = buildJsonObject {
        putBytes("hk", hk)
        putNum("n", n)
        putBytes("mk", mk)
        putNum("stored_at", storedAt)
    }

    companion object {
        fun fromJson(o: JsonObject) = Skipped4(o.bytes("hk", 32), o.u32("n"), o.bytes("mk", 32), o.u64("stored_at"))
    }
}

/**
 * Une paire ML-KEM-768 de cliquet : la graine `d ‖ z` et sa clé
 * d'encapsulation (gardée pour ne pas la recalculer à chaque message).
 */
private class KemPair(val seed: ByteArray, val ek: ByteArray) {
    fun copy() = KemPair(seed.copyOf(), ek.copyOf())

    fun toJson() = buildJsonObject {
        putBytes("seed", seed)
        putBytes("ek", ek)
    }

    companion object {
        fun fromSeed(seed: ByteArray) = KemPair(seed.copyOf(), MlKem.publicKey(seed))
        fun fromJson(o: JsonObject) = KemPair(o.bytes("seed", 64), o.bytes("ek"))
    }
}

/** Le préambule que l'initiateur répète dans ses messages 0x01 (rien de secret). */
private class StoredPreamble(val ephemeral: ByteArray, val kemCiphertext: ByteArray, val sealedIdentity: ByteArray) {
    fun toPreamble(): Preamble4 = Preamble4(ephemeral, kemCiphertext, sealedIdentity)

    fun toJson() = buildJsonObject {
        putBytes("ephemeral", ephemeral)
        putBytes("kem_ciphertext", kemCiphertext)
        putBytes("sealed_identity", sealedIdentity)
    }

    companion object {
        // La référence relit des longueurs quelconques et n'échoue qu'à
        // l'envoi ; ici, un préambule mal formé est refusé dès la relecture.
        fun fromJson(o: JsonObject) = StoredPreamble(
            o.bytes("ephemeral", 32), o.bytes("kem_ciphertext", Token4.KEM_CT_LEN), o.bytes("sealed_identity", Token4.PREAMBLE_LEN),
        )
    }
}

/**
 * Une session v4 (§9, `brocolis_proto::session4`) : établissement hybride à
 * identité cachée, triple cliquet (X25519 + ML-KEM-768 à chaque tour) et
 * en-têtes chiffrés.
 *
 * Recevoir un jeton v4 ([Token4]) :
 *
 * 1. essayer chaque session connue : [decrypt] ; une
 *    [Erreur.SessionInconnue] veut dire « pas cette session » (aucune clé
 *    d'en-tête ne l'ouvre) — passer à la suivante ; toute autre erreur est
 *    définitive (rejeu, altération…) ;
 * 2. aucune session : un 0x01 va à [Device.accept4], un 0x02 à
 *    [Session4.acceptPsk] (clé partagée).
 *
 * Comme en v3, chaque déchiffrement est **transactionnel** : un échec laisse
 * la session exactement telle qu'elle était.
 *
 * Sérialisable ([toJson], même forme que la référence Rust) ; à garder
 * chiffrée par la clé matérielle (§3.1). Pas faite pour être partagée entre
 * fils sans verrou.
 */
class Session4 private constructor(
    private var mode: Mode4,
    private var ad: ByteArray,
    private var sessionIdBytes: ByteArray,
    private var rk: ByteArray,
    private var dhsSecret: ByteArray,
    private var dhsPublic: ByteArray,
    private var dhr: ByteArray?,
    private var kem: KemPair?,
    private var peerEk: ByteArray?,
    private var sendCt: ByteArray?,
    private var cks: ByteArray?,
    private var ckr: ByteArray?,
    private var ns: Long,
    private var nr: Long,
    private var pn: Long,
    private var hks: ByteArray?,
    private var hkr: ByteArray?,
    private var nhks: ByteArray,
    private var nhkr: ByteArray,
    private var skipped: MutableList<Skipped4>,
    private var previousHkr: MutableList<ByteArray>,
    private var preamble: StoredPreamble?,
    private var initialEphemeral: ByteArray?,
    private var peerIdentityBytes: ByteArray?,
    private var confirmed: Boolean,
    /** Le répondeur n'a encore reçu aucune chaîne : la première peut être sans `ct` (la toute première chaîne de l'initiateur). */
    private var responderFresh: Boolean,
) {
    private val v: Int = 4

    /** Une copie profonde (pour la transaction d'un déchiffrement). */
    private fun copy(): Session4 = Session4(
        mode, ad.copyOf(), sessionIdBytes.copyOf(), rk.copyOf(), dhsSecret.copyOf(), dhsPublic.copyOf(), dhr?.copyOf(),
        kem?.copy(), peerEk?.copyOf(), sendCt?.copyOf(), cks?.copyOf(), ckr?.copyOf(), ns, nr, pn,
        hks?.copyOf(), hkr?.copyOf(), nhks.copyOf(), nhkr.copyOf(),
        skipped.map { it.copy() }.toMutableList(), previousHkr.map { it.copyOf() }.toMutableList(),
        preamble, initialEphemeral?.copyOf(), peerIdentityBytes?.copyOf(), confirmed, responderFresh,
    )

    /** Remplace l'état par `o` (fin d'une transaction réussie), en effaçant l'ancien. */
    private fun commit(o: Session4) {
        wipeSecrets()
        mode = o.mode; ad = o.ad; sessionIdBytes = o.sessionIdBytes; rk = o.rk
        dhsSecret = o.dhsSecret; dhsPublic = o.dhsPublic; dhr = o.dhr; kem = o.kem; peerEk = o.peerEk; sendCt = o.sendCt
        cks = o.cks; ckr = o.ckr; ns = o.ns; nr = o.nr; pn = o.pn
        hks = o.hks; hkr = o.hkr; nhks = o.nhks; nhkr = o.nhkr; skipped = o.skipped; previousHkr = o.previousHkr
        preamble = o.preamble; initialEphemeral = o.initialEphemeral; peerIdentityBytes = o.peerIdentityBytes
        confirmed = o.confirmed; responderFresh = o.responderFresh
    }

    private fun wipeSecrets() {
        Octets.wipe(rk, dhsSecret, cks, ckr, hks, hkr, nhks, nhkr, kem?.seed)
        skipped.forEach { Octets.wipe(it.mk, it.hk) }
        previousHkr.forEach { Octets.wipe(it) }
    }

    /** Efface les secrets de la session (elle devient inutilisable). */
    fun wipe() {
        wipeSecrets()
        cks = null
        ckr = null
        kem = null
        skipped.clear()
        previousHkr.clear()
    }

    // ----- Envoi -------------------------------------------------------------

    private fun seal(genre: Int, data: ByteArray): Token4 {
        if (data.size > Session.MAX_PLAINTEXT) echec(Erreur.TropGrand)
        val ck = cks ?: echec(Erreur.Etat)
        val hk = hks ?: echec(Erreur.Etat)
        val k = kem ?: echec(Erreur.Etat)
        val nextNs = ns + 1
        if (nextNs > Octets.U32_MAX) echec(Erreur.Epuise)
        val (next, mk) = Kdf.kdfCk(ck)
        val (key, nonce, hnonce) = Kdf.messageKeys4(mk)
        val header = Header4(dhsPublic, pn, ns, k.ek, sendCt)
        val kind = if (preamble != null) Token4.TYPE_INITIAL else Token4.TYPE_MESSAGE
        val plain = Octets.concat(byteArrayOf(genre.toByte()), data)
        val padded = Remplissage.pad(plain)
        val encHeader: ByteArray
        val ciphertext: ByteArray
        try {
            encHeader = Kdf.aesGcmSeal(hk, hnonce, byteArrayOf(kind.toByte()), header.toBytes())
            ciphertext = Kdf.aesGcmSeal(key, nonce, aad(kind, hnonce, encHeader), padded)
        } finally {
            Octets.wipe(mk, key, plain, padded)
        }
        Octets.wipe(ck)
        cks = next
        ns = nextNs
        val body = Body4(hnonce, encHeader, ciphertext)
        val p = preamble
        return if (p != null) Token4.Initial(p.toPreamble(), body) else Token4.Message(body)
    }

    /** Les données associées du chiffré : `AD ‖ type ‖ nonce d'en-tête ‖ en-tête chiffré`. */
    private fun aad(kind: Int, hnonce: ByteArray, encHeader: ByteArray): ByteArray =
        Octets.concat(ad, byteArrayOf(kind.toByte()), hnonce, encHeader)

    /** Chiffre un texte (le jeton décodé : 0x01 tant que l'initiateur par paquet n'a pas reçu de réponse, 0x02 ensuite). */
    fun encryptToken(text: String): Token4 = seal(Token4.GENRE_TEXTE, Octets.utf8(text))

    /** Chiffre un texte : `[[BROCOLIS:v4:…]]`. */
    fun encrypt(text: String): String = encryptToken(text).encode()

    /** Envoie une chaîne de groupe par cette session (genre 0x01). */
    fun encryptDistribution(d: SenderKeyDistribution): String {
        val b = d.toBytes()
        try {
            return seal(Token4.GENRE_DISTRIBUTION, b).encode()
        } finally {
            Octets.wipe(b)
        }
    }

    // ----- Réception ---------------------------------------------------------

    /**
     * Déchiffre un jeton v4. [Erreur.SessionInconnue] : il n'est pas de cette
     * session. Transactionnel. Peut tirer une nouvelle chaîne d'envoi (secret
     * X25519 32, graine ML-KEM 64, `m` 32) si le message fait tourner le
     * cliquet.
     */
    fun decrypt(token: Token4, now: Long, rng: CryptoRng = Hasard.system()): Content {
        if (token is Token4.Initial) {
            // Notre propre premier message, renvoyé.
            if (preamble?.ephemeral?.contentEquals(token.preamble.ephemeral) == true) echec(Erreur.Rejoue)
            if (initialEphemeral?.contentEquals(token.preamble.ephemeral) != true) echec(Erreur.SessionInconnue)
        }
        val next = copy()
        val content: Content
        try {
            val plain = next.ratchetDecrypt(token.kind, token.body, now, rng)
            try {
                if (plain.isEmpty()) echec(Erreur.Format)
                val data = plain.copyOfRange(1, plain.size)
                try {
                    content = when (plain[0].toInt()) {
                        Token4.GENRE_TEXTE -> Content.Text(Octets.fromUtf8(data))
                        Token4.GENRE_DISTRIBUTION -> Content.Distribution(SenderKeyDistribution.fromBytes(data))
                        else -> echec(Erreur.Format)
                    }
                } finally {
                    Octets.wipe(data)
                }
            } finally {
                Octets.wipe(plain)
            }
        } catch (e: BrocolisException) {
            next.wipeSecrets()
            throw e
        }
        // Une réponse est arrivée : l'initiateur passe aux messages 0x02.
        if (next.ckr != null) {
            next.preamble = null
            next.confirmed = true
        }
        commit(next)
        return content
    }

    /** [decrypt] d'un jeton texte `[[BROCOLIS:v4:…]]`. */
    fun decryptText(token: String, now: Long, rng: CryptoRng = Hasard.system()): Content =
        decrypt(Token4.decode(token), now, rng)

    private fun open(mk: ByteArray, kind: Int, body: Body4): ByteArray {
        val (key, nonce, hnonce) = Kdf.messageKeys4(mk)
        try {
            if (!hnonce.contentEquals(body.headerNonce)) echec(Erreur.Dechiffrement)
            val padded = Kdf.aesGcmOpen(key, nonce, aad(kind, body.headerNonce, body.header), body.ciphertext)
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
    private fun ratchetDecrypt(kind: Int, body: Body4, now: Long, rng: CryptoRng): ByteArray {
        purge(now)
        // 1. Les clés sautées des chaînes passées : une fois par clé d'en-tête
        //    distincte (la chaîne courante est traitée en 2).
        val tried = mutableListOf<ByteArray>()
        for (i in skipped.indices) {
            val hk = skipped[i].hk
            if (hkr?.contentEquals(hk) == true || tried.any { it.contentEquals(hk) }) continue
            tried.add(hk)
            val header = openHeader(hk, kind, body) ?: continue
            return takeSkipped(hk, header.n, kind, body)
        }
        // 2. La chaîne de réception courante : une clé sautée, ou la suite.
        val current = hkr
        if (current != null) {
            val header = openHeader(current, kind, body)
            if (header != null) {
                if (header.n < nr) return takeSkipped(current, header.n, kind, body)
                skip(header.n, now)
                return nextMessage(kind, body)
            }
        }
        // 3. La chaîne suivante : le cliquet tourne.
        val header = openHeader(nhkr.copyOf(), kind, body)
        if (header != null) {
            skip(header.pn, now)
            dhRatchet(header, rng)
            skip(header.n, now)
            return nextMessage(kind, body)
        }
        // 4. Nos propres messages, ou une chaîne passée : un rejeu.
        val own = hks?.let { openHeaderPlain(it, kind, body) != null } == true
        val old = previousHkr.any { openHeaderPlain(it, kind, body) != null }
        if (own || old) echec(Erreur.Rejoue)
        echec(Erreur.SessionInconnue)
    }

    /** Le message `n` d'une chaîne dont la clé a été sautée ; absente : déjà lu. */
    private fun takeSkipped(hk: ByteArray, n: Long, kind: Int, body: Body4): ByteArray {
        val pos = skipped.indexOfFirst { it.hk.contentEquals(hk) && it.n == n }
        if (pos < 0) echec(Erreur.Rejoue)
        val plain = open(skipped[pos].mk, kind, body)
        val s = skipped.removeAt(pos)
        Octets.wipe(s.mk)
        return plain
    }

    private fun nextMessage(kind: Int, body: Body4): ByteArray {
        val ck = ckr ?: echec(Erreur.Etat)
        val (next, mk) = Kdf.kdfCk(ck)
        ckr = next
        Octets.wipe(ck)
        if (nr + 1 > Octets.U32_MAX) echec(Erreur.Epuise)
        nr += 1
        try {
            return open(mk, kind, body)
        } finally {
            Octets.wipe(mk)
        }
    }

    private fun skip(until: Long, now: Long) {
        if (nr + Protocole.MAX_SKIP < until) echec(Erreur.TropDeClesSautees)
        val c = ckr
        val h = hkr
        if (c != null && h != null) {
            var ck: ByteArray = c
            while (nr < until) {
                val (next, mk) = Kdf.kdfCk(ck)
                skipped.add(Skipped4(h.copyOf(), nr, mk, now))
                Octets.wipe(ck)
                ck = next
                nr += 1
            }
            ckr = ck
            while (skipped.size > Protocole.MAX_SKIP) Octets.wipe(skipped.removeAt(0).mk)
        }
    }

    /**
     * Le tour de cliquet (§9.2, §9.3) : la chaîne de réception mélange X25519
     * et la décapsulation de `ct`, puis une nouvelle chaîne d'envoi mélange un
     * nouveau X25519 et une encapsulation vers la clé ML-KEM annoncée par
     * l'autre.
     */
    private fun dhRatchet(header: Header4, rng: CryptoRng) {
        if (header.ek.size != Paquet.PQPK_LEN) echec(Erreur.Format)
        val ct = header.ct
        val ssR: ByteArray? = when {
            ct != null && ct.size == Token4.KEM_CT_LEN -> {
                val k = kem ?: echec(Erreur.Format)
                MlKem.decapsulate(k.seed, ct)
            }
            ct != null -> echec(Erreur.Format)
            // Seule la toute première chaîne de l'initiateur est sans `ct`.
            responderFresh -> null
            else -> echec(Erreur.Format)
        }
        responderFresh = false
        pn = ns
        ns = 0
        nr = 0
        hkr?.let { old ->
            previousHkr.add(old.copyOf())
            if (previousHkr.size > PREVIOUS_HKR) Octets.wipe(previousHkr.removeAt(0))
        }
        hks = nhks.copyOf()
        hkr = nhkr.copyOf()
        dhr = header.dh.copyOf()
        val dh1 = Kdf.x25519(dhsSecret, header.dh)
        val (rk1, ckr1, nhkr1) = Kdf.kdfRk4(rk, dh1, ssR)
        Octets.wipe(rk, dh1, ssR, ckr, nhkr)
        rk = rk1
        ckr = ckr1
        nhkr = nhkr1
        // Nouvelle chaîne d'envoi.
        val secret = rng.bytes(32)
        val seed = rng.bytes(64)
        val m = rng.bytes(32)
        val (newCt, ssS) = try {
            MlKem.encapsulate(header.ek, m)
        } finally {
            Octets.wipe(m)
        }
        Octets.wipe(dhsSecret)
        dhsSecret = secret
        dhsPublic = Kdf.x25519Public(secret)
        Octets.wipe(kem?.seed)
        kem = KemPair.fromSeed(seed)
        Octets.wipe(seed)
        peerEk = header.ek.copyOf()
        sendCt = newCt
        val dh2 = Kdf.x25519(dhsSecret, header.dh)
        val (rk2, cks2, nhks2) = Kdf.kdfRk4(rk, dh2, ssS)
        Octets.wipe(rk, dh2, ssS, cks, nhks)
        rk = rk2
        cks = cks2
        nhks = nhks2
    }

    // ----- État --------------------------------------------------------------

    /** Efface les clés sautées de plus de 30 jours. */
    fun purge(now: Long) {
        val old = skipped.filter { Octets.satAdd(it.storedAt, Protocole.MAX_SKIP_AGE) <= now }
        old.forEach { Octets.wipe(it.mk) }
        skipped.removeAll(old)
    }

    /** L'identifiant local de la session (`SHA-256(AD)[0..8]`) : pour la ranger, jamais transmis. */
    val sessionId: ByteArray get() = sessionIdBytes.copyOf()

    /** AD = IK_A ‖ IK_B (ou EK_A ‖ R en clé partagée). */
    val associatedData: ByteArray get() = ad.copyOf()

    /** Le mode d'établissement. */
    fun mode(): Mode4 = mode

    /** Vrai si l'autre côté a répondu (l'initiateur envoie des 0x01 jusque-là). */
    val isConfirmed: Boolean get() = confirmed

    /** IK X25519 du correspondant (absent en clé partagée). */
    val peerIdentity: ByteArray? get() = peerIdentityBytes?.copyOf()

    /** Le nombre de clés sautées gardées. */
    val skippedLen: Int get() = skipped.size

    /** La clé publique de cliquet X25519 courante (vecteurs). */
    val ratchetPublic: ByteArray get() = dhsPublic.copyOf()

    /** La clé racine courante (vecteurs : un secret !). */
    internal val debugRootKey: ByteArray get() = rk.copyOf()

    /** Les clés de chaîne courantes (envoi, réception) — vecteurs seulement. */
    internal val debugChainKeys: Pair<ByteArray?, ByteArray?> get() = Pair(cks?.copyOf(), ckr?.copyOf())

    /** Les clés d'en-tête courantes `(HKs, HKr, NHKs, NHKr)` — vecteurs seulement. */
    internal val debugHeaderKeys: List<ByteArray?> get() = listOf(hks?.copyOf(), hkr?.copyOf(), nhks.copyOf(), nhkr.copyOf())

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
            put("kem", kem?.toJson() ?: JsonNull)
            putBytes("peer_ek", peerEk)
            putBytes("send_ct", sendCt)
            putBytes("cks", cks)
            putBytes("ckr", ckr)
            putNum("ns", ns)
            putNum("nr", nr)
            putNum("pn", pn)
            putBytes("hks", hks)
            putBytes("hkr", hkr)
            putBytes("nhks", nhks)
            putBytes("nhkr", nhkr)
            put("skipped", JsonArray(skipped.map { it.toJson() }))
            put("previous_hkr", JsonArray(previousHkr.map { JsonPrimitive(Octets.b64(it)) }))
            put("preamble", preamble?.toJson() ?: JsonNull)
            putBytes("initial_ephemeral", initialEphemeral)
            putBytes("peer_identity", peerIdentityBytes)
            put("confirmed", confirmed)
            put("responder_fresh", responderFresh)
        },
    )

    companion object {
        /** Le nombre de clés d'en-tête de réception passées dont on se souvient pour reconnaître un rejeu. */
        private const val PREVIOUS_HKR = 16

        /** Ouvre un en-tête chiffré avec `hk` : `null` si ce n'est pas la bonne clé (le clair sinon). */
        private fun openHeaderPlain(hk: ByteArray, kind: Int, body: Body4): ByteArray? = try {
            Kdf.aesGcmOpen(hk, body.headerNonce, byteArrayOf(kind.toByte()), body.header)
        } catch (e: BrocolisException) {
            if (e.erreur != Erreur.Dechiffrement) throw e
            null
        }

        /** Ouvre et relit un en-tête : `null` si ce n'est pas la bonne clé ; malformé : [Erreur.Format]. */
        private fun openHeader(hk: ByteArray, kind: Int, body: Body4): Header4? =
            openHeaderPlain(hk, kind, body)?.let { Header4.fromBytes(it) }

        private fun newInitiator(
            mode: Mode4,
            sk: ByteArray,
            ad: ByteArray,
            ratchetSecret: ByteArray,
            remoteRatchet: ByteArray,
            kem: KemPair,
            preamble: StoredPreamble?,
            peerIdentity: ByteArray?,
        ): Session4 {
            val (hkAb, nhkBa) = Kdf.headerKeys4(sk)
            val dh = Kdf.x25519(ratchetSecret, remoteRatchet)
            val (rk, cks, nhks) = Kdf.kdfRk4(sk, dh, null)
            Octets.wipe(dh)
            return Session4(
                mode, ad.copyOf(), Kdf.sessionId(ad), rk, ratchetSecret.copyOf(), Kdf.x25519Public(ratchetSecret),
                remoteRatchet.copyOf(), kem, null, null, cks, null, 0, 0, 0,
                hkAb, null, nhks, nhkBa, mutableListOf(), mutableListOf(), preamble, null, peerIdentity?.copyOf(), false, false,
            )
        }

        internal fun newResponder(
            mode: Mode4,
            sk: ByteArray,
            ad: ByteArray,
            ratchetSecret: ByteArray,
            initialEphemeral: ByteArray,
            peerIdentity: ByteArray?,
        ): Session4 {
            val (hkAb, nhkBa) = Kdf.headerKeys4(sk)
            return Session4(
                mode, ad.copyOf(), Kdf.sessionId(ad), sk.copyOf(), ratchetSecret.copyOf(), Kdf.x25519Public(ratchetSecret),
                null, null, null, null, null, null, 0, 0, 0,
                null, null, nhkBa, hkAb, mutableListOf(), mutableListOf(), null, initialEphemeral.copyOf(), peerIdentity?.copyOf(), true, true,
            )
        }

        /**
         * Ouvre une session v4 vers l'appareil du paquet (§9.1, §9.4). Le
         * paquet doit proposer ML-KEM ([Erreur.PqIndisponible] sinon).
         *
         * Ordre de tirage : secret EK (32), secret de cliquet (32), message
         * ML-KEM `m` vers la PQPK (32), graine ML-KEM de cliquet (64).
         */
        fun initiate(identity: IdentitySecret, bundle: KeyBundle, rng: CryptoRng = Hasard.system()): Session4 {
            bundle.verify()
            val ek = rng.bytes(32)
            val ratchet = rng.bytes(32)
            val m = rng.bytes(32)
            val seed = rng.bytes(64)
            try {
                return initiateWith(identity, bundle, ek, ratchet, m, seed)
            } finally {
                Octets.wipe(ek, ratchet, m, seed)
            }
        }

        /** [initiate] avec le hasard donné (les vecteurs). Le paquet doit avoir été vérifié. */
        fun initiateWith(
            identity: IdentitySecret,
            bundle: KeyBundle,
            ekSecret: ByteArray,
            ratchetSecret: ByteArray,
            kemM: ByteArray,
            kemSeed: ByteArray,
        ): Session4 {
            val pq = bundle.pq ?: echec(Erreur.PqIndisponible)
            require(ekSecret.size == 32 && ratchetSecret.size == 32 && kemM.size == 32 && kemSeed.size == MlKem.SEED_LEN)
            val ikA = identity.public().dh
            val ikB = bundle.identity.dh
            val dh1 = Kdf.x25519(identity.dh, bundle.spk)
            val dh2 = Kdf.x25519(ekSecret, ikB)
            val dh3 = Kdf.x25519(ekSecret, bundle.spk)
            val (ct, ss) = MlKem.encapsulate(pq.key, kemM)
            val sk = Kdf.sk4(dh1, dh2, dh3, ss)
            val ephemeral = Kdf.x25519Public(ekSecret)
            val (kPre, nPre) = Kdf.preambleKey4(dh3, ss)
            Octets.wipe(dh1, dh2, dh3, ss)
            try {
                val aad = Octets.concat(byteArrayOf(Token4.TYPE_INITIAL.toByte()), ephemeral, ct)
                val sealedIdentity = Kdf.aesGcmSeal(kPre, nPre, aad, ikA)
                val preamble = StoredPreamble(ephemeral, ct, sealedIdentity)
                return newInitiator(
                    Mode4.Bundle, sk, Octets.concat(ikA, ikB), ratchetSecret, bundle.spk, KemPair.fromSeed(kemSeed), preamble, ikB,
                )
            } finally {
                Octets.wipe(sk, kPre)
            }
        }

        /** Ouvre une session v4 à partir d'une clé partagée. Tire le secret EK (32, aussi première clé de cliquet), puis la graine ML-KEM (64). */
        fun initiatePsk(key: ByteArray, rng: CryptoRng = Hasard.system()): Session4 {
            val ek = rng.bytes(32)
            val seed = rng.bytes(64)
            try {
                return initiatePskWith(key, ek, seed)
            } finally {
                Octets.wipe(ek, seed)
            }
        }

        /**
         * [initiatePsk] avec le hasard donné. SK = `HKDF(0³², clé,
         * "Brocolis_v4_PSK_SHA-256")` ; la clé de cliquet initiale du répondeur
         * R vient de `r_PSK` ; AD = EK_A ‖ R ; la première clé de cliquet de A
         * est EK_A.
         */
        fun initiatePskWith(key: ByteArray, ekSecret: ByteArray, kemSeed: ByteArray): Session4 {
            require(key.size == 32 && ekSecret.size == 32 && kemSeed.size == MlKem.SEED_LEN)
            val sk = Kdf.sk4Psk(key)
            val rSecret = Kdf.psk4RatchetSecret(sk)
            val r = Kdf.x25519Public(rSecret)
            Octets.wipe(rSecret)
            try {
                val ad = Octets.concat(Kdf.x25519Public(ekSecret), r)
                return newInitiator(Mode4.Psk, sk, ad, ekSecret, r, KemPair.fromSeed(kemSeed), null, null)
            } finally {
                Octets.wipe(sk)
            }
        }

        /**
         * Accepte le premier message d'une session v4 à clé partagée : un 0x02
         * qu'aucune session n'ouvre. Essaie la clé d'en-tête initiale de
         * chaque clé ; [Erreur.SessionInconnue] si aucune ne l'ouvre. Une EK
         * déjà vue est refusée ([Erreur.Rejoue]).
         */
        fun acceptPsk(
            keys: List<ByteArray>,
            token: Token4,
            guard: ReplayGuard,
            now: Long,
            rng: CryptoRng = Hasard.system(),
        ): Pair<Session4, Content> {
            if (token !is Token4.Message) echec(Erreur.SessionInconnue)
            for (key in keys) {
                val sk = Kdf.sk4Psk(key)
                val (hkAb, nhkBa) = Kdf.headerKeys4(sk)
                Octets.wipe(nhkBa)
                try {
                    val header = openHeader(hkAb, Token4.TYPE_MESSAGE, token.body) ?: continue
                    if (!Kdf.x25519IsCanonical(header.dh)) echec(Erreur.CleInvalide)
                    if (guard.seen(header.dh)) echec(Erreur.Rejoue)
                    val rSecret = Kdf.psk4RatchetSecret(sk)
                    try {
                        val ad = Octets.concat(header.dh, Kdf.x25519Public(rSecret))
                        val s = newResponder(Mode4.Psk, sk, ad, rSecret, header.dh, null)
                        val content = s.decrypt(token, now, rng)
                        guard.insert(header.dh, now)
                        return Pair(s, content)
                    } finally {
                        Octets.wipe(rSecret)
                    }
                } finally {
                    Octets.wipe(sk, hkAb)
                }
            }
            echec(Erreur.SessionInconnue)
        }

        /** [Device.accept4] : voir sa documentation. */
        internal fun accept(device: Device, token: Token4, now: Long, rng: CryptoRng): Pair<Session4, Content> {
            if (token !is Token4.Initial) echec(Erreur.Format)
            val p = token.preamble
            if (!Kdf.x25519IsCanonical(p.ephemeral)) echec(Erreur.CleInvalide)
            if (device.replayGuard.seen(p.ephemeral)) echec(Erreur.Rejoue)
            val aad = p.aad()
            val spks = device.spkSecrets()
            val seeds = device.pqSeeds()
            try {
                var found: Triple<ByteArray, ByteArray, ByteArray>? = null
                var ikA: ByteArray? = null
                search@ for (spk in spks) {
                    val dh3 = Kdf.x25519(spk, p.ephemeral)
                    for (seed in seeds) {
                        val ss = MlKem.decapsulate(seed, p.kemCiphertext)
                        val (k, n) = Kdf.preambleKey4(dh3, ss)
                        val ik = try {
                            Kdf.aesGcmOpen(k, n, aad, p.sealedIdentity)
                        } catch (e: BrocolisException) {
                            if (e.erreur != Erreur.Dechiffrement) throw e
                            null
                        } finally {
                            Octets.wipe(k)
                        }
                        if (ik != null) {
                            if (ik.size != 32) echec(Erreur.Format)
                            found = Triple(spk, ss, dh3)
                            ikA = ik
                            break@search
                        }
                        Octets.wipe(ss)
                    }
                    Octets.wipe(dh3)
                }
                val (spk, ss, dh3) = found ?: echec(Erreur.CleInconnue)
                val ik = ikA ?: echec(Erreur.CleInconnue)
                val own = device.identitySecret
                val dh1 = Kdf.x25519(spk, ik)
                val dh2 = Kdf.x25519(own.dh, p.ephemeral)
                val sk = Kdf.sk4(dh1, dh2, dh3, ss)
                Octets.wipe(dh1, dh2, dh3, ss)
                try {
                    val ad = Octets.concat(ik, Kdf.x25519Public(own.dh))
                    val s = newResponder(Mode4.Bundle, sk, ad, spk, p.ephemeral, ik)
                    val content = s.decrypt(token, now, rng)
                    device.replayGuard.insert(p.ephemeral, now)
                    return Pair(s, content)
                } finally {
                    Octets.wipe(sk)
                }
            } finally {
                spks.forEach { Octets.wipe(it) }
                seeds.forEach { Octets.wipe(it) }
            }
        }

        /** Relit un état JSON (vérifie sa cohérence). */
        fun fromJson(text: String): Session4 {
            val o = EtatJson.parse(text)
            if (o.u8("v") != 4L) echec(Erreur.Etat)
            val kemEl = o["kem"] ?: echec(Erreur.Etat)
            val preambleEl = o["preamble"] ?: echec(Erreur.Etat)
            val s = Session4(
                Mode4.fromJson(o.str("mode")),
                o.bytes("ad"),
                o.bytes("session_id", 8),
                o.bytes("rk", 32),
                o.bytes("dhs_secret", 32),
                o.bytes("dhs_public", 32),
                o.optBytes("dhr", 32),
                if (kemEl is JsonNull) null else KemPair.fromJson(kemEl.asObj()),
                o.optBytes("peer_ek"),
                o.optBytes("send_ct"),
                o.optBytes("cks", 32),
                o.optBytes("ckr", 32),
                o.u32("ns"),
                o.u32("nr"),
                o.u32("pn"),
                o.optBytes("hks", 32),
                o.optBytes("hkr", 32),
                o.bytes("nhks", 32),
                o.bytes("nhkr", 32),
                o.arr("skipped").map { Skipped4.fromJson(it.asObj()) }.toMutableList(),
                // `#[serde(default)]` : absent = vide.
                (if (o["previous_hkr"] == null) JsonArray(emptyList()) else o.arr("previous_hkr")).map { it.bytes(32) }.toMutableList(),
                if (preambleEl is JsonNull) null else StoredPreamble.fromJson(preambleEl.asObj()),
                o.optBytes("initial_ephemeral", 32),
                o.optBytes("peer_identity", 32),
                o.bool("confirmed"),
                o.bool("responder_fresh"),
            )
            val adOk = s.ad.size == 64 && Kdf.sessionId(s.ad).contentEquals(s.sessionIdBytes)
            val kemOk = s.kem?.let { it.ek.size == Paquet.PQPK_LEN } ?: true
            val peerOk = s.peerEk?.let { it.size == Paquet.PQPK_LEN } ?: true
            val ctOk = s.sendCt?.let { it.size == Token4.KEM_CT_LEN } ?: true
            if (!adOk || !kemOk || !peerOk || !ctOk || s.skipped.size > Protocole.MAX_SKIP ||
                !Kdf.x25519Public(s.dhsSecret).contentEquals(s.dhsPublic)
            ) {
                echec(Erreur.Etat)
            }
            return s
        }
    }
}
