package rs.brocolis.messagerie.crypto

import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.net.PairingPeer
import rs.brocolis.messagerie.net.WrapInbox
import rs.brocolis.messagerie.proto.Erreur
import rs.brocolis.messagerie.proto.KeyBundle
import rs.brocolis.messagerie.proto.Token
import rs.brocolis.messagerie.proto.Token4
import rs.brocolis.messagerie.store.BrocolisV3Store
import rs.brocolis.messagerie.store.NamedKey

/**
 * Le v3 pour l'app (docs/SECURITE.md §8) : chiffrer pour une clé nommée, lire
 * un texte collé, la protection affichée, l'appairage, la messagerie. Tout
 * passe par une transaction du magasin ([BrocolisV3Store]) ; v3 indisponible
 * (Keystore muet, état non écrivable) = l'ancien format (§8.5).
 *
 * Port de la façade `BrocolisV3` d'iOS (`Shared/BrocolisV3Store.swift`).
 * [BrocolisV3] est celle de l'app ; [BrocolisV3Api.of] en fait une autre sur
 * un autre magasin (tests, essais d'interopérabilité).
 *
 * Toute méthode fait des entrées-sorties (fichier, Keystore) : hors du fil
 * principal.
 */
abstract class BrocolisV3Api {
    /** Le magasin, ou `null` (v3 indisponible). */
    abstract val store: BrocolisV3Store?

    companion object {
        fun of(store: BrocolisV3Store?): BrocolisV3Api = object : BrocolisV3Api() {
            override val store = store
        }

        fun now(): Long = maxOf(0L, System.currentTimeMillis() / 1000)

        private val bundleCache = object : LinkedHashMap<String, KeyBundle>(64, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, KeyBundle>?) = size > 64
        }

        /** Le paquet d'un contact, vérifié une fois puis gardé en mémoire. */
        fun bundle(base64: String?): KeyBundle? {
            if (base64.isNullOrEmpty()) return null
            synchronized(bundleCache) { bundleCache[base64]?.let { return it } }
            val b = runCatching { KeyBundle.fromBase64(base64) }.getOrNull() ?: return null
            synchronized(bundleCache) { bundleCache[base64] = b }
            return b
        }

        /** Une clé nommée → la clé du moteur (`null` si elle n'est pas de 32 octets). */
        fun key(k: NamedKey): BrocolisV3Key? {
            val raw = BrocolisCrypto.b64decode(k.base64.trim()) ?: return null
            if (raw.size != 32) return null
            return BrocolisV3Key(
                id = k.id, raw = raw, bundle = bundle(k.v3Bundle),
                bundleAt = maxOf(0L, k.v3SinceSeconds ?: 0L),
                group = k.duo == false, psk = k.psk == true,
                caps = k.v3Caps?.let { BrocolisCrypto.b64decode(it.trim()) }?.takeIf { it.size == 64 },
            )
        }

        fun keys(ks: List<NamedKey>): List<BrocolisV3Key> = ks.mapNotNull(::key)

        val alreadyRead: String
            get() = loc("🔐 (déjà lu sur cet appareil)", "🔐 (already read on this device)", "🔐 (ya leído en este dispositivo)")

        val sentFromThisDevice: String
            get() = loc("🔐 envoyé depuis cet appareil", "🔐 sent from this device", "🔐 enviado desde este dispositivo")
    }

    /** Une transaction sur le magasin ; `null` si le v3 est indisponible. */
    fun <T> run(body: (BrocolisV3Engine, Long) -> T): T? {
        val s = store ?: return null
        val t = now()
        return try {
            s.transaction(t) { body(it, t) }
        } catch (_: Exception) {
            null
        }
    }

    // MARK: Envoyer, lire

    /** Le jeton v3 de `text` pour la clé `k`, ou `null` (→ v1/v2). */
    fun seal(text: String, k: NamedKey): String? {
        val key = key(k) ?: return null
        return run { e, t -> e.seal(text, key, t) }
    }

    /**
     * Ce qui chiffre et ce qui lit pour Partager et l'écran Conversation : v3
     * pour UNE clé destinataire qui le permet (§8.5), sinon v1 (une clé) ou v2
     * (plusieurs) ; lecture v3, v2, v1.
     */
    fun codec(recipients: List<NamedKey>, all: List<NamedKey>): BrocolisCodec {
        val sym = recipients.mapNotNull { runCatching { BrocolisCrypto.keyBytes(it.base64) }.getOrNull() }
        return BrocolisCodec(
            seal = { text ->
                (if (recipients.size == 1) seal(text, recipients[0]) else null)
                    ?: BrocolisCrypto.sealTokenOrNull(text.toByteArray(Charsets.UTF_8), sym)
            },
            open = { openTokens(it, all) },
        )
    }

    /**
     * Remplace chaque jeton d'un texte collé par son clair : les v3 en une
     * seule transaction, puis v2 et v1 avec toutes les clés.
     */
    fun openTokens(input: String, keys: List<NamedKey>): BrocolisCrypto.Decrypted {
        val sym = keys.mapNotNull { runCatching { BrocolisCrypto.keyBytes(it.base64) }.getOrNull() }
        val found = BrocolisV3Format.findTokens(input).map { input.substring(it.first, it.last + 1) }
        val clear = memo.lookup(found).toMutableMap()
        val missing = found.filter { clear[it] == null }.distinct()
        if (missing.isNotEmpty()) {
            val v3keys = keys(keys)
            val opened = run { e, t ->
                val out = LinkedHashMap<String, String>()
                for (token in missing) {
                    when (val r = e.open(token, v3keys, t)) {
                        is BrocolisV3Opened.Text -> out[token] = r.text
                        BrocolisV3Opened.Replay -> out[token] = alreadyRead
                        is BrocolisV3Opened.Failed -> Unit
                    }
                }
                out
            } ?: emptyMap()
            memo.store(opened.filterValues { it != alreadyRead })
            for ((k, v) in opened) clear.putIfAbsent(k, v)
        }
        return BrocolisCrypto.decryptTokens(input, sym) { clear[it] }
    }

    /**
     * Les clairs v3 ouverts récemment par ce processus : un écran qui se
     * redessine ne refait pas une transaction par ligne.
     */
    private val memo = Memo()

    private class Memo {
        private val map = object : LinkedHashMap<String, String>() {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?) = size > 256
        }

        @Synchronized
        fun lookup(tokens: List<String>): Map<String, String> =
            tokens.mapNotNull { t -> map[t]?.let { t to it } }.toMap()

        @Synchronized
        fun store(entries: Map<String, String>) {
            for ((t, c) in entries) map.putIfAbsent(t, c)
        }
    }

    // MARK: Protection affichée (§8.8)

    /** La protection de chaque clé, en une transaction (`LEGACY` partout si le v3 est indisponible). */
    fun protections(ks: List<NamedKey>): Map<String, BrocolisProtection> {
        val pairs = ks.mapNotNull { k -> key(k)?.let { k.id to it } }
        val result = run { e, t -> pairs.associate { (id, key) -> id to e.protection(key, t) } }
        return ks.associate { it.id to (result?.get(it.id) ?: BrocolisProtection.LEGACY) }
    }

    fun protection(k: NamedKey): BrocolisProtection = protections(listOf(k))[k.id] ?: BrocolisProtection.LEGACY

    /**
     * La protection qu'a reçue un texte qu'on vient de chiffrer : celle de la
     * clé s'il porte un jeton v3, sinon l'ancien format.
     */
    fun protectionUsed(sealed: String, recipients: List<NamedKey>): BrocolisProtection {
        if (recipients.size != 1 || (!sealed.contains(Token.HEAD) && !sealed.contains(Token4.HEAD))) return BrocolisProtection.LEGACY
        return protection(recipients[0])
    }

    // MARK: Appairage (§8.4)

    /** Mon paquet de clés, à publier dans le salon. */
    fun myBundle(): String? = run { e, _ -> e.bundleBase64 }

    /** Mon paquet et ma capacité v4 signée (§9.6), publiés ensemble dans le salon. */
    fun myBundleAndCaps(): Pair<String?, String?> = run { e, _ -> e.bundleBase64 to e.capsBase64 } ?: (null to null)

    /**
     * L'empreinte d'appairage à deux, si le correspondant a publié un paquet
     * valide (sinon `null` : l'empreinte d'avant) ; sous le contexte v4 si sa
     * capacité v4 est valide (§9.7).
     */
    fun pairingFingerprint(keyBase64: String, peerBundle: String?, peerCaps: String? = null): String? {
        val peer = bundle(peerBundle) ?: return null
        val raw = runCatching { BrocolisCrypto.keyBytes(keyBase64) }.getOrNull() ?: return null
        if (raw.size != 32) return null
        val caps = peerCaps?.let { BrocolisCrypto.b64decode(it.trim()) }?.takeIf { it.size == 64 }
        return run { e, _ -> e.fingerprint(BrocolisV3Key("", raw, peer, 0, group = false, psk = false, caps = caps)) }
    }

    /** L'invitant ouvre la session dès l'appairage (§8.4). */
    fun openSession(k: NamedKey) {
        val key = key(k) ?: return
        run { e, t -> e.openSession(key, t) }
    }

    /** Une clé supprimée : ses sessions PSK partent avec elle. */
    fun forget(keyId: String) {
        run { e, _ -> e.forget(keyId) }
    }

    // MARK: Messagerie (§8.7)

    /** Le `ciphertext` d'un message, en v3 si la clé le permet, sinon `null`. */
    fun sealMessage(clear: String, k: NamedKey): String? {
        val key = key(k) ?: return null
        return run { e, t -> e.sealMessage(clear, key, t) }
    }

    /** Un message de la messagerie, vu par [openMessages]. */
    class Incoming(val ciphertext: String, val mine: Boolean)

    /**
     * Ouvre des messages de la messagerie en une transaction : pour chacun,
     * `null` s'il ne porte pas de jeton v3 (→ v1), sinon le résultat.
     */
    fun openMessages(messages: List<Incoming>, conversation: NamedKey, all: List<NamedKey>): List<BrocolisV3Opened?> {
        val conv = key(conversation)
        if (conv == null || messages.none { BrocolisV3Format.findTokens(it.ciphertext).isNotEmpty() }) {
            return messages.map { null }
        }
        val v3keys = keys(all)
        return run { e, t -> messages.map { e.openMessage(it.ciphertext, v3keys, conv, it.mine, t) } }
            ?: messages.map {
                if (BrocolisV3Format.findTokens(it.ciphertext).isEmpty()) null else BrocolisV3Opened.Failed(Erreur.Etat)
            }
    }
}

/** Le v3 de l'app : le magasin est posé au démarrage (`BrocolisApplication`). */
object BrocolisV3 : BrocolisV3Api() {
    @Volatile
    override var store: BrocolisV3Store? = null
}

/**
 * Ce que l'appairage dit du correspondant v3 (docs/SECURITE.md §8.4, §8.11 1–3).
 *
 * @property bundle son paquet, s'il en a publié un ET que j'ai publié le mien ;
 * @property duo à deux (sinon : clé de groupe, jamais de v3) ;
 * @property caps sa capacité v4 signée (§9.6), publiée avec son paquet.
 */
data class BrocolisV3Contact(val bundle: String?, val duo: Boolean, val caps: String? = null) {

    /**
     * L'empreinte à comparer : celle qui couvre les identités v3 si l'on est
     * à deux avec un appareil v3, sinon celle d'avant (`legacy`).
     */
    fun fingerprint(key: String, legacy: String, v3: BrocolisV3Api = BrocolisV3): String {
        if (!duo) return legacy
        return v3.pairingFingerprint(key, bundle, caps) ?: legacy
    }

    companion object {
        /** Le mode compatible (« Appairer à deux ») : toujours à deux. */
        fun compatible(peer: PairingPeer, myBundle: String?) =
            BrocolisV3Contact(
                bundle = if (myBundle == null) null else peer.bundle, duo = true,
                caps = if (myBundle == null) null else peer.caps,
            )

        /**
         * L'invitant : à deux tant qu'il a remis la clé à UNE personne
         * (`recipients` : tous ceux qui l'ont reçue) ; son paquet est celui de
         * la personne à qui il la remet.
         */
        fun inviting(recipients: List<PairingPeer>, myBundle: String?) =
            BrocolisV3Contact(
                bundle = if (myBundle == null) null else recipients.firstOrNull()?.bundle,
                duo = recipients.size == 1,
                caps = if (myBundle == null) null else recipients.firstOrNull()?.caps,
            )

        /**
         * Celui qui rejoint : l'invitant est `wrap.from` / `wrap.fromPub` ; à
         * deux si le salon ne compte qu'un autre participant (moi exclu).
         */
        fun joining(room: List<PairingPeer>, wrap: WrapInbox, myBundle: String?): BrocolisV3Contact {
            val inviter = room.firstOrNull { it.peerId == wrap.from && it.pub == wrap.fromPub }
            return BrocolisV3Contact(
                bundle = if (myBundle == null) null else inviter?.bundle, duo = room.size <= 1,
                caps = if (myBundle == null) null else inviter?.caps,
            )
        }
    }
}
