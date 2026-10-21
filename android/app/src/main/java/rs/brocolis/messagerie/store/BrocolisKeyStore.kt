package rs.brocolis.messagerie.store

import android.content.Context
import android.content.SharedPreferences
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.crypto.BrocolisIdentity
import rs.brocolis.messagerie.crypto.BrocolisV3
import rs.brocolis.messagerie.i18n.loc
import java.util.UUID

/**
 * Gère PLUSIEURS clés nommées (chacune avec sa validité), la clé sélectionnée,
 * les destinataires, l'état « Actif », l'appairage X25519, etc.
 *
 * Port de Shared/BrocolisKeyStore.swift. iOS utilise l'App Group + UserDefaults ;
 * ici un unique fichier SharedPreferences nommé comme l'App Group. Les clés ne
 * quittent jamais l'appareil.
 *
 * Les SECRETS (`keys_json` : les clés nommées ; `x25519_private_b64` : la clé
 * privée d'appairage) sont chiffrés au repos par une clé AES-256-GCM non
 * exportable de l'Android Keystore (voir `SecretsAtRest`), et le fichier est
 * exclu des sauvegardes et des transferts d'appareil (AndroidManifest.xml,
 * res/xml/data_extraction_rules.xml). Les autres réglages restent en clair.
 *
 * `init(context)` doit être appelé une fois au démarrage (BrocolisApplication).
 */
object BrocolisKeyStore {

    const val APP_GROUP = "group.rs.brocolis.messagerie"
    /** URL du serveur de rendez-vous / messagerie (instance Heroku du projet). */
    const val SERVER_URL = "https://brocolis-serveur-839b43057467.herokuapp.com"

    private const val KEYS_NAME = "keys_json"
    private const val SELECTED_ID = "selected_key_id"
    private const val ACTIVE = "is_active"
    private const val ENCRYPT_WHOLE = "encrypt_whole_always"
    private const val PRIVATE_KEY = "x25519_private_b64"
    private const val FINGERPRINT = "pairing_fingerprint"
    private const val RECIPIENT_IDS = "recipient_key_ids"
    private const val KEY_PHONES = "key_phones_json"
    private const val PAIRING_CODE = "pairing_code"
    private const val PAIRING_PEER_ID = "pairing_peer_id"
    private const val PAIRING_PEER_IDS = "pairing_peer_ids"

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        prefs = context.applicationContext.getSharedPreferences(APP_GROUP, Context.MODE_PRIVATE)
        // Anciennes installations : les secrets encore en clair sont rechiffrés.
        SecretsAtRest.migrateAll(prefs, listOf(KEYS_NAME, PRIVATE_KEY))
    }

    // MARK: Liste de clés

    private fun loadKeys(): List<NamedKey> {
        val data = SecretsAtRest.read(prefs, KEYS_NAME) ?: return emptyList()
        return try { json.decodeFromString(data) } catch (_: Exception) { emptyList() }
    }

    private fun saveKeys(keys: List<NamedKey>) {
        SecretsAtRest.write(prefs, KEYS_NAME, json.encodeToString(keys))
    }

    val keys: List<NamedKey> get() = loadKeys()

    var selectedKeyId: String?
        get() = prefs.getString(SELECTED_ID, null)
        set(value) {
            prefs.edit().apply { if (value == null) remove(SELECTED_ID) else putString(SELECTED_ID, value) }.apply()
        }

    val selectedKey: NamedKey?
        get() {
            val ks = loadKeys()
            selectedKeyId?.let { id -> ks.firstOrNull { it.id == id }?.let { return it } }
            return ks.firstOrNull()
        }

    fun selectKey(id: String) { selectedKeyId = id }

    fun addKey(name: String, base64: String, ttlSeconds: Int = 0): String {
        val ks = loadKeys().toMutableList()
        val trimmedName = name.trim()
        val ttl = maxOf(0, ttlSeconds)
        val defaultName = loc("Clé ${ks.size + 1}", "Key ${ks.size + 1}", "Clave ${ks.size + 1}")
        val key = NamedKey(
            id = UUID.randomUUID().toString(),
            name = if (trimmedName.isEmpty()) defaultName else trimmedName,
            base64 = base64.trim(),
            ttlSeconds = ttl,
            expiresAtMillis = computeExpiry(ttl, System.currentTimeMillis())
        )
        ks.add(key)
        saveKeys(ks)
        selectKey(key.id)
        return key.id
    }

    fun renameKey(id: String, name: String) {
        val ks = loadKeys().toMutableList()
        val i = ks.indexOfFirst { it.id == id }
        if (i >= 0) {
            val trimmed = name.trim()
            if (trimmed.isNotEmpty()) ks[i].name = trimmed
            saveKeys(ks)
        }
    }

    fun deleteKey(id: String) {
        val ks = loadKeys().toMutableList()
        ks.removeAll { it.id == id }
        saveKeys(ks)
        // Ses sessions PSK partent avec elle (hors du fil principal).
        Thread { BrocolisV3.forget(id) }.start()
        setKeyPhone(null, id)
        if (selectedKeyId == id) {
            val first = ks.firstOrNull()
            if (first != null) selectKey(first.id) else {
                selectedKeyId = null
                pairingFingerprint = null
                setActive(false)
            }
        }
    }

    // MARK: v3 (docs/SECURITE.md §8.4, §8.5)

    /**
     * Le contact v3 d'une clé appairée : le paquet du correspondant (ou `null` :
     * un ancien client) et « à deux » / « en groupe » ; `caps` : sa capacité v4
     * signée (§9.6), gardée avec le paquet.
     */
    fun setV3Contact(keyId: String, bundle: String?, duo: Boolean, caps: String? = null) = updateKey(keyId) { k ->
        k.v3Bundle = bundle
        k.v3Caps = if (bundle == null) null else caps
        k.v3SinceSeconds = if (bundle == null) null else System.currentTimeMillis() / 1000
        k.duo = duo
    }

    /**
     * Le contact appairé (à deux) de ce nom, s'il y en a un : un nouvel
     * appairage sous le même nom est un ré-appairage (§9.8).
     */
    fun pairedByName(name: String): NamedKey? =
        loadKeys().firstOrNull { it.duo == true && it.name.trim().equals(name.trim(), ignoreCase = true) }

    /**
     * Ré-appaire un contact existant (nouvelle clé, nouveau paquet) ; `true`
     * si son identité a changé (ou l'avait déjà fait sans confirmation) :
     * l'envoi vers lui est bloqué (§9.8). Ses sessions PSK partent avec
     * l'ancienne clé.
     */
    fun repairPaired(keyId: String, keyBase64: String, bundle: String?, duo: Boolean, caps: String?): Boolean {
        val ks = loadKeys().toMutableList()
        val i = ks.indexOfFirst { it.id == keyId }
        if (i < 0) return false
        val (k, changed) = BrocolisIdentity.repaired(ks[i], keyBase64, bundle, duo, caps, System.currentTimeMillis() / 1000)
        ks[i] = k
        saveKeys(ks)
        Thread { BrocolisV3.forget(keyId) }.start()
        return changed
    }

    /** « J'ai comparé l'empreinte » : l'alerte tombe, l'envoi reprend (§9.8). */
    fun confirmIdentity(keyId: String) {
        val ks = loadKeys().toMutableList()
        val i = ks.indexOfFirst { it.id == keyId }
        if (i < 0) return
        ks[i] = BrocolisIdentity.confirmed(ks[i])
        saveKeys(ks)
    }

    /**
     * La clé devient une clé de groupe (une deuxième personne l'a reçue) : plus
     * jamais de v3 avec elle.
     */
    fun markGroup(keyId: String) = updateKey(keyId) { it.duo = false }

    /** « À deux, double cliquet » (PSK) pour une clé sans appairage v3. */
    fun setPsk(on: Boolean, keyId: String) = updateKey(keyId) { it.psk = if (on) true else null }

    private fun updateKey(id: String, change: (NamedKey) -> Unit) {
        val ks = loadKeys().toMutableList()
        val i = ks.indexOfFirst { it.id == id }
        if (i < 0) return
        change(ks[i])
        saveKeys(ks)
    }

    // MARK: Numéro rattaché à une clé

    private fun loadPhones(): MutableMap<String, String> {
        val data = prefs.getString(KEY_PHONES, null) ?: return mutableMapOf()
        return try { json.decodeFromString<Map<String, String>>(data).toMutableMap() }
        catch (_: Exception) { mutableMapOf() }
    }

    private fun savePhones(dict: Map<String, String>) {
        prefs.edit().putString(KEY_PHONES, json.encodeToString(dict)).apply()
    }

    fun keyPhone(id: String): String? = loadPhones()[id]

    fun setKeyPhone(phone: String?, forKeyId: String) {
        val dict = loadPhones()
        if (!phone.isNullOrEmpty()) dict[forKeyId] = phone else dict.remove(forKeyId)
        savePhones(dict)
    }

    // MARK: Accès clé

    val hasKey: Boolean get() = keys.isNotEmpty()

    /** Octets de la clé sélectionnée (pour chiffrer), ou null. */
    fun selectedKeyBytes(): ByteArray? =
        selectedKey?.base64?.let { try { BrocolisCrypto.keyBytes(it) } catch (_: Exception) { null } }

    /** Toutes les clés (pour déchiffrer : on les essaie toutes). */
    fun allKeyBytes(): List<ByteArray> =
        keys.mapNotNull { try { BrocolisCrypto.keyBytes(it.base64) } catch (_: Exception) { null } }

    // MARK: Destinataires multiples

    var recipientKeyIds: List<String>
        get() {
            val data = prefs.getString(RECIPIENT_IDS, null) ?: return emptyList()
            val arr = try { json.decodeFromString<List<String>>(data) } catch (_: Exception) { emptyList() }
            val existing = keys.map { it.id }.toSet()
            return arr.filter { existing.contains(it) }
        }
        set(ids) {
            prefs.edit().apply {
                if (ids.isEmpty()) remove(RECIPIENT_IDS) else putString(RECIPIENT_IDS, json.encodeToString(ids))
            }.apply()
        }

    fun encryptionNamedKeys(): List<NamedKey> {
        val ids = recipientKeyIds
        val chosen: List<NamedKey> = if (ids.isEmpty()) {
            selectedKey?.let { listOf(it) } ?: emptyList()
        } else {
            val byId = keys.associateBy { it.id }
            ids.mapNotNull { byId[it] }
        }
        val now = System.currentTimeMillis()
        return chosen.filter { !isExpired(it.expiresAtMillis, now) }
    }

    fun encryptionKeyBytes(): List<ByteArray> =
        encryptionNamedKeys().mapNotNull { try { BrocolisCrypto.keyBytes(it.base64) } catch (_: Exception) { null } }

    val hasUsableEncryptionKey: Boolean get() = encryptionNamedKeys().isNotEmpty()

    // MARK: État « Actif »

    val isActive: Boolean get() = prefs.getBoolean(ACTIVE, false) && hasKey

    fun setActive(value: Boolean) { prefs.edit().putBoolean(ACTIVE, value).apply() }

    // MARK: « Tout chiffrer » (activé par défaut)

    var encryptWholeAlways: Boolean
        get() = if (!prefs.contains(ENCRYPT_WHOLE)) true else prefs.getBoolean(ENCRYPT_WHOLE, true)
        set(value) { prefs.edit().putBoolean(ENCRYPT_WHOLE, value).apply() }

    // MARK: Appairage X25519

    var privateKeyBase64: String?
        get() = SecretsAtRest.read(prefs, PRIVATE_KEY)
        set(value) { SecretsAtRest.write(prefs, PRIVATE_KEY, value) }

    var pairingFingerprint: String?
        get() = prefs.getString(FINGERPRINT, null)
        set(value) { prefs.edit().apply { if (value == null) remove(FINGERPRINT) else putString(FINGERPRINT, value) }.apply() }

    val pairingCode: String? get() = prefs.getString(PAIRING_CODE, null)
    val pairingPeerId: String? get() = prefs.getString(PAIRING_PEER_ID, null)

    fun setPairingIdentity(code: String, peerId: String) {
        prefs.edit().putString(PAIRING_CODE, code).putString(PAIRING_PEER_ID, peerId).apply()
    }

    var pairingPeerIds: List<String>
        get() {
            val data = prefs.getString(PAIRING_PEER_IDS, null) ?: return emptyList()
            return try { json.decodeFromString(data) } catch (_: Exception) { emptyList() }
        }
        set(ids) {
            prefs.edit().apply {
                if (ids.isEmpty()) remove(PAIRING_PEER_IDS) else putString(PAIRING_PEER_IDS, json.encodeToString(ids))
            }.apply()
        }

    // MARK: Validité / expiration — PAR CLÉ

    fun setKeyTTL(seconds: Int, forKeyId: String) {
        val ks = loadKeys().toMutableList()
        val i = ks.indexOfFirst { it.id == forKeyId }
        if (i >= 0) {
            val ttl = maxOf(0, seconds)
            ks[i].ttlSeconds = ttl
            ks[i].expiresAtMillis = computeExpiry(ttl, System.currentTimeMillis())
            saveKeys(ks)
        }
    }

    fun reapplyExpiry(forKeyId: String) {
        val ks = loadKeys().toMutableList()
        val i = ks.indexOfFirst { it.id == forKeyId }
        if (i >= 0) {
            ks[i].expiresAtMillis = computeExpiry(ks[i].ttlSeconds, System.currentTimeMillis())
            saveKeys(ks)
        }
    }

    /** Supprime TOUTES les clés expirées. Renvoie true si au moins une l'a été. */
    fun purgeExpiredKey(): Boolean {
        val ks = loadKeys()
        val now = System.currentTimeMillis()
        val kept = ks.filter { !isExpired(it.expiresAtMillis, now) }
        if (kept.size == ks.size) return false
        saveKeys(kept)
        val sel = selectedKeyId
        if (sel != null && kept.none { it.id == sel }) {
            val first = kept.firstOrNull()
            if (first != null) selectKey(first.id) else selectedKeyId = null
        }
        if (kept.isEmpty()) setActive(false)
        return true
    }

    // MARK: Helpers purs

    fun computeExpiry(ttlSeconds: Int, fromMillis: Long): Long? =
        if (ttlSeconds > 0) fromMillis + ttlSeconds * 1000L else null

    fun isExpired(expiresAtMillis: Long?, now: Long): Boolean {
        val e = expiresAtMillis ?: return false
        return now >= e
    }

    fun notificationLead(ttlSeconds: Int): Long? =
        if (ttlSeconds > 0) minOf(3600L, ttlSeconds / 2L) else null
}
