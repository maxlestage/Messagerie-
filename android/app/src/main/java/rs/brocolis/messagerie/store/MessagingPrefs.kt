package rs.brocolis.messagerie.store

import android.content.Context
import android.content.SharedPreferences
import java.util.UUID

/**
 * Réglages de la messagerie : identité stable de l'appareil (X-User-Id / senderId),
 * URL du serveur, verrou biométrique, effacement à la fermeture, et le « plancher »
 * de confidentialité par conversation. Port de `MessagingPrefs` (MessagingView.swift).
 */
object MessagingPrefs {

    private const val DEVICE_ID = "messaging_device_id"
    private const val SERVER_URL = "messaging_server_url"
    private const val ERASE_ON_CLOSE = "messaging_erase_on_close"
    private const val LOCK_ENABLED = "messaging_lock_enabled"
    private const val FLOOR_PREFIX = "messaging_floor_" // + conversationId

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        // Même fichier que le trousseau (équivalent App Group).
        prefs = context.applicationContext.getSharedPreferences(BrocolisKeyStore.APP_GROUP, Context.MODE_PRIVATE)
    }

    /** Identité stable de CET appareil (attribuée une fois). UUID opaque. */
    val deviceId: String
        get() {
            prefs.getString(DEVICE_ID, null)?.let { if (it.isNotEmpty()) return it }
            val id = UUID.randomUUID().toString()
            prefs.edit().putString(DEVICE_ID, id).apply()
            return id
        }

    var serverURL: String
        get() {
            val saved = prefs.getString(SERVER_URL, "") ?: ""
            return if (saved.isEmpty()) BrocolisKeyStore.SERVER_URL else saved
        }
        set(value) { prefs.edit().putString(SERVER_URL, value.trim()).apply() }

    val isConfigured: Boolean get() = serverURL.isNotEmpty()

    /** Efface l'historique affiché à la fermeture (activé par défaut). */
    var eraseOnClose: Boolean
        get() = if (!prefs.contains(ERASE_ON_CLOSE)) true else prefs.getBoolean(ERASE_ON_CLOSE, true)
        set(value) { prefs.edit().putBoolean(ERASE_ON_CLOSE, value).apply() }

    /** Exige la biométrie / le code de l'appareil pour voir les messages (par défaut). */
    var lockEnabled: Boolean
        get() = if (!prefs.contains(LOCK_ENABLED)) true else prefs.getBoolean(LOCK_ENABLED, true)
        set(value) { prefs.edit().putBoolean(LOCK_ENABLED, value).apply() }

    /** Plancher d'une conversation : plus grand seq déjà effacé. */
    fun floor(conversationId: String): Long =
        prefs.getLong(FLOOR_PREFIX + conversationId, 0L)

    fun setFloor(seq: Long, conversationId: String) {
        prefs.edit().putLong(FLOOR_PREFIX + conversationId, seq).apply()
    }
}
