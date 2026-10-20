package rs.brocolis.messagerie.store

import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Les SECRETS du trousseau (clés Brocolis, clé privée X25519) chiffrés au repos
 * par une clé AES-256-GCM de l'**Android Keystore** :
 *
 * - générée DANS `AndroidKeyStore`, non exportable : ses octets ne sont jamais
 *   accessibles à l'app ni au système de fichiers (puce StrongBox si
 *   l'appareil en a une, sinon le TEE — matériel sur presque tous les
 *   téléphones Android 8+) ;
 * - `setRandomizedEncryptionRequired(true)` : c'est le Keystore qui tire un
 *   nonce neuf à chaque chiffrement, impossible d'en réutiliser un ;
 * - la valeur stockée est `ks1:` + base64(nonce (12) ‖ chiffré ‖ tag (16)),
 *   avec le NOM de l'entrée en données associées (on ne peut pas échanger deux
 *   entrées chiffrées entre elles).
 *
 * Chaque secret vit sous un nom distinct de l'ancien nom en clair
 * (`keys_json` → `keys_json.ks`) : la migration écrit d'abord la version
 * chiffrée, et n'efface l'ancienne qu'une fois cette écriture réussie.
 *
 * REPLI : si le Keystore est indisponible (tests JVM, ROM cassée), on garde
 * l'ancien comportement — valeur en clair dans les SharedPreferences privées de
 * l'app — plutôt que de perdre les clés de l'utilisateur. C'est explicite et
 * journalisé ; ce cas ne se produit pas sur un appareil Android normal.
 */
internal object SecretsAtRest {

    private const val TAG = "BrocolisSecrets"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "rs.brocolis.messagerie.secrets.v1"
    private const val SEALED_PREFIX = "ks1:"
    private const val SEALED_SUFFIX = ".ks"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val NONCE_LENGTH = 12
    private const val TAG_BITS = 128

    /**
     * Dernière valeur déchiffrée par entrée (chiffré → clair) : le trousseau est
     * relu très souvent par l'interface, on évite un aller-retour Keystore à
     * chaque fois. Ne contient que ce qui est déjà en mémoire pendant l'usage.
     */
    private val cache = HashMap<String, Pair<String, String>>()

    // MARK: Lecture / écriture

    /** Lit le secret `name` (chiffré, ou ancien en clair qu'on migre au passage). */
    @Synchronized
    fun read(prefs: SharedPreferences, name: String): String? {
        prefs.getString(name + SEALED_SUFFIX, null)?.let { sealed ->
            cache[name]?.let { (c, plain) -> if (c == sealed) return plain }
            val plain = open(sealed, name)
            if (plain == null) {
                // Clé Keystore perdue (réinitialisation, restauration sur un autre
                // appareil…) : la valeur est illisible. On NE l'efface PAS ici.
                Log.w(TAG, "Secret « $name » illisible (clé Keystore absente ou changée).")
                return null
            }
            cache[name] = sealed to plain
            return plain
        }
        val legacy = prefs.getString(name, null) ?: return null
        migrate(prefs, name, legacy)
        return legacy
    }

    /** Écrit (ou efface, si null) le secret `name`. */
    @Synchronized
    fun write(prefs: SharedPreferences, name: String, value: String?) {
        if (value == null) {
            cache.remove(name)
            prefs.edit().remove(name + SEALED_SUFFIX).remove(name).apply()
            return
        }
        val sealed = seal(value, name)
        if (sealed != null) {
            cache[name] = sealed to value
            // L'ancienne valeur en clair (s'il en restait une) disparaît avec.
            prefs.edit().putString(name + SEALED_SUFFIX, sealed).remove(name).apply()
        } else {
            // REPLI sans Keystore : en clair, comme avant (voir l'en-tête).
            Log.w(TAG, "Keystore indisponible : « $name » est gardé sans chiffrement.")
            cache.remove(name)
            prefs.edit().putString(name, value).remove(name + SEALED_SUFFIX).apply()
        }
    }

    /** Migre tous les secrets encore en clair (appelé au démarrage). */
    @Synchronized
    fun migrateAll(prefs: SharedPreferences, names: List<String>) {
        for (name in names) {
            if (prefs.contains(name + SEALED_SUFFIX)) continue
            val legacy = prefs.getString(name, null) ?: continue
            migrate(prefs, name, legacy)
        }
    }

    /**
     * Rechiffre une valeur en clair. La version chiffrée est d'abord relue et
     * vérifiée, écrite SYNCHRONEMENT (`commit`), et seulement si cette écriture
     * a réussi l'ancienne valeur en clair est effacée.
     */
    private fun migrate(prefs: SharedPreferences, name: String, legacy: String) {
        val sealed = seal(legacy, name) ?: return // Keystore indisponible : on reste en clair.
        if (open(sealed, name) != legacy) return
        if (!prefs.edit().putString(name + SEALED_SUFFIX, sealed).commit()) return
        cache[name] = sealed to legacy
        prefs.edit().remove(name).commit()
    }

    // MARK: Keystore

    private fun seal(plain: String, name: String): String? {
        val key = key() ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key) // nonce tiré par le Keystore
            cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
            val nonce = cipher.iv
            if (nonce == null || nonce.size != NONCE_LENGTH) null
            else SEALED_PREFIX + Base64.getEncoder().encodeToString(nonce + cipher.doFinal(plain.toByteArray(Charsets.UTF_8)))
        } catch (e: Exception) {
            Log.w(TAG, "Chiffrement Keystore impossible : ${e.javaClass.simpleName}")
            null
        }
    }

    private fun open(stored: String, name: String): String? {
        if (!stored.startsWith(SEALED_PREFIX)) return null
        return try {
            val packed = Base64.getDecoder().decode(stored.substring(SEALED_PREFIX.length))
            if (packed.size < NONCE_LENGTH + TAG_BITS / 8) return null
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE, existingKey() ?: return null,
                GCMParameterSpec(TAG_BITS, packed, 0, NONCE_LENGTH)
            )
            cipher.updateAAD(name.toByteArray(Charsets.UTF_8))
            String(cipher.doFinal(packed, NONCE_LENGTH, packed.size - NONCE_LENGTH), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun keyStore(): KeyStore? = try {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    } catch (_: Exception) {
        null // JVM des tests unitaires, ou Keystore hors service.
    }

    private fun existingKey(): SecretKey? = try {
        (keyStore()?.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
    } catch (_: Exception) {
        null
    }

    /**
     * La clé maîtresse : celle du Keystore, créée au premier usage. On la
     * demande d'abord dans la puce StrongBox (Android 9+, si l'appareil en a
     * une), sinon dans le TEE — matérielle dans les deux cas quand le téléphone
     * le permet.
     */
    private fun key(): SecretKey? {
        existingKey()?.let { return it }
        if (keyStore() == null) return null
        val strongBoxFirst = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) listOf(true, false) else listOf(false)
        for (strongBox in strongBoxFirst) {
            try {
                val builder = KeyGenParameterSpec.Builder(
                    KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
                return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                    .apply { init(builder.build()) }
                    .generateKey()
            } catch (e: Exception) {
                // StrongBoxUnavailableException (pas de puce dédiée) : on retente dans le TEE.
                Log.w(TAG, "Création de la clé Keystore (StrongBox=$strongBox) impossible : ${e.javaClass.simpleName}")
            }
        }
        return null
    }
}
