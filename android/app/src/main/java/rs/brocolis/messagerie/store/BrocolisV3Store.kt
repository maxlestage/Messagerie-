package rs.brocolis.messagerie.store

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import rs.brocolis.messagerie.crypto.BrocolisV3Engine
import rs.brocolis.messagerie.crypto.BrocolisV3Stored
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

/*
 * Où vit le v3 sur Android, et comment plusieurs fils (et processus) s'en
 * servent sans jamais réutiliser une clé de message (docs/SECURITE.md §8.1,
 * §8.3) :
 *
 * - l'appareil v3 (`Device`, JSON de la référence) dans `appareil.ks`, chiffré
 *   par la clé AES-256-GCM non exportable de l'Android Keystore (StrongBox si
 *   l'appareil en a une : `SecretsAtRest`) — sans repli en clair : Keystore
 *   indisponible = v3 indisponible pour cette opération (l'envoi se fait alors
 *   en v1/v2) ;
 * - les sessions et les messages ouverts dans `etat.bin` :
 *   nonce (12) ‖ AES-256-GCM(JSON) ‖ tag (16), données associées
 *   `brocolis-v3-etat-v1`, sous une clé de 32 octets elle-même gardée par le
 *   Keystore (`cle-etat.ks`) ; écrit d'un bloc (fichier temporaire renommé) ;
 * - le tout dans `no_backup/BrocolisV3/` : jamais sauvegardé ni transféré
 *   (un état de cliquet restauré en retard réutiliserait des clés de message)
 *   — et les règles de sauvegarde excluent de toute façon tout le reste ;
 * - chaque opération est une TRANSACTION : verrou du processus (deux fils)
 *   puis `FileChannel.lock()` sur `verrou` (deux processus), lire → chiffrer /
 *   déchiffrer → écrire l'appareil, puis l'état → lâcher → rendre le jeton.
 *   Rien d'asynchrone dedans (le verrou dure quelques millisecondes).
 */

/** Le résultat d'une lecture au coffre. */
sealed class BrocolisVaultRead {
    class Found(val data: ByteArray) : BrocolisVaultRead()
    /** Rien d'écrit (ou plus rien de lisible : clé Keystore perdue, fichier abîmé). */
    object NotFound : BrocolisVaultRead()
    /** Le coffre ne répond pas : le v3 est indisponible pour cette opération. */
    object Failed : BrocolisVaultRead()
}

/** Où sont gardés l'appareil et la clé de l'état. */
interface BrocolisSecretVault {
    fun read(name: String): BrocolisVaultRead
    fun write(name: String, data: ByteArray): Boolean
}

/** Écrit un fichier d'un bloc : fichier temporaire, `fsync`, renommage. */
internal fun writeAtomically(file: File, data: ByteArray) {
    val tmp = File(file.parentFile, "${file.name}.${System.nanoTime()}.${Thread.currentThread().id}.tmp")
    try {
        FileOutputStream(tmp).use { out ->
            out.write(data)
            out.fd.sync()
        }
        Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    } finally {
        tmp.delete()
    }
}

/**
 * Le coffre de l'app : chaque entrée est un fichier `<nom>.ks` chiffré par la
 * clé du Keystore (le nom en données associées : `SecretsAtRest.sealBytes`).
 */
class KeystoreVault(private val directory: File) : BrocolisSecretVault {
    private fun file(name: String) = File(directory, "$name.ks")

    override fun read(name: String): BrocolisVaultRead {
        val f = file(name)
        if (!f.exists()) return BrocolisVaultRead.NotFound
        val sealed = try { f.readBytes() } catch (_: Exception) { return BrocolisVaultRead.Failed }
        return when (val r = SecretsAtRest.openBytes(sealed, name)) {
            is SecretsAtRest.Opened.Ok -> BrocolisVaultRead.Found(r.data)
            // Clé Keystore perdue ou valeur abîmée : illisible pour toujours.
            SecretsAtRest.Opened.Unreadable -> BrocolisVaultRead.NotFound
            SecretsAtRest.Opened.Unavailable -> BrocolisVaultRead.Failed
        }
    }

    override fun write(name: String, data: ByteArray): Boolean {
        val sealed = SecretsAtRest.sealBytes(data, name) ?: return false
        return try {
            directory.mkdirs()
            writeAtomically(file(name), sealed)
            true
        } catch (_: Exception) {
            false
        }
    }
}

/**
 * Un coffre EN CLAIR (fichiers), pour les tests JVM et les essais
 * d'interopérabilité seulement : jamais dans l'app.
 */
class PlainFileVault(private val directory: File) : BrocolisSecretVault {
    override fun read(name: String): BrocolisVaultRead {
        val f = File(directory, name)
        if (!f.exists()) return BrocolisVaultRead.NotFound
        return try { BrocolisVaultRead.Found(f.readBytes()) } catch (_: Exception) { BrocolisVaultRead.Failed }
    }

    override fun write(name: String, data: ByteArray): Boolean = try {
        directory.mkdirs()
        writeAtomically(File(directory, name), data)
        true
    } catch (_: Exception) {
        false
    }
}

class BrocolisV3StoreException(message: String) : Exception(message)

/**
 * L'appareil et l'état v3, sous verrou entre fils et entre processus.
 *
 * `locking = false` et `pauseMillis` ne servent qu'aux tests (le contre-essai
 * sans verrou, et une fenêtre de course élargie).
 */
class BrocolisV3Store(
    val directory: File,
    val vault: BrocolisSecretVault,
    internal val locking: Boolean = true,
    internal val pauseMillis: Long = 0,
) {
    companion object {
        const val DEVICE_ACCOUNT = "v3_device"
        const val STATE_KEY_ACCOUNT = "v3_state_key"
        val STATE_AAD: ByteArray = "brocolis-v3-etat-v1".toByteArray(Charsets.UTF_8)
        private const val NONCE = 12
        private const val TAG_BITS = 128

        /** Un verrou par fichier de verrou, pour tous les magasins du processus. */
        private val processLocks = ConcurrentHashMap<String, ReentrantLock>()
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    }

    val stateFile: File get() = File(directory, "etat.bin")
    val lockFile: File get() = File(directory, "verrou")

    /**
     * Une transaction (§8.3). Si `body` lève, rien n'est écrit. Si une
     * écriture échoue, la transaction lève : un jeton n'est jamais rendu sans
     * que l'état qui l'a produit soit écrit.
     */
    fun <T> transaction(now: Long, body: (BrocolisV3Engine) -> T): T {
        if (!directory.isDirectory && !directory.mkdirs()) throw BrocolisV3StoreException("dossier")
        if (!locking) return locked(now, body)
        val lock = processLocks.getOrPut(lockFile.canonicalPath) { ReentrantLock() }
        // Une transaction dans une transaction bloquerait sur le verrou de fichier.
        check(!lock.isHeldByCurrentThread) { "transaction v3 imbriquée" }
        return lock.withLock {
            RandomAccessFile(lockFile, "rw").use { raf ->
                raf.channel.lock().use { locked(now, body) }
            }
        }
    }

    private fun <T> locked(now: Long, body: (BrocolisV3Engine) -> T): T {
        val key = stateKey()
        try {
            val deviceJson = when (val r = vault.read(DEVICE_ACCOUNT)) {
                is BrocolisVaultRead.Found -> String(r.data, Charsets.UTF_8)
                BrocolisVaultRead.NotFound -> null
                BrocolisVaultRead.Failed -> throw BrocolisV3StoreException("coffre indisponible")
            }
            val engine = BrocolisV3Engine(deviceJson, readState(key), now)
            val out = body(engine)
            if (pauseMillis > 0) Thread.sleep(pauseMillis)
            // L'appareil d'abord : sa mémoire des premiers messages n'est jamais
            // en retard sur les sessions (§8.3).
            if (engine.deviceDirty && !vault.write(DEVICE_ACCOUNT, engine.device.toJson().toByteArray(Charsets.UTF_8))) {
                throw BrocolisV3StoreException("appareil non écrit")
            }
            if (engine.stateDirty) writeState(engine.stored, key)
            return out
        } finally {
            key.fill(0)
        }
    }

    /**
     * La clé de l'état : lue au coffre, ou créée (sous le verrou : deux
     * processus n'en créent jamais deux).
     */
    private fun stateKey(): ByteArray {
        when (val r = vault.read(STATE_KEY_ACCOUNT)) {
            is BrocolisVaultRead.Found -> if (r.data.size == 32) return r.data
            BrocolisVaultRead.NotFound -> Unit
            BrocolisVaultRead.Failed -> throw BrocolisV3StoreException("coffre indisponible")
        }
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        if (!vault.write(STATE_KEY_ACCOUNT, key)) throw BrocolisV3StoreException("clé de l'état non écrite")
        // Une clé neuve n'ouvre pas l'ancien fichier : il repart de zéro.
        stateFile.delete()
        return key
    }

    /** L'état, ou `null` (absent, illisible : il repart de zéro, les sessions se rouvrent). */
    private fun readState(key: ByteArray): BrocolisV3Stored? {
        val sealed = try { stateFile.takeIf { it.exists() }?.readBytes() } catch (_: Exception) { null } ?: return null
        if (sealed.size < NONCE + TAG_BITS / 8) return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, sealed, 0, NONCE))
            cipher.updateAAD(STATE_AAD)
            val plain = cipher.doFinal(sealed, NONCE, sealed.size - NONCE)
            json.decodeFromString<BrocolisV3Stored>(String(plain, Charsets.UTF_8))
        } catch (_: Exception) {
            null // clé changée, fichier abîmé ou d'une autre forme
        }
    }

    private fun writeState(stored: BrocolisV3Stored, key: ByteArray) {
        val sealed = try {
            val nonce = ByteArray(NONCE).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(STATE_AAD)
            nonce + cipher.doFinal(json.encodeToString(stored).toByteArray(Charsets.UTF_8))
        } catch (e: Exception) {
            throw BrocolisV3StoreException("état non chiffré")
        }
        try {
            writeAtomically(stateFile, sealed)
        } catch (e: Exception) {
            throw BrocolisV3StoreException("état non écrit")
        }
    }
}
