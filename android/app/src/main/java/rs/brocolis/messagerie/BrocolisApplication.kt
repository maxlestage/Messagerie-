package rs.brocolis.messagerie

import android.app.Application
import rs.brocolis.messagerie.crypto.BrocolisV3
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.BrocolisV3Store
import rs.brocolis.messagerie.store.KeystoreVault
import rs.brocolis.messagerie.store.MessagingPrefs
import java.io.File

/**
 * Initialise les stores (équivalent de l'App Group iOS) une fois pour toute
 * l'app, puis purge les clés expirées au démarrage — comme `AppDelegate` iOS.
 *
 * Le v3 (docs/SECURITE.md §8.1) vit dans `no_backup/BrocolisV3/` (jamais
 * sauvegardé), ses secrets chiffrés par la clé du Keystore ; l'appareil v3 est
 * créé à la première transaction.
 */
class BrocolisApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        BrocolisKeyStore.init(this)
        MessagingPrefs.init(this)
        val v3 = File(noBackupFilesDir, "BrocolisV3")
        BrocolisV3.store = BrocolisV3Store(v3, KeystoreVault(v3))
        BrocolisKeyStore.purgeExpiredKey()
    }
}
