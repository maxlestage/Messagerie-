package rs.brocolis.messagerie

import android.app.Application
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.MessagingPrefs

/**
 * Initialise les stores (équivalent de l'App Group iOS) une fois pour toute
 * l'app, puis purge les clés expirées au démarrage — comme `AppDelegate` iOS.
 */
class BrocolisApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        BrocolisKeyStore.init(this)
        MessagingPrefs.init(this)
        BrocolisKeyStore.purgeExpiredKey()
    }
}
