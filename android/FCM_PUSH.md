# Notifications push Android (FCM) — guide prêt à appliquer

Le push nécessite un projet **Firebase** (et son `google-services.json`), que je ne
peux pas créer à ta place. Voici exactement quoi ajouter quand tu l'auras — le
reste de l'app est déjà prêt (identité d'appareil stable, serveur commun).

## 1. Firebase console
1. Crée un projet Firebase, ajoute une app Android avec l'`applicationId`
   **`rs.brocolis.messagerie`**.
2. Télécharge **`google-services.json`** et place-le dans `android/app/`.

## 2. Gradle
`android/build.gradle.kts` (racine) — ajoute le plugin :
```kotlin
plugins {
    // …existants…
    id("com.google.gms.google-services") version "4.4.2" apply false
}
```
`android/app/build.gradle.kts` :
```kotlin
plugins {
    // …existants…
    id("com.google.gms.google-services")
}
dependencies {
    implementation(platform("com.google.firebase:firebase-bom:33.1.2"))
    implementation("com.google.firebase:firebase-messaging")
}
```

## 3. Service de réception
`android/app/src/main/java/rs/brocolis/messagerie/push/BrocolisFcmService.kt` :
```kotlin
package rs.brocolis.messagerie.push

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import rs.brocolis.messagerie.R
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.BrocolisKeyStore

class BrocolisFcmService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        // À enregistrer côté serveur, sous (pairingCode, pairingPeerId) via
        // un futur endpoint, comme la Live Activity iOS.
        BrocolisKeyStore.init(applicationContext)
        // TODO: PairingClient.registerPushToken(...)
    }

    override fun onMessageReceived(msg: RemoteMessage) {
        // La charge push ne contient JAMAIS de clair : juste un signal
        // « nouveau message », l'app va chercher et déchiffre localement.
        val channelId = "brocolis_messages"
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(channelId, "Messages", NotificationManager.IMPORTANCE_HIGH)
        )
        val notif = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.brocolis_logo)
            .setContentTitle("Brocolis 🥦")
            .setContentText(loc("Nouveau message chiffré", "New encrypted message", "Nuevo mensaje cifrado"))
            .setAutoCancel(true)
            .build()
        nm.notify(1, notif)
    }
}
```

## 4. Manifeste
Dans `<application>` de `AndroidManifest.xml` :
```xml
<service
    android:name=".push.BrocolisFcmService"
    android:exported="false">
    <intent-filter>
        <action android:name="com.google.firebase.MESSAGING_EVENT" />
    </intent-filter>
</service>
```
Et la permission (Android 13+) :
```xml
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
```
(pense à demander `POST_NOTIFICATIONS` au runtime sur Android 13+).

## 5. Côté serveur
Ajouter un endpoint pour enregistrer le token FCM (sous `code`/`peerId`, comme
`/push/live-activity/token`) et un envoi via l'API FCM HTTP v1 lors d'un nouveau
message. Le principe reste : **le push ne transporte aucun clair**, seulement un
réveil ; l'app récupère le jeton chiffré et le déchiffre localement.

> Rien à faire côté cryptographie : l'interop avec iOS/serveur est déjà garantie.
