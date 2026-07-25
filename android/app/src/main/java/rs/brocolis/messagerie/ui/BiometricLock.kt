package rs.brocolis.messagerie.ui

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.MessagingPrefs

/**
 * Porte de verrouillage : exige la biométrie / le code de l'appareil avant
 * d'afficher `content`, si le verrou est activé. Équivalent Android de LockGate
 * (LocalAuthentication) sur iOS.
 */
@Composable
fun LockGate(content: @Composable () -> Unit) {
    if (!MessagingPrefs.lockEnabled) { content(); return }

    val context = LocalContext.current
    var unlocked by remember { mutableStateOf(false) }
    var canAuth by remember { mutableStateOf(true) }

    fun prompt() {
        val activity = context as? FragmentActivity ?: run { unlocked = true; return }
        val available = BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        if (available != BiometricManager.BIOMETRIC_SUCCESS) { unlocked = true; return }

        val executor = ContextCompat.getMainExecutor(context)
        val prompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { unlocked = true }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) { canAuth = false }
        })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(loc("Déverrouiller Brocolis", "Unlock Brocolis", "Desbloquear Brocolis"))
            .setSubtitle(loc("Authentifie-toi pour voir tes messages.", "Authenticate to see your messages.", "Autentícate para ver tus mensajes."))
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()
        prompt.authenticate(info)
    }

    LaunchedEffect(Unit) { prompt() }

    if (unlocked) {
        content()
    } else {
        Column(
            Modifier.fillMaxSize().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(Icons.Default.Lock, null)
            Text(loc("Messages verrouillés", "Messages locked", "Mensajes bloqueados"))
            if (!canAuth) {
                Button(onClick = { canAuth = true; prompt() }, modifier = Modifier.padding(top = 12.dp)) {
                    Text(loc("Réessayer", "Retry", "Reintentar"))
                }
            }
            androidx.compose.foundation.layout.Spacer(Modifier.size(4.dp))
        }
    }
}
