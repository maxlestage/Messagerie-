@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import rs.brocolis.messagerie.crypto.BrocolisKeyAgreement
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.net.PairingClient
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.MessagingPrefs

/**
 * Appairage automatique X25519 : les deux correspondants saisissent le MÊME code
 * (canal convenu de vive voix / SMS) ; chacun publie sa clé publique, récupère
 * celle de l'autre, et dérive la MÊME clé AES-256. Comparez l'empreinte pour
 * détecter un intercepteur. Port simplifié de PairingView.swift.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(onBack: () -> Unit) {
    var code by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var fingerprint by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun pair() {
        val trimmedCode = code.trim()
        if (trimmedCode.isEmpty()) { message = loc("Entre un code.", "Enter a code.", "Introduce un código."); return }
        busy = true; message = null; fingerprint = null
        scope.launch {
            try {
                val client = PairingClient(BrocolisKeyStore.SERVER_URL)
                val priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
                val myPub = BrocolisKeyAgreement.publicKeyBase64(priv)
                val peerId = MessagingPrefs.deviceId

                // 1) Publie ma clé publique.
                var peers = client.publish(trimmedCode, peerId, myPub)
                // 2) Attend la clé publique de l'autre (quelques tentatives).
                var attempts = 0
                var peer = peers.firstOrNull { it.peerId != peerId }
                while (peer == null && attempts < 10) {
                    delay(1500)
                    peers = client.fetch(trimmedCode, peerId)
                    peer = peers.firstOrNull { it.peerId != peerId }
                    attempts++
                }
                if (peer == null) {
                    message = loc("En attente du correspondant… réessaie.", "Waiting for the contact… try again.", "Esperando al contacto… reinténtalo.")
                    busy = false; return@launch
                }
                // 3) Dérive la clé partagée + l'empreinte.
                val derived = BrocolisKeyAgreement.derive(priv, peer.pub)
                val contactName = name.trim().ifEmpty { loc("Correspondant", "Contact", "Contacto") }
                BrocolisKeyStore.addKey(contactName, derived.symmetricKeyBase64)
                BrocolisKeyStore.setActive(true)
                BrocolisKeyStore.pairingFingerprint = derived.fingerprint
                BrocolisKeyStore.setPairingIdentity(trimmedCode, peerId)
                val newPeers = (BrocolisKeyStore.pairingPeerIds + peer.peerId).distinct()
                BrocolisKeyStore.pairingPeerIds = newPeers
                fingerprint = derived.fingerprint
                message = loc("Appairé ✅ Vérifie l'empreinte de vive voix.", "Paired ✅ Verify the fingerprint out loud.", "Emparejado ✅ Verifica la huella de viva voz.")
            } catch (e: Exception) {
                message = e.message ?: loc("Échec de l'appairage.", "Pairing failed.", "Error de emparejamiento.")
            } finally {
                busy = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(loc("Appairage", "Pairing", "Emparejamiento")) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) } }
            )
        }
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                loc(
                    "Convenez d'un code commun (par SMS, de vive voix…). Saisissez-le tous les deux ici : la clé se crée sans jamais transiter en clair.",
                    "Agree on a shared code (by text, out loud…). Both enter it here: the key is created without ever being sent in the clear.",
                    "Acordad un código común (por SMS, de viva voz…). Introducidlo ambos aquí: la clave se crea sin transmitirse nunca en claro."
                ),
                style = MaterialTheme.typography.bodyMedium
            )
            OutlinedTextField(
                value = code, onValueChange = { code = it }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(loc("Code commun", "Shared code", "Código común")) }
            )
            OutlinedTextField(
                value = name, onValueChange = { name = it }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                label = { Text(loc("Nom du correspondant", "Contact name", "Nombre del contacto")) }
            )
            Button(onClick = { pair() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                if (busy) { CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp); Spacer(Modifier.size(8.dp)) }
                Text(loc("Appairer", "Pair", "Emparejar"))
            }
            fingerprint?.let {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(loc("Empreinte à comparer", "Fingerprint to compare", "Huella a comparar"), style = MaterialTheme.typography.labelMedium)
                        Text(it, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)
                    }
                }
            }
            message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
        }
    }
}
