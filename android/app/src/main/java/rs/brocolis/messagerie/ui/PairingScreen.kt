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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rs.brocolis.messagerie.crypto.BrocolisIdentity
import rs.brocolis.messagerie.crypto.BrocolisKeyAgreement
import rs.brocolis.messagerie.crypto.BrocolisProtection
import rs.brocolis.messagerie.crypto.BrocolisV3
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.net.PairingClient
import rs.brocolis.messagerie.net.PairingFlow
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.MessagingPrefs

/**
 * Appairage automatique X25519 : les deux correspondants saisissent le MÊME code
 * (canal convenu de vive voix / SMS) ; chacun publie sa clé publique, récupère
 * celle de l'autre, et dérive la MÊME clé AES-256. Comparez l'empreinte pour
 * détecter un intercepteur. Port simplifié de PairingView.swift (le mode
 * compatible, toujours à deux).
 *
 * v3 (docs/SECURITE.md §8.4) : chacun publie aussi son paquet de clés ; avec
 * les deux paquets, la clé garde celui du correspondant (session à double
 * cliquet au premier envoi) et l'empreinte couvre les deux identités v3.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PairingScreen(onBack: () -> Unit) {
    var code by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var fingerprint by remember { mutableStateOf<String?>(null) }
    var protection by remember { mutableStateOf<BrocolisProtection?>(null) }
    var identityChanged by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun pair() {
        val trimmedCode = code.trim()
        if (trimmedCode.isEmpty()) { message = loc("Entre un code.", "Enter a code.", "Introduce un código."); return }
        busy = true; message = null; fingerprint = null; protection = null; identityChanged = false
        scope.launch {
            try {
                val client = PairingClient(BrocolisKeyStore.SERVER_URL)
                val (priv, mine) = withContext(Dispatchers.IO) {
                    BrocolisKeyAgreement.loadOrCreatePrivateKey() to BrocolisV3.myBundleAndCaps()
                }
                val (myBundle, myCaps) = mine
                val peerId = MessagingPrefs.deviceId

                // Publie ma clé publique (et mon paquet v3, avec ma capacité v4),
                // attend celle de l'autre.
                val paired = PairingFlow.pairTwo(client, trimmedCode, peerId, priv, myBundle, myCaps = myCaps)
                if (paired == null) {
                    message = loc("En attente du correspondant… réessaie.", "Waiting for the contact… try again.", "Esperando al contacto… reinténtalo.")
                    busy = false; return@launch
                }
                // Range la clé et son contact v3 (§8.4) ; l'empreinte couvre les
                // identités v3 si les deux ont publié un paquet (contexte v4 si les
                // deux ont une capacité v4 valide, §9.7).
                val contactName = name.trim().ifEmpty { loc("Correspondant", "Contact", "Contacto") }
                var changed = false
                val (fp, shown) = withContext(Dispatchers.IO) {
                    val fp = paired.contact.fingerprint(paired.keyBase64, paired.legacyFingerprint)
                    val bundle = if (paired.contact.duo) paired.contact.bundle else null
                    // Un contact déjà appairé sous ce nom : ré-appairage. Une autre
                    // identité que la sienne bloque l'envoi (§9.8).
                    val existing = BrocolisKeyStore.pairedByName(contactName)
                    val keyId: String
                    if (existing != null) {
                        keyId = existing.id
                        changed = BrocolisKeyStore.repairPaired(
                            keyId, paired.keyBase64, bundle, paired.contact.duo, paired.contact.caps,
                        )
                        BrocolisKeyStore.selectKey(keyId)
                    } else {
                        keyId = BrocolisKeyStore.addKey(contactName, paired.keyBase64)
                        BrocolisKeyStore.setV3Contact(keyId, bundle, paired.contact.duo, paired.contact.caps)
                    }
                    BrocolisKeyStore.setActive(true)
                    BrocolisKeyStore.pairingFingerprint = fp
                    BrocolisKeyStore.setPairingIdentity(trimmedCode, peerId)
                    BrocolisKeyStore.pairingPeerIds = (BrocolisKeyStore.pairingPeerIds + paired.peer.peerId).distinct()
                    val shown = BrocolisKeyStore.keys.firstOrNull { it.id == keyId }
                        ?.let { BrocolisV3.protection(it) } ?: BrocolisProtection.LEGACY
                    fp to shown
                }
                fingerprint = fp
                protection = shown
                identityChanged = changed
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
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) } },
                colors = rs.brocolis.messagerie.ui.theme.brocolisTopBarColors()
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
                        protection?.let { p -> Text(p.label, style = MaterialTheme.typography.bodySmall) }
                        if (identityChanged) {
                            Text(BrocolisIdentity.warning, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
            message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
        }
    }
}
