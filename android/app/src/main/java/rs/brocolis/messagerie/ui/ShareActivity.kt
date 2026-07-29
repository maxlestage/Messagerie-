@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.ui.theme.BrocolisTheme

/**
 * Équivalent Android de l'extension « Partager » iOS : reçoit du texte partagé
 * (ACTION_SEND) ou sélectionné (ACTION_PROCESS_TEXT) depuis n'importe quelle app,
 * et propose de le CHIFFRER (avec la/les clés destinataires) ou de le DÉCHIFFRER.
 */
class ShareActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val incoming = when (intent?.action) {
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        } ?: ""
        setContent { BrocolisTheme { ShareScreen(incoming) { finish() } } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ShareScreen(incoming: String, onClose: () -> Unit) {
    var text by remember { mutableStateOf(incoming) }
    var result by remember { mutableStateOf<String?>(null) }
    var info by remember { mutableStateOf<String?>(null) }
    val clipboard = LocalClipboardManager.current
    val context = androidx.compose.ui.platform.LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Brocolis 🥦") },
                navigationIcon = { IconButton(onClick = onClose) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) } },
                colors = rs.brocolis.messagerie.ui.theme.brocolisTopBarColors()
            )
        }
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = text, onValueChange = { text = it },
                modifier = Modifier.fillMaxWidth(), minLines = 3,
                label = { Text(loc("Texte", "Text", "Texto")) }
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = {
                        val keys = BrocolisKeyStore.encryptionKeyBytes()
                        if (keys.isEmpty()) {
                            info = loc("Aucune clé utilisable.", "No usable key.", "Ninguna clave utilizable.")
                            return@Button
                        }
                        result = if (BrocolisKeyStore.encryptWholeAlways) {
                            BrocolisCrypto.sealTokenOrNull(text.toByteArray(Charsets.UTF_8), keys) ?: text
                        } else {
                            BrocolisCrypto.encryptMarked(text, keys).text
                        }
                        info = loc("Chiffré.", "Encrypted.", "Cifrado.")
                    }
                ) { Text(loc("Chiffrer", "Encrypt", "Cifrar")) }

                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = {
                        val (out, count) = BrocolisCrypto.decryptTokens(text, BrocolisKeyStore.allKeyBytes())
                        result = out
                        info = loc("$count déchiffré(s).", "$count decrypted.", "$count descifrado(s).")
                    }
                ) { Text(loc("Déchiffrer", "Decrypt", "Descifrar")) }
            }

            info?.let { Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium) }

            result?.let { r ->
                Card(Modifier.fillMaxWidth()) {
                    SelectionContainer {
                        Text(r, modifier = Modifier.padding(12.dp), fontFamily = FontFamily.Monospace)
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        clipboard.setText(AnnotatedString(r))
                        info = loc("Copié.", "Copied.", "Copiado.")
                    }) { Text(loc("Copier", "Copy", "Copiar")) }
                    OutlinedButton(onClick = {
                        val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, r) }
                        context.startActivity(Intent.createChooser(send, null))
                    }) { Text(loc("Partager", "Share", "Compartir")) }
                }
            }

            Spacer(Modifier.size(8.dp))
        }
    }
}
