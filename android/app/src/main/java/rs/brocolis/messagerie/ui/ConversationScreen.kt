@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import rs.brocolis.messagerie.crypto.BrocolisConversation
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.BrocolisKeyStore

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationScreen(onBack: () -> Unit) {
    var input by remember { mutableStateOf("") }
    val clipboard = LocalClipboardManager.current

    val keys = remember { BrocolisKeyStore.allKeyBytes() }
    val rendered = remember(input) {
        if (input.isBlank()) null else BrocolisConversation.render(input, keys)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(loc("Conversation", "Conversation", "Conversación")) },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, loc("Retour", "Back", "Atrás")) }
                }
            )
        }
    ) { padding ->
        Column(
            Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = input,
                onValueChange = { input = it },
                modifier = Modifier.fillMaxWidth(),
                minLines = 4,
                label = { Text(loc("Colle la discussion ici", "Paste the conversation here", "Pega la conversación aquí")) }
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { clipboard.getText()?.let { input = it.text } }) {
                    Text(loc("Coller", "Paste", "Pegar"))
                }
                if (input.isNotEmpty()) {
                    OutlinedButton(onClick = { input = "" }) { Text(loc("Effacer", "Clear", "Borrar")) }
                }
            }

            rendered?.let { r ->
                Text(
                    loc("${r.decryptedCount} déchiffré(s), ${r.lockedCount} verrouillé(s)",
                        "${r.decryptedCount} decrypted, ${r.lockedCount} locked",
                        "${r.decryptedCount} descifrado(s), ${r.lockedCount} bloqueado(s)"),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                r.lines.forEach { line ->
                    if (line.display.isNotEmpty()) LineCard(line)
                }
                if (r.decryptedCount > 0) {
                    Button(onClick = { clipboard.setText(AnnotatedString(r.fullText)) }, modifier = Modifier.fillMaxWidth()) {
                        Text(loc("Copier le texte rendu", "Copy rendered text", "Copiar el texto renderizado"))
                    }
                }
            }
        }
    }
}

@Composable
private fun LineCard(line: BrocolisConversation.Line) {
    val (icon, tint) = when (line.status) {
        BrocolisConversation.Status.CLEAR -> "" to MaterialTheme.colorScheme.onSurface
        BrocolisConversation.Status.DECRYPTED -> "🔓 " to MaterialTheme.colorScheme.primary
        BrocolisConversation.Status.LOCKED -> "🔒 " to Color(0xFFB26A00)
        BrocolisConversation.Status.MIXED -> "🔓🔒 " to MaterialTheme.colorScheme.primary
    }
    Card(Modifier.fillMaxWidth()) {
        SelectionContainer {
            Row(Modifier.padding(12.dp)) {
                if (icon.isNotEmpty()) Text(icon)
                Text(line.display, color = tint)
            }
        }
    }
    Spacer(Modifier.size(2.dp))
}
