@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.MessagingPrefs
import rs.brocolis.messagerie.store.NamedKey

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RootScreen(
    onOpenMessaging: () -> Unit,
    onOpenConversation: () -> Unit,
    onOpenPairing: () -> Unit
) {
    var version by remember { mutableIntStateOf(0) }
    fun reload() { version++ }

    val keys = remember(version) { BrocolisKeyStore.keys }
    val hasKey = keys.isNotEmpty()
    val selectedId = remember(version) { BrocolisKeyStore.selectedKeyId }
    val isActive = remember(version) { BrocolisKeyStore.isActive }
    val encryptWhole = remember(version) { BrocolisKeyStore.encryptWholeAlways }
    val recipientIds = remember(version) { BrocolisKeyStore.recipientKeyIds }

    var lockEnabled by remember { mutableStateOf(MessagingPrefs.lockEnabled) }
    var eraseOnClose by remember { mutableStateOf(MessagingPrefs.eraseOnClose) }

    // Dialogs
    var showGenerate by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<NamedKey?>(null) }

    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var snackbar by remember { mutableStateOf<String?>(null) }
    val snackbarHost = remember { SnackbarHostState() }
    LaunchedEffect(snackbar) { snackbar?.let { snackbarHost.showSnackbar(it); snackbar = null } }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Brocolis 🥦") }) },
        snackbarHost = { SnackbarHost(snackbarHost) }
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // MARK: État / démarrage
            if (!hasKey) {
                SectionCard(loc("Bienvenue 🥦", "Welcome 🥦", "Bienvenido 🥦")) {
                    Button(onClick = { showGenerate = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(loc("Créer ma première clé", "Create my first key", "Crear mi primera clave"))
                    }
                    OutlinedButton(onClick = onOpenPairing, modifier = Modifier.fillMaxWidth()) {
                        Text(loc("M'appairer avec quelqu'un", "Pair with someone", "Emparejar con alguien"))
                    }
                    Text(
                        loc(
                            "Une clé = une discussion privée avec une personne.",
                            "A key = a private conversation with one person.",
                            "Una clave = una conversación privada con una persona."
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            } else {
                SectionCard(loc("État", "Status", "Estado")) {
                    ToggleRow(
                        title = if (isActive) loc("Prêt à chiffrer", "Ready to encrypt", "Listo para cifrar")
                                else loc("En pause", "Paused", "En pausa"),
                        subtitle = if (isActive) loc("Utilise « Partager » dans tes apps.", "Use “Share” in your apps.", "Usa «Compartir» en tus apps.")
                                   else loc("Active pour chiffrer.", "Turn on to encrypt.", "Actívalo para cifrar."),
                        checked = isActive,
                        onChange = { BrocolisKeyStore.setActive(it); reload() }
                    )
                }

                // MARK: Messagerie
                SectionCard(loc("Discuter en direct", "Chat live", "Chatear en directo")) {
                    Button(onClick = onOpenMessaging, modifier = Modifier.fillMaxWidth()) {
                        Text(loc("Ouvrir la messagerie", "Open messaging", "Abrir mensajería"))
                    }
                }

                // MARK: Confidentialité
                SectionCard(loc("Confidentialité", "Privacy", "Privacidad")) {
                    ToggleRow(
                        title = loc("Verrouiller par biométrie / code", "Lock with biometrics / passcode", "Bloquear con biometría / código"),
                        subtitle = loc("Exige une authentification pour voir tes messages.", "Requires authentication to see your messages.", "Requiere autenticación para ver tus mensajes."),
                        checked = lockEnabled,
                        onChange = { MessagingPrefs.lockEnabled = it; lockEnabled = it }
                    )
                    ToggleRow(
                        title = loc("Effacer à la fermeture", "Erase on close", "Borrar al cerrar"),
                        subtitle = loc("Les messages affichés disparaissent en quittant.", "Displayed messages disappear on leaving.", "Los mensajes mostrados desaparecen al salir."),
                        checked = eraseOnClose,
                        onChange = { MessagingPrefs.eraseOnClose = it; eraseOnClose = it }
                    )
                }
            }

            // MARK: Conversation à la volée
            SectionCard(loc("Lire à la volée", "Read on the fly", "Leer al vuelo")) {
                OutlinedButton(onClick = onOpenConversation, modifier = Modifier.fillMaxWidth()) {
                    Text(loc("Ouvrir la conversation", "Open conversation", "Abrir conversación"))
                }
                Text(
                    loc(
                        "Colle toute une discussion : Brocolis déchiffre ce qu'il peut et laisse 🔒 le reste.",
                        "Paste a whole conversation: Brocolis decrypts what it can and leaves 🔒 the rest.",
                        "Pega una conversación entera: Brocolis descifra lo que puede y deja 🔒 el resto."
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
            }

            // MARK: Chiffrement
            if (hasKey) {
                SectionCard(loc("Chiffrement", "Encryption", "Cifrado")) {
                    ToggleRow(
                        title = loc("Tout chiffrer", "Encrypt everything", "Cifrar todo"),
                        subtitle = if (encryptWhole)
                            loc("Toute la sélection est chiffrée d'un bloc.", "The whole selection is encrypted as one block.", "Toda la selección se cifra en un bloque.")
                        else
                            loc("Seuls les passages entre ((…)) sont chiffrés.", "Only parts between ((…)) are encrypted.", "Solo se cifran los fragmentos entre ((…))."),
                        checked = encryptWhole,
                        onChange = { BrocolisKeyStore.encryptWholeAlways = it; reload() }
                    )
                }
            }

            // MARK: Appairage
            SectionCard(loc("Correspondant", "Contact", "Contacto")) {
                OutlinedButton(onClick = onOpenPairing, modifier = Modifier.fillMaxWidth()) {
                    Text(loc("Appairer automatiquement", "Pair automatically", "Emparejar automáticamente"))
                }
                BrocolisKeyStore.pairingFingerprint?.let { fp ->
                    Text(
                        loc("Empreinte : ", "Fingerprint: ", "Huella: ") + fp,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            // MARK: Clés
            SectionCard(loc("Clés", "Keys", "Claves")) {
                keys.forEach { key ->
                    KeyRow(
                        key = key,
                        selected = key.id == selectedId,
                        onSelect = { BrocolisKeyStore.selectKey(key.id); reload() },
                        onRename = { renameTarget = key },
                        onDelete = { BrocolisKeyStore.deleteKey(key.id); reload() }
                    )
                    Divider()
                }
                OutlinedButton(onClick = { showGenerate = true }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Add, null); Spacer(Modifier.size(6.dp))
                    Text(loc("Générer une nouvelle clé", "Generate a new key", "Generar una nueva clave"))
                }
                OutlinedButton(onClick = { showImport = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(loc("Importer une clé", "Import a key", "Importar una clave"))
                }
            }

            // MARK: Destinataires (multi)
            if (keys.size >= 2) {
                SectionCard(loc("Chiffrer pour", "Encrypt for", "Cifrar para")) {
                    keys.forEach { key ->
                        val on = recipientIds.contains(key.id)
                        Row(
                            Modifier.fillMaxWidth().clickable {
                                val next = recipientIds.toMutableList()
                                if (on) next.remove(key.id) else next.add(key.id)
                                BrocolisKeyStore.recipientKeyIds = next
                                reload()
                            }.padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                if (on) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked,
                                null, tint = if (on) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
                            )
                            Spacer(Modifier.size(8.dp))
                            Text(key.name)
                        }
                    }
                    if (recipientIds.isNotEmpty()) {
                        TextButton(onClick = { BrocolisKeyStore.recipientKeyIds = emptyList(); reload() }) {
                            Text(loc("Tout décocher", "Uncheck all", "Desmarcar todo"))
                        }
                    }
                    Text(
                        loc(
                            "Coche plusieurs clés pour qu'un même message soit lisible par plusieurs correspondants.",
                            "Check several keys so the same message is readable by several contacts.",
                            "Marca varias claves para que un mismo mensaje sea legible por varios contactos."
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            // MARK: Clé sélectionnée
            val selected = keys.firstOrNull { it.id == selectedId } ?: keys.firstOrNull()
            if (selected != null) {
                SelectedKeyCard(
                    key = selected,
                    onCopy = {
                        clipboard.setText(AnnotatedString(selected.base64))
                        snackbar = loc("Clé copiée.", "Key copied.", "Clave copiada.")
                    },
                    onShare = {
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"; putExtra(Intent.EXTRA_TEXT, selected.base64)
                        }
                        context.startActivity(Intent.createChooser(send, null))
                    },
                    onTTL = { seconds -> BrocolisKeyStore.setKeyTTL(seconds, selected.id); reload() }
                )
            }

            Spacer(Modifier.size(24.dp))
        }
    }

    // MARK: Dialogs
    if (showGenerate) {
        NameDialog(
            title = loc("Nouvelle clé", "New key", "Nueva clave"),
            confirmLabel = loc("Générer", "Generate", "Generar"),
            fields = 1,
            onConfirm = { values ->
                BrocolisKeyStore.addKey(values[0], BrocolisCrypto.generateKeyBase64())
                BrocolisKeyStore.setActive(true)
                showGenerate = false; reload()
            },
            onCancel = { showGenerate = false }
        )
    }
    if (showImport) {
        NameDialog(
            title = loc("Importer une clé", "Import a key", "Importar una clave"),
            confirmLabel = loc("Importer", "Import", "Importar"),
            fields = 2,
            secondPlaceholder = loc("Clé base64 (32 octets)", "Base64 key (32 bytes)", "Clave base64 (32 bytes)"),
            onConfirm = { values ->
                val name = values[0]; val b64 = values[1].trim()
                if (BrocolisCrypto.isValidKey(b64)) {
                    BrocolisKeyStore.addKey(name, b64); BrocolisKeyStore.setActive(true)
                    showImport = false; reload()
                } else {
                    snackbar = loc("Clé invalide.", "Invalid key.", "Clave no válida.")
                }
            },
            onCancel = { showImport = false }
        )
    }
    renameTarget?.let { target ->
        NameDialog(
            title = loc("Renommer la clé", "Rename key", "Renombrar clave"),
            confirmLabel = "OK",
            fields = 1,
            initialFirst = target.name,
            onConfirm = { values ->
                BrocolisKeyStore.renameKey(target.id, values[0]); renameTarget = null; reload()
            },
            onCancel = { renameTarget = null }
        )
    }
}

@Composable
private fun SectionCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(title.uppercase(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
        }
    }
}

@Composable
private fun ToggleRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun KeyRow(
    key: NamedKey, selected: Boolean,
    onSelect: () -> Unit, onRename: () -> Unit, onDelete: () -> Unit
) {
    Row(Modifier.fillMaxWidth().clickable { onSelect() }.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(
            if (selected) Icons.Default.CheckCircle else Icons.Default.RadioButtonUnchecked, null,
            tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline
        )
        Spacer(Modifier.size(8.dp))
        Column(Modifier.weight(1f)) {
            Text(key.name)
            BrocolisKeyStore.keyPhone(key.id)?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        IconButton(onClick = onRename) { Icon(Icons.Default.Edit, loc("Renommer", "Rename", "Renombrar")) }
        IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, loc("Supprimer", "Delete", "Eliminar")) }
    }
}

@Composable
private fun SelectedKeyCard(
    key: NamedKey, onCopy: () -> Unit, onShare: () -> Unit, onTTL: (Int) -> Unit
) {
    val ttlOptions = listOf(
        loc("Jamais", "Never", "Nunca") to 0,
        loc("1 heure", "1 hour", "1 hora") to 3600,
        loc("24 heures", "24 hours", "24 horas") to 86_400,
        loc("7 jours", "7 days", "7 días") to 604_800,
    )
    SectionCard(loc("Clé sélectionnée", "Selected key", "Clave seleccionada")) {
        Text(key.name, style = MaterialTheme.typography.titleMedium)
        SelectionContainer {
            Text(key.base64, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onCopy) { Icon(Icons.Default.ContentCopy, null); Spacer(Modifier.size(6.dp)); Text(loc("Copier", "Copy", "Copiar")) }
            OutlinedButton(onClick = onShare) { Icon(Icons.Default.Share, null); Spacer(Modifier.size(6.dp)); Text(loc("Partager", "Share", "Compartir")) }
        }
        Text(loc("Validité", "Validity", "Validez"), style = MaterialTheme.typography.labelMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ttlOptions.forEach { (label, seconds) ->
                val on = key.ttlSeconds == seconds
                FilterChip(selected = on, onClick = { onTTL(seconds) }, label = { Text(label) })
            }
        }
    }
}

@Composable
private fun NameDialog(
    title: String,
    confirmLabel: String,
    fields: Int,
    initialFirst: String = "",
    secondPlaceholder: String = "",
    onConfirm: (List<String>) -> Unit,
    onCancel: () -> Unit
) {
    var first by remember { mutableStateOf(initialFirst) }
    var second by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = first, onValueChange = { first = it }, singleLine = true,
                    placeholder = { Text(loc("Nom (ex. Maman)", "Name (e.g. Mom)", "Nombre (ej. Mamá)")) }
                )
                if (fields >= 2) {
                    OutlinedTextField(
                        value = second, onValueChange = { second = it }, singleLine = true,
                        placeholder = { Text(secondPlaceholder) }
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(listOf(first, second)) }) { Text(confirmLabel) } },
        dismissButton = { TextButton(onClick = onCancel) { Text(loc("Annuler", "Cancel", "Cancelar")) } }
    )
}
