@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.ContactsContract
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Lock
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.crypto.BrocolisKeyProtection
import rs.brocolis.messagerie.crypto.BrocolisProtection
import rs.brocolis.messagerie.crypto.BrocolisV3
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.MessagingPrefs
import rs.brocolis.messagerie.store.NamedKey
import rs.brocolis.messagerie.widget.BrocolisWidgetProvider

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
    // La protection de chaque clé (docs/SECURITE.md §8.8), en une transaction.
    val protections by produceState(emptyMap<String, BrocolisProtection>(), keys) {
        value = withContext(Dispatchers.IO) { BrocolisV3.protections(keys) }
    }

    var lockEnabled by remember { mutableStateOf(MessagingPrefs.lockEnabled) }
    var eraseOnClose by remember { mutableStateOf(MessagingPrefs.eraseOnClose) }
    var serverUrl by remember { mutableStateOf(MessagingPrefs.serverURL) }

    // Dialogs
    var showGenerate by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var renameTarget by remember { mutableStateOf<NamedKey?>(null) }
    var deleteTarget by remember { mutableStateOf<NamedKey?>(null) }
    // Partage : protégé par une phrase secrète (recommandé) ou en clair (avec avertissement).
    var protectTarget by remember { mutableStateOf<NamedKey?>(null) }
    var plainShare by remember { mutableStateOf<Pair<NamedKey, Boolean>?>(null) } // (clé, true = copier)
    // Import d'un jeton `[[BROCOLIS-CLE:v1:…]]` ou `v2` : (nom, texte collé) en attente de la phrase.
    var protectedImport by remember { mutableStateOf<Pair<String, String>?>(null) }

    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var snackbar by remember { mutableStateOf<String?>(null) }
    val snackbarHost = remember { SnackbarHostState() }
    LaunchedEffect(snackbar) { snackbar?.let { snackbarHost.showSnackbar(it); snackbar = null } }

    // Maintient le widget d'écran d'accueil à jour à chaque changement d'état.
    LaunchedEffect(version) { BrocolisWidgetProvider.refresh(context) }

    // Ajouter une clé depuis un contact : on choisit un numéro (sans permission,
    // l'URI choisi est lisible), on crée une clé neuve nommée d'après le contact.
    val pickContact = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri ->
                val (name, number) = readPickedContact(context, uri)
                if (number != null) {
                    val id = BrocolisKeyStore.addKey(name ?: number, BrocolisCrypto.generateKeyBase64())
                    BrocolisKeyStore.setKeyPhone(number, id)
                    BrocolisKeyStore.setActive(true)
                    reload()
                    snackbar = loc(
                        "Clé créée pour ${name ?: number}. Partage-la (ou appaire-toi).",
                        "Key created for ${name ?: number}. Share it (or pair up).",
                        "Clave creada para ${name ?: number}. Compártela (o empareja)."
                    )
                }
            }
        }
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Brocolis 🥦") }, colors = rs.brocolis.messagerie.ui.theme.brocolisTopBarColors()) },
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
                        protection = protections[key.id],
                        selected = key.id == selectedId,
                        onSelect = { BrocolisKeyStore.selectKey(key.id); reload() },
                        onRename = { renameTarget = key },
                        onDelete = { deleteTarget = key }
                    )
                    Divider()
                }
                OutlinedButton(
                    onClick = {
                        pickContact.launch(Intent(Intent.ACTION_PICK, ContactsContract.CommonDataKinds.Phone.CONTENT_URI))
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(loc("Ajouter depuis mes contacts", "Add from my contacts", "Añadir desde mis contactos"))
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
                    protection = protections[selected.id],
                    onPsk = { on -> BrocolisKeyStore.setPsk(on, selected.id); reload() },
                    onProtectedShare = { protectTarget = selected },
                    onCopy = { plainShare = selected to true },
                    onShare = { plainShare = selected to false },
                    onTTL = { seconds -> BrocolisKeyStore.setKeyTTL(seconds, selected.id); reload() }
                )
            }

            // MARK: Avancé (serveur)
            SectionCard(loc("Avancé", "Advanced", "Avanzado")) {
                OutlinedTextField(
                    value = serverUrl,
                    onValueChange = { serverUrl = it; MessagingPrefs.serverURL = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text(loc("Serveur (messagerie & appairage)", "Server (messaging & pairing)", "Servidor (mensajería y emparejamiento)")) }
                )
                Text(
                    loc(
                        "Laisse par défaut sauf si tu héberges ton propre serveur.",
                        "Leave the default unless you host your own server.",
                        "Deja el valor por defecto salvo que alojes tu propio servidor."
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
            }

            // MARK: Crédits
            Column(
                Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text("Brocolis 🥦", style = MaterialTheme.typography.titleSmall)
                Text(
                    loc("Conçu et développé par Maxime Nathan Lestage", "Designed and developed by Maxime Nathan Lestage", "Diseñado y desarrollado por Maxime Nathan Lestage"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
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
            secondPlaceholder = loc(
                "Clé protégée [[BROCOLIS-CLE:…]] ou base64",
                "Protected key [[BROCOLIS-CLE:…]] or base64",
                "Clave protegida [[BROCOLIS-CLE:…]] o base64"
            ),
            onConfirm = { values ->
                val name = values[0]; val b64 = values[1].trim()
                if (BrocolisKeyProtection.containsToken(b64)) {
                    // Clé protégée par une phrase secrète : on demande la phrase.
                    showImport = false; protectedImport = name to b64
                } else if (BrocolisCrypto.isValidKey(b64)) {
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

    protectTarget?.let { target ->
        ProtectedExportDialog(
            key = target,
            onCopy = { token ->
                clipboard.setText(AnnotatedString(token))
                snackbar = loc(
                    "Clé protégée copiée. Donne la phrase secrète à part, de vive voix.",
                    "Protected key copied. Give the passphrase separately, in person.",
                    "Clave protegida copiada. Da la frase secreta aparte, de viva voz."
                )
                protectTarget = null
            },
            onShare = { token ->
                val send = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, token) }
                context.startActivity(Intent.createChooser(send, null))
                protectTarget = null
            },
            onCancel = { protectTarget = null }
        )
    }

    // Partage EN CLAIR : toujours possible (compatibilité), mais après avertissement.
    plainShare?.let { (target, copy) ->
        AlertDialog(
            onDismissRequest = { plainShare = null },
            title = { Text(loc("Partager la clé en clair ?", "Share the key in clear?", "¿Compartir la clave en claro?")) },
            text = {
                Text(loc(
                    "Quiconque voit ce texte (presse-papiers, messagerie, sauvegarde, capture d'écran) pourra lire tous les messages de « ${target.name} ». Préfère « Partager protégée par une phrase secrète ».",
                    "Anyone who sees this text (clipboard, messaging app, backup, screenshot) can read every message of “${target.name}”. Prefer “Share protected by a passphrase”.",
                    "Cualquiera que vea este texto (portapapeles, mensajería, copia de seguridad, captura) podrá leer todos los mensajes de «${target.name}». Mejor «Compartir protegida con una frase secreta»."
                ))
            },
            confirmButton = {
                TextButton(onClick = {
                    if (copy) {
                        clipboard.setText(AnnotatedString(target.base64))
                        snackbar = loc("Clé copiée en clair.", "Key copied in clear.", "Clave copiada en claro.")
                    } else {
                        val send = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"; putExtra(Intent.EXTRA_TEXT, target.base64)
                        }
                        context.startActivity(Intent.createChooser(send, null))
                    }
                    plainShare = null
                }) { Text(loc("En clair quand même", "Share in clear anyway", "En claro de todos modos")) }
            },
            dismissButton = {
                TextButton(onClick = { protectTarget = target; plainShare = null }) {
                    Text(loc("Protéger", "Protect", "Proteger"))
                }
            }
        )
    }

    protectedImport?.let { (name, text) ->
        ProtectedImportDialog(
            text = text,
            onImported = { b64 ->
                BrocolisKeyStore.addKey(name, b64); BrocolisKeyStore.setActive(true)
                protectedImport = null; reload()
                snackbar = loc("Clé importée.", "Key imported.", "Clave importada.")
            },
            onCancel = { protectedImport = null }
        )
    }

    // Confirmation avant suppression : perdre une clé = perdre le déchiffrement.
    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(loc("Supprimer la clé ?", "Delete key?", "¿Eliminar la clave?")) },
            text = {
                Text(loc(
                    "« ${target.name} » sera supprimée. Tu ne pourras plus déchiffrer les messages qui l'utilisent.",
                    "“${target.name}” will be deleted. You will no longer be able to decrypt messages that use it.",
                    "«${target.name}» se eliminará. Ya no podrás descifrar los mensajes que la usan."))
            },
            confirmButton = {
                TextButton(onClick = {
                    BrocolisKeyStore.deleteKey(target.id); deleteTarget = null; reload()
                }) { Text(loc("Supprimer", "Delete", "Eliminar")) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) { Text(loc("Annuler", "Cancel", "Cancelar")) }
            }
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
    key: NamedKey, protection: BrocolisProtection?, selected: Boolean,
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
            protection?.let {
                Text(it.label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        IconButton(onClick = onRename) { Icon(Icons.Default.Edit, loc("Renommer", "Rename", "Renombrar")) }
        IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, loc("Supprimer", "Delete", "Eliminar")) }
    }
}

@Composable
private fun SelectedKeyCard(
    key: NamedKey, protection: BrocolisProtection?, onPsk: (Boolean) -> Unit,
    onProtectedShare: () -> Unit, onCopy: () -> Unit, onShare: () -> Unit, onTTL: (Int) -> Unit
) {
    val ttlOptions = listOf(
        loc("Jamais", "Never", "Nunca") to 0,
        loc("1 heure", "1 hour", "1 hora") to 3600,
        loc("24 heures", "24 hours", "24 horas") to 86_400,
        loc("7 jours", "7 days", "7 días") to 604_800,
    )
    SectionCard(loc("Clé sélectionnée", "Selected key", "Clave seleccionada")) {
        Text(key.name, style = MaterialTheme.typography.titleMedium)
        protection?.let {
            Text(it.label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        // Une clé sans appairage v3, partagée avec UNE personne à jour : le
        // double cliquet à partir de la clé (PSK, §8.5). Jamais automatique :
        // un ancien correspondant ne lirait plus rien.
        if (key.v3Bundle == null && key.duo != false) {
            ToggleRow(
                title = loc("Double cliquet avec cette clé (PSK)", "Double ratchet with this key (PSK)", "Doble trinquete con esta clave (PSK)"),
                subtitle = loc(
                    "Seulement si cette clé est partagée avec UNE personne dont l’app Brocolis est à jour. Ses réponses suivront toutes seules.",
                    "Only if this key is shared with ONE person whose Brocolis app is up to date. Their replies will follow on their own.",
                    "Solo si esta clave se comparte con UNA persona cuya app Brocolis está actualizada. Sus respuestas seguirán solas."
                ),
                checked = key.psk == true,
                onChange = onPsk
            )
        }
        SelectionContainer {
            Text(key.base64, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Button(onClick = onProtectedShare, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Default.Lock, null); Spacer(Modifier.size(6.dp))
            Text(loc("Partager protégée par une phrase secrète", "Share protected by a passphrase", "Compartir protegida con una frase secreta"))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onCopy) { Icon(Icons.Default.ContentCopy, null); Spacer(Modifier.size(6.dp)); Text(loc("Copier en clair", "Copy in clear", "Copiar en claro")) }
            OutlinedButton(onClick = onShare) { Icon(Icons.Default.Share, null); Spacer(Modifier.size(6.dp)); Text(loc("En clair", "In clear", "En claro")) }
        }
        Text(
            loc(
                "⚠️ En clair, quiconque voit la clé lit tes messages. Protégée, il faut aussi la phrase, à donner à part (de vive voix).",
                "⚠️ In clear, anyone who sees the key reads your messages. Protected, the passphrase is also needed — give it separately (in person).",
                "⚠️ En claro, cualquiera que vea la clave lee tus mensajes. Protegida, también hace falta la frase, que se da aparte (de viva voz)."
            ),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
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

/** Champ de phrase secrète (masquée, clavier « mot de passe »). */
@Composable
private fun PassphraseField(value: String, onChange: (String) -> Unit, label: String, enabled: Boolean = true) {
    OutlinedTextField(
        value = value, onValueChange = onChange, singleLine = true, enabled = enabled,
        label = { Text(label) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrect = false)
    )
}

/**
 * Export d'une clé protégée par une phrase secrète (format commun
 * `[[BROCOLIS-CLE:v2:…]]`, docs/SECURITE.md §8.9) : phrase de 8 caractères au
 * moins, saisie deux fois. La dérivation (Argon2id, 64 Mio) tourne hors du fil
 * principal.
 */
@Composable
private fun ProtectedExportDialog(
    key: NamedKey, onCopy: (String) -> Unit, onShare: (String) -> Unit, onCancel: () -> Unit
) {
    var phrase by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var token by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val longEnough = BrocolisKeyProtection.isPassphraseAcceptable(phrase)
    val same = phrase == again

    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        title = { Text(loc("Protéger « ${key.name} »", "Protect “${key.name}”", "Proteger «${key.name}»")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (token == null) {
                    Text(
                        loc(
                            "Choisis une phrase secrète (8 caractères au moins). Donne-la à ton correspondant à part, de vive voix — jamais dans le même message que la clé.",
                            "Choose a passphrase (at least 8 characters). Give it to your contact separately, in person — never in the same message as the key.",
                            "Elige una frase secreta (8 caracteres como mínimo). Dásela a tu contacto aparte, de viva voz — nunca en el mismo mensaje que la clave."
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                    PassphraseField(phrase, { phrase = it; error = null }, loc("Phrase secrète", "Passphrase", "Frase secreta"), !busy)
                    PassphraseField(again, { again = it; error = null }, loc("Encore une fois", "Once more", "Otra vez"), !busy)
                    when {
                        phrase.isNotEmpty() && !longEnough -> Text(
                            loc("8 caractères au moins.", "At least 8 characters.", "8 caracteres como mínimo."),
                            color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall
                        )
                        again.isNotEmpty() && !same -> Text(
                            loc("Les deux phrases diffèrent.", "The two passphrases differ.", "Las dos frases no coinciden."),
                            color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall
                        )
                    }
                    error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                } else {
                    Text(
                        loc(
                            "Clé protégée prête. Envoie-la, puis donne la phrase à part.",
                            "Protected key ready. Send it, then give the passphrase separately.",
                            "Clave protegida lista. Envíala y da la frase aparte."
                        ),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Text(token!!, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }
        },
        confirmButton = {
            val ready = token
            if (ready == null) {
                TextButton(
                    enabled = !busy && longEnough && same,
                    onClick = {
                        busy = true
                        val raw = try { BrocolisCrypto.keyBytes(key.base64) } catch (_: Exception) { null }
                        scope.launch {
                            val sealed = raw?.let {
                                withContext(Dispatchers.Default) {
                                    try { BrocolisKeyProtection.seal(it, phrase) } catch (_: Exception) { null }
                                }
                            }
                            busy = false
                            if (sealed != null) { token = sealed; phrase = ""; again = "" }
                            else error = loc("Impossible de protéger cette clé.", "Unable to protect this key.", "No se puede proteger esta clave.")
                        }
                    }
                ) { Text(loc("Protéger", "Protect", "Proteger")) }
            } else {
                Row {
                    TextButton(onClick = { onCopy(ready) }) { Text(loc("Copier", "Copy", "Copiar")) }
                    TextButton(onClick = { onShare(ready) }) { Text(loc("Partager", "Share", "Compartir")) }
                }
            }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onCancel) { Text(loc("Annuler", "Cancel", "Cancelar")) }
        }
    )
}

/**
 * Import d'une clé protégée `[[BROCOLIS-CLE:v1:…]]` ou `v2` : on demande la
 * phrase et on déchiffre (hors du fil principal) ; phrase fausse ou jeton
 * abîmé → message d'erreur, rien d'importé.
 */
@Composable
private fun ProtectedImportDialog(text: String, onImported: (String) -> Unit, onCancel: () -> Unit) {
    var phrase by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    AlertDialog(
        onDismissRequest = { if (!busy) onCancel() },
        title = { Text(loc("Clé protégée", "Protected key", "Clave protegida")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    loc(
                        "Cette clé est protégée par une phrase secrète. Saisis la phrase que ton correspondant t'a donnée.",
                        "This key is protected by a passphrase. Enter the passphrase your contact gave you.",
                        "Esta clave está protegida con una frase secreta. Escribe la frase que te dio tu contacto."
                    ),
                    style = MaterialTheme.typography.bodySmall
                )
                PassphraseField(phrase, { phrase = it; error = null }, loc("Phrase secrète", "Passphrase", "Frase secreta"), !busy)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && phrase.isNotEmpty(),
                onClick = {
                    busy = true
                    scope.launch {
                        val raw = withContext(Dispatchers.Default) { BrocolisKeyProtection.openOrNull(text, phrase) }
                        busy = false
                        if (raw != null) {
                            phrase = ""
                            onImported(BrocolisCrypto.b64encode(raw))
                        } else {
                            error = loc(
                                "Phrase incorrecte ou clé abîmée. Rien n'a été importé.",
                                "Wrong passphrase or damaged key. Nothing was imported.",
                                "Frase incorrecta o clave dañada. No se importó nada."
                            )
                        }
                    }
                }
            ) { Text(loc("Importer", "Import", "Importar")) }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onCancel) { Text(loc("Annuler", "Cancel", "Cancelar")) }
        }
    )
}

/** Lit le nom + numéro du contact choisi (URI issu du sélecteur, sans permission). */
private fun readPickedContact(context: android.content.Context, uri: Uri): Pair<String?, String?> {
    val projection = arrayOf(
        ContactsContract.CommonDataKinds.Phone.NUMBER,
        ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME
    )
    context.contentResolver.query(uri, projection, null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            val number = c.getString(0)?.trim()
            val name = c.getString(1)?.trim()
            return name to number
        }
    }
    return null to null
}
