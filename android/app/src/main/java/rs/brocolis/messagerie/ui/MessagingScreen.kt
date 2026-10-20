@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package rs.brocolis.messagerie.ui

import android.content.Context
import android.graphics.BitmapFactory
import android.media.MediaPlayer
import android.media.MediaRecorder
import android.net.Uri
import android.os.Build
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.sse.EventSource
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import rs.brocolis.messagerie.crypto.BrocolisProtection
import rs.brocolis.messagerie.crypto.BrocolisV3
import rs.brocolis.messagerie.crypto.BrocolisV3Api
import rs.brocolis.messagerie.crypto.BrocolisV3Format
import rs.brocolis.messagerie.crypto.BrocolisV3Opened
import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.net.BrocolisMessagingClient
import rs.brocolis.messagerie.net.RawMessage
import rs.brocolis.messagerie.store.BrocolisKeyStore
import rs.brocolis.messagerie.store.MessagingPrefs
import rs.brocolis.messagerie.store.NamedKey
import rs.brocolis.messagerie.ui.theme.BrocoliGreen
import java.io.File

// MARK: - Médias dans le texte chiffré (le serveur ne voit qu'un jeton).

private object MediaPayload {
    const val IMG = "BRCM1:img:"
    const val AUD = "BRCM1:aud:"
    fun imageClear(jpeg: ByteArray) = IMG + Base64.encodeToString(jpeg, Base64.NO_WRAP)
    fun audioClear(m4a: ByteArray) = AUD + Base64.encodeToString(m4a, Base64.NO_WRAP)
}

sealed class ChatBody {
    data class Text(val value: String) : ChatBody()
    data class ImageData(val bytes: ByteArray) : ChatBody()
    data class AudioData(val bytes: ByteArray) : ChatBody()
    object Locked : ChatBody()
}

data class ChatLineUi(
    val id: String, val body: ChatBody, val isMine: Boolean, val seq: Long, val timeLabel: String = ""
)

/** RFC3339 UTC → heure locale « HH:mm » (API 26+). Vide si absent/illisible. */
private fun formatTime(sentAt: String?): String {
    if (sentAt.isNullOrBlank()) return ""
    return try {
        java.time.Instant.parse(sentAt)
            .atZone(java.time.ZoneId.systemDefault())
            .format(java.time.format.DateTimeFormatter.ofPattern("HH:mm"))
    } catch (_: Exception) { "" }
}

private fun bodyFrom(clear: String): ChatBody {
    if (clear.startsWith(MediaPayload.IMG))
        BrocolisCrypto.b64decode(clear.removePrefix(MediaPayload.IMG))?.let { return ChatBody.ImageData(it) }
    if (clear.startsWith(MediaPayload.AUD))
        BrocolisCrypto.b64decode(clear.removePrefix(MediaPayload.AUD))?.let { return ChatBody.AudioData(it) }
    return ChatBody.Text(clear)
}

// MARK: - Contrôleur d'une conversation (déchiffre localement, flux temps réel).

class ChatController(val correspondent: NamedKey) {
    val lines: SnapshotStateList<ChatLineUi> = mutableStateListOf()
    var status by mutableStateOf<String?>(null)
    var otherReadUpTo by mutableStateOf(0L)
    /** Ce que donnera le prochain envoi (docs/SECURITE.md §8.8). */
    var protection by mutableStateOf<BrocolisProtection?>(null)

    private val key: ByteArray = BrocolisCrypto.keyBytes(correspondent.base64)
    private val conversationId: String =
        BrocolisMessagingClient.conversationId(correspondent.base64) ?: ""
    private val deviceId = MessagingPrefs.deviceId
    private val client = BrocolisMessagingClient(MessagingPrefs.serverURL, deviceId)

    private val raw = LinkedHashMap<String, RawMessage>()
    private val seenIds = HashSet<String>()
    private var cursor = 0L
    private var source: EventSource? = null
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    /** Une reconstruction (une transaction v3) à la fois, dans l'ordre. */
    private val rebuildLock = Mutex()

    /**
     * La clé du correspondant telle qu'elle est maintenant (son contact v3 a
     * pu changer : passage en groupe…).
     */
    private val currentKey: NamedKey
        get() = BrocolisKeyStore.keys.firstOrNull { it.id == correspondent.id } ?: correspondent

    fun start() {
        cursor = maxOf(cursor, MessagingPrefs.floor(conversationId))
        val floor = cursor
        scope.launch {
            protection = withContext(Dispatchers.IO) { BrocolisV3.protection(currentKey) }
            try {
                val res = client.fetch(conversationId, floor)
                res.readers[peerReaderKey()]?.let { otherReadUpTo = maxOf(otherReadUpTo, it) }
                res.readers.filterKeys { it != deviceId }.values.maxOrNull()?.let {
                    otherReadUpTo = maxOf(otherReadUpTo, it)
                }
                ingest(res.messages, res.cursor)
            } catch (e: Exception) {
                status = loc("Hors ligne", "Offline", "Sin conexión")
            }
            openStream()
        }
    }

    private fun peerReaderKey(): String = "" // pas d'id de pair connu ; on prend le max des autres

    private fun openStream() {
        source = client.openStream(
            conversationId,
            onMessage = { m -> scope.launch { ingest(listOf(m), maxOf(cursor, m.seq)) } },
            onRead = { reader, upTo -> if (reader != deviceId) otherReadUpTo = maxOf(otherReadUpTo, upTo) },
            onClosed = { }
        )
    }

    private fun ingest(msgs: List<RawMessage>, cur: Long) {
        var changed = false
        for (m in msgs) {
            if (seenIds.contains(m.id)) continue
            seenIds.add(m.id); raw[m.id] = m; changed = true
        }
        cursor = maxOf(cursor, cur)
        if (changed) {
            scope.launch { rebuild() }
            val top = raw.values.maxOfOrNull { it.seq } ?: 0L
            if (top > 0) scope.launch { client.markRead(conversationId, top) }
        }
    }

    /**
     * Les jetons v3 en UNE transaction (§8.6 : mes envois relus dans les
     * messages ouverts, jamais déchiffrés ; réparation d'une session perdue),
     * le reste en v1/v2 comme avant. Hors du fil principal.
     */
    private suspend fun rebuild() = rebuildLock.withLock {
        val snapshot = raw.values.toList()
        val (ui, shown) = withContext(Dispatchers.IO) { render(snapshot) }
        lines.clear(); lines.addAll(ui)
        protection = shown
    }

    private fun render(messages: List<RawMessage>): Pair<List<ChatLineUi>, BrocolisProtection> {
        // Un même jeton v3 republié sous un autre identifiant (le serveur peut
        // rejouer) : ignoré, seule sa première apparition s'affiche (§8.7).
        val seenTokens = HashSet<String>()
        val sorted = messages.sortedBy { it.seq }.filter { m ->
            val r = BrocolisV3Format.findTokens(m.ciphertext).firstOrNull() ?: return@filter true
            seenTokens.add(BrocolisV3Format.tokenHash(m.ciphertext.substring(r.first, r.last + 1)))
        }
        val k = currentKey
        val v3 = BrocolisV3.openMessages(
            sorted.map { BrocolisV3Api.Incoming(it.ciphertext, it.senderId == deviceId) }, k, BrocolisKeyStore.keys
        )
        val ui = sorted.zip(v3).map { (m, opened) ->
            val isMine = m.senderId == deviceId
            val body = when (opened) {
                is BrocolisV3Opened.Text -> bodyFrom(opened.text)
                BrocolisV3Opened.Replay ->
                    ChatBody.Text(if (isMine) BrocolisV3Api.sentFromThisDevice else BrocolisV3Api.alreadyRead)
                is BrocolisV3Opened.Failed -> ChatBody.Locked
                null -> {
                    val (text, n) = BrocolisCrypto.decryptTokens(m.ciphertext, listOf(key))
                    if (n > 0) bodyFrom(text) else ChatBody.Locked
                }
            }
            ChatLineUi(m.id, body, isMine, m.seq, formatTime(m.sentAt))
        }
        return ui to BrocolisV3.protection(k)
    }

    fun sendText(text: String) = sendClear(text)
    fun sendImage(jpeg: ByteArray) = sendClear(MediaPayload.imageClear(jpeg))
    fun sendAudio(m4a: ByteArray) = sendClear(MediaPayload.audioClear(m4a))

    /**
     * v3 si la conversation le permet (§8.5, §8.7) : l'état est écrit AVANT
     * l'envoi. Sinon l'ancien format.
     */
    private fun sendClear(clear: String) {
        scope.launch {
            try {
                val k = currentKey
                val v3 = withContext(Dispatchers.IO) { BrocolisV3.sealMessage(clear, k) }
                if (v3 != null) {
                    protection = withContext(Dispatchers.IO) { BrocolisV3.protection(k) }
                    client.send(v3, conversationId)
                } else {
                    client.send(clear, conversationId, key)
                }
            } catch (e: Exception) {
                status = loc("Envoi échoué", "Send failed", "Envío fallido")
            }
        }
    }

    /** App passée en arrière-plan : on remonte le plancher (parité « effacer à la
     *  fermeture » d'iOS) sans couper le flux. */
    fun onBackground() {
        if (MessagingPrefs.eraseOnClose) MessagingPrefs.setFloor(cursor, conversationId)
    }

    fun stop() {
        source?.cancel()
        if (MessagingPrefs.eraseOnClose) MessagingPrefs.setFloor(cursor, conversationId)
        scope.cancel()
    }
}

// MARK: - Liste des correspondants (une clé = un correspondant).

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MessagingHomeScreen(onOpenChat: (String) -> Unit, onBack: () -> Unit) {
    LockGate {
        val keys = remember { BrocolisKeyStore.keys }
        // La protection de chaque correspondant (§8.8), en une transaction.
        val protections by produceState(emptyMap<String, BrocolisProtection>(), keys) {
            value = withContext(Dispatchers.IO) { BrocolisV3.protections(keys) }
        }
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text(loc("Messagerie", "Messaging", "Mensajería")) },
                    navigationIcon = {
                        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) }
                    },
                    colors = rs.brocolis.messagerie.ui.theme.brocolisTopBarColors()
                )
            }
        ) { padding ->
            if (keys.isEmpty()) {
                Box(Modifier.padding(padding).fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        loc("Crée une clé pour discuter.", "Create a key to chat.", "Crea una clave para chatear."),
                        textAlign = TextAlign.Center
                    )
                }
            } else {
                LazyColumn(Modifier.padding(padding).fillMaxSize()) {
                    items(keys) { key ->
                        ListItem(
                            headlineContent = { Text(key.name) },
                            supportingContent = {
                                Column {
                                    BrocolisKeyStore.keyPhone(key.id)?.let { Text(it) }
                                    protections[key.id]?.let {
                                        Text(it.label, style = MaterialTheme.typography.labelSmall)
                                    }
                                }
                            },
                            leadingContent = { Avatar(key.name) },
                            modifier = Modifier.clickable { onOpenChat(key.id) }
                        )
                        Divider()
                    }
                }
            }
        }
    }
}

@Composable
private fun Avatar(name: String) {
    val initial = name.firstOrNull()?.uppercase() ?: "🥦"
    Box(
        Modifier.size(40.dp).clip(RoundedCornerShape(20.dp)).background(BrocoliGreen),
        contentAlignment = Alignment.Center
    ) { Text(initial, color = androidx.compose.ui.graphics.Color.White) }
}

// MARK: - Écran de chat.

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(keyId: String, onBack: () -> Unit) {
    val context = LocalContext.current
    val correspondent = remember(keyId) { BrocolisKeyStore.keys.firstOrNull { it.id == keyId } }

    if (correspondent == null || !BrocolisCrypto.isValidKey(correspondent.base64)) {
        Scaffold(topBar = { TopAppBar(title = { Text("Brocolis") }, navigationIcon = {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) }
        }, colors = rs.brocolis.messagerie.ui.theme.brocolisTopBarColors()) }) { p ->
            Box(Modifier.padding(p).fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(loc("Clé introuvable.", "Key not found.", "Clave no encontrada."))
            }
        }
        return
    }

    val controller = remember(keyId) { ChatController(correspondent) }
    DisposableEffect(keyId) {
        controller.start()
        onDispose { controller.stop() }
    }

    // Effacer à la fermeture : quand l'app passe en arrière-plan, on remonte le
    // plancher de confidentialité (comme iOS efface les messages à la fermeture).
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val obs = androidx.lifecycle.LifecycleEventObserver { _, e ->
            if (e == androidx.lifecycle.Lifecycle.Event.ON_STOP) controller.onBackground()
        }
        lifecycleOwner.lifecycle.addObserver(obs)
        onDispose { lifecycleOwner.lifecycle.removeObserver(obs) }
    }

    var draft by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    LaunchedEffect(controller.lines.size) {
        if (controller.lines.isNotEmpty()) listState.animateScrollToItem(controller.lines.size - 1)
    }

    // Sélecteur de photo → compression → envoi chiffré.
    val scope = rememberCoroutineScope()
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri: Uri? ->
        if (uri != null) scope.launch {
            val jpeg = withContextIO { compressJpeg(context, uri) }
            if (jpeg != null) controller.sendImage(jpeg)
        }
    }

    // Enregistrement vocal (permission + MediaRecorder).
    val recorder = remember { VoiceRecorder(context) }
    var recording by remember { mutableStateOf(false) }
    val askMic = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) { recorder.start(); recording = true }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(correspondent.name)
                        controller.protection?.let { Text(it.label, style = MaterialTheme.typography.labelSmall) }
                    }
                },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) } },
                colors = rs.brocolis.messagerie.ui.theme.brocolisTopBarColors()
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            controller.status?.let {
                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp))
            }
            LazyColumn(
                state = listState,
                modifier = Modifier.weight(1f).fillMaxWidth().padding(horizontal = 8.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                items(controller.lines) { line ->
                    MessageBubble(line, isRead = line.isMine && line.seq <= controller.otherReadUpTo, context = context)
                }
            }
            // Barre de saisie.
            Row(
                Modifier.fillMaxWidth().padding(8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                IconButton(onClick = {
                    pickImage.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                }) { Icon(Icons.Default.Image, loc("Photo", "Photo", "Foto")) }

                IconButton(onClick = {
                    if (recording) {
                        val bytes = recorder.stop(); recording = false
                        if (bytes != null && bytes.isNotEmpty()) controller.sendAudio(bytes)
                    } else {
                        askMic.launch(android.Manifest.permission.RECORD_AUDIO)
                    }
                }) {
                    Icon(if (recording) Icons.Default.Stop else Icons.Default.Mic,
                        loc("Vocal", "Voice", "Voz"),
                        tint = if (recording) MaterialTheme.colorScheme.error else LocalContentColorOrPrimary())
                }

                OutlinedTextField(
                    value = draft, onValueChange = { draft = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text(loc("Message secret…", "Secret message…", "Mensaje secreto…")) },
                    maxLines = 4
                )
                IconButton(
                    enabled = draft.isNotBlank(),
                    onClick = { controller.sendText(draft.trim()); draft = "" }
                ) { Icon(Icons.AutoMirrored.Filled.Send, loc("Envoyer", "Send", "Enviar")) }
            }
        }
    }
}

@Composable
private fun LocalContentColorOrPrimary() = MaterialTheme.colorScheme.primary

@Composable
private fun MessageBubble(line: ChatLineUi, isRead: Boolean, context: Context) {
    val alignment = if (line.isMine) Alignment.CenterEnd else Alignment.CenterStart
    val bubbleColor = if (line.isMine) BrocoliGreen else MaterialTheme.colorScheme.surfaceVariant
    val textColor = if (line.isMine) androidx.compose.ui.graphics.Color.White else MaterialTheme.colorScheme.onSurface

    Box(Modifier.fillMaxWidth(), contentAlignment = alignment) {
        Surface(
            color = bubbleColor,
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.widthIn(max = 300.dp)
        ) {
            Column(Modifier.padding(10.dp)) {
                when (val b = line.body) {
                    is ChatBody.Text -> SelectionContainer { Text(b.value, color = textColor) }
                    is ChatBody.ImageData -> {
                        val bmp = remember(b.bytes) {
                            BitmapFactory.decodeByteArray(b.bytes, 0, b.bytes.size)?.asImageBitmap()
                        }
                        if (bmp != null) Image(bitmap = bmp, contentDescription = null,
                            modifier = Modifier.widthIn(max = 260.dp).clip(RoundedCornerShape(10.dp)))
                        else Text("🖼️", color = textColor)
                    }
                    is ChatBody.AudioData -> AudioBubble(b.bytes, textColor, context)
                    ChatBody.Locked -> Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Lock, null, tint = textColor)
                        Spacer(Modifier.size(4.dp))
                        Text(loc("Message chiffré", "Encrypted message", "Mensaje cifrado"), color = textColor)
                    }
                }
                val meta = buildString {
                    if (line.timeLabel.isNotEmpty()) append(line.timeLabel)
                    if (isRead) { if (isNotEmpty()) append(" · "); append(loc("Lu", "Read", "Leído")) }
                }
                if (meta.isNotEmpty()) {
                    Text(meta, style = MaterialTheme.typography.labelSmall,
                        color = textColor.copy(alpha = 0.7f), modifier = Modifier.align(Alignment.End))
                }
            }
        }
    }
}

@Composable
private fun AudioBubble(bytes: ByteArray, textColor: androidx.compose.ui.graphics.Color, context: Context) {
    var playing by remember { mutableStateOf(false) }
    val player = remember { mutableStateOf<MediaPlayer?>(null) }
    DisposableEffect(Unit) { onDispose { player.value?.release() } }
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable {
        if (playing) {
            player.value?.stop(); player.value?.release(); player.value = null; playing = false
        } else {
            val f = File.createTempFile("brocolis-voix", ".m4a", context.cacheDir)
            f.writeBytes(bytes)
            val mp = MediaPlayer().apply {
                setDataSource(f.absolutePath); setOnCompletionListener { playing = false }; prepare(); start()
            }
            player.value = mp; playing = true
        }
    }) {
        Icon(if (playing) Icons.Default.Stop else Icons.Default.PlayArrow, null, tint = textColor)
        Spacer(Modifier.size(6.dp))
        Text(loc("Vocal", "Voice message", "Mensaje de voz"), color = textColor)
    }
}

// MARK: - Utilitaires média.

private suspend fun <T> withContextIO(block: () -> T): T =
    kotlinx.coroutines.withContext(Dispatchers.IO) { block() }

/** Compresse une image (URI) en JPEG sous ~60 Ko pour tenir dans un jeton. */
private fun compressJpeg(context: Context, uri: Uri, targetBytes: Int = 62_000): ByteArray? {
    val input = context.contentResolver.openInputStream(uri) ?: return null
    val bitmap = input.use { BitmapFactory.decodeStream(it) } ?: return null
    val dims = listOf(720, 600, 480, 360, 280)
    val qualities = listOf(50, 40, 30, 20)
    for (dim in dims) {
        val scale = minOf(1f, dim.toFloat() / maxOf(bitmap.width, bitmap.height))
        val w = (bitmap.width * scale).toInt().coerceAtLeast(1)
        val h = (bitmap.height * scale).toInt().coerceAtLeast(1)
        val scaled = android.graphics.Bitmap.createScaledBitmap(bitmap, w, h, true)
        for (q in qualities) {
            val out = java.io.ByteArrayOutputStream()
            scaled.compress(android.graphics.Bitmap.CompressFormat.JPEG, q, out)
            val data = out.toByteArray()
            if (data.size <= targetBytes) return data
        }
    }
    val out = java.io.ByteArrayOutputStream()
    android.graphics.Bitmap.createScaledBitmap(bitmap, 220, 220, true)
        .compress(android.graphics.Bitmap.CompressFormat.JPEG, 15, out)
    return out.toByteArray()
}

/** Enregistreur vocal M4A (AAC) court. */
private class VoiceRecorder(private val context: Context) {
    private var recorder: MediaRecorder? = null
    private var file: File? = null

    fun start() {
        val f = File.createTempFile("brocolis-rec", ".m4a", context.cacheDir)
        file = f
        val r = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) MediaRecorder(context) else @Suppress("DEPRECATION") MediaRecorder()
        r.setAudioSource(MediaRecorder.AudioSource.MIC)
        r.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
        r.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
        r.setAudioSamplingRate(16_000)
        r.setAudioEncodingBitRate(24_000)
        r.setOutputFile(f.absolutePath)
        r.prepare(); r.start()
        recorder = r
    }

    fun stop(): ByteArray? {
        return try {
            recorder?.stop(); recorder?.release(); recorder = null
            file?.readBytes()
        } catch (_: Exception) { null } finally { file?.delete() }
    }
}
