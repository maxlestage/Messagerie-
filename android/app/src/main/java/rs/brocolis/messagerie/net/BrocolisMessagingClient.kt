package rs.brocolis.messagerie.net

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.sse.EventSource
import okhttp3.sse.EventSourceListener
import okhttp3.sse.EventSources
import rs.brocolis.messagerie.crypto.BrocolisCrypto
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

@Serializable data class RawMessage(
    val id: String,
    val senderId: String,
    val ciphertext: String,
    val seq: Long
)

@Serializable private data class Page(
    val messages: List<RawMessage> = emptyList(),
    val cursor: Long = 0,
    val readers: Map<String, Long>? = null
)

@Serializable private data class ReadEvent(val type: String, val reader: String, val upTo: Long)

@Serializable private data class SendBody(
    val id: String, val conversationId: String, val senderId: String, val ciphertext: String
)

@Serializable private data class ReadBody(val conversationId: String, val upTo: Long)

/**
 * Parle à l'API de messagerie Rust (`/v1/*`). Chiffre/déchiffre avec une clé
 * Brocolis ; le serveur ne voit que des jetons `[[BROCOLIS:v1:…]]`. Port de
 * `BrocolisMessagingClient` (MessagingView.swift). En-tête `X-User-Id = deviceId`.
 */
class BrocolisMessagingClient(private val baseURL: String, private val deviceId: String) {

    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMedia = "application/json".toMediaType()
    private val http = OkHttpClient.Builder().callTimeout(20, TimeUnit.SECONDS).build()
    // Client dédié au flux SSE : aucun timeout de lecture.
    private val streamHttp = OkHttpClient.Builder()
        .readTimeout(0, TimeUnit.MILLISECONDS)
        .callTimeout(0, TimeUnit.MILLISECONDS)
        .build()

    data class FetchResult(val messages: List<RawMessage>, val cursor: Long, val readers: Map<String, Long>)

    companion object {
        /**
         * Identifiant de conversation dérivé de la clé partagée : SHA-256 de
         * "brocolis-conv-v1" ‖ clé, en base64url sans padding. Déterministe et à
         * sens unique — identique pour les deux correspondants. Doit matcher iOS.
         */
        fun conversationId(forKeyBase64: String): String? {
            val key = try { BrocolisCrypto.keyBytes(forKeyBase64) } catch (_: Exception) { return null }
            val md = MessageDigest.getInstance("SHA-256")
            md.update("brocolis-conv-v1".toByteArray(Charsets.UTF_8))
            md.update(key)
            val digest = md.digest()
            return Base64.encodeToString(digest, Base64.NO_WRAP)
                .replace("+", "-").replace("/", "_").replace("=", "")
        }
    }

    private fun urlFor(path: String): String = baseURL.trimEnd('/') + "/" + path.trimStart('/')

    suspend fun send(text: String, conversationId: String, key: ByteArray) = withContext(Dispatchers.IO) {
        val token = BrocolisCrypto.encryptToken(text.toByteArray(Charsets.UTF_8), key)
        val body = SendBody(UUID.randomUUID().toString(), conversationId, deviceId, token)
        val req = Request.Builder()
            .url(urlFor("v1/messages"))
            .header("X-User-Id", deviceId)
            .header("Content-Type", "application/json")
            .post(json.encodeToString(body).toRequestBody(jsonMedia))
            .build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw Exception("Envoi refusé (${resp.code}).")
        }
    }

    suspend fun fetch(conversationId: String, after: Long): FetchResult = withContext(Dispatchers.IO) {
        val url = urlFor("v1/messages").toHttpUrlish("conversationId" to conversationId, "after" to after.toString())
        val req = Request.Builder().url(url).header("X-User-Id", deviceId).get().build()
        http.newCall(req).execute().use { resp ->
            val data = resp.body?.string() ?: "{}"
            val page = json.decodeFromString<Page>(data)
            FetchResult(page.messages, page.cursor, page.readers ?: emptyMap())
        }
    }

    suspend fun markRead(conversationId: String, upTo: Long) = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url(urlFor("v1/read"))
            .header("X-User-Id", deviceId)
            .header("Content-Type", "application/json")
            .post(json.encodeToString(ReadBody(conversationId, upTo)).toRequestBody(jsonMedia))
            .build()
        try { http.newCall(req).execute().use { } } catch (_: Exception) { }
        Unit
    }

    /**
     * Flux temps réel (SSE). Renvoie l'`EventSource` : appeler `.cancel()` pour
     * arrêter. `onMessage` pour un message, `onRead` pour un accusé de lecture.
     */
    fun openStream(
        conversationId: String,
        onMessage: (RawMessage) -> Unit,
        onRead: (String, Long) -> Unit,
        onClosed: () -> Unit
    ): EventSource {
        val url = urlFor("v1/stream").toHttpUrlish("conversationId" to conversationId)
        val req = Request.Builder()
            .url(url)
            .header("X-User-Id", deviceId)
            .header("Accept", "text/event-stream")
            .build()
        val listener = object : EventSourceListener() {
            override fun onEvent(eventSource: EventSource, id: String?, type: String?, data: String) {
                // Chaque évènement : soit un accusé {type:"read"}, soit un message.
                try {
                    val ev = json.decodeFromString<ReadEvent>(data)
                    if (ev.type == "read") { onRead(ev.reader, ev.upTo); return }
                } catch (_: Exception) { }
                try { onMessage(json.decodeFromString<RawMessage>(data)) } catch (_: Exception) { }
            }
            override fun onClosed(eventSource: EventSource) { onClosed() }
            override fun onFailure(eventSource: EventSource, t: Throwable?, response: Response?) { onClosed() }
        }
        return EventSources.createFactory(streamHttp).newEventSource(req, listener)
    }
}

/** Petit utilitaire : construit une URL avec paramètres de requête encodés. */
private fun String.toHttpUrlish(vararg params: Pair<String, String>): String {
    val base = this.toHttpUrl().newBuilder()
    for ((k, v) in params) base.addQueryParameter(k, v)
    return base.build().toString()
}
