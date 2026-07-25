package rs.brocolis.messagerie.net

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

@Serializable data class PairingPeer(val peerId: String, val pub: String)
@Serializable data class WrapItem(val toPeerId: String, val blob: String)
@Serializable data class WrapInbox(val from: String, val fromPub: String, val blob: String)

@Serializable private data class PairingResponse(val peers: List<PairingPeer> = emptyList())
@Serializable private data class WrapResponse(val wrap: WrapInbox? = null)

@Serializable private data class PublishBody(val code: String, val peerId: String, val pub: String)
@Serializable private data class WrapBody(
    val code: String, val fromPeerId: String, val fromPub: String, val items: List<WrapItem>
)

class PairingException(message: String) : Exception(message)

/**
 * Client du serveur de rendez-vous : échange de clés publiques (appairage à deux)
 * et distribution des clés de groupe emballées. Port de PairingClient.swift.
 * Le serveur ne voit que des clés publiques et des blobs chiffrés.
 */
class PairingClient(private val baseURL: String) {

    private val json = Json { ignoreUnknownKeys = true }
    private val jsonMedia = "application/json".toMediaType()
    private val http = OkHttpClient.Builder()
        .callTimeout(15, TimeUnit.SECONDS)
        .build()

    suspend fun publish(code: String, peerId: String, pub: String): List<PairingPeer> {
        val data = raw("POST", "/pair", json.encodeToString(PublishBody(code, peerId, pub)))
        return json.decodeFromString<PairingResponse>(data).peers
    }

    suspend fun fetch(code: String, peerId: String): List<PairingPeer> {
        val data = raw("GET", "/pair?" + query(code, peerId), null)
        return json.decodeFromString<PairingResponse>(data).peers
    }

    suspend fun postWraps(code: String, fromPeerId: String, fromPub: String, items: List<WrapItem>) {
        raw("POST", "/wrap", json.encodeToString(WrapBody(code, fromPeerId, fromPub, items)))
    }

    suspend fun fetchWrap(code: String, peerId: String): WrapInbox? {
        val data = raw("GET", "/wrap?" + query(code, peerId), null)
        return json.decodeFromString<WrapResponse>(data).wrap
    }

    private fun query(code: String, peerId: String): String {
        val c = URLEncoder.encode(code, "UTF-8")
        val p = URLEncoder.encode(peerId, "UTF-8")
        return "code=$c&peerId=$p"
    }

    private suspend fun raw(method: String, path: String, body: String?): String =
        withContext(Dispatchers.IO) {
            val base = baseURL.trimEnd('/')
            val builder = Request.Builder().url(base + path)
            if (body != null) {
                builder.header("content-type", "application/json")
                builder.method(method, body.toRequestBody(jsonMedia))
            } else {
                builder.method(method, null)
            }
            try {
                http.newCall(builder.build()).execute().use { resp ->
                    if (!resp.isSuccessful) throw PairingException("Le serveur a répondu ${resp.code}.")
                    resp.body?.string() ?: ""
                }
            } catch (e: PairingException) {
                throw e
            } catch (e: Exception) {
                throw PairingException("Erreur réseau : ${e.message}")
            }
        }
}
