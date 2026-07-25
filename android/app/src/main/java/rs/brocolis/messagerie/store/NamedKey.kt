package rs.brocolis.messagerie.store

import kotlinx.serialization.Serializable

/**
 * Une clé nommée, avec sa durée de validité propre. Port de la struct iOS
 * `NamedKey`. `expiresAt` est un timestamp epoch en millisecondes (nullable).
 */
@Serializable
data class NamedKey(
    val id: String,
    var name: String,
    val base64: String,
    var ttlSeconds: Int = 0,          // 0 = jamais d'expiration
    var expiresAtMillis: Long? = null // calculée à l'ajout / au changement de TTL
)
