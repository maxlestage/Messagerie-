package rs.brocolis.messagerie.store

import kotlinx.serialization.Serializable

/**
 * Une clé nommée, avec sa durée de validité propre. Port de la struct iOS
 * `NamedKey`. `expiresAt` est un timestamp epoch en millisecondes (nullable).
 *
 * v3 (docs/SECURITE.md §8.4, §8.5) : `v3Bundle` est le paquet de clés du
 * correspondant reçu à l'appairage (base64, public et signé) et
 * `v3SinceSeconds` sa date d'arrivée (secondes Unix) ; `duo` : appairés à
 * deux (`true`) ou clé de groupe (`false`), `null` pour une clé créée ou
 * importée ; `psk` : l'utilisateur l'a marquée « à deux, double cliquet ».
 */
@Serializable
data class NamedKey(
    val id: String,
    var name: String,
    val base64: String,
    var ttlSeconds: Int = 0,          // 0 = jamais d'expiration
    var expiresAtMillis: Long? = null, // calculée à l'ajout / au changement de TTL
    var v3Bundle: String? = null,
    var v3SinceSeconds: Long? = null,
    var duo: Boolean? = null,
    var psk: Boolean? = null
)
