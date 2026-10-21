package rs.brocolis.messagerie.crypto

import rs.brocolis.messagerie.i18n.loc
import rs.brocolis.messagerie.proto.Octets
import rs.brocolis.messagerie.store.NamedKey

/**
 * L'alerte de changement d'identité (docs/SECURITE.md §9.8), comme Signal :
 * l'identité d'un contact (IK X25519 ‖ IK Ed25519 de son paquet) ne change
 * pas en silence. Un ré-appairage qui en donne une autre garde l'ancienne,
 * marque le contact, et **rien ne part plus vers lui** — ni v3/v4 ni v1/v2,
 * puisque la clé partagée vient du même ré-appairage — tant que
 * l'utilisateur n'a pas comparé l'empreinte. La lecture reste possible.
 *
 * Logique pure (port de `repair_paired` / `confirm_identity` de brocolis) ;
 * le rangement est dans `BrocolisKeyStore`.
 */
object BrocolisIdentity {
    /** Ce que l'interface affiche pour un contact dont l'identité a changé. */
    val warning: String
        get() = loc(
            "⚠️ L'identité de ce contact a changé — comparez l'empreinte avant d'écrire",
            "⚠️ This contact's identity has changed — compare the fingerprint before writing",
            "⚠️ La identidad de este contacto ha cambiado — compara la huella antes de escribir",
        )

    /** Le bouton qui lève l'alerte. */
    val confirm: String
        get() = loc("J'ai comparé l'empreinte", "I compared the fingerprint", "He comparado la huella")

    /** L'identité d'un paquet (base64) : IK X25519 ‖ IK Ed25519, ou `null` s'il est invalide. */
    fun identityOf(bundle: String?): ByteArray? = BrocolisV3Api.bundle(bundle)?.let(BrocolisV3Format::identity)

    /** L'envoi vers cette clé est-il bloqué (§9.8) ? */
    fun blocked(k: NamedKey): Boolean = k.identityChanged == true

    /** L'envoi vers l'une de ces clés est-il bloqué (échec fermé pour tout l'envoi) ? */
    fun blocked(ks: List<NamedKey>): Boolean = ks.any(::blocked)

    /**
     * Ré-appaire `k` : nouvelle clé, nouveau paquet (et capacité v4). Si le
     * paquet porte une autre identité que celui d'avant, l'ancienne est
     * gardée (une alerte encore en attente garde celle d'avant la première)
     * et le contact est marqué. Renvoie la clé mise à jour et `true` si
     * l'envoi est bloqué.
     */
    fun repaired(
        k: NamedKey,
        keyBase64: String,
        bundle: String?,
        duo: Boolean,
        caps: String?,
        nowSeconds: Long,
    ): Pair<NamedKey, Boolean> {
        val old = identityOf(k.v3Bundle)
        val new = identityOf(bundle)
        val already = k.identityChanged == true
        val changed = old != null && new != null && !old.contentEquals(new)
        val out = k.copy(
            base64 = keyBase64.trim(),
            v3Bundle = bundle,
            v3SinceSeconds = if (bundle == null) null else nowSeconds,
            v3Caps = if (bundle == null) null else caps,
            duo = duo,
            psk = null,
            identityChanged = if (changed || already) true else null,
            previousIdentity = when {
                already -> k.previousIdentity
                changed -> Octets.b64(old!!)
                else -> null
            },
        )
        return out to (changed || already)
    }

    /** « J'ai comparé l'empreinte » : l'alerte tombe. */
    fun confirmed(k: NamedKey): NamedKey = k.copy(identityChanged = null, previousIdentity = null)
}
