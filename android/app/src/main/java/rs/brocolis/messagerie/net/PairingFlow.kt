package rs.brocolis.messagerie.net

import kotlinx.coroutines.delay
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import rs.brocolis.messagerie.crypto.BrocolisKeyAgreement
import rs.brocolis.messagerie.crypto.BrocolisV3Contact

/**
 * L'appairage « à deux » (mode compatible : les deux saisissent le même code),
 * sans interface ni stockage : l'écran (`PairingScreen`) range ensuite la clé
 * et son contact v3. Chacun publie sa clé publique X25519 et, s'il l'a, son
 * paquet v3 (docs/SECURITE.md §8.4) ; toujours à deux.
 */
object PairingFlow {

    /**
     * @property keyBase64 la clé partagée dérivée ;
     * @property legacyFingerprint l'empreinte d'avant (sans v3) ;
     * @property peer le correspondant ;
     * @property contact son contact v3 (paquet, à deux).
     */
    class Paired(
        val keyBase64: String,
        val legacyFingerprint: String,
        val peer: PairingPeer,
        val contact: BrocolisV3Contact,
    )

    /**
     * Publie ma clé (et `myBundle`, avec `myCaps`, §9.6), attend celle de l'autre (`attempts`
     * relectures), dérive la clé. `null` : personne n'est venu.
     */
    suspend fun pairTwo(
        client: PairingClient,
        code: String,
        peerId: String,
        priv: X25519PrivateKeyParameters,
        myBundle: String?,
        attempts: Int = 10,
        delayMillis: Long = 1_500,
        myCaps: String? = null,
    ): Paired? {
        val myPub = BrocolisKeyAgreement.publicKeyBase64(priv)
        var peers = client.publish(code, peerId, myPub, bundle = myBundle, caps = if (myBundle == null) null else myCaps)
        var peer = peers.firstOrNull { it.peerId != peerId }
        var tries = 0
        while (peer == null && tries < attempts) {
            delay(delayMillis)
            peers = client.fetch(code, peerId)
            peer = peers.firstOrNull { it.peerId != peerId }
            tries++
        }
        if (peer == null) return null
        val derived = BrocolisKeyAgreement.derive(priv, peer.pub)
        return Paired(derived.symmetricKeyBase64, derived.fingerprint, peer, BrocolisV3Contact.compatible(peer, myBundle))
    }
}
