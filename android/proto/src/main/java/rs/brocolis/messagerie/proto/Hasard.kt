package rs.brocolis.messagerie.proto

import java.security.SecureRandom

/**
 * Le hasard (`brocolis_proto::hasard`). En production : le CSPRNG du système
 * ([Hasard.system], `SecureRandom`), et rien d'autre. Toutes les fonctions
 * qui tirent du hasard le reçoivent en paramètre, ce qui permet aux vecteurs
 * de test d'injecter [Deterministic] : **jamais en production**.
 */
interface CryptoRng {
    /** Remplit `dst` d'octets aléatoires. */
    fun fill(dst: ByteArray)

    /** `n` octets aléatoires. */
    fun bytes(n: Int): ByteArray = ByteArray(n).also { fill(it) }

    /** Un u32 (4 octets, gros-boutiste, comme `next_u32` du générateur Rust). */
    fun nextU32(): Long = Octets.readU32(bytes(4), 0)
}

/** Le hasard du système. */
object Hasard {
    private val random = SecureRandom()

    /** Le CSPRNG du système (`SecureRandom`). */
    fun system(): CryptoRng = object : CryptoRng {
        override fun fill(dst: ByteArray) = random.nextBytes(dst)
    }
}

/**
 * Un générateur **déterministe**, pour les vecteurs de test et les tests : le
 * bloc `i` (32 octets) vaut `SHA-256("Brocolis_vecteurs" ‖ graine ‖ i u64
 * gros-boutiste)`, `i` partant de 0, et les octets sont servis dans l'ordre,
 * sans en jeter. Il ne doit **jamais** servir en production.
 */
class Deterministic(seed: ByteArray) : CryptoRng {
    constructor(seed: String) : this(Octets.utf8(seed))

    private val seed = seed.copyOf()
    private var counter = 0L
    private var block = ByteArray(32)
    private var used = 32

    private fun refill() {
        block = Kdf.sha256(Octets.concat(Octets.utf8("Brocolis_vecteurs"), seed, Octets.u64be(counter)))
        counter++
        used = 0
    }

    override fun fill(dst: ByteArray) {
        for (i in dst.indices) {
            if (used == 32) refill()
            dst[i] = block[used++]
        }
    }
}
