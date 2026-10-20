package rs.brocolis.messagerie.proto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Fuzzing « du pauvre » (port de `proto/tests/robustesse.rs`) : des
 * milliers d'entrées aléatoires et de mutations de jetons valides passent par
 * chaque décodeur et par le déchiffrement v3. Aucune ne doit lever autre
 * chose qu'une [BrocolisException] (l'équivalent Kotlin de « ne jamais
 * paniquer »), et aucune entrée mutée ne doit être acceptée par le
 * déchiffrement.
 */
class RobustesseTest {
    private val t0 = 1_790_000_000L

    /** Exécute `bloc` : il réussit ou lève une [BrocolisException], rien d'autre. */
    private fun <T> sansPanique(quoi: String = "", bloc: () -> T): T? = try {
        bloc()
    } catch (_: BrocolisException) {
        null
    } catch (e: Throwable) {
        fail("$quoi : exception inattendue $e")
        null
    }

    private fun randomBytes(rng: CryptoRng, max: Int): ByteArray = rng.bytes((rng.nextU32() % (max + 1)).toInt())

    /** Une mutation : bits, octets, coupe, insertion, duplication. */
    private fun mutate(rng: CryptoRng, data: ByteArray): ByteArray {
        val v = data.toMutableList()
        repeat((1 + rng.nextU32() % 4).toInt()) {
            val len = maxOf(v.size, 1)
            val i = (rng.nextU32() % len).toInt()
            when ((rng.nextU32() % 6).toInt()) {
                0 -> if (v.isNotEmpty()) v[i] = (v[i].toInt() xor (1 shl (rng.nextU32() % 8).toInt())).toByte() else v.addAll(randomBytes(rng, 8).toList())
                1 -> if (v.isNotEmpty()) v[i] = rng.nextU32().toByte() else v.addAll(randomBytes(rng, 8).toList())
                2 -> while (v.size > i) v.removeAt(v.size - 1)
                3 -> v.add(minOf(i, v.size), rng.nextU32().toByte())
                4 -> if (v.isNotEmpty()) {
                    val j = (rng.nextU32() % v.size).toInt()
                    val (a, b) = minOf(i, j) to maxOf(i, j)
                    v.addAll(a, v.subList(a, b).toList())
                } else {
                    v.addAll(randomBytes(rng, 8).toList())
                }
                else -> v.addAll(randomBytes(rng, 8).toList())
            }
        }
        return v.toByteArray()
    }

    private fun lossy(b: ByteArray) = String(b, Charsets.UTF_8)

    @Test
    fun decodeursEntreesAleatoires() {
        val rng = Deterministic("aleatoire")
        val k1 = listOf(ByteArray(32) { 1 })
        for (i in 0 until 20_000) {
            val data = randomBytes(rng, 2_000)
            // Forcer de temps en temps un type valide en tête.
            if (data.isNotEmpty() && i % 2 == 0) data[0] = (1 + i % 4).toByte()
            sansPanique("Token") { Token.fromBytes(data) }
            sansPanique("KeyBundle") { KeyBundle.fromBytes(data) }
            sansPanique("distribution") { SenderKeyDistribution.fromBytes(data) }
            sansPanique("unpad") { Remplissage.unpad(data) }
            val text = lossy(data)
            sansPanique("decode") { Token.decode(text) }
            sansPanique("open") { Jetons.open(text, k1) }
            sansPanique("masked") { Jetons.masked(text) }
            sansPanique("findKey") { Jetons.findKey(text) }
            sansPanique("findAll") { Token.findAll(text) }
            sansPanique("v2Params") { CleProtegee.v2Params(text) }
            val b64 = Octets.b64(data)
            sansPanique("decode b64") { Token.decode("[[BROCOLIS:v3:$b64]]") }
            sansPanique("open b64") { Jetons.open("[[BROCOLIS:v1:$b64]] [[BROCOLIS:v2:$b64]]", k1) }
            sansPanique("v2Params b64") { CleProtegee.v2Params("[[BROCOLIS-CLE:v2:$b64]]") }
            sansPanique("Session json") { Session.fromJson(text) }
            sansPanique("Device json") { Device.fromJson(text) }
            if (i % 50 == 0) {
                sansPanique("bundle b64") { KeyBundle.fromBase64(b64) }
                sansPanique("Ed25519") { Kdf.ed25519Verify(data.copyOf(32), data, data.copyOf(64)) }
                sansPanique("X25519") { Kdf.x25519(ByteArray(32) { 5 }, data.copyOf(32)) }
            }
        }
    }

    @Test
    fun mutationsDeJetonsV3() {
        val rng = Deterministic("mutations")
        val alice = Device.generate(rng, t0, true)
        val bob = Device.generate(rng, t0, true)
        val a = alice.initiate(bob.bundle(), true, rng)
        val first = a.encryptToken("premier")
        val (b, _) = bob.accept((first as Token.InitialMessage).initial, t0, rng)
        val reply = b.encryptToken("réponse")
        val chain = SenderKeyState.generate(ByteArray(16) { 5 }, rng)
        val recv = ReceivedSenderKey.fromDistribution(chain.distribution())
        val group = chain.encryptToken("groupe")
        val dist = Token.decode(b.encryptDistribution(chain.distribution()))
        val samples = listOf(first.toBytes(), reply.toBytes(), group.toBytes(), dist.toBytes())
        val bobBefore = bob.toJson()
        val aBefore = a.toJson()
        var decoded = 0
        for (k in 0 until 6_000) {
            val base = samples[k % samples.size]
            val m = mutate(rng, base)
            if (m.contentEquals(base)) continue
            val t = sansPanique("fromBytes") { Token.fromBytes(m) } ?: continue
            decoded++
            // Le jeton muté peut rester bien formé : il ne doit jamais être lu.
            if (t.toBytes().contentEquals(base)) continue
            when (t) {
                is Token.InitialMessage -> {
                    assertTrue(sansPanique { bob.accept(t.initial, t0, rng) } == null)
                    assertTrue(sansPanique { Session.acceptPsk(listOf(ByteArray(32) { 1 }), t.initial, ReplayGuard(), t0, rng) } == null)
                    assertTrue(sansPanique { b.decrypt(t, t0, rng) } == null)
                }
                is Token.Message, is Token.Distribution -> assertTrue(sansPanique { a.decrypt(t, t0, rng) } == null)
                is Token.Group -> assertTrue(sansPanique { recv.decrypt(t.message, t0) } == null)
            }
        }
        assertTrue("$decoded", decoded > 100)
        assertEquals(bobBefore, bob.toJson())
        assertEquals(aBefore, a.toJson())
        // Les originaux passent toujours.
        assertEquals("réponse", texte(a.decrypt(reply, t0, rng)))
        assertEquals("groupe", recv.decrypt((group as Token.Group).message, t0))
    }

    @Test
    fun mutationsDEtatsJson() {
        val rng = Deterministic("json")
        val alice = Device.generate(rng, t0, false)
        val bob = Device.generate(rng, t0, false)
        val a = alice.initiate(bob.bundle(), false, rng)
        val (b, _) = bob.accept((a.encryptToken("x") as Token.InitialMessage).initial, t0, rng)
        val texts = listOf(b.toJson(), bob.toJson())
        for (k in 0 until 3_000) {
            val text = lossy(mutate(rng, Octets.utf8(texts[k % 2])))
            sansPanique("session") { Session.fromJson(text) }?.let { s ->
                // Un état relu, même altéré, ne fait jamais planter.
                sansPanique("encrypt") { s.encrypt("y") }
                sansPanique("decrypt") { s.decryptText("[[BROCOLIS:v3:AAAA]]", t0, rng) }
            }
            sansPanique("device") { Device.fromJson(text) }?.let { d -> sansPanique("bundle") { d.bundle() } }
        }
    }

    @Test
    fun mutationsDeClesProtegeesEtJetonsV1V2() {
        val rng = Deterministic("anciens")
        val key = ByteArray(32) { 3 }
        val v1 = Jetons.sealWith("ancien", listOf(key), rng)
        val v2 = Jetons.sealWith("ancien", listOf(key, ByteArray(32) { 4 }), rng)
        for (k in 0 until 4_000) {
            val text = lossy(mutate(rng, Octets.utf8(if (k % 2 == 0) v1 else v2)))
            val o = sansPanique { Jetons.open(text, listOf(key)) }!!
            // Une altération qui garde l'enveloppe ne s'ouvre jamais en un autre texte.
            if (o.opened > 0) assertTrue(o.text.contains("ancien"))
        }
        val protected = CleProtegee.protectKeyV2With(key, "phrase longue", Argon2Params.MINIMUM, ByteArray(16) { 1 }, ByteArray(12) { 2 })
        for (k in 0 until 2_000) {
            sansPanique { CleProtegee.v2Params(lossy(mutate(rng, Octets.utf8(protected)))) }
        }
    }
}
