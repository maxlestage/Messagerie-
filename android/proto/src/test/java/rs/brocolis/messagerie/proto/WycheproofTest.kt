package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Les vecteurs Wycheproof (C2SP/wycheproof, `testvectors_v1`, Apache 2.0 :
 * `proto/tests/wycheproof/LICENSE`) des primitives du protocole, passés aux
 * fonctions de [Kdf] et [MlKem] elles-mêmes, avec la politique de la
 * référence Rust (`proto/tests/wycheproof.rs`) : chaque cas « invalid » est
 * refusé ; un cas « acceptable » suit la politique dite pour chacun.
 */
class WycheproofTest {
    private fun cas(fichier: String): List<Pair<JsonObject, JsonObject>> {
        val v = Depot.json("proto/tests/wycheproof/$fichier")
        return v.a("testGroups").flatMap { g -> g.jsonObject.a("tests").map { g.jsonObject to it.jsonObject } }
    }

    private fun JsonObject.flags(): List<String> = a("flags").map { it.s() }

    private fun compter(primitive: String, n: Int) {
        Compteur.ajouter("wycheproof", n)
        println("Wycheproof $primitive : $n cas")
    }

    @Test
    fun aes256Gcm() {
        var n = 0
        for ((g, t) in cas("aes_gcm_test.json")) {
            // Le protocole n'utilise qu'AES-256, nonce 96 bits, tag 128 bits.
            if (g["keySize"]!!.jsonPrimitive.int != 256 || g["ivSize"]!!.jsonPrimitive.int != 96 || g["tagSize"]!!.jsonPrimitive.int != 128) continue
            val id = t.n("tcId")
            val key = t.b("key")
            val iv = t.b("iv")
            val ct = Octets.concat(t.b("ct"), t.b("tag"))
            when (t.s("result")) {
                "valid" -> {
                    assertArrayEquals("tcId $id", ct, Kdf.aesGcmSeal(key, iv, t.b("aad"), t.b("msg")))
                    assertArrayEquals("tcId $id", t.b("msg"), Kdf.aesGcmOpen(key, iv, t.b("aad"), ct))
                }
                else -> attendreErreur(Erreur.Dechiffrement, "tcId $id") { Kdf.aesGcmOpen(key, iv, t.b("aad"), ct) }
            }
            n++
        }
        assertTrue("$n", n >= 60)
        compter("AES-256-GCM", n)
    }

    @Test
    fun x25519() {
        var n = 0
        for ((_, t) in cas("x25519_test.json")) {
            val id = t.n("tcId")
            val f = t.flags()
            val shared = t.s("shared")
            val r = runCatching { Kdf.x25519(t.b("private"), t.b("public")) }
            // Notre politique : refuser un secret nul (petit ordre) et une clé
            // publique non canonique (bit 255 levé ou u ≥ p). Tout le reste
            // doit donner exactement le secret attendu.
            if ("ZeroSharedSecret" in f || "NonCanonicalPublic" in f) {
                assertEquals("tcId $id $f", Erreur.CleInvalide, (r.exceptionOrNull() as? BrocolisException)?.erreur)
            } else if (t.s("result") == "invalid") {
                assertTrue("tcId $id", r.isFailure || hex(r.getOrThrow()) != shared)
            } else {
                assertEquals("tcId $id $f", shared, hex(r.getOrThrow()))
            }
            n++
        }
        assertTrue(n > 500)
        // La clé publique de base : RFC 7748 §6.1.
        assertEquals(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            hex(Kdf.x25519Public(unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))),
        )
        compter("X25519", n)
    }

    @Test
    fun hkdfSha256() {
        var n = 0
        for ((_, t) in cas("hkdf_sha256_test.json")) {
            val size = t.n("size").toInt()
            val r = runCatching { Kdf.hkdfSha256(t.b("salt"), t.b("ikm"), t.b("info"), size) }
            when (t.s("result")) {
                "valid" -> assertEquals("tcId ${t.n("tcId")}", t.s("okm"), hex(r.getOrThrow()))
                else -> assertEquals("tcId ${t.n("tcId")}", Erreur.TropGrand, (r.exceptionOrNull() as? BrocolisException)?.erreur)
            }
            n++
        }
        assertTrue(n > 80)
        compter("HKDF-SHA256", n)
    }

    @Test
    fun hmacSha256() {
        var n = 0
        for ((g, t) in cas("hmac_sha256_test.json")) {
            val bits = g["tagSize"]!!.jsonPrimitive.int
            val tag = Kdf.hmacSha256(t.b("key"), t.b("msg"))
            val same = tag.copyOf(bits / 8).contentEquals(t.b("tag"))
            assertEquals("tcId ${t.n("tcId")}", t.s("result") == "valid", same)
            n++
        }
        assertTrue(n > 150)
        compter("HMAC-SHA256", n)
    }

    @Test
    fun ed25519() {
        var n = 0
        for ((g, t) in cas("ed25519_test.json")) {
            val pk = unhex(g.o("publicKey").s("pk"))
            val sig = t.b("sig")
            val ok = runCatching { Kdf.ed25519Verify(pk, t.b("msg"), sig) }.isSuccess
            assertEquals("tcId ${t.n("tcId")} ${t.s("comment")}", t.s("result") == "valid", ok)
            n++
        }
        assertTrue(n > 140)
        compter("Ed25519 (vérification stricte)", n)
    }

    @Test
    fun mlkem768() {
        var n = 0
        for ((_, t) in cas("mlkem_768_test.json")) {
            val id = t.n("tcId")
            val seed = t.b("seed")
            if (seed.size != 64) {
                // Graine de mauvaise longueur : refusée.
                assertEquals("tcId $id", "invalid", t.s("result"))
                attendreErreur(Erreur.Format, "tcId $id") { MlKem.decapsulate(seed, t.b("c")) }
                n++
                continue
            }
            if (t["ek"] != null) assertEquals("tcId $id", t.s("ek"), hex(MlKem.publicKey(seed)))
            val r = runCatching { MlKem.decapsulate(seed, t.b("c")) }
            when (t.s("result")) {
                "valid" -> assertEquals("tcId $id", t.s("K"), hex(r.getOrThrow()))
                else -> assertEquals("tcId $id", Erreur.Format, (r.exceptionOrNull() as? BrocolisException)?.erreur)
            }
            n++
        }
        assertTrue(n > 190)
        compter("ML-KEM-768", n)
    }

    companion object {
        @AfterClass
        @JvmStatic
        fun bilan() {
            println("Cas Wycheproof passés : ${Compteur.total("wycheproof")}")
        }
    }
}
