package rs.brocolis.messagerie.proto

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Interopérabilité avec la référence Rust au-delà de vectors.json :
 * `proto-swift/Tests/BrocolisProtoTests/Fixtures/reference-rust.json` a été
 * produit par la référence elle-même (programme `reference-rust.rs` à côté,
 * qui dépend de `proto/` par chemin) :
 *
 * - des états JSON écrits par Rust (appareils, sessions hybride et PSK,
 *   chaînes de groupe, mémoire des premiers messages, une session riche en
 *   clés sautées et en cliquets passés) : Kotlin les relit, les réécrit
 *   sous la même forme JSON, et continue les conversations ;
 * - le décodage des points Ed25519 de curve25519-dalek (point ou non, petit
 *   ordre ou non), comparé à [Kdf.ed25519IsValidPublic] ;
 * - Argon2id de la crate `argon2` (plusieurs voies, sortie longue).
 *
 * Le sens inverse (Rust relit les états et les jetons écrits par Kotlin) se
 * vérifie en lançant ces tests avec `BROCOLIS_INTEROP_OUT=<fichier>`, puis
 * `reference-rust phase3 <fichier>` (même format que pour Swift).
 */
class ReferenceRustTest {
    private val t0 = 1_790_000_000L
    private val fixture by lazy { Depot.json("proto-swift/Tests/BrocolisProtoTests/Fixtures/reference-rust.json") }

    @Test
    fun argon2idCommeLaCrateArgon2() {
        for (e in fixture.a("argon2id")) {
            val c = e.jsonObject
            val out = CleProtegee.argon2id(
                Octets.utf8("brocoli"), ByteArray(16) { 0x55 }, c.n("m").toInt(), c.n("t").toInt(), c.n("p").toInt(), c.n("len").toInt(),
            )
            egal(c.s("out"), hex(out), "Argon2id m=${c.n("m")} t=${c.n("t")} p=${c.n("p")} ${c.n("len")} octets", "rust")
        }
    }

    @Test
    fun pointsEd25519CommeDalek() {
        val cases = fixture.a("ed25519_points")
        var points = 0
        var small = 0
        for (e in cases) {
            val c = e.jsonObject
            val enc = c.b("enc")
            val isPoint = c["point"]!!.jsonPrimitive.boolean
            val isSmall = c["small"]!!.jsonPrimitive.boolean
            // Une clé publique utilisable (dalek : `from_bytes` puis `!is_weak()`) :
            // un point, pas de petit ordre.
            assertEquals(hex(enc), isPoint && !isSmall, Kdf.ed25519IsValidPublic(enc))
            if (isPoint) points++
            if (isSmall) small++
            Compteur.ajouter("rust")
        }
        println("Points Ed25519 comparés à curve25519-dalek : ${cases.size} ($points points, $small de petit ordre)")
    }

    @Test
    fun etatsEtJetonsDeLaReference() {
        val e = fixture.o("etats")
        val rng = Deterministic("phase2")
        val texts = e.a("texts").map { it.s() }
        val tokens = e.a("tokens").map { it.s() }

        // Les états relus se réécrivent sous la même forme JSON.
        val bobJson = e.o("bob_device").toString()
        val bob = Device.fromJson(bobJson)
        memeForme(bobJson, bob.toJson(), "appareil")
        memeForme(e.o("alice_device").toString(), Device.fromJson(e.o("alice_device").toString()).toJson(), "appareil")
        val aliceJson = e.o("alice_session").toString()
        val alice = Session.fromJson(aliceJson)
        memeForme(aliceJson, alice.toJson(), "session (préambule hybride compris)")
        val pskJson = e.o("psk_session").toString()
        val pskA = Session.fromJson(pskJson)
        memeForme(pskJson, pskA.toJson(), "session PSK")
        val chainJson = e.o("chain").toString()
        val chain = SenderKeyState.fromJson(chainJson)
        memeForme(chainJson, chain.toJson(), "chaîne de groupe")
        val receivedJson = e.o("received").toString()
        val received = ReceivedSenderKey.fromJson(receivedJson)
        memeForme(receivedJson, received.toJson(), "chaîne reçue")
        val guardJson = e.o("replay_guard").toString()
        val replay = ReplayGuard.fromJson(guardJson)
        memeForme(guardJson, replay.toJson(), "mémoire des premiers messages")
        assertTrue(replay.seen(ByteArray(32) { 9 }))

        // Une session riche (clés sautées, cliquets passés) : même forme, et
        // le message en retard s'ouvre par sa clé sautée gardée par Rust.
        val rich = e.o("rich")
        val dJson = rich.o("d").toString()
        val cJson = rich.o("c").toString()
        val dSession = Session.fromJson(dJson)
        val cSession = Session.fromJson(cJson)
        memeForme(dJson, dSession.toJson(), "session avec clés sautées")
        memeForme(cJson, cSession.toJson(), "session avec cliquets passés")
        memeForme(rich.o("dave_device").toString(), Device.fromJson(rich.o("dave_device").toString()).toJson(), "appareil après un premier message")
        assertEquals(2, dSession.skippedLen)
        egal(rich.s("pending_text"), texte(dSession.decryptText(rich.s("pending"), t0, rng)), "clé sautée gardée par Rust", "rust")
        assertEquals(1, dSession.skippedLen)
        egal("d2", texte(cSession.decryptText(dSession.encrypt("d2"), t0, rng)), "suite", "rust")
        val richRecvJson = rich.o("received").toString()
        val richRecv = ReceivedSenderKey.fromJson(richRecvJson)
        memeForme(richRecvJson, richRecv.toJson(), "chaîne reçue avec clé sautée")
        egal(
            rich.s("late_group_text"),
            richRecv.decrypt((Token.decode(rich.s("late_group")) as Token.Group).message, t0),
            "message de groupe en retard", "rust",
        )

        // Le paquet de Bob (signé par Rust) se vérifie ; Kotlin le refait à l'identique.
        val bundle = KeyBundle.fromBase64(e.s("bob_bundle"))
        egal(hex(bundle.toBytes()), hex(bob.bundle().toBytes()), "paquet refait par Kotlin", "rust")

        // Bob (Kotlin, état Rust) accepte les premiers messages d'Alice (Rust),
        // dans le désordre.
        val i2 = (Token.decode(tokens[1]) as Token.InitialMessage).initial
        val (b, c2) = bob.accept(i2, t0, rng)
        egal(texts[1], texte(c2), "Rust → Kotlin (2)", "rust")
        egal(texts[0], texte(b.decryptText(tokens[0], t0, rng)), "Rust → Kotlin (1)", "rust")
        assertTrue(b.isPostQuantum)
        // La distribution (0x03) envoyée par Alice, puis le groupe.
        val d = (b.decryptText(e.s("distribution"), t0, rng) as Content.Distribution).distribution
        val recv = ReceivedSenderKey.fromDistribution(d)
        for ((i, g) in e.a("group_tokens").map { it.s() }.withIndex()) {
            egal("groupe ${i + 1}", recv.decrypt((Token.decode(g) as Token.Group).message, t0), "groupe", "rust")
        }
        // La chaîne Rust (relue) continue ; la chaîne reçue Rust (relue) lit.
        val g3 = (chain.encryptToken("groupe 3") as Token.Group).message
        egal("groupe 3", received.decrypt(g3, t0), "chaîne relue", "rust")
        egal("groupe 3", recv.decrypt(g3, t0), "chaîne reçue", "rust")
        // Alice (Kotlin, session Rust) lit la réponse de Bob (Kotlin).
        val r1 = b.encrypt("Kotlin → Rust 1")
        egal("Kotlin → Rust 1", texte(alice.decryptText(r1, t0, rng)), "réponse", "rust")
        assertTrue(alice.isConfirmed)
        // PSK : le premier message de Rust, accepté par Kotlin.
        val (pskB, pc) = Session.acceptPsk(
            listOf(e.b("psk_key")), (Token.decode(e.s("psk_token")) as Token.InitialMessage).initial, ReplayGuard(), t0, rng,
        )
        egal("PSK de Rust", texte(pc), "PSK", "rust")
        egal("PSK de Kotlin", texte(pskA.decryptText(pskB.encrypt("PSK de Kotlin"), t0, rng)), "PSK retour", "rust")

        // Pour le sens inverse (manuel) : ce que Rust relira (`reference-rust phase3`).
        val out = System.getenv("BROCOLIS_INTEROP_OUT") ?: return
        val toAlice = listOf("Kotlin → Rust 2", "Kotlin → Rust 3 🥦")
        val pending = toAlice.map { b.encrypt(it) }
        val sys = Hasard.system()
        val dev = Device.generate(sys, t0, true)
        val initiator = Device.generate(sys, t0, true)
        val sInit = initiator.initiate(dev.bundle(), true, sys)
        val kChain = SenderKeyState.generate(Groupe.newGroupId(sys), sys)
        val kRecv = ReceivedSenderKey.fromDistribution(kChain.distribution())
        val kGuard = ReplayGuard()
        kGuard.insert(ByteArray(32) { 7 }, t0)
        val v = buildJsonObject {
            put("alice_session", alice.toJson())
            put("bob_session", b.toJson())
            put("to_alice", JsonArray(pending.map { JsonPrimitive(it) }))
            put("to_alice_texts", JsonArray(toAlice.map { JsonPrimitive(it) }))
            put("swift_device", dev.toJson())
            put("swift_bundle", dev.bundle().toBase64())
            put("swift_initial", sInit.encrypt("Kotlin initie"))
            put("swift_initial_text", "Kotlin initie")
            put("swift_initial_pq", sInit.isPostQuantum)
            put("received", kRecv.toJson())
            put("chain", kChain.toJson())
            put("group_token", kChain.encrypt("groupe Kotlin"))
            put("group_text", "groupe Kotlin")
            put("replay_guard", kGuard.toJson())
        }
        File(out).writeText(v.toString())
        println("États Kotlin écrits pour la référence : $out")
    }

    companion object {
        @AfterClass
        @JvmStatic
        fun bilan() {
            println("Valeurs comparées à la référence Rust (états, points, Argon2) : ${Compteur.total("rust")}")
        }
    }
}
