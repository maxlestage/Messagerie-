package rs.brocolis.messagerie.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Les tests unitaires de chaque module de la référence Rust (`#[cfg(test)]`
 * de `kdf`, `remplissage`, `cle_protegee`, `jetons`, `jeton_v3`, `paquet`,
 * `hasard`), portés tels quels, plus les contrôles propres au portage
 * (base64 et UTF-8 stricts, espaces Unicode, Ed25519 strict).
 */
class ModulesTest {
    private fun cle() = ByteArray(32) { it.toByte() }

    // ----- hasard -----------------------------------------------------------

    @Test
    fun deterministeEtContinu() {
        val x = Deterministic("x").bytes(40)
        val b = Deterministic("x")
        val y = Octets.concat(b.bytes(7), b.bytes(33))
        assertArrayEquals(x, y)
        assertArrayEquals(Kdf.sha256(Octets.concat(Octets.utf8("Brocolis_vecteurs"), Octets.utf8("x"), ByteArray(8))), x.copyOf(32))
        assertFalse(Hasard.system().bytes(32).contentEquals(Hasard.system().bytes(32)))
    }

    // ----- kdf --------------------------------------------------------------

    @Test
    fun hkdfRfc5869Cas1() {
        val okm = Kdf.hkdfSha256(ByteArray(13) { it.toByte() }, ByteArray(22) { 0x0b }, ByteArray(10) { (0xf0 + it).toByte() }, 42)
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", hex(okm))
        attendreErreur(Erreur.TropGrand) { Kdf.hkdfSha256(ByteArray(0), ByteArray(1), ByteArray(0), 255 * 32 + 1) }
        assertEquals(255 * 32, Kdf.hkdfSha256(ByteArray(0), ByteArray(1), ByteArray(0), 255 * 32).size)
    }

    @Test
    fun x25519Rfc7748EtCanonicite() {
        val a = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val b = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", hex(Kdf.x25519Public(a)))
        assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", hex(Kdf.x25519(a, Kdf.x25519Public(b))))
        // DH nul refusé (§7.3).
        attendreErreur(Erreur.CleInvalide) { Kdf.x25519(a, ByteArray(32)) }
        attendreErreur(Erreur.CleInvalide) { Kdf.x25519(a, ByteArray(32).also { it[0] = 1 }) }
        // La même clé, bit 255 levé : refusée.
        val bPub = Kdf.x25519Public(b)
        bPub[31] = (bPub[31].toInt() or 0x80).toByte()
        attendreErreur(Erreur.CleInvalide) { Kdf.x25519(a, bPub) }
        val p = ByteArray(32) { 0xff.toByte() }
        p[31] = 0x7f
        p[0] = 0xed.toByte()
        assertFalse(Kdf.x25519IsCanonical(p))
        p[0] = 0xec.toByte()
        assertTrue(Kdf.x25519IsCanonical(p))
    }

    @Test
    fun ed25519Strict() {
        val seed = ByteArray(32) { 7 }
        val pk = Kdf.ed25519Public(seed)
        val msg = Octets.utf8("Brocolis")
        val sig = Kdf.ed25519Sign(seed, msg)
        Kdf.ed25519Verify(pk, msg, sig)
        attendreErreur(Erreur.Signature) { Kdf.ed25519Verify(pk, Octets.utf8("brocolis"), sig) }
        // La signature « universelle » A = R = identité, S = 0 : refusée
        // (CryptoKit et BoringSSL l'acceptent ; dalek strict non).
        val identite = ByteArray(32).also { it[0] = 1 }
        attendreErreur(Erreur.CleInvalide) { Kdf.ed25519Verify(identite, msg, Octets.concat(identite, ByteArray(32))) }
        // R de petit ordre avec une clé valide : refusé.
        attendreErreur(Erreur.Signature) { Kdf.ed25519Verify(pk, msg, Octets.concat(identite, sig.copyOfRange(32, 64))) }
        // S non canonique (S + L) : refusé.
        val l = unhex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
        val s = sig.copyOfRange(32, 64)
        var carry = 0
        val sl = ByteArray(32) { i -> val v = (s[i].toInt() and 0xff) + (l[i].toInt() and 0xff) + carry; carry = v shr 8; v.toByte() }
        if (carry == 0) attendreErreur(Erreur.Signature) { Kdf.ed25519Verify(pk, msg, Octets.concat(sig.copyOf(32), sl)) }
        attendreErreur(Erreur.Signature) { Kdf.ed25519Verify(pk, msg, sig.copyOf(63)) }
        assertFalse(Kdf.ed25519IsValidPublic(ByteArray(32)))
        assertFalse(Kdf.ed25519IsValidPublic(identite))
    }

    /**
     * L'écart documenté (README du module) : A = [a]B + T, T d'ordre 2, et une
     * signature que `brocolis_proto::kdf::ed25519_verify` (dalek
     * `verify_strict`) accepte, car k est pair (produite par la référence
     * Rust). La clé reste « valide » comme chez dalek, mais Kotlin refuse la
     * signature : plus strict, jamais plus laxiste.
     */
    @Test
    fun ed25519CleAvecTorsion() {
        val pk = unhex("fb8247ebfd1979f36d9007e0c6c2ebcbf1be58f43f4fe6a309b56f4cb734d03b")
        val sig = unhex(
            "f87a22889707d326b221b2dba4102625f99227c2febe06664c8d9409eb213e21" +
                "24b8cc49d7faec30395f16b08137aaf98028d7f6ef3fe50f4074334d1857480e",
        )
        assertTrue(Kdf.ed25519IsValidPublic(pk))
        attendreErreur(Erreur.Signature) { Kdf.ed25519Verify(pk, unhex("00000000"), sig) }
    }

    @Test
    fun empreintes() {
        val f = Kdf.fingerprint(ByteArray(32) { 7 })
        assertEquals(19, f.length)
        assertEquals(3, f.count { it == '-' })
        assertEquals(f.uppercase(), f)
    }

    // ----- octets -----------------------------------------------------------

    @Test
    fun base64Strict() {
        assertArrayEquals(Octets.utf8("ab"), Octets.unb64("YWI="))
        for (bad in listOf("YWI", "YWJ=", "YW I=", "YWI=\n", "A===", "====", "YWI==", "Y-I=", "YWI=YWI=")) {
            assertNull(bad, Octets.unb64(bad))
        }
        assertArrayEquals(ByteArray(0), Octets.unb64(""))
    }

    @Test
    fun utf8EtEspaces() {
        attendreErreur(Erreur.Utf8) { Octets.fromUtf8(byteArrayOf(0xc0.toByte(), 0x80.toByte())) }
        attendreErreur(Erreur.Utf8) { Octets.fromUtf8(byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte())) }
        attendreErreur(Erreur.Utf8) { Octets.fromUtf8(byteArrayOf(0xff.toByte())) }
        assertEquals("é🥦", Octets.fromUtf8(Octets.utf8("é🥦")))
        assertEquals(6L, Octets.utf8Len("é🥦"))
        assertEquals("x", Octets.rustTrim(" 　 x \u0085"))
        assertEquals("\u001cx", Octets.rustTrim("\u001cx"))
    }

    // ----- remplissage ------------------------------------------------------

    @Test
    fun remplissage() {
        for ((n, attendu) in listOf(0 to 160, 1 to 160, 158 to 160, 159 to 160, 160 to 320, 319 to 320, 320 to 480)) {
            val data = ByteArray(n) { 0x41 }
            val p = Remplissage.pad(data)
            assertEquals("$n", attendu, p.size)
            assertEquals(0x80.toByte(), p[n])
            assertArrayEquals(data, Remplissage.unpad(p))
        }
        val data = byteArrayOf(0x80.toByte(), 0, 0, 0x80.toByte(), 0)
        assertArrayEquals(data, Remplissage.unpad(Remplissage.pad(data)))
        attendreErreur(Erreur.Remplissage) { Remplissage.unpad(ByteArray(0)) }
        attendreErreur(Erreur.Remplissage) { Remplissage.unpad(ByteArray(160)) }
        val p = Remplissage.pad(Octets.utf8("abc"))
        p[3] = 0x81.toByte()
        attendreErreur(Erreur.Remplissage) { Remplissage.unpad(p) }
        attendreErreur(Erreur.Remplissage) { Remplissage.unpad(Remplissage.pad(Octets.utf8("abc")).copyOf(159)) }
    }

    // ----- clé protégée -----------------------------------------------------

    @Test
    fun clesProtegees() {
        val p = Argon2Params.MINIMUM
        val token = CleProtegee.protectKeyV2With(cle(), "une phrase longue", p, ByteArray(16) { 1 }, ByteArray(12) { 2 })
        assertTrue(token.startsWith(CleProtegee.HEAD_V2) && token.endsWith("]]"))
        assertEquals(p, CleProtegee.v2Params(token))
        assertArrayEquals(cle(), CleProtegee.unprotectKey(token, "une phrase longue"))
        attendreErreur(Erreur.Dechiffrement) { CleProtegee.unprotectKey(token, "une phrase longuE") }
        // Chaque octet modifié (en-tête, sel, nonce, chiffré, tag) est refusé.
        val data = Octets.unb64(token.removePrefix(CleProtegee.HEAD_V2).removeSuffix("]]"))!!
        for (i in data.indices) {
            val d = data.copyOf()
            d[i] = (d[i].toInt() xor 1).toByte()
            attendreEchec("octet $i") { CleProtegee.unprotectKey(CleProtegee.HEAD_V2 + Octets.b64(d) + "]]", "une phrase longue") }
        }
        // Bornes à l'import.
        for ((m, t, par, ok) in listOf(
            listOf(19_455L, 2, 1, false), listOf(19_456L, 1, 1, false), listOf(1_048_577L, 3, 1, false),
            listOf(19_456L, 2, 0, false), listOf(19_456L, 17, 1, false), listOf(0xFFFF_FFFFL, 255, 255, false),
            listOf(19_456L, 2, 1, true),
        )) {
            val bytes = Octets.concat(byteArrayOf(2), Octets.u32be(m as Long), byteArrayOf((t as Int).toByte(), (par as Int).toByte())).copyOf(83)
            assertEquals("$m $t $par", ok, runCatching { CleProtegee.parseV2Params(bytes) }.isSuccess)
        }
        attendreErreur(Erreur.Format) { CleProtegee.parseV2Params(ByteArray(83).also { it[0] = 3 }) }
        // Phrase courte et jetons abîmés.
        attendreErreur(Erreur.PhraseTropCourte) { CleProtegee.protectKeyV2With(cle(), "court", p, ByteArray(16), ByteArray(12)) }
        attendreErreur(Erreur.PhraseTropCourte) { CleProtegee.protectKeyV2With(cle(), "🥦🥦🥦🥦🥦🥦🥦", p, ByteArray(16), ByteArray(12)) }
        attendreErreur(Erreur.JetonAbsent) { CleProtegee.unprotectKey("rien", "x") }
        attendreErreur(Erreur.Format) { CleProtegee.unprotectKey("[[BROCOLIS-CLE:v1:AAAA]]", "x") }
        attendreErreur(Erreur.Base64) { CleProtegee.unprotectKey("[[BROCOLIS-CLE:v1:pas du base64]]", "x") }
        attendreErreur(Erreur.JetonAbsent) { CleProtegee.unprotectKey("[[BROCOLIS-CLE:v2:AAAA", "x") }
        attendreErreur(Erreur.Format) { CleProtegee.unprotectKey("[[BROCOLIS-CLE:v2:${"A".repeat(10_000)}]]", "x") }
        assertTrue(CleProtegee.hasProtectedKey("… $token …"))
    }

    @Test
    fun protectKeyParDefaut() {
        val token = CleProtegee.protectKey(cle(), "une phrase longue", Deterministic("defaut"))
        assertEquals(Argon2Params.DEFAULT, CleProtegee.v2Params(token))
        assertArrayEquals(cle(), CleProtegee.unprotectKey(token, "une phrase longue"))
    }

    // ----- jetons v1/v2 -----------------------------------------------------

    private fun key(n: Int) = ByteArray(32) { n.toByte() }

    @Test
    fun jetonsV1V2() {
        val token = Jetons.seal("Salut 🥦", listOf(key(1)))
        assertTrue(token.startsWith("[[BROCOLIS:v1:") && token.endsWith("]]"))
        assertEquals(Jetons.Opened("Salut 🥦", 1, 0), Jetons.open(token, listOf(key(9), key(1))))
        val multi = Jetons.seal("À tous", listOf(key(1), key(2), key(3)))
        assertTrue(multi.startsWith("[[BROCOLIS:v2:"))
        for (k in 1..3) assertEquals("À tous", Jetons.open(multi, listOf(key(k))).text)
        assertEquals(Jetons.Opened(multi, 0, 1), Jetons.open(multi, listOf(key(4))))
        val text = Jetons.seal("Rendez-vous ((au parc)) à ((18 h)) !", listOf(key(1)))
        assertTrue(text.startsWith("Rendez-vous [[BROCOLIS:v1:") && text.endsWith("]] !") && !text.contains("parc"))
        assertEquals(Jetons.Opened("Rendez-vous au parc à 18 h !", 2, 0), Jetons.open(text, listOf(key(1))))
        assertEquals(token, Jetons.seal(token, listOf(key(2))))
        assertEquals("", Jetons.seal("", listOf(key(1))))
        assertEquals("clair", Jetons.seal("clair", emptyList()))
        assertTrue(Jetons.seal("pas fermé ((", listOf(key(1))).startsWith("[[BROCOLIS:v1:"))
        assertNull(Jetons.sealToken("x", List(256) { key(it) }, Hasard.system()))
    }

    @Test
    fun ouvreLesJetonsDeLAppBrocolis() {
        // Fait par `BrocolisCrypto.encryptTokenMulti` (l'app Brocolis) pour deux clés.
        val token = "[[BROCOLIS:v2:AQLvnoxtj3mqrlMIb1HabsfA84XQ4aZVWz8VLKLbBBRDFX2RZlp6az6BeW8WOMl5FTYB94D0rDj6fDJYoNN7ChsNt7sw0O9LKxrI0KCf7Mc0w0x7mIAiuEK2GEtWrVaagyR3wxedqSiL4QrBphtW7PNxDrLzxNe53E58AnsGGchl3SjQ5700f6rruRdr66oPOJOMYxtHEHd7nqKZ1PAEoDBJD9w=]]"
        val k = Jetons.keyFromB64("Ie2Z71cbvIw+OLOnnmIdfTenOUIxKShDsFQhDH5C7Uw=")!!
        assertEquals("Pour vous deux", Jetons.open(token, listOf(key(1), k)).text)
        val nonce = ByteArray(12) { 3 }
        val combined = Octets.concat(nonce, Kdf.aesGcmSeal(key(7), nonce, ByteArray(0), Octets.utf8("brocolis")))
        assertEquals("avant brocolis après", Jetons.open("avant [[BROCOLIS:v1:${Octets.b64(combined)}]] après", listOf(key(7))).text)
    }

    @Test
    fun clesEmpreintesMasques() {
        val k = Jetons.generateKey()
        val invite = "3) Colle CETTE clé :\n\n$k\n\n(C'est notre clé commune.)"
        assertEquals(k, Jetons.findKey(invite))
        assertEquals(k, Jetons.findKey("«$k»"))
        assertEquals(k, Jetons.findKey("clé $k !"))
        assertNull(Jetons.findKey("pas de clé ici"))
        val kb = Octets.b64(ByteArray(32) { 7 })
        val f = Jetons.fingerprint(kb)!!
        assertEquals(19, f.length)
        assertEquals(f, Jetons.fingerprint(kb))
        assertNotEquals(f, Jetons.fingerprint(Octets.b64(ByteArray(32) { 8 })))
        assertNull(Jetons.fingerprint("pas une clé"))
        val token = Jetons.seal("secret", listOf(key(1)))
        assertEquals("Voici 🔒🥦 !", Jetons.masked("Voici $token !"))
        assertEquals("rien à cacher", Jetons.masked("rien à cacher"))
        for (t in listOf("[[BROCOLIS:v1:pas-du-base64]]", "[[BROCOLIS:v3:AAAA]]", "[[BROCOLIS:v1:AAAA")) {
            val o = Jetons.open(t, listOf(key(1)))
            assertEquals(t, o.text)
            assertEquals(0, o.opened)
        }
    }

    // ----- jeton v3 ---------------------------------------------------------

    private fun env() = Envelope(ByteArray(8) { 1 }, Header(ByteArray(32) { 2 }, 3, 0x01020304), ByteArray(176) { 9 })

    @Test
    fun jetonV3AllerRetourEtRefusStricts() {
        val tokens = listOf(
            Token.Message(env()),
            Token.Distribution(env()),
            Token.InitialMessage(Initial(ByteArray(32) { 4 }, ByteArray(32) { 5 }, Mode.Hybrid, ByteArray(Token.KEM_CT_LEN) { 6 }, 7, 8, env())),
            Token.InitialMessage(Initial(ByteArray(32) { 4 }, ByteArray(32) { 5 }, Mode.Classic, null, 7, 0, env())),
            Token.InitialMessage(Initial(ByteArray(32), ByteArray(32) { 5 }, Mode.Psk, null, 0, 0, env())),
            Token.Group(GroupMessage(ByteArray(16) { 1 }, ByteArray(8) { 2 }, 3, ByteArray(176) { 4 }, ByteArray(64) { 5 })),
        )
        for (t in tokens) {
            assertEquals(t, Token.decode(t.encode()))
            val bytes = t.toBytes()
            for (n in bytes.indices) attendreEchec("$n") { Token.fromBytes(bytes.copyOf(n)) }
        }
        attendreErreur(Erreur.Format) { Token.fromBytes(Octets.concat(Token.Message(env()).toBytes(), byteArrayOf(0))) }
        attendreErreur(Erreur.Format) { Token.fromBytes(Token.Message(env()).toBytes().also { it[0] = 5 }) }
        val classicWithPq = Token.InitialMessage(Initial(ByteArray(32) { 4 }, ByteArray(32) { 5 }, Mode.Classic, null, 7, 1, env()))
        attendreErreur(Erreur.Format) { Token.fromBytes(classicWithPq.toBytes()) }
        val pskWithIdentity = Token.InitialMessage(Initial(ByteArray(32) { 4 }, ByteArray(32) { 5 }, Mode.Psk, null, 0, 0, env()))
        attendreErreur(Erreur.Format) { Token.fromBytes(pskWithIdentity.toBytes()) }
        attendreErreur(Erreur.JetonAbsent) { Token.decode("[[BROCOLIS:v3:AAAA]] ") }
        attendreErreur(Erreur.JetonAbsent) { Token.decode("[[BROCOLIS:v3:]") }
        attendreErreur(Erreur.Base64) { Token.decode("[[BROCOLIS:v3:A===]]") }
        attendreErreur(Erreur.Format) { Token.fromBytes(ByteArray(0)) }
        attendreErreur(Erreur.TropGrand) { Token.fromBytes(ByteArray(Token.MAX_TOKEN_BYTES + 1) { 2 }) }
        // Jetons dans un texte collé.
        val a = Token.Message(env()).encode()
        val found = Token.findAll("avant $a milieu [[BROCOLIS:v3:AAAA]] fin [[BROCOLIS:v3:")
        assertEquals(2, found.size)
        assertEquals(a, found[0].first)
        assertTrue(found[0].second.isSuccess && found[1].second.isFailure)
    }

    // ----- paquet -----------------------------------------------------------

    @Test
    fun paquetAllerRetourEtSignatures() {
        for (pq in listOf(false, true)) {
            val d = Device.generate(Deterministic("paquet"), 1_000, pq)
            val b = d.bundle()
            val bytes = b.toBytes()
            assertEquals(if (pq) Paquet.BUNDLE_LEN_PQ else Paquet.BUNDLE_LEN_CLASSIC, bytes.size)
            assertEquals(b, KeyBundle.fromBytes(bytes))
            assertEquals(b, KeyBundle.fromBase64(b.toBase64()))
            assertEquals(b, KeyBundle.fromBase64(" ${b.toBase64()}\n"))
            // Chaque bit modifié est refusé.
            for (i in bytes.indices) {
                val x = bytes.copyOf()
                x[i] = (x[i].toInt() xor 1).toByte()
                attendreEchec("octet $i") { KeyBundle.fromBytes(x) }
            }
        }
        // Une PQPK hors module (coefficient ≥ q) est refusée, même bien signée.
        val d = Device.generate(Deterministic("module"), 0, true)
        val b = d.bundle()
        val key = b.pq!!.key.copyOf()
        key[0] = 0xff.toByte()
        key[1] = (key[1].toInt() or 0x0f).toByte()
        assertFalse(MlKem.isValidPublicKey(key))
        val sig = Kdf.ed25519Sign(d.identitySecret.sign, Paquet.pqpkSignedMessage(b.identity.dh, b.pq!!.id, key))
        val forged = KeyBundle(b.identity, b.spkId, b.spk, b.spkSignature, PqBundle(b.pq!!.id, key, sig))
        attendreErreur(Erreur.CleInvalide) { KeyBundle.fromBytes(forged.toBytes()) }
        attendreErreur(Erreur.CleInvalide) { MlKem.encapsulate(key, ByteArray(32)) }
    }

    @Test
    fun rotationEtPurge() {
        val rng = Deterministic("rotation")
        val d = Device.generate(rng, 0, true)
        val first = d.bundle()
        assertFalse(d.needsRotation(Paquet.PREKEY_ROTATION - 1))
        assertTrue(d.needsRotation(Paquet.PREKEY_ROTATION))
        d.rotate(rng, Paquet.PREKEY_ROTATION)
        val second = d.bundle()
        assertEquals(maxOf((first.spkId + 1) and 0xFFFF_FFFFL, 1L), second.spkId)
        d.spkSecret(first.spkId)
        d.pqSeed(first.pq!!.id)
        d.purge(Paquet.PREKEY_ROTATION + Paquet.PREKEY_GRACE)
        attendreErreur(Erreur.CleInconnue) { d.spkSecret(first.spkId) }
        d.spkSecret(second.spkId)
        assertEquals(second, Device.fromJson(d.toJson()).bundle())
        attendreErreur(Erreur.Etat) { Device.fromJson("{}") }
        // Ajouter ML-KEM à un appareil qui n'en avait pas.
        val c = Device.generate(rng, 0, false)
        assertFalse(c.supportsPq())
        c.enablePq(rng, 10)
        assertTrue(c.supportsPq())
        KeyBundle.fromBytes(c.bundle().toBytes())
    }

    @Test
    fun replayGuardBorne() {
        val g = ReplayGuard()
        for (i in 0 until ReplayGuard.MAX + 10) g.insert(Octets.u64be(i.toLong()).copyOf(32), 0)
        assertEquals(ReplayGuard.MAX, g.size)
        assertFalse(g.seen(ByteArray(32)))
        assertTrue(g.seen(Octets.u64be(ReplayGuard.MAX + 9L).copyOf(32)))
        assertEquals(g.toJson(), ReplayGuard.fromJson(g.toJson()).toJson())
        g.purge(ReplayGuard.MAX_AGE)
        assertTrue(g.isEmpty())
    }
}
