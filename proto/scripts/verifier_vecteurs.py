#!/usr/bin/env python3
"""Vérification indépendante de proto/vectors.json.

Réimplémente le protocole à partir de docs/SECURITE.md seulement, avec la
bibliothèque Python `cryptography` (OpenSSL) : aucune ligne du Rust n'est
reprise. Chaque vecteur doit être retrouvé octet pour octet.

    python3 -I proto/scripts/verifier_vecteurs.py proto/vectors.json

Dépend de `cryptography` >= 45 (X25519, Ed25519, HKDF, AES-GCM, PBKDF2,
Argon2id, ML-KEM-768).
"""

import base64
import hashlib
import hmac
import json
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

H = bytes.fromhex
checks = 0


def ok(cond, what):
    global checks
    if not cond:
        raise SystemExit(f"ÉCHEC : {what}")
    checks += 1


def hkdf(salt, ikm, info, n):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


def x_pub(sk):
    from cryptography.hazmat.primitives import serialization as s
    return X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)


def x_dh(sk, pk):
    return X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))


def ed_pub(seed):
    from cryptography.hazmat.primitives import serialization as s
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)


def kdf_rk(rk, dh):
    o = hkdf(rk, dh, b"Brocolis_v3_Ratchet", 64)
    return o[:32], o[32:]


def kdf_ck(ck):
    return hmac.new(ck, b"\x02", hashlib.sha256).digest(), hmac.new(ck, b"\x01", hashlib.sha256).digest()


def msg_keys(mk):
    o = hkdf(b"\x00" * 32, mk, b"Brocolis_v3_MessageKeys", 44)
    return o[:32], o[32:]


def sk_x3dh(dh1, dh2, dh3, ss=None):
    ikm = b"\xff" * 32 + dh1 + dh2 + dh3 + (ss or b"")
    info = b"Brocolis_v3_X25519_MLKEM768_SHA-256" if ss else b"Brocolis_v3_X25519_SHA-256"
    return hkdf(b"\x00" * 32, ikm, info, 32)


def pad(data):
    n = (len(data) // 160 + 1) * 160
    return data + b"\x80" + b"\x00" * (n - len(data) - 1)


def unpad(p):
    if not p or len(p) % 160:
        raise ValueError("longueur")
    s = p.rstrip(b"\x00")
    if not s or s[-1] != 0x80:
        raise ValueError("0x80")
    return s[:-1]


def fingerprint(data):
    h = hashlib.sha256(data).hexdigest().upper()[:16]
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


def token_bytes(tok, head="[[BROCOLIS:v3:"):
    assert tok.startswith(head) and tok.endswith("]]")
    return base64.b64decode(tok[len(head):-2], validate=True)


# ----- Primitives -------------------------------------------------------

def primitives(p):
    rk, ck = kdf_rk(H(p["kdf_rk"]["rk"]), H(p["kdf_rk"]["dh"]))
    ok(rk.hex() == p["kdf_rk"]["rk_out"] and ck.hex() == p["kdf_rk"]["ck_out"], "KDF_RK")
    ck2, mk = kdf_ck(H(p["kdf_ck"]["ck"]))
    ok(ck2.hex() == p["kdf_ck"]["ck_out"] and mk.hex() == p["kdf_ck"]["mk"], "KDF_CK")
    k, n = msg_keys(H(p["message_key"]["mk"]))
    ok(k.hex() == p["message_key"]["key"] and n.hex() == p["message_key"]["nonce"], "ENCRYPT(mk)")
    c = p["sk_classic"]
    ok(sk_x3dh(H(c["dh1"]), H(c["dh2"]), H(c["dh3"])).hex() == c["sk"], "SK classique")
    c = p["sk_hybrid"]
    ok(sk_x3dh(H(c["dh1"]), H(c["dh2"]), H(c["dh3"]), H(c["ss"])).hex() == c["sk"], "SK hybride")
    c = p["sk_psk"]
    sk = hkdf(b"\x00" * 32, H(c["key"]), b"Brocolis_v3_PSK_SHA-256", 32)
    ok(sk.hex() == c["sk"], "SK PSK")
    r = hkdf(b"\x00" * 32, sk, b"Brocolis_v3_PSK_Ratchet", 32)
    ok(r.hex() == c["psk_ratchet_secret"] and x_pub(r).hex() == c["psk_ratchet_public"], "PSK cliquet")
    ok(hashlib.sha256(H(p["session_id"]["ad"])).digest()[:8].hex() == p["session_id"]["id"], "id session")
    ok(fingerprint(H(p["fingerprint"]["data"])) == p["fingerprint"]["fingerprint"], "empreinte")
    x = p["x25519"]
    ok(x_pub(H(x["secret"])).hex() == x["public"], "X25519 public")
    ok(x_dh(H(x["secret"]), H(x["peer_public"])).hex() == x["shared"], "X25519")
    m = p["mlkem768"]
    dk = MLKEM768PrivateKey.from_seed_bytes(H(m["seed"]))
    from cryptography.hazmat.primitives import serialization as s
    ok(dk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex() == m["encapsulation_key"], "ML-KEM ek")
    ok(dk.decapsulate(H(m["ciphertext"])).hex() == m["shared"], "ML-KEM decaps")


def padding(p):
    for c in p["cases"]:
        ok(pad(H(c["data"])).hex() == c["padded"], "remplissage")
        ok(unpad(H(c["padded"])).hex() == c["data"], "retrait")
    for bad in p["invalid"]:
        try:
            unpad(H(bad))
            ok(False, "remplissage invalide accepté")
        except ValueError:
            ok(True, "")


def protected(p):
    key = H(p["key"])
    v1 = p["v1"]
    d = token_bytes(v1["token"], "[[BROCOLIS-CLE:v1:")
    salt, nonce, ct = d[:16], d[16:28], d[28:]
    k = PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000).derive(v1["phrase"].encode())
    ok(AESGCM(k).decrypt(nonce, ct, b"brocolis-cle-v1") == key, "clé protégée v1")
    for v in p["v2"]:
        d = token_bytes(v["token"], "[[BROCOLIS-CLE:v2:")
        ok(len(d) == 83 and d[0] == 2, "v2 longueur")
        m, t, par = int.from_bytes(d[1:5], "big"), d[5], d[6]
        ok((m, t, par) == (v["m_kib"], v["t"], v["p"]), "v2 paramètres")
        ok(d[7:23].hex() == v["salt"] and d[23:35].hex() == v["nonce"], "v2 sel/nonce")
        k = Argon2id(salt=d[7:23], length=32, iterations=t, lanes=par, memory_cost=m).derive(v["phrase"].encode())
        ok(k.hex() == v["argon2id_key"], "Argon2id")
        ok(AESGCM(k).decrypt(d[23:35], d[35:], d[:35]) == key, "clé protégée v2")


def legacy(p):
    keys = [H(k) for k in p["keys"]]
    d = token_bytes(p["v1"]["token"], "[[BROCOLIS:v1:")
    ok(AESGCM(keys[0]).decrypt(d[:12], d[12:], None).decode() == p["v1"]["text"], "jeton v1")
    d = token_bytes(p["v2"]["token"], "[[BROCOLIS:v2:")
    ok(d[0] == 1 and d[1] == 2, "jeton v2 en-tête")
    w = d[2:62]
    mk = AESGCM(keys[0]).decrypt(w[:12], w[12:], None)
    body = d[2 + 2 * 60:]
    ok(AESGCM(mk).decrypt(body[:12], body[12:], None).decode() == p["v2"]["text"], "jeton v2")


# ----- Paquets et sessions ---------------------------------------------

def bundle(v):
    b = H(v["bundle"])
    ok(b[0] == 1, "version paquet")
    ik, ed = b[1:33], b[33:65]
    ok(ik == x_pub(H(v["ik_x25519_secret"])) and ed == ed_pub(H(v["ik_ed25519_seed"])), "IK")
    spk_id = int.from_bytes(b[65:69], "big")
    spk, sig = b[69:101], b[101:165]
    ok(spk == x_pub(H(v["spk_secret"])) and spk_id == v["spk_id"], "SPK")
    pk = Ed25519PublicKey.from_public_bytes(ed)
    pk.verify(sig, b"Brocolis_v3_SPK" + ik + b[65:69] + spk)
    ok(True, "signature SPK")
    if b[165] == 1:
        ok(len(b) == 1418, "longueur paquet PQ")
        pq_id, pqpk, pqsig = b[166:170], b[170:1354], b[1354:1418]
        pk.verify(pqsig, b"Brocolis_v3_PQPK" + ik + pq_id + pqpk)
        from cryptography.hazmat.primitives import serialization as s
        dk = MLKEM768PrivateKey.from_seed_bytes(H(v["pq_seed"]))
        ok(dk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw) == pqpk, "PQPK")
    else:
        ok(b[165] == 0 and len(b) == 166, "paquet classique")
    ok(fingerprint(ik + ed) == v["fingerprint"], "empreinte identité")


class Party:
    """Un côté du Double Ratchet, écrit d'après la spécification de Signal."""

    def __init__(self, ad, rk, dhs, dhr=None, cks=None):
        self.ad, self.rk, self.dhs, self.dhr, self.cks = ad, rk, dhs, dhr, cks
        self.ckr, self.ns, self.nr, self.pn, self.skipped = None, 0, 0, 0, {}

    def decrypt(self, hdr, ct, draw, extra=b""):
        dh, pn, n = hdr[:32], int.from_bytes(hdr[32:36], "big"), int.from_bytes(hdr[36:40], "big")
        if (dh, n) in self.skipped:
            mk = self.skipped.pop((dh, n))
        else:
            if dh != self.dhr:
                self.skip(pn)
                self.pn, self.ns, self.nr, self.dhr = self.ns, 0, 0, dh
                self.rk, self.ckr = kdf_rk(self.rk, x_dh(self.dhs, dh))
                self.dhs = draw()
                self.rk, self.cks = kdf_rk(self.rk, x_dh(self.dhs, dh))
            self.skip(n)
            self.ckr, mk = kdf_ck(self.ckr)
            self.nr += 1
        k, nonce = msg_keys(mk)
        return unpad(AESGCM(k).decrypt(nonce, ct, self.ad + hdr + extra))

    def skip(self, until):
        while self.ckr is not None and self.nr < until:
            self.ckr, mk = kdf_ck(self.ckr)
            self.skipped[(self.dhr, self.nr)] = mk
            self.nr += 1


def parse_v3(tok):
    d = token_bytes(tok)
    t, sid, rest = d[0], d[1:9], d[9:]
    pre = None
    if t == 1:
        ik, ek, mode = rest[:32], rest[32:64], rest[64]
        i = 65
        ct = None
        if mode == 1:
            ct, i = rest[65:65 + 1088], 65 + 1088
        spk_id, pq_id = rest[i:i + 4], rest[i + 4:i + 8]
        pre = (ik, ek, mode, ct, spk_id, pq_id)
        rest = rest[i + 8:]
    return t, sid, pre, rest[:40], rest[40:]


def session(case):
    s = case["setup"]
    steps = case["steps"]
    if case["mode"] == "psk":
        key = H(s["key"])
        sk = hkdf(b"\x00" * 32, key, b"Brocolis_v3_PSK_SHA-256", 32)
        r = hkdf(b"\x00" * 32, sk, b"Brocolis_v3_PSK_Ratchet", 32)
        ek = H(s["ek_secret"])
        ad = x_pub(ek) + x_pub(r)
        bob_init = r
        alice_ratchet = ek
        remote = x_pub(r)
    else:
        bundle(s["alice"])
        bundle(s["bob"])
        ika, ikb = H(s["alice"]["ik_x25519_secret"]), H(s["bob"]["ik_x25519_secret"])
        spkb = H(s["bob"]["spk_secret"])
        ek = H(s["ek_secret"])
        dh1, dh2, dh3 = x_dh(ika, x_pub(spkb)), x_dh(ek, x_pub(ikb)), x_dh(ek, x_pub(spkb))
        ok((dh1.hex(), dh2.hex(), dh3.hex()) == (s["dh1"], s["dh2"], s["dh3"]), "DH1..3")
        ss = None
        if case["mode"] == "hybrid":
            dk = MLKEM768PrivateKey.from_seed_bytes(H(s["bob"]["pq_seed"]))
            ss = dk.decapsulate(H(s["mlkem_ciphertext"]))
            ok(ss.hex() == s["mlkem_shared"], "ML-KEM SS")
        sk = sk_x3dh(dh1, dh2, dh3, ss)
        ad = x_pub(ika) + x_pub(ikb)
        bob_init = spkb
        alice_ratchet = H(s["alice_ratchet_secret"])
        remote = x_pub(spkb)
    ok(sk.hex() == s["sk"] and ad.hex() == s["ad"], "SK et AD")
    sid = hashlib.sha256(ad).digest()[:8]
    ok(sid.hex() == s["session_id"], "id session")
    rk, cks = kdf_rk(sk, x_dh(alice_ratchet, remote))
    ok(rk.hex() == s["alice_root_key"] and cks.hex() == s["alice_sending_chain"], "racine d'Alice")
    alice = Party(ad, rk, alice_ratchet, remote, cks)
    bob = Party(ad, sk, bob_init)
    # Les secrets tirés au cliquet, dans l'ordre des événements.
    draws = {"alice": [], "bob": []}
    for st in steps:
        for who in ("alice", "bob"):
            if f"{who}_ratchet_secret_drawn" in st:
                draws[who].append(H(st[f"{who}_ratchet_secret_drawn"]))
    pending = [st for st in steps if "token" in st]
    # Ordre de réception du scénario : 2, 1, 3, 4, 5.
    order = [1, 0, 2, 3, 4]
    for i in order:
        st = pending[i]
        t, tsid, pre, hdr, ct = parse_v3(st["token"])
        ok(tsid == sid, "id dans le jeton")
        ok(hdr.hex() == st["header"]["header"] and ct.hex() == st["header"]["ciphertext"], "en-tête/chiffré")
        receiver = bob if st["from"] == "alice" else alice
        name = "bob" if st["from"] == "alice" else "alice"
        if pre is not None:
            ok(t == 1 and st["from"] == "alice", "type 0x01 d'Alice")
            if case["mode"] == "psk":
                ok(pre[0] == b"\x00" * 32 and pre[1] == x_pub(ek) and pre[2] == 2, "préambule PSK")
            else:
                ok(pre[0] == x_pub(ika) and pre[1] == x_pub(ek), "préambule")
        plain = receiver.decrypt(hdr, ct, lambda n=name: draws[n].pop(0))
        ok(plain.decode() == st["text"], f"message « {st['text']} »")


def group(g):
    seed = H(g["signing_seed"])
    pub = ed_pub(seed)
    ok(pub.hex() == g["signing_public"], "clé de groupe")
    ok(hashlib.sha256(pub).digest()[:8].hex() == g["sender_id"], "id expéditeur")
    d = H(g["distribution"])
    ok(d == H(g["group_id"]) + H(g["sender_id"]) + (0).to_bytes(4, "big") + H(g["chain_key"]) + pub, "distribution")
    ck = H(g["chain_key"])
    for m in g["messages"]:
        b = token_bytes(m["token"])
        ok(b[0] == 4 and b[1:17] == H(g["group_id"]) and b[17:25] == H(g["sender_id"]), "en-tête groupe")
        it = int.from_bytes(b[25:29], "big")
        ok(it == m["iteration"], "itération")
        body, sig = b[29:-64], b[-64:]
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, b[:-64])
        ck, mk = kdf_ck(ck)
        k, n = msg_keys(mk)
        ok(unpad(AESGCM(k).decrypt(n, body, b[:29])).decode() == m["text"], "message de groupe")
        try:
            AESGCM(k).decrypt(n, bytes([body[0] ^ 1]) + body[1:], b[:29])
            ok(False, "altération acceptée")
        except InvalidTag:
            ok(True, "")
    # La distribution par une session PSK (type 0x03, AAD ‖ 0x03).
    v = g["distribution_via_psk_session"]
    key, ek = H(v["key"]), H(v["ek_secret"])
    sk = hkdf(b"\x00" * 32, key, b"Brocolis_v3_PSK_SHA-256", 32)
    r = hkdf(b"\x00" * 32, sk, b"Brocolis_v3_PSK_Ratchet", 32)
    ad = x_pub(ek) + x_pub(r)
    t, tsid, _, hdr, ct = parse_v3(v["token"])
    ok(t == 3 and tsid == hashlib.sha256(ad).digest()[:8], "jeton 0x03")
    bob = Party(ad, sk, r)
    plain = bob.decrypt(hdr, ct, lambda: b"\x01" * 32, extra=b"\x03")
    ok(plain == d, "distribution déchiffrée")


def main():
    v = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "proto/vectors.json"))
    primitives(v["primitives"])
    padding(v["padding"])
    protected(v["protected_key"])
    legacy(v["legacy_tokens"])
    for case in v["sessions"]:
        session(case)
    group(v["group"])
    print(f"vecteurs vérifiés indépendamment : {checks} contrôles, tous bons")


main()
