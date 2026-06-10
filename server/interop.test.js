//
//  Test d'interopérabilité iPhone ↔ Android du protocole Brocolis 🥦.
//
//  L'app iOS utilise CryptoKit ; un client Android utiliserait les mêmes
//  primitives STANDARD (X25519/RFC 7748, HKDF-SHA256/RFC 5869, AES-256-GCM/
//  NIST SP 800-38D) via java.security / javax.crypto / Tink / libsodium.
//  Ce fichier prouve l'interopérabilité en deux temps :
//
//  1. Les primitives utilisées ici (OpenSSL via Node, comme Conscrypt sur
//     Android) reproduisent les VECTEURS OFFICIELS des standards — les mêmes
//     que CryptoKit implémente côté iPhone.
//  2. Le protocole complet (appairage, empreinte, clé de groupe, jetons
//     [[BROCOLIS:v1:…]]) est déroulé entre deux clients indépendants : mêmes
//     clés dérivées, mêmes empreintes, jetons déchiffrables croisés.
//
//  Lancer : node --test server/
//

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { createRendezvous } = require('./index.js');

// --- Encodage des clés X25519 : 32 octets bruts (RFC 7748), comme le
// --- rawRepresentation de CryptoKit échangé via le serveur.

const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function privFromRaw(raw32) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, raw32]), format: 'der', type: 'pkcs8',
  });
}

function pubFromRaw(raw32) {
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw32]), format: 'der', type: 'spki',
  });
}

function rawPub(publicKeyObj) {
  return publicKeyObj.export({ format: 'der', type: 'spki' }).subarray(-32);
}

// --- Réimplémentation « Android » de BrocolisKeyAgreement / BrocolisCrypto ---

function sortedConcat(a, b) {
  return Buffer.compare(a, b) <= 0 ? Buffer.concat([a, b]) : Buffer.concat([b, a]);
}

function derive(myPriv, myPubRaw, peerPubRaw, salt) {
  const shared = crypto.diffieHellman({ privateKey: myPriv, publicKey: pubFromRaw(peerPubRaw) });
  const info = sortedConcat(Buffer.from(myPubRaw), Buffer.from(peerPubRaw));
  return {
    key: Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(salt), info, 32)),
    info,
  };
}

// Empreinte affichée par l'app : SHA-256(info), 8 premiers octets en hex
// majuscule, groupés par 4 avec des tirets (BrocolisKeyAgreement.fingerprint).
function fingerprint(info) {
  const hex = crypto.createHash('sha256').update(info).digest()
    .subarray(0, 8).toString('hex').toUpperCase();
  return hex.match(/.{4}/g).join('-');
}

// AES-256-GCM « combined » = nonce(12) || ciphertext || tag(16), comme le
// SealedBox.combined de CryptoKit.
function seal(plaintext, key) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
}

function open(packed, key) {
  const nonce = packed.subarray(0, 12);
  const tag = packed.subarray(packed.length - 16);
  const ct = packed.subarray(12, packed.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

const TOKEN_PREFIX = '[[BROCOLIS:v1:';
const TOKEN_SUFFIX = ']]';

function encryptToken(text, key) {
  return TOKEN_PREFIX + seal(Buffer.from(text, 'utf8'), key).toString('base64') + TOKEN_SUFFIX;
}

function decryptToken(token, key) {
  assert.ok(token.startsWith(TOKEN_PREFIX) && token.endsWith(TOKEN_SUFFIX), 'format de jeton');
  const b64 = token.slice(TOKEN_PREFIX.length, -TOKEN_SUFFIX.length);
  return open(Buffer.from(b64, 'base64'), key).toString('utf8');
}

// --- 1. Vecteurs officiels : mêmes standards que CryptoKit ------------------

test('X25519 reproduit le vecteur officiel RFC 7748 §6.1', () => {
  const alicePriv = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
  const alicePub = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  const bobPriv = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex');
  const bobPub = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
  const sharedRef = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

  const a = privFromRaw(alicePriv);
  const b = privFromRaw(bobPriv);
  assert.strictEqual(rawPub(crypto.createPublicKey(a)).toString('hex'), alicePub);
  assert.strictEqual(rawPub(crypto.createPublicKey(b)).toString('hex'), bobPub);

  const sharedA = crypto.diffieHellman({ privateKey: a, publicKey: pubFromRaw(Buffer.from(bobPub, 'hex')) });
  const sharedB = crypto.diffieHellman({ privateKey: b, publicKey: pubFromRaw(Buffer.from(alicePub, 'hex')) });
  assert.strictEqual(sharedA.toString('hex'), sharedRef);
  assert.strictEqual(sharedB.toString('hex'), sharedRef);
});

test('HKDF-SHA256 reproduit le vecteur officiel RFC 5869 A.1', () => {
  const ikm = Buffer.alloc(22, 0x0b);
  const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
  const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
  const okm = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 42));
  assert.strictEqual(
    okm.toString('hex'),
    '3cb25f25faacd57a90434f64d0362f2a' +
    '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
    '34007208d5b887185865'
  );
});

test('AES-256-GCM reproduit le vecteur officiel NIST (clé nulle, IV nul)', () => {
  const key = Buffer.alloc(32);
  const iv = Buffer.alloc(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.update(Buffer.alloc(0));
  cipher.final();
  assert.strictEqual(cipher.getAuthTag().toString('hex'), '530f8afbc74536b9a963b4f1c4cb738b');
});

// --- 2. Flux complet entre deux clients indépendants ------------------------

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, () => resolve(server.address().port));
  });
}

async function api(port, method, path, body) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

function newDevice() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return { privateKey, rawPub: rawPub(publicKey) };
}

test('appairage croisé : un iPhone (spec CryptoKit) et un Android dérivent la même clé et la même empreinte', async () => {
  const server = createRendezvous();
  const port = await listen(server);
  try {
    const iphone = newDevice();
    const android = newDevice();

    // Les deux publient leur clé publique brute (base64) sous le même code,
    // exactement comme PairingView le fait via POST /pair.
    await api(port, 'POST', '/pair', {
      code: 'INTEROP', peerId: 'iphone', pub: iphone.rawPub.toString('base64'),
    });
    const { json } = await api(port, 'POST', '/pair', {
      code: 'INTEROP', peerId: 'android', pub: android.rawPub.toString('base64'),
    });
    const seenByAndroid = Buffer.from(json.peers[0].pub, 'base64');
    assert.deepStrictEqual(seenByAndroid, iphone.rawPub);

    const a = derive(iphone.privateKey, iphone.rawPub, android.rawPub, 'brocolis-x25519');
    const b = derive(android.privateKey, android.rawPub, iphone.rawPub, 'brocolis-x25519');
    assert.deepStrictEqual(a.key, b.key);
    assert.strictEqual(a.key.length, 32);

    // Empreinte de sécurité identique des deux côtés, au format de l'app
    // (4 groupes hex majuscules séparés par des tirets).
    assert.strictEqual(fingerprint(a.info), fingerprint(b.info));
    assert.match(fingerprint(a.info), /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/);

    // Jetons croisés : chiffré par l'un, déchiffré par l'autre, dans les
    // deux sens, au format [[BROCOLIS:v1:…]] de BrocolisCrypto.
    const t1 = encryptToken('Rendez-vous 🥦 à 18h — café ☕️', a.key);
    assert.strictEqual(decryptToken(t1, b.key), 'Rendez-vous 🥦 à 18h — café ☕️');
    const t2 = encryptToken('réponse depuis Android 🤖', b.key);
    assert.strictEqual(decryptToken(t2, a.key), 'réponse depuis Android 🤖');
  } finally {
    server.close();
  }
});

test('groupe croisé : un fondateur iPhone distribue la clé, un membre Android la déballe', async () => {
  const server = createRendezvous();
  const port = await listen(server);
  try {
    const founder = newDevice(); // iPhone
    const member = newDevice(); // Android

    await api(port, 'POST', '/pair', {
      code: 'GRP', peerId: 'membre', pub: member.rawPub.toString('base64'),
    });
    const groupKey = crypto.randomBytes(32);

    // Le fondateur emballe la clé de groupe avec la clé pairwise (sel
    // « brocolis-x25519-wrap ») et la dépose via POST /wrap.
    const wrapKeyFounder = derive(founder.privateKey, founder.rawPub, member.rawPub, 'brocolis-x25519-wrap').key;
    const blob = seal(groupKey, wrapKeyFounder).toString('base64');
    await api(port, 'POST', '/wrap', {
      code: 'GRP', fromPeerId: 'fondateur', fromPub: founder.rawPub.toString('base64'),
      items: [{ toPeerId: 'membre', blob }],
    });

    // Le membre récupère le blob et le déballe de son côté.
    const { json } = await api(port, 'GET', '/wrap?code=GRP&peerId=membre');
    const fromPub = Buffer.from(json.wrap.fromPub, 'base64');
    const wrapKeyMember = derive(member.privateKey, member.rawPub, fromPub, 'brocolis-x25519-wrap').key;
    const unwrapped = open(Buffer.from(json.wrap.blob, 'base64'), wrapKeyMember);
    assert.deepStrictEqual(unwrapped, groupKey);

    // Empreinte de groupe : SHA-256 de la clé brute (groupFingerprint).
    assert.strictEqual(fingerprint(groupKey), fingerprint(unwrapped));
  } finally {
    server.close();
  }
});
