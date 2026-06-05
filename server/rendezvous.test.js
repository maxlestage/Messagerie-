//
//  Test du serveur de rendez-vous + du protocole d'accord de clé X25519.
//  Simule deux appareils qui s'appairent via un code et vérifie qu'ils
//  dérivent la MÊME clé AES (ECDH + HKDF), sans que le serveur la voie.
//
//  Lancer : node --test server/
//

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { createRendezvous } = require('./index.js');

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

// Reproduit la dérivation faite côté app (ECDH X25519 + HKDF-SHA256), avec un
// sharedInfo = concat trié des deux clés publiques (identique des deux côtés).
function deriveKey(myPrivateKeyObj, peerPubRaw, myPubRaw) {
  const peerKey = crypto.createPublicKey({
    key: Buffer.concat([
      Buffer.from('302a300506032b656e032100', 'hex'), // préfixe SPKI X25519
      Buffer.from(peerPubRaw),
    ]),
    format: 'der',
    type: 'spki',
  });
  const shared = crypto.diffieHellman({ privateKey: myPrivateKeyObj, publicKey: peerKey });
  const a = Buffer.from(myPubRaw);
  const b = Buffer.from(peerPubRaw);
  const sorted = Buffer.compare(a, b) <= 0 ? Buffer.concat([a, b]) : Buffer.concat([b, a]);
  const salt = Buffer.from('brocolis-x25519', 'utf8');
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, sorted, 32));
}

function newPeer() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub };
}

function pubKeyObjFromRaw(raw) {
  return crypto.createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

// Clé d'emballage pairwise (sel distinct du flux à deux).
function deriveWrapKey(myPrivate, peerPubRaw, myPubRaw) {
  const shared = crypto.diffieHellman({ privateKey: myPrivate, publicKey: pubKeyObjFromRaw(peerPubRaw) });
  const a = Buffer.from(myPubRaw);
  const b = Buffer.from(peerPubRaw);
  const sorted = Buffer.compare(a, b) <= 0 ? Buffer.concat([a, b]) : Buffer.concat([b, a]);
  const salt = Buffer.from('brocolis-x25519-wrap', 'utf8');
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, sorted, 32));
}

// Emballage AES-256-GCM, format combined = iv(12) || ciphertext || tag(16).
function wrap(wrapKey, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]).toString('base64');
}

function unwrap(wrapKey, blobB64) {
  const packed = Buffer.from(blobB64, 'base64');
  const iv = packed.subarray(0, 12);
  const tag = packed.subarray(packed.length - 16);
  const ct = packed.subarray(12, packed.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', wrapKey, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

test('deux appareils dérivent la même clé via le rendez-vous', async () => {
  const server = createRendezvous();
  const port = await listen(server);
  try {
    const code = 'ABC123';
    const alice = newPeer();
    const bob = newPeer();

    // Alice publie sa clé publique (personne d'autre encore).
    const a1 = await api(port, 'POST', '/pair', {
      code, peerId: 'alice', pub: alice.rawPub.toString('base64'),
    });
    assert.strictEqual(a1.status, 200);
    assert.strictEqual(a1.json.peers.length, 0);

    // Bob publie la sienne et reçoit immédiatement celle d'Alice.
    const b1 = await api(port, 'POST', '/pair', {
      code, peerId: 'bob', pub: bob.rawPub.toString('base64'),
    });
    assert.strictEqual(b1.status, 200);
    assert.strictEqual(b1.json.peers.length, 1);
    assert.strictEqual(b1.json.peers[0].peerId, 'alice');

    // Alice interroge à son tour et trouve Bob.
    const a2 = await api(port, 'GET', `/pair?code=${code}&peerId=alice`);
    assert.strictEqual(a2.json.peers.length, 1);
    assert.strictEqual(a2.json.peers[0].peerId, 'bob');

    // Chacun dérive la clé de son côté.
    const bobPubRaw = Buffer.from(a2.json.peers[0].pub, 'base64');
    const alicePubRaw = Buffer.from(b1.json.peers[0].pub, 'base64');

    const keyAlice = deriveKey(alice.privateKey, bobPubRaw, alice.rawPub);
    const keyBob = deriveKey(bob.privateKey, alicePubRaw, bob.rawPub);

    assert.deepStrictEqual(keyAlice, keyBob, 'les deux clés dérivées doivent être identiques');
    assert.strictEqual(keyAlice.length, 32, 'clé AES-256');
  } finally {
    server.close();
  }
});

test('plusieurs participants peuvent se rejoindre sous un code', async () => {
  const server = createRendezvous({ maxPeers: 4 });
  const port = await listen(server);
  try {
    const code = 'GROUP1';
    await api(port, 'POST', '/pair', { code, peerId: 'a', pub: 'AA' });
    await api(port, 'POST', '/pair', { code, peerId: 'b', pub: 'BB' });
    const c = await api(port, 'POST', '/pair', { code, peerId: 'c', pub: 'CC' });
    assert.strictEqual(c.status, 200);
    // c voit a et b.
    assert.strictEqual(c.json.peers.length, 2);
    const ids = c.json.peers.map((p) => p.peerId).sort();
    assert.deepStrictEqual(ids, ['a', 'b']);
    // a voit b et c.
    const a = await api(port, 'GET', `/pair?code=${code}&peerId=a`);
    assert.strictEqual(a.json.peers.length, 2);
  } finally {
    server.close();
  }
});

test('le plafond configurable est respecté', async () => {
  const server = createRendezvous({ maxPeers: 2 });
  const port = await listen(server);
  try {
    const code = 'FULL01';
    await api(port, 'POST', '/pair', { code, peerId: 'a', pub: 'AA' });
    await api(port, 'POST', '/pair', { code, peerId: 'b', pub: 'BB' });
    const third = await api(port, 'POST', '/pair', { code, peerId: 'c', pub: 'CC' });
    assert.strictEqual(third.status, 409);
    // Mais un participant déjà présent peut toujours se réactualiser.
    const refresh = await api(port, 'POST', '/pair', { code, peerId: 'a', pub: 'AA2' });
    assert.strictEqual(refresh.status, 200);
  } finally {
    server.close();
  }
});

test('POST incomplet est rejeté', async () => {
  const server = createRendezvous();
  const port = await listen(server);
  try {
    const r = await api(port, 'POST', '/pair', { code: 'X' });
    assert.strictEqual(r.status, 400);
  } finally {
    server.close();
  }
});

test('le fondateur distribue une clé de groupe à plusieurs membres', async () => {
  const server = createRendezvous({ maxPeers: 8 });
  const port = await listen(server);
  try {
    const code = 'GRP777';
    const founder = newPeer();
    const bob = newPeer();
    const carol = newPeer();

    // Les membres publient leur clé publique d'abord.
    await api(port, 'POST', '/pair', { code, peerId: 'bob', pub: bob.rawPub.toString('base64') });
    await api(port, 'POST', '/pair', { code, peerId: 'carol', pub: carol.rawPub.toString('base64') });

    // Avant distribution, pas de clé pour bob.
    const before = await api(port, 'GET', `/wrap?code=${code}&peerId=bob`);
    assert.strictEqual(before.json.wrap, null);

    // Le fondateur rejoint, voit les membres, génère et emballe la clé de groupe.
    await api(port, 'POST', '/pair', { code, peerId: 'founder', pub: founder.rawPub.toString('base64') });
    const seen = await api(port, 'GET', `/pair?code=${code}&peerId=founder`);
    assert.strictEqual(seen.json.peers.length, 2);

    const groupKey = crypto.randomBytes(32);
    const items = seen.json.peers.map((p) => {
      const peerPubRaw = Buffer.from(p.pub, 'base64');
      const wk = deriveWrapKey(founder.privateKey, peerPubRaw, founder.rawPub);
      return { toPeerId: p.peerId, blob: wrap(wk, groupKey) };
    });
    const posted = await api(port, 'POST', '/wrap', {
      code, fromPeerId: 'founder', fromPub: founder.rawPub.toString('base64'), items,
    });
    assert.strictEqual(posted.json.count, 2);

    // Chaque membre récupère et déballe la même clé de groupe.
    for (const member of [{ id: 'bob', peer: bob }, { id: 'carol', peer: carol }]) {
      const got = await api(port, 'GET', `/wrap?code=${code}&peerId=${member.id}`);
      assert.ok(got.json.wrap, `${member.id} doit recevoir un blob`);
      const fromPubRaw = Buffer.from(got.json.wrap.fromPub, 'base64');
      const wk = deriveWrapKey(member.peer.privateKey, fromPubRaw, member.peer.rawPub);
      const groupKeyGot = unwrap(wk, got.json.wrap.blob);
      assert.deepStrictEqual(groupKeyGot, groupKey, `${member.id} doit retrouver la clé de groupe`);
    }
  } finally {
    server.close();
  }
});

test('rotation : une nouvelle distribution remplace l’ancienne clé', async () => {
  const server = createRendezvous();
  const port = await listen(server);
  try {
    const code = 'ROT001';
    const founder = newPeer();
    const bob = newPeer();
    await api(port, 'POST', '/pair', { code, peerId: 'bob', pub: bob.rawPub.toString('base64') });

    const wk = deriveWrapKey(founder.privateKey, bob.rawPub, founder.rawPub);

    const key1 = crypto.randomBytes(32);
    await api(port, 'POST', '/wrap', {
      code, fromPeerId: 'founder', fromPub: founder.rawPub.toString('base64'),
      items: [{ toPeerId: 'bob', blob: wrap(wk, key1) }],
    });
    const got1 = await api(port, 'GET', `/wrap?code=${code}&peerId=bob`);
    assert.deepStrictEqual(unwrap(wk, got1.json.wrap.blob), key1);

    // Rotation : le fondateur redistribue une nouvelle clé.
    const key2 = crypto.randomBytes(32);
    await api(port, 'POST', '/wrap', {
      code, fromPeerId: 'founder', fromPub: founder.rawPub.toString('base64'),
      items: [{ toPeerId: 'bob', blob: wrap(wk, key2) }],
    });
    const got2 = await api(port, 'GET', `/wrap?code=${code}&peerId=bob`);
    const rotated = unwrap(wk, got2.json.wrap.blob);
    assert.deepStrictEqual(rotated, key2);
    assert.ok(!rotated.equals(key1), 'la clé après rotation doit différer');
  } finally {
    server.close();
  }
});

test('un intrus ne peut pas déballer la clé d’un autre membre', async () => {
  const founder = newPeer();
  const bob = newPeer();
  const intruder = newPeer();
  const groupKey = crypto.randomBytes(32);

  const wkForBob = deriveWrapKey(founder.privateKey, bob.rawPub, founder.rawPub);
  const blob = wrap(wkForBob, groupKey);

  // L'intrus tente avec sa propre clé privée + la clé publique du fondateur.
  const wkIntruder = deriveWrapKey(intruder.privateKey, founder.rawPub, intruder.rawPub);
  assert.throws(() => unwrap(wkIntruder, blob));
});

test('health répond ok', async () => {
  const server = createRendezvous();
  const port = await listen(server);
  try {
    const res = await fetch(`http://127.0.0.1:${port}/health`);
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), 'ok');
  } finally {
    server.close();
  }
});
