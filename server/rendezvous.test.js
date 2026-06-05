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
