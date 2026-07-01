//
//  Tests des mises à jour push de Live Activity (APNs).
//  - JWT ES256 vérifiable, forme de la charge utile.
//  - Endpoints d'enregistrement de token + déclenchement, avec un expéditeur
//    APNs injecté (aucun appel réseau réel).
//
//  Lancer : node --test server/
//

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { createRendezvous } = require('./index.js');
const { buildJWT, buildLiveActivityPayload, createApnsSender } = require('./apns.js');

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

test('buildJWT produit un JWT ES256 vérifiable', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
  });
  const keyP8 = privateKey.export({ format: 'pem', type: 'pkcs8' });

  const now = 1_700_000_000_000;
  const jwt = buildJWT({ keyP8, keyId: 'KEY123', teamId: '2FW8T4UX4L', now });
  const [h, p, s] = jwt.split('.');

  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  assert.strictEqual(header.alg, 'ES256');
  assert.strictEqual(header.kid, 'KEY123');

  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  assert.strictEqual(payload.iss, '2FW8T4UX4L');
  assert.strictEqual(payload.iat, Math.floor(now / 1000));

  const ok = crypto.verify(
    'sha256',
    Buffer.from(`${h}.${p}`),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(s, 'base64url')
  );
  assert.ok(ok, 'la signature ES256 doit être valide');
});

test('buildLiveActivityPayload : update vs end', () => {
  const upd = buildLiveActivityPayload({
    event: 'update',
    contentState: { since: 42 },
    timestamp: 100,
  });
  assert.deepStrictEqual(upd, {
    aps: { timestamp: 100, event: 'update', 'content-state': { since: 42 } },
  });

  const end = buildLiveActivityPayload({
    event: 'end',
    contentState: { since: 42 },
    timestamp: 100,
    dismissalDate: 200,
  });
  assert.strictEqual(end.aps.event, 'end');
  assert.strictEqual(end.aps['dismissal-date'], 200);
});

test('createApnsSender renvoie null si la config est incomplète', () => {
  assert.strictEqual(createApnsSender({}), null);
  assert.strictEqual(
    createApnsSender({ keyP8: 'x', keyId: 'y', teamId: 'z' }), // bundleId manquant
    null
  );
});

test('createApnsSender : sendLiveActivity passe les bons champs au transport', async () => {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keyP8 = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const calls = [];
  const sender = createApnsSender({
    keyP8,
    keyId: 'K',
    teamId: 'T',
    bundleId: 'rs.brocolis.messagerie',
    environment: 'production',
    now: () => 1_700_000_000_000,
    transport: async (args) => {
      calls.push(args);
      return { status: 200, body: '' };
    },
  });
  const r = await sender.sendLiveActivity({
    token: 'DEVTOK',
    event: 'update',
    contentState: { since: 1 },
  });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].host, 'https://api.push.apple.com');
  assert.strictEqual(calls[0].deviceToken, 'DEVTOK');
  assert.strictEqual(calls[0].topic, 'rs.brocolis.messagerie.push-type.liveactivity');
  assert.strictEqual(calls[0].payload.aps.event, 'update');
});

test('endpoint : enregistrement du token puis déclenchement APNs', async () => {
  const calls = [];
  const server = createRendezvous({
    apns: {
      sendLiveActivity: async (args) => {
        calls.push(args);
        return { status: 200, body: '' };
      },
    },
  });
  const port = await listen(server);
  try {
    const reg = await api(port, 'POST', '/push/live-activity/token', {
      code: '1234',
      peerId: 'alice',
      token: 'TOKEN_ABC',
    });
    assert.strictEqual(reg.status, 200);
    assert.strictEqual(reg.json.ok, true);

    const upd = await api(port, 'POST', '/push/live-activity/update', {
      code: '1234',
      peerId: 'alice',
      event: 'update',
      contentState: { since: 7 },
    });
    assert.strictEqual(upd.status, 200);
    assert.strictEqual(upd.json.apns, 200);
    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].token, 'TOKEN_ABC');
    assert.strictEqual(calls[0].event, 'update');
    assert.deepStrictEqual(calls[0].contentState, { since: 7 });
  } finally {
    server.close();
  }
});

test('update : 404 si aucun token enregistré', async () => {
  const server = createRendezvous({ apns: { sendLiveActivity: async () => ({ status: 200 }) } });
  const port = await listen(server);
  try {
    const r = await api(port, 'POST', '/push/live-activity/update', {
      code: 'zzz',
      peerId: 'inconnu',
      event: 'update',
      contentState: { since: 1 },
    });
    assert.strictEqual(r.status, 404);
  } finally {
    server.close();
  }
});

test('update : 503 si push non configuré, 400 si event invalide', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    await api(port, 'POST', '/push/live-activity/token', {
      code: 'c',
      peerId: 'p',
      token: 't',
    });
    const bad = await api(port, 'POST', '/push/live-activity/update', {
      code: 'c',
      peerId: 'p',
      event: 'boom',
      contentState: {},
    });
    assert.strictEqual(bad.status, 400);

    const noConf = await api(port, 'POST', '/push/live-activity/update', {
      code: 'c',
      peerId: 'p',
      event: 'update',
      contentState: {},
    });
    assert.strictEqual(noConf.status, 503);
  } finally {
    server.close();
  }
});
