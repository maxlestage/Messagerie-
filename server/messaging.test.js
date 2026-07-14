//
//  Tests de la messagerie chiffrée (E2E) ajoutée au serveur.
//  Le serveur ne route/stocke que du chiffré ; ici on envoie des `ciphertext`
//  factices (le serveur ne les lit pas). Couvre : auth, flux create→send→fetch,
//  conversation « scellée » (clé partagée, deux identités), idempotence, et le
//  flux temps réel SSE.
//
//  Lancer : node --test server/
//

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createRendezvous } = require('./index.js');

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, () => resolve(server.address().port));
  });
}

async function api(port, method, path, { userId, body } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (userId) headers['x-user-id'] = userId;
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

test('la messagerie exige X-User-Id', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    const r = await api(port, 'GET', '/v1/conversations');
    assert.strictEqual(r.status, 401);
  } finally {
    server.close();
  }
});

test('flux complet : créer → envoyer → lire par l’autre participant', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    const created = await api(port, 'POST', '/v1/conversations', {
      userId: 'alice',
      body: {
        participants: [
          { id: 'alice', displayName: 'Alice' },
          { id: 'bob', displayName: 'Bob' },
        ],
      },
    });
    assert.strictEqual(created.status, 201);
    const cid = created.json.id;

    const sent = await api(port, 'POST', '/v1/messages', {
      userId: 'alice',
      body: { conversationId: cid, senderId: 'alice', ciphertext: 'QUJD' },
    });
    assert.strictEqual(sent.status, 201);
    assert.strictEqual(sent.json.seq, 1);

    const page = await api(port, 'GET', `/v1/messages?conversationId=${cid}`, { userId: 'bob' });
    assert.strictEqual(page.status, 200);
    assert.strictEqual(page.json.messages.length, 1);
    assert.strictEqual(page.json.messages[0].ciphertext, 'QUJD');
    assert.strictEqual(page.json.cursor, 1);
  } finally {
    server.close();
  }
});

test('conversation scellée : deux identités, même id dérivé de la clé', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    const cid = 'empreinte-de-la-cle-partagee';
    // Alice poste sans créer de conversation → auto-scellée.
    const sent = await api(port, 'POST', '/v1/messages', {
      userId: 'alice-device',
      body: { conversationId: cid, senderId: 'alice-device', ciphertext: 'W1tCUk9DT0xJUzp2MTouXV0=' },
    });
    assert.strictEqual(sent.status, 201);

    // Bob (autre identité, même clé donc même id) lit.
    const page = await api(port, 'GET', `/v1/messages?conversationId=${cid}`, { userId: 'bob-device' });
    assert.strictEqual(page.status, 200);
    assert.strictEqual(page.json.messages.length, 1);
  } finally {
    server.close();
  }
});

test('un non-participant ne lit pas une conversation à participants', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    const created = await api(port, 'POST', '/v1/conversations', {
      userId: 'alice',
      body: {
        participants: [
          { id: 'alice', displayName: 'Alice' },
          { id: 'bob', displayName: 'Bob' },
        ],
      },
    });
    const cid = created.json.id;
    const page = await api(port, 'GET', `/v1/messages?conversationId=${cid}`, { userId: 'eve' });
    assert.strictEqual(page.status, 403);
  } finally {
    server.close();
  }
});

test('l’envoi est idempotent sur id', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    const cid = 'conv-idempotence';
    const payload = { conversationId: cid, senderId: 'a', ciphertext: 'QUJD', id: 'fixe-1' };
    await api(port, 'POST', '/v1/messages', { userId: 'a', body: payload });
    await api(port, 'POST', '/v1/messages', { userId: 'a', body: payload });
    const page = await api(port, 'GET', `/v1/messages?conversationId=${cid}`, { userId: 'a' });
    assert.strictEqual(page.json.messages.length, 1);
  } finally {
    server.close();
  }
});

test('accusé de lecture : /v1/read met à jour readers', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  try {
    const cid = 'conv-lu';
    await api(port, 'POST', '/v1/messages', {
      userId: 'alice',
      body: { conversationId: cid, senderId: 'alice', ciphertext: 'QUJD' },
    });
    // Bob lit jusqu'au seq 1.
    const r = await api(port, 'POST', '/v1/read', { userId: 'bob', body: { conversationId: cid, upTo: 1 } });
    assert.strictEqual(r.status, 200);
    // Alice voit que bob a lu jusqu'à 1.
    const page = await api(port, 'GET', `/v1/messages?conversationId=${cid}`, { userId: 'alice' });
    assert.strictEqual(page.json.readers.bob, 1);
  } finally {
    server.close();
  }
});

test('SSE : un message posté arrive en temps réel', async () => {
  const server = createRendezvous({ apns: null });
  const port = await listen(server);
  const controller = new AbortController();
  try {
    const cid = 'conv-sse';
    const res = await fetch(`http://127.0.0.1:${port}/v1/stream?conversationId=${cid}`, {
      headers: { 'x-user-id': 'bob' },
      signal: controller.signal,
    });
    assert.strictEqual(res.status, 200);

    // Lit le flux en tâche de fond jusqu'à recevoir un évènement `data:`.
    const received = (async () => {
      const decoder = new TextDecoder();
      let buffer = '';
      for await (const chunk of res.body) {
        buffer += decoder.decode(chunk, { stream: true });
        const idx = buffer.indexOf('data:');
        if (idx !== -1) {
          const line = buffer.slice(idx).split('\n\n')[0];
          return line.slice('data:'.length).trim();
        }
      }
      return null;
    })();

    // Laisse le flux s'établir, puis poste.
    await new Promise((r) => setTimeout(r, 100));
    await api(port, 'POST', '/v1/messages', {
      userId: 'alice',
      body: { conversationId: cid, senderId: 'alice', ciphertext: 'SEVMTE8=' },
    });

    const json = await Promise.race([
      received,
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout SSE')), 3000)),
    ]);
    const msg = JSON.parse(json);
    assert.strictEqual(msg.ciphertext, 'SEVMTE8=');
    assert.strictEqual(msg.senderId, 'alice');
  } finally {
    controller.abort();
    server.close();
  }
});
