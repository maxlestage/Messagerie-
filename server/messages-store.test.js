//
//  Tests du stockage des messages : idempotence, conversations scellées, et
//  surtout la PERSISTANCE (les messages survivent à la réouverture de la base,
//  c'est-à-dire à un redémarrage du process).
//
//  Lancer : node --test server/
//

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createMessageStore } = require('./messages-store.js');

function tmpDb() {
  return path.join(os.tmpdir(), `brocolis-test-${process.pid}-${Math.random().toString(36).slice(2)}.db`);
}

test('SQLite : les messages survivent à la réouverture (persistance)', () => {
  const file = tmpDb();
  try {
    const s1 = createMessageStore({ dbPath: file });
    assert.strictEqual(s1.backend, 'sqlite');
    s1.ensureSealed('conv-persist', new Date().toISOString());
    const stored = s1.appendMessage('conv-persist', {
      id: 'm1', senderId: 'alice', ciphertext: '[[BROCOLIS:v1:AAAA]]', sentAt: new Date().toISOString(),
    });
    assert.strictEqual(stored.seq, 1);

    // Réouverture (simule un redémarrage du process) sur le MÊME fichier.
    const s2 = createMessageStore({ dbPath: file });
    const after = s2.messagesAfter('conv-persist', 0);
    assert.strictEqual(after.length, 1);
    assert.strictEqual(after[0].id, 'm1');
    assert.strictEqual(after[0].ciphertext, '[[BROCOLIS:v1:AAAA]]');
  } finally {
    for (const ext of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(file + ext); } catch { /* absent */ }
    }
  }
});

test('SQLite : idempotence sur (conversation, id)', () => {
  const file = tmpDb();
  try {
    const s = createMessageStore({ dbPath: file });
    const msg = { id: 'dup', senderId: 'a', ciphertext: 'X', sentAt: new Date().toISOString() };
    const a = s.appendMessage('c', msg);
    const b = s.appendMessage('c', msg);
    assert.strictEqual(a.seq, b.seq);
    assert.strictEqual(s.messagesAfter('c', 0).length, 1);
  } finally {
    for (const ext of ['', '-wal', '-shm']) {
      try { fs.unlinkSync(file + ext); } catch { /* absent */ }
    }
  }
});

test('curseur seq : messagesAfter ne renvoie que la suite', () => {
  const s = createMessageStore({ dbPath: ':memory:' });
  s.appendMessage('c', { id: '1', senderId: 'a', ciphertext: 'X', sentAt: 't' });
  s.appendMessage('c', { id: '2', senderId: 'a', ciphertext: 'Y', sentAt: 't' });
  const all = s.messagesAfter('c', 0);
  assert.strictEqual(all.length, 2);
  const after1 = s.messagesAfter('c', all[0].seq);
  assert.strictEqual(after1.length, 1);
  assert.strictEqual(after1[0].id, '2');
});

test('conversation à participants : accès filtré', () => {
  const s = createMessageStore({ dbPath: ':memory:' });
  s.createConversation('cX', [{ id: 'alice', displayName: 'Alice' }, { id: 'bob', displayName: 'Bob' }], 't');
  const c = s.getConversation('cX');
  assert.strictEqual(c.participants.length, 2);
  assert.deepStrictEqual(s.listConversationsFor('alice').map((x) => x.id), ['cX']);
  assert.deepStrictEqual(s.listConversationsFor('eve'), []);
});

test('repli mémoire quand aucun dbPath', () => {
  const s = createMessageStore({});
  assert.strictEqual(s.backend, 'memory');
  const m = s.appendMessage('c', { id: '1', senderId: 'a', ciphertext: 'X', sentAt: 't' });
  assert.strictEqual(m.seq, 1);
});

// Rétention : les messages plus vieux que la fenêtre sont purgés, les récents
// gardés. Testé sur les DEUX backends (SQLite + mémoire).
for (const makeStore of [
  { name: 'SQLite', build: () => createMessageStore({ dbPath: ':memory:' }) },
  { name: 'mémoire', build: () => createMessageStore({}) },
]) {
  test(`rétention (${makeStore.name}) : pruneBefore garde 7 j, supprime le reste`, () => {
    const s = makeStore.build();
    const day = 24 * 60 * 60 * 1000;
    const now = Date.now();
    const old = new Date(now - 10 * day).toISOString(); // 10 j → doit partir
    const recent = new Date(now - 2 * day).toISOString(); // 2 j → doit rester

    s.ensureSealed('c', old);
    s.appendMessage('c', { id: 'vieux', senderId: 'a', ciphertext: 'X', sentAt: old });
    s.appendMessage('c', { id: 'recent', senderId: 'a', ciphertext: 'Y', sentAt: recent });
    assert.strictEqual(s.messagesAfter('c', 0).length, 2);

    const cutoff = new Date(now - 7 * day).toISOString();
    const removed = s.pruneBefore(cutoff);
    assert.strictEqual(removed, 1);

    const left = s.messagesAfter('c', 0);
    assert.strictEqual(left.length, 1);
    assert.strictEqual(left[0].id, 'recent');
  });
}
