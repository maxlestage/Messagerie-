//
//  Serveur de rendez-vous brocolis 🥦
//
//  Rôle : permettre à deux appareils partageant un même CODE court d'échanger
//  automatiquement leurs CLÉS PUBLIQUES X25519. Chacun dérive ensuite, de son
//  côté, la même clé symétrique AES (ECDH + HKDF) — le serveur ne voit donc
//  jamais la clé secrète ni les messages.
//
//  Le serveur ne stocke que des clés publiques, de façon éphémère (TTL), et
//  limite chaque code à 2 participants.
//
//  API :
//    POST /pair   { code, peerId, pub }  -> { peers: [{ peerId, pub }, ...] }
//    GET  /pair?code=...&peerId=...       -> { peers: [...] }
//    GET  /health                         -> "ok"
//

'use strict';

const http = require('http');

const TTL_MS = 10 * 60 * 1000; // 10 min
const DEFAULT_MAX_PEERS = Number(process.env.MAX_PEERS) || 16;

function createRendezvous(options = {}) {
  // Plafond de participants par code (configurable).
  const maxPeers = options.maxPeers ?? DEFAULT_MAX_PEERS;
  // code -> Map(peerId -> { pub, ts })
  const codes = new Map();
  // code -> Map(toPeerId -> { from, fromPub, blob, ts })  (clés de groupe emballées)
  const wraps = new Map();

  function prune() {
    const now = Date.now();
    for (const [code, peers] of codes) {
      for (const [peerId, entry] of peers) {
        if (now - entry.ts > TTL_MS) peers.delete(peerId);
      }
      if (peers.size === 0) codes.delete(code);
    }
    for (const [code, recips] of wraps) {
      for (const [toId, entry] of recips) {
        if (now - entry.ts > TTL_MS) recips.delete(toId);
      }
      if (recips.size === 0) wraps.delete(code);
    }
  }

  function peersExcluding(code, peerId) {
    const peers = codes.get(code);
    if (!peers) return [];
    return [...peers.entries()]
      .filter(([id]) => id !== peerId)
      .map(([id, entry]) => ({ peerId: id, pub: entry.pub }));
  }

  function sendJSON(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(body);
  }

  const server = http.createServer((req, res) => {
    prune();
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('Serveur de rendez-vous Brocolis 🥦 — tout va bien.');
      return;
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }

    if (req.method === 'GET' && url.pathname === '/pair') {
      const code = (url.searchParams.get('code') || '').trim();
      const peerId = url.searchParams.get('peerId') || '';
      if (!code) return sendJSON(res, 400, { error: 'code requis' });
      return sendJSON(res, 200, { peers: peersExcluding(code, peerId) });
    }

    if (req.method === 'POST' && url.pathname === '/pair') {
      let raw = '';
      req.on('data', (chunk) => {
        raw += chunk;
        if (raw.length > 8192) req.destroy(); // garde-fou
      });
      req.on('end', () => {
        let body;
        try {
          body = JSON.parse(raw);
        } catch {
          return sendJSON(res, 400, { error: 'JSON invalide' });
        }
        const code = (body.code || '').trim();
        const peerId = (body.peerId || '').trim();
        const pub = (body.pub || '').trim();
        if (!code || !peerId || !pub) {
          return sendJSON(res, 400, { error: 'code, peerId et pub requis' });
        }

        let peers = codes.get(code);
        if (!peers) {
          peers = new Map();
          codes.set(code, peers);
        }
        // Autorise la mise à jour d'un peerId déjà présent ; sinon applique le plafond.
        if (!peers.has(peerId) && peers.size >= maxPeers) {
          return sendJSON(res, 409, { error: `ce code a déjà ${maxPeers} participants` });
        }
        peers.set(peerId, { pub, ts: Date.now() });
        return sendJSON(res, 200, { peers: peersExcluding(code, peerId) });
      });
      return;
    }

    // --- Clés de groupe emballées (key-wrapping X25519) ---

    if (req.method === 'GET' && url.pathname === '/wrap') {
      const code = (url.searchParams.get('code') || '').trim();
      const peerId = url.searchParams.get('peerId') || '';
      if (!code || !peerId) return sendJSON(res, 400, { error: 'code et peerId requis' });
      const recips = wraps.get(code);
      const entry = recips ? recips.get(peerId) : undefined;
      if (!entry) return sendJSON(res, 200, { wrap: null });
      return sendJSON(res, 200, { wrap: { from: entry.from, fromPub: entry.fromPub, blob: entry.blob } });
    }

    if (req.method === 'POST' && url.pathname === '/wrap') {
      let raw = '';
      req.on('data', (chunk) => {
        raw += chunk;
        if (raw.length > 65536) req.destroy();
      });
      req.on('end', () => {
        let body;
        try {
          body = JSON.parse(raw);
        } catch {
          return sendJSON(res, 400, { error: 'JSON invalide' });
        }
        const code = (body.code || '').trim();
        const from = (body.fromPeerId || '').trim();
        const fromPub = (body.fromPub || '').trim();
        const items = Array.isArray(body.items) ? body.items : null;
        if (!code || !from || !fromPub || !items) {
          return sendJSON(res, 400, { error: 'code, fromPeerId, fromPub et items requis' });
        }
        let recips = wraps.get(code);
        if (!recips) {
          recips = new Map();
          wraps.set(code, recips);
        }
        let count = 0;
        const now = Date.now();
        for (const it of items) {
          const toId = (it && it.toPeerId || '').trim();
          const blob = (it && it.blob || '').trim();
          if (toId && blob) {
            recips.set(toId, { from, fromPub, blob, ts: now });
            count += 1;
          }
        }
        return sendJSON(res, 200, { ok: true, count });
      });
      return;
    }

    sendJSON(res, 404, { error: 'route inconnue' });
  });

  return server;
}

if (require.main === module) {
  const PORT = process.env.PORT || 8788;
  createRendezvous().listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Rendez-vous brocolis 🥦 à l'écoute sur le port ${PORT}`);
  });
}

module.exports = { createRendezvous };
