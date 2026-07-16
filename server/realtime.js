//
//  Temps réel inter-dynos via Redis (Heroku Key-Value).
//
//  Le flux SSE (`/v1/stream`) diffuse les nouveaux messages aux clients CONNECTÉS
//  au même dyno. Avec plusieurs dynos web, un message reçu par le dyno A doit
//  aussi atteindre les clients du dyno B : on publie chaque message sur un canal
//  Redis, et chaque dyno rediffuse à SES clients locaux.
//
//  Le serveur ne diffuse que du chiffré. Tout est no-op sans `REDIS_URL` ou si
//  le module `redis` est absent : on retombe sur le temps réel intra-dyno, qui
//  suffit à un seul dyno. Les clients dédoublonnent par id : une éventuelle
//  double livraison est inoffensive.
//

'use strict';

const crypto = require('node:crypto');

function disabled() {
  return { enabled: false, onMessage() {}, publish() {}, async stop() {} };
}

function createRealtime({ redisUrl, channel = 'brocolis:messages' } = {}) {
  if (!redisUrl) return disabled();

  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`Redis indisponible (${e && e.message}), temps réel intra-dyno.`);
    return disabled();
  }

  const tls = redisUrl.startsWith('rediss://');
  const opts = { url: redisUrl, socket: tls ? { tls: true, rejectUnauthorized: false } : {} };
  const pub = createClient(opts);
  const sub = pub.duplicate();
  const originId = crypto.randomUUID();

  pub.on('error', (e) => { /* eslint-disable-next-line no-console */ console.warn(`Redis pub: ${e && e.message}`); });
  sub.on('error', (e) => { /* eslint-disable-next-line no-console */ console.warn(`Redis sub: ${e && e.message}`); });

  let handler = null;
  let connected = false;

  (async () => {
    try {
      await pub.connect();
      await sub.connect();
      await sub.subscribe(channel, (raw) => {
        try {
          const msg = JSON.parse(raw);
          // Ignore ce que CE dyno a publié (déjà diffusé en local).
          if (msg.origin === originId) return;
          if (handler) handler(msg.convId, msg.payload);
        } catch { /* message ignoré */ }
      });
      connected = true;
      // eslint-disable-next-line no-console
      console.log('Redis connecté : temps réel inter-dynos actif.');
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`Connexion Redis impossible (${e && e.message}), temps réel intra-dyno.`);
    }
  })();

  return {
    enabled: true,
    onMessage(fn) { handler = fn; },
    publish(convId, payload) {
      if (!connected) return;
      pub.publish(channel, JSON.stringify({ origin: originId, convId, payload }))
        .catch(() => { /* publication best-effort */ });
    },
    async stop() {
      try { await sub.quit(); } catch { /* ignore */ }
      try { await pub.quit(); } catch { /* ignore */ }
    },
  };
}

module.exports = { createRealtime };
