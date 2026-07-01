//
//  Client APNs minimal (sans dépendance) — mises à jour de Live Activity.
//
//  Envoie des pushs `liveactivity` à App Store / APNs pour mettre à jour ou
//  terminer la Live Activity « Brocolis actif » 🥦 à distance. Authentification
//  par jeton (clé APNs .p8, JWT ES256), transport HTTP/2 natif. Le token de la
//  Live Activity est fourni par l'app (cf. docs/ios-push-live-activity.md).
//

'use strict';

const crypto = require('node:crypto');
const http2 = require('node:http2');

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

/// Construit un JWT ES256 signé pour APNs (header alg/kid, payload iss/iat).
/// `now` est un timestamp en millisecondes.
function buildJWT({ keyP8, keyId, teamId, now }) {
  const header = base64url(JSON.stringify({ alg: 'ES256', kid: keyId }));
  const payload = base64url(
    JSON.stringify({ iss: teamId, iat: Math.floor(now / 1000) })
  );
  const signingInput = `${header}.${payload}`;
  const privateKey = crypto.createPrivateKey(keyP8);
  // `ieee-p1363` produit la signature R||S brute attendue par JOSE/ES256
  // (et non l'encodage DER par défaut d'OpenSSL).
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${base64url(signature)}`;
}

/// Construit la charge utile `aps` d'une mise à jour de Live Activity.
/// `event` vaut "update" ou "end". `timestamp`/`dismissalDate` sont des
/// secondes Unix. `contentState` doit correspondre à
/// `BrocolisActivityAttributes.ContentState`.
function buildLiveActivityPayload({
  event,
  contentState,
  timestamp,
  dismissalDate,
  staleDate,
  alert,
}) {
  const aps = { timestamp, event, 'content-state': contentState };
  if (event === 'end' && dismissalDate != null) {
    aps['dismissal-date'] = dismissalDate;
  }
  if (staleDate != null) aps['stale-date'] = staleDate;
  if (alert != null) aps.alert = alert;
  return { aps };
}

/// Envoie une requête POST APNs via HTTP/2. Résout `{ status, body }`.
function sendHttp2({ host, deviceToken, jwt, topic, payload }) {
  return new Promise((resolve, reject) => {
    const client = http2.connect(host);
    client.on('error', reject);

    const body = JSON.stringify(payload);
    const req = client.request({
      ':method': 'POST',
      ':path': `/3/device/${deviceToken}`,
      authorization: `bearer ${jwt}`,
      'apns-topic': topic,
      'apns-push-type': 'liveactivity',
      'apns-priority': '10',
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    });

    let status = 0;
    let data = '';
    req.on('response', (headers) => {
      status = headers[':status'];
    });
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('error', (err) => {
      client.close();
      reject(err);
    });
    req.on('end', () => {
      client.close();
      resolve({ status, body: data });
    });
    req.end(body);
  });
}

/// Fabrique un « expéditeur » de mises à jour de Live Activity, ou `null` si la
/// configuration APNs est incomplète (le serveur répond alors 503).
///
/// Options :
///   keyP8, keyId, teamId, bundleId : identifiants APNs.
///   environment : "sandbox" (défaut, builds development) ou "production".
///   now : injectable pour les tests (défaut Date.now).
///   transport : injectable pour les tests (défaut sendHttp2).
function createApnsSender({
  keyP8,
  keyId,
  teamId,
  bundleId,
  environment = 'sandbox',
  now = () => Date.now(),
  transport = sendHttp2,
} = {}) {
  if (!keyP8 || !keyId || !teamId || !bundleId) return null;

  const host =
    environment === 'production'
      ? 'https://api.push.apple.com'
      : 'https://api.sandbox.push.apple.com';
  const topic = `${bundleId}.push-type.liveactivity`;

  // Le JWT APNs est valable ≤ 60 min ; on le renouvelle toutes les ~50 min.
  let cached = null;
  function jwt() {
    const t = now();
    if (cached && t < cached.exp) return cached.jwt;
    const token = buildJWT({ keyP8, keyId, teamId, now: t });
    cached = { jwt: token, exp: t + 50 * 60 * 1000 };
    return token;
  }

  return {
    async sendLiveActivity({ token, event, contentState, timestamp, dismissalDate }) {
      const payload = buildLiveActivityPayload({
        event,
        contentState,
        timestamp: timestamp != null ? timestamp : Math.floor(now() / 1000),
        dismissalDate,
      });
      return transport({ host, deviceToken: token, jwt: jwt(), topic, payload });
    },
  };
}

module.exports = { buildJWT, buildLiveActivityPayload, createApnsSender };
