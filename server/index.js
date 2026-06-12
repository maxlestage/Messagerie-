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
const fs = require('fs');
const path = require('path');

const TTL_MS = 10 * 60 * 1000; // 10 min

// Vitrine statique (le site React de site/, pré-construit dans public/) servie
// sur /site/. L'API de rendez-vous reste sur /pair, /wrap, /health.
const SITE_DIR = path.join(__dirname, 'public');
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
  '.woff2': 'font/woff2',
};

// Sert un fichier de la vitrine pour un chemin commençant par /site/.
// Renvoie true si la requête a été traitée (fichier servi ou 404 vitrine).
function serveSite(res, pathname) {
  let rel = decodeURIComponent(pathname.slice('/site/'.length));
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';
  // Garde anti-traversée : on résout puis on vérifie qu'on reste dans SITE_DIR.
  const filePath = path.join(SITE_DIR, rel);
  if (filePath !== SITE_DIR && !filePath.startsWith(SITE_DIR + path.sep)) {
    res.writeHead(403, { 'content-type': 'text/plain' });
    res.end('forbidden');
    return true;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('introuvable');
      return;
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(filePath)] || 'application/octet-stream' });
    res.end(data);
  });
  return true;
}
const DEFAULT_MAX_PEERS = Number(process.env.MAX_PEERS) || 16;

// Page d'accueil HTML rigolote et multilingue (FR/EN/ES). Sert juste de vitrine ;
// l'API reste sur /pair, /wrap, /health. Le <script> n'utilise pas de template
// literal (pas de ${...}) pour rester dans cette chaîne backtick côté Node.
const HOME_HTML = `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Brocolis 🥦 — serveur de rendez-vous</title>
<style>
  :root, :root[data-theme="green"] {
    --bg: #e9f6ec; --bg-glow: #bfe6c8; --card: #ffffff; --card-border: #d6e8da;
    --ink: #15321f; --muted: #45624f; --accent: #2f9e4a; --accent-dark: #1f6d2c;
    --on-accent: #ffffff; --box-bg: #f1f8f3; --box-border: #dcebe0;
    --pill-bg: #eef6f0; --pill-border: #d6e8da; --shadow: rgba(20,80,40,.12); --foot: #7b9484;
  }
  :root[data-theme="light"] {
    --bg: #ffffff; --bg-glow: #eef7ef; --card: #f8faf8; --card-border: #e6e6e6;
    --ink: #1b1b1b; --muted: #555555; --accent: #2f9e4a; --accent-dark: #1f6d2c;
    --on-accent: #ffffff; --box-bg: #f3f5f3; --box-border: #e6e6e6;
    --pill-bg: #eef0ee; --pill-border: #e0e0e0; --shadow: rgba(0,0,0,.08); --foot: #8a8a8a;
  }
  :root[data-theme="dark"] {
    --bg: #0d1410; --bg-glow: #13311e; --card: #161d18; --card-border: #26302a;
    --ink: #e7efe9; --muted: #9fb2a5; --accent: #4cc66a; --accent-dark: #6fd98a;
    --on-accent: #08160c; --box-bg: #12211a; --box-border: #26302a;
    --pill-bg: #12211a; --pill-border: #26302a; --shadow: rgba(0,0,0,.5); --foot: #7b9484;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: var(--ink);
    background: radial-gradient(1200px 600px at 50% -10%, var(--bg-glow), transparent), var(--bg);
    padding: 24px; transition: background-color .25s ease, color .25s ease;
  }
  .card {
    background: var(--card); border: 1px solid var(--card-border); border-radius: 22px;
    max-width: 560px; width: 100%; padding: 30px 26px 22px;
    box-shadow: 0 20px 60px var(--shadow); text-align: center;
  }
  .veg { font-size: 84px; line-height: 1; display: inline-block; animation: bob 2.2s ease-in-out infinite; }
  @keyframes bob { 0%,100% { transform: translateY(0) rotate(-3deg); } 50% { transform: translateY(-12px) rotate(3deg); } }
  h1 { margin: 10px 0 4px; font-size: 26px; letter-spacing: -.3px; }
  .status { display: inline-flex; align-items: center; gap: 8px; font-weight: 700; color: var(--accent); margin: 6px 0 14px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 0 0 rgba(47,158,74,.6); animation: pulse 1.6s infinite; }
  @keyframes pulse { 0% { box-shadow: 0 0 0 0 rgba(47,158,74,.55);} 70% { box-shadow: 0 0 0 12px rgba(47,158,74,0);} 100% { box-shadow: 0 0 0 0 rgba(47,158,74,0);} }
  .tagline { font-size: 18px; color: var(--muted); margin: 0 auto 16px; max-width: 460px; }
  .box { background: var(--box-bg); border: 1px solid var(--box-border); border-radius: 14px; padding: 14px 16px; text-align: left; margin: 14px 0; }
  .box h2 { margin: 0 0 6px; font-size: 15px; }
  .box p { margin: 0; font-size: 14px; color: var(--muted); }
  .joke { font-style: italic; color: var(--muted); font-size: 14px; margin: 10px 0 16px; }
  .cta { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; margin-bottom: 8px; }
  .btn { text-decoration: none; padding: 11px 18px; border-radius: 11px; font-weight: 700; font-size: 15px; border: 1px solid var(--accent); }
  .btn.primary { background: var(--accent); color: var(--on-accent); }
  .btn.ghost { color: var(--accent-dark); background: var(--card); }
  .switchers { display: inline-flex; gap: 10px; flex-wrap: wrap; justify-content: center; margin: 4px 0 14px; }
  .pills { display: inline-flex; gap: 2px; background: var(--pill-bg); border: 1px solid var(--pill-border); border-radius: 999px; padding: 3px; }
  .lang, .theme { border: 0; background: transparent; cursor: pointer; font-weight: 700; font-size: 13px; padding: 6px 12px; border-radius: 999px; color: var(--ink); }
  .lang.active, .theme.active { background: var(--accent); color: var(--on-accent); }
  footer { margin-top: 12px; font-size: 12.5px; color: var(--foot); }
</style>
</head>
<body>
  <main class="card">
    <div class="veg">🥦</div>
    <div class="switchers">
      <div class="pills">
        <button class="lang" data-lang="fr">FR</button>
        <button class="lang" data-lang="en">EN</button>
        <button class="lang" data-lang="es">ES</button>
      </div>
      <div class="pills">
        <button class="theme" data-theme="green" title="Vert">🥦</button>
        <button class="theme" data-theme="light" title="Clair">☀</button>
        <button class="theme" data-theme="dark" title="Sombre">🌙</button>
      </div>
    </div>
    <h1 data-i18n="title">Serveur de rendez-vous</h1>
    <div class="status"><span class="dot"></span><span data-i18n="status">En ligne — tout roule !</span></div>
    <p class="tagline" data-i18n="tagline">Je présente les téléphones entre eux pour qu'ils échangent leurs clés. Promis, je ne lis rien. 🤫</p>
    <div class="box">
      <h2 data-i18n="explainTitle">C'est quoi ce truc ?</h2>
      <p data-i18n="explain">Ce serveur met juste deux téléphones en relation (échange de clés publiques X25519). Il ne voit jamais tes messages ni ta clé secrète — seulement du charabia chiffré.</p>
    </div>
    <p class="joke" data-i18n="joke">Aucun brocoli n'a été blessé pendant le chiffrement.</p>
    <div class="cta">
      <a class="btn primary" data-i18n="ctaApp" href="/site/">Découvrir l'app</a>
      <a class="btn ghost" data-i18n="ctaBrocolis" href="https://maxlestage.github.io/brocolis/">Projet brocolis</a>
    </div>
    <footer data-i18n="footer">Hébergé avec amour et un peu de chlorophylle.</footer>
  </main>
<script>
  var I18N = {
    fr: {
      title: "Serveur de rendez-vous",
      status: "En ligne — tout roule !",
      tagline: "Je présente les téléphones entre eux pour qu'ils échangent leurs clés. Promis, je ne lis rien. 🤫",
      explainTitle: "C'est quoi ce truc ?",
      explain: "Ce serveur met juste deux téléphones en relation (échange de clés publiques X25519). Il ne voit jamais tes messages ni ta clé secrète — seulement du charabia chiffré.",
      joke: "Aucun brocoli n'a été blessé pendant le chiffrement.",
      ctaApp: "Découvrir l'app",
      ctaBrocolis: "Projet brocolis",
      footer: "Hébergé avec amour et un peu de chlorophylle."
    },
    en: {
      title: "Rendezvous server",
      status: "Online — all good!",
      tagline: "I introduce phones to each other so they can swap keys. I promise I read nothing. 🤫",
      explainTitle: "What is this thing?",
      explain: "This server only connects two phones (X25519 public-key exchange). It never sees your messages or your secret key — just encrypted gibberish.",
      joke: "No broccoli was harmed during encryption.",
      ctaApp: "Discover the app",
      ctaBrocolis: "brocolis project",
      footer: "Hosted with love and a little chlorophyll."
    },
    es: {
      title: "Servidor de encuentro",
      status: "En línea — ¡todo bien!",
      tagline: "Presento los teléfonos entre sí para que intercambien claves. Prometo que no leo nada. 🤫",
      explainTitle: "¿Qué es esto?",
      explain: "Este servidor solo conecta dos teléfonos (intercambio de claves públicas X25519). Nunca ve tus mensajes ni tu clave secreta — solo galimatías cifrado.",
      joke: "Ningún brócoli resultó herido durante el cifrado.",
      ctaApp: "Descubrir la app",
      ctaBrocolis: "Proyecto brocolis",
      footer: "Alojado con amor y un poco de clorofila."
    }
  };
  function apply(lang){
    var d = I18N[lang] || I18N.fr;
    document.documentElement.lang = lang;
    var nodes = document.querySelectorAll('[data-i18n]');
    for (var i = 0; i < nodes.length; i++){
      var k = nodes[i].getAttribute('data-i18n');
      if (d[k]) nodes[i].textContent = d[k];
    }
    var btns = document.querySelectorAll('.lang');
    for (var j = 0; j < btns.length; j++){
      btns[j].classList.toggle('active', btns[j].getAttribute('data-lang') === lang);
    }
    try { localStorage.setItem('brocolis.srv.lang', lang); } catch (e) {}
  }
  function detect(){
    try { var s = localStorage.getItem('brocolis.srv.lang'); if (s && I18N[s]) return s; } catch (e) {}
    var n = (navigator.language || 'fr').slice(0, 2).toLowerCase();
    return I18N[n] ? n : 'fr';
  }
  function applyTheme(theme){
    document.documentElement.setAttribute('data-theme', theme);
    var tb = document.querySelectorAll('.theme');
    for (var i = 0; i < tb.length; i++){
      tb[i].classList.toggle('active', tb[i].getAttribute('data-theme') === theme);
    }
    try { localStorage.setItem('brocolis.srv.theme', theme); } catch (e) {}
  }
  function detectTheme(){
    try { var s = localStorage.getItem('brocolis.srv.theme'); if (s) return s; } catch (e) {}
    return 'green';
  }
  document.addEventListener('click', function(e){
    if (!e.target.closest) return;
    var l = e.target.closest('.lang');
    if (l) { apply(l.getAttribute('data-lang')); return; }
    var t = e.target.closest('.theme');
    if (t) { applyTheme(t.getAttribute('data-theme')); }
  });
  apply(detect());
  applyTheme(detectTheme());
</script>
</body>
</html>`;

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
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(HOME_HTML);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }

    // Vitrine : /site -> /site/ (pour que les liens relatifs résolvent), puis
    // sert les fichiers statiques pré-construits.
    if (req.method === 'GET' && url.pathname === '/site') {
      res.writeHead(302, { location: '/site/' });
      res.end();
      return;
    }
    if (req.method === 'GET' && url.pathname.startsWith('/site/')) {
      if (serveSite(res, url.pathname)) return;
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
