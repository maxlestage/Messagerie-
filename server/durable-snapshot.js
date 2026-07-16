//
//  Persistance DURABLE du store SQLite sur Heroku Postgres.
//
//  Heroku efface le disque du dyno à chaque déploiement / recyclage : le fichier
//  SQLite ne survit donc pas. On garde une COPIE du fichier `.db` dans Postgres
//  (colonne `bytea`), restaurée au démarrage et ré-enregistrée périodiquement +
//  à l'arrêt (SIGTERM, envoyé par Heroku avant de couper le dyno).
//
//  Avantage : ZÉRO changement du chemin runtime (mêmes `seq`, mêmes curseurs de
//  lecture) — on sauvegarde/restaure le fichier tel quel. Le serveur ne stocke
//  que du chiffré, donc la sauvegarde ne contient QUE des jetons illisibles.
//
//  Tout est no-op sans `DATABASE_URL` ou si le module `pg` est absent (tests,
//  dev local) : le serveur fonctionne alors comme avant (SQLite éphémère).
//

'use strict';

const fs = require('node:fs');

function makePool(databaseUrl) {
  let Pool;
  try { ({ Pool } = require('pg')); }
  catch (e) { throw new Error(`module 'pg' indisponible (${e && e.message})`); }
  // Heroku Postgres impose TLS avec un certificat non vérifiable par défaut.
  const local = /@(localhost|127\.0\.0\.1)[:/]/.test(databaseUrl);
  const ssl = local ? false : { rejectUnauthorized: false };
  return new Pool({ connectionString: databaseUrl, ssl, max: 3 });
}

function usable({ databaseUrl, dbPath }) {
  return Boolean(databaseUrl) && Boolean(dbPath) && dbPath !== ':memory:';
}

/// Restaure le fichier `dbPath` depuis Postgres s'il existe une sauvegarde.
/// Renvoie true si un fichier a été écrit. À APPELER avant d'ouvrir la base.
async function restoreSnapshot({ databaseUrl, dbPath }) {
  if (!usable({ databaseUrl, dbPath })) return false;
  let pool;
  try {
    pool = makePool(databaseUrl);
    await pool.query(
      `CREATE TABLE IF NOT EXISTS db_snapshot (
         id INT PRIMARY KEY,
         data BYTEA NOT NULL,
         updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
       )`
    );
    const r = await pool.query('SELECT data FROM db_snapshot WHERE id = 1');
    const data = r.rows[0] && r.rows[0].data;
    if (data && data.length) {
      fs.writeFileSync(dbPath, data);
      // Un -wal/-shm périmé à côté d'un fichier restauré corromprait la lecture.
      for (const ext of ['-wal', '-shm']) {
        try { fs.unlinkSync(dbPath + ext); } catch { /* absent */ }
      }
      // eslint-disable-next-line no-console
      console.log(`Snapshot restauré depuis Postgres (${data.length} octets).`);
      return true;
    }
    return false;
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`Restauration snapshot impossible (${e && e.message}).`);
    return false;
  } finally {
    try { if (pool) await pool.end(); } catch { /* ignore */ }
  }
}

/// Démarre les sauvegardes : périodiques (si le fichier a changé) + à l'arrêt.
/// Renvoie { save, stop }. No-op si non utilisable.
function startSnapshots({ databaseUrl, dbPath, intervalMs = 3 * 60 * 1000 }) {
  if (!usable({ databaseUrl, dbPath })) return { save: async () => {}, stop() {} };

  let pool;
  try { pool = makePool(databaseUrl); }
  catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`Snapshots désactivés (${e && e.message}).`);
    return { save: async () => {}, stop() {} };
  }

  let saving = false;
  let lastSavedMtime = 0;

  async function save(reason) {
    if (saving || !fs.existsSync(dbPath)) return;
    // Rien de neuf depuis la dernière sauvegarde → on n'ré-uploade pas.
    let mtime = 0;
    try { mtime = fs.statSync(dbPath).mtimeMs; } catch { /* ignore */ }
    if (reason === 'périodique' && mtime && mtime === lastSavedMtime) return;

    saving = true;
    try {
      // Checkpoint WAL → le fichier principal contient tout, via une connexion
      // courte (deux connexions au même fichier SQLite sont autorisées).
      try {
        const { DatabaseSync } = require('node:sqlite');
        const d = new DatabaseSync(dbPath);
        try { d.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch { /* pas de WAL */ }
        d.close();
      } catch { /* node:sqlite absent */ }

      const data = fs.readFileSync(dbPath);
      await pool.query(
        `INSERT INTO db_snapshot (id, data, updated_at) VALUES (1, $1, now())
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
        [data]
      );
      lastSavedMtime = mtime;
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`Sauvegarde snapshot impossible (${e && e.message}).`);
    } finally {
      saving = false;
    }
  }

  const timer = setInterval(() => { save('périodique'); }, intervalMs);
  if (timer.unref) timer.unref();

  // Heroku envoie SIGTERM avant de couper le dyno (déploiement / recyclage) :
  // dernière sauvegarde pour ne rien perdre, puis on sort.
  let stopping = false;
  async function onExit(sig) {
    if (stopping) return;
    stopping = true;
    clearInterval(timer);
    await save(`arrêt ${sig}`);
    try { await pool.end(); } catch { /* ignore */ }
    process.exit(0);
  }
  process.on('SIGTERM', () => { onExit('SIGTERM'); });
  process.on('SIGINT', () => { onExit('SIGINT'); });

  return { save, stop() { clearInterval(timer); } };
}

module.exports = { restoreSnapshot, startSnapshots };
