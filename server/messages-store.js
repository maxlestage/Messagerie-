//
//  Stockage des messages (et conversations) de la messagerie chiffrée.
//
//  Deux implémentations derrière une MÊME interface :
//   - SQLite (via le module intégré `node:sqlite`, aucune dépendance externe) :
//     les messages survivent au redémarrage du PROCESSUS.
//   - En mémoire (repli) : si `node:sqlite` est indisponible.
//
//  ⚠️ Rappel Heroku : le système de fichiers d'un dyno est ÉPHÉMÈRE — un
//  déploiement ou un redémarrage de dyno efface le fichier SQLite. Pour une
//  persistance DURABLE sur Heroku, il faut une base gérée (Heroku Postgres).
//  SQLite reste utile en auto-hébergement (disque persistant) et pour résister
//  aux simples redémarrages de process.
//
//  Le serveur ne stocke QUE du chiffré : la colonne `ciphertext` est un jeton
//  Brocolis illisible sans la clé.
//
//  RÉTENTION : `pruneBefore(cutoffISO)` supprime les messages plus vieux que la
//  fenêtre choisie (7 jours par défaut, réglable côté serveur). Appelé
//  périodiquement par le serveur pour ne garder qu'une semaine d'historique.
//

'use strict';

/// Fabrique un store. `dbPath` : chemin du fichier SQLite, `':memory:'` pour une
/// base en mémoire (tests), ou absent → repli mémoire pur.
function createMessageStore({ dbPath } = {}) {
  if (dbPath) {
    try {
      return createSqliteStore(dbPath);
    } catch (err) {
      // node:sqlite absent (Node trop ancien) ou fichier non ouvrable : on
      // bascule proprement en mémoire plutôt que de planter le serveur.
      // eslint-disable-next-line no-console
      console.warn(`SQLite indisponible (${err && err.message}), repli en mémoire.`);
    }
  }
  return createMemoryStore();
}

// ── Implémentation SQLite ─────────────────────────────────────────────────────

function createSqliteStore(dbPath) {
  const { DatabaseSync } = require('node:sqlite');
  const db = new DatabaseSync(dbPath);

  db.exec(`
    CREATE TABLE IF NOT EXISTS conversations (
      id           TEXT PRIMARY KEY,
      participants TEXT NOT NULL DEFAULT '[]',
      created_at   TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      seq             INTEGER PRIMARY KEY AUTOINCREMENT,
      msg_id          TEXT NOT NULL,
      conversation_id TEXT NOT NULL,
      sender_id       TEXT NOT NULL,
      ciphertext      TEXT NOT NULL,
      sent_at         TEXT NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_msg_unique ON messages(conversation_id, msg_id);
    CREATE INDEX IF NOT EXISTS idx_msg_conv_seq ON messages(conversation_id, seq);
    CREATE INDEX IF NOT EXISTS idx_msg_sent_at ON messages(sent_at);
    CREATE TABLE IF NOT EXISTS read_cursors (
      conversation_id TEXT NOT NULL,
      user_id         TEXT NOT NULL,
      up_to           INTEGER NOT NULL,
      PRIMARY KEY (conversation_id, user_id)
    );
  `);

  const q = {
    ensureConv: db.prepare(
      `INSERT OR IGNORE INTO conversations (id, participants, created_at) VALUES (?, ?, ?)`
    ),
    getConv: db.prepare(`SELECT participants, created_at FROM conversations WHERE id = ?`),
    allConvs: db.prepare(`SELECT id, participants, created_at FROM conversations`),
    insertMsg: db.prepare(
      `INSERT OR IGNORE INTO messages (msg_id, conversation_id, sender_id, ciphertext, sent_at)
       VALUES (?, ?, ?, ?, ?)`
    ),
    getMsg: db.prepare(
      `SELECT seq, msg_id, conversation_id, sender_id, ciphertext, sent_at
         FROM messages WHERE conversation_id = ? AND msg_id = ?`
    ),
    msgsAfter: db.prepare(
      `SELECT seq, msg_id, conversation_id, sender_id, ciphertext, sent_at
         FROM messages WHERE conversation_id = ? AND seq > ? ORDER BY seq`
    ),
    setRead: db.prepare(
      `INSERT INTO read_cursors (conversation_id, user_id, up_to) VALUES (?, ?, ?)
       ON CONFLICT(conversation_id, user_id)
       DO UPDATE SET up_to = MAX(up_to, excluded.up_to)`
    ),
    getReads: db.prepare(`SELECT user_id, up_to FROM read_cursors WHERE conversation_id = ?`),
    // Rétention : on efface les messages plus vieux que la fenêtre (7 j par
    // défaut), puis les conversations scellées devenues vides et les curseurs
    // de lecture orphelins. `sent_at`/`created_at` sont des ISO 8601 : leur ordre
    // lexicographique == ordre chronologique, donc `<` compare bien les dates.
    pruneMsgs: db.prepare(`DELETE FROM messages WHERE sent_at < ?`),
    pruneConvs: db.prepare(
      `DELETE FROM conversations
        WHERE participants = '[]' AND created_at < ?
          AND id NOT IN (SELECT DISTINCT conversation_id FROM messages)`
    ),
    pruneReads: db.prepare(
      `DELETE FROM read_cursors
        WHERE conversation_id NOT IN (SELECT DISTINCT conversation_id FROM messages)`
    ),
  };

  function mapRow(r) {
    return {
      id: r.msg_id,
      conversationId: r.conversation_id,
      senderId: r.sender_id,
      ciphertext: r.ciphertext,
      sentAt: r.sent_at,
      seq: Number(r.seq),
    };
  }

  return {
    backend: 'sqlite',

    ensureSealed(convId, createdAt) {
      q.ensureConv.run(convId, '[]', createdAt);
    },

    createConversation(id, participants, createdAt) {
      q.ensureConv.run(id, JSON.stringify(participants), createdAt);
    },

    getConversation(convId) {
      const r = q.getConv.get(convId);
      if (!r) return null;
      let participants = [];
      try { participants = JSON.parse(r.participants); } catch { participants = []; }
      return { participants, createdAt: r.created_at };
    },

    listConversationsFor(userId) {
      const out = [];
      for (const r of q.allConvs.all()) {
        let participants = [];
        try { participants = JSON.parse(r.participants); } catch { participants = []; }
        if (participants.length && participants.some((p) => p.id === userId)) {
          out.push({ id: r.id, participants, createdAt: r.created_at });
        }
      }
      return out;
    },

    /// Insère (idempotent sur msg_id par conversation) et renvoie le message
    /// stocké avec son `seq`.
    appendMessage(convId, m) {
      q.insertMsg.run(m.id, convId, m.senderId, m.ciphertext, m.sentAt);
      return mapRow(q.getMsg.get(convId, m.id));
    },

    messagesAfter(convId, after) {
      return q.msgsAfter.all(convId, after).map(mapRow);
    },

    /// Marque que `userId` a lu jusqu'au `seq` = upTo (max monotone).
    setReadCursor(convId, userId, upTo) {
      q.setRead.run(convId, userId, Math.max(0, Number(upTo) || 0));
    },
    /// { userId: dernierSeqLu } pour une conversation.
    readCursors(convId) {
      const out = {};
      for (const r of q.getReads.all(convId)) out[r.user_id] = Number(r.up_to);
      return out;
    },

    /// Rétention : supprime tout message dont `sent_at` est antérieur à
    /// `cutoffISO`, puis fait le ménage (conversations scellées vides, curseurs
    /// orphelins). Renvoie le nombre de messages supprimés.
    pruneBefore(cutoffISO) {
      const r = q.pruneMsgs.run(cutoffISO);
      q.pruneConvs.run(cutoffISO);
      q.pruneReads.run();
      return Number((r && r.changes) || 0);
    },
  };
}

// ── Implémentation en mémoire (repli) ─────────────────────────────────────────

function createMemoryStore() {
  const conversations = new Map(); // id -> { participants, createdAt }
  const messages = new Map();      // id -> [msg]
  const reads = new Map();         // convId -> Map(userId -> upTo)
  let seq = 0;

  return {
    backend: 'memory',

    ensureSealed(convId, createdAt) {
      if (!conversations.has(convId)) {
        conversations.set(convId, { participants: [], createdAt });
      }
      if (!messages.has(convId)) messages.set(convId, []);
    },

    createConversation(id, participants, createdAt) {
      conversations.set(id, { participants, createdAt });
      if (!messages.has(id)) messages.set(id, []);
    },

    getConversation(convId) {
      return conversations.get(convId) || null;
    },

    listConversationsFor(userId) {
      const out = [];
      for (const [id, c] of conversations) {
        if (c.participants.length && c.participants.some((p) => p.id === userId)) {
          out.push({ id, participants: c.participants, createdAt: c.createdAt });
        }
      }
      return out;
    },

    appendMessage(convId, m) {
      const arr = messages.get(convId) || [];
      const existing = arr.find((x) => x.id === m.id);
      if (existing) return existing;
      seq += 1;
      const stored = {
        id: m.id,
        conversationId: convId,
        senderId: m.senderId,
        ciphertext: m.ciphertext,
        sentAt: m.sentAt,
        seq,
      };
      arr.push(stored);
      messages.set(convId, arr);
      return stored;
    },

    messagesAfter(convId, after) {
      return (messages.get(convId) || []).filter((m) => m.seq > after);
    },

    setReadCursor(convId, userId, upTo) {
      let m = reads.get(convId);
      if (!m) { m = new Map(); reads.set(convId, m); }
      m.set(userId, Math.max(m.get(userId) || 0, Number(upTo) || 0));
    },
    readCursors(convId) {
      const out = {};
      const m = reads.get(convId);
      if (m) for (const [u, v] of m) out[u] = v;
      return out;
    },

    /// Rétention (même contrat que SQLite) : purge les messages plus vieux que
    /// `cutoffISO`, puis les conversations scellées vides et curseurs orphelins.
    pruneBefore(cutoffISO) {
      let removed = 0;
      for (const [convId, arr] of messages) {
        const kept = arr.filter((m) => m.sentAt >= cutoffISO);
        removed += arr.length - kept.length;
        messages.set(convId, kept);
      }
      for (const [id, c] of conversations) {
        const empty = (messages.get(id) || []).length === 0;
        if (empty && c.participants.length === 0 && c.createdAt < cutoffISO) {
          conversations.delete(id);
          messages.delete(id);
          reads.delete(id);
        }
      }
      return removed;
    },
  };
}

module.exports = { createMessageStore };
