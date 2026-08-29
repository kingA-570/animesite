const crypto = require('crypto');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = process.env.DB_PATH || path.join(process.cwd(), 'animeverse.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    avatar TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS watchlist (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    anilist_id INTEGER NOT NULL,
    title TEXT,
    image TEXT,
    format TEXT,
    score INTEGER,
    status TEXT,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, anilist_id)
  );

  CREATE TABLE IF NOT EXISTS watch_history (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    anilist_id INTEGER NOT NULL,
    episode INTEGER NOT NULL DEFAULT 1,
    title TEXT,
    image TEXT,
    timestamp INTEGER NOT NULL,
    PRIMARY KEY (user_id, anilist_id)
  );

  CREATE INDEX IF NOT EXISTS idx_watch_history_user ON watch_history (user_id, timestamp DESC);
`);

function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(salt + password + salt).digest('hex');
}

function newSalt() {
  return crypto.randomBytes(16).toString('hex');
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const stmt = db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)');
  stmt.run(token, userId, Date.now());
  return token;
}

function getUserBySession(token) {
  if (!token) return null;
  const stmt = db.prepare(`
    SELECT u.* FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token = ?
  `);
  const row = stmt.get(token);
  return row || null;
}

function registerUser(username, password, email) {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return { error: 'Username already taken' };
  const salt = newSalt();
  const hash = hashPassword(password, salt);
  const stmt = db.prepare('INSERT INTO users (username, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)');
  const info = stmt.run(username, email || null, hash, salt, Date.now());
  const token = createSession(Number(info.lastInsertRowid));
  return { user: getUserBySession(token), token };
}

function loginUser(username, password) {
  const stmt = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?');
  const user = stmt.get(username, username);
  if (!user) return { error: 'Invalid username or password' };
  const hash = hashPassword(password, user.salt);
  if (hash !== user.password_hash) return { error: 'Invalid username or password' };
  const token = createSession(user.id);
  return { user, token };
}

function logoutUser(token) {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token || '');
}

// ================= watchlist =================
function addWatchlist(userId, item) {
  db.prepare(`
    INSERT OR REPLACE INTO watchlist (user_id, anilist_id, title, image, format, score, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    userId, Number(item.anilistId), item.title || null, item.image || null,
    item.format || null, item.score != null ? Number(item.score) : null,
    item.status || null, Date.now()
  );
}

function removeWatchlist(userId, anilistId) {
  db.prepare('DELETE FROM watchlist WHERE user_id = ? AND anilist_id = ?').run(userId, Number(anilistId));
}

function getWatchlist(userId) {
  return db.prepare(`
    SELECT anilist_id AS anilistId, title, image, format, score, status, created_at
    FROM watchlist WHERE user_id = ? ORDER BY created_at DESC
  `).all(userId);
}

function getWatchlistIds(userId) {
  return db.prepare('SELECT anilist_id FROM watchlist WHERE user_id = ?').all(userId).map((r) => r.anilist_id);
}

// ================= watch history =================
function saveHistory(userId, item) {
  db.prepare(`
    INSERT OR REPLACE INTO watch_history (user_id, anilist_id, episode, title, image, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    userId, Number(item.anilistId), Number(item.episode || 1),
    item.title || null, item.image || null, Date.now()
  );
}

function getHistory(userId, limit = 30) {
  return db.prepare(`
    SELECT anilist_id AS anilistId, episode, title, image, timestamp
    FROM watch_history WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?
  `).all(userId, Number(limit));
}

function getHistoryItem(userId, anilistId) {
  return db.prepare('SELECT * FROM watch_history WHERE user_id = ? AND anilist_id = ?').get(userId, Number(anilistId)) || null;
}

module.exports = {
  db,
  registerUser,
  loginUser,
  logoutUser,
  createSession,
  getUserBySession,
  addWatchlist,
  removeWatchlist,
  getWatchlist,
  getWatchlistIds,
  saveHistory,
  getHistory,
  getHistoryItem,
};
