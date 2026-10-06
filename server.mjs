import { createServer } from 'node:http';
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const root = resolve(import.meta.dirname);
const publicDir = join(root, 'dist');
const dataDir = join(root, 'data');
const port = Number(process.env.PORT || 3004);
mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(process.env.FORMA_DB_PATH || join(dataDir, 'forma.sqlite'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    login TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    avatar INTEGER NOT NULL DEFAULT 0,
    height REAL,
    goal REAL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS auth_sessions_user_idx ON auth_sessions(user_id);
  CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);
  CREATE TABLE IF NOT EXISTS workout_states (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    state_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

const statements = {
  createUser: db.prepare('INSERT INTO users (id,name,login,password_hash,password_salt,avatar,height,goal,created_at) VALUES (?,?,?,?,?,?,?,?,?)'),
  findUserByLogin: db.prepare('SELECT * FROM users WHERE login = ? COLLATE NOCASE'),
  findUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
  createSession: db.prepare('INSERT INTO auth_sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)'),
  findSession: db.prepare('SELECT user_id,expires_at FROM auth_sessions WHERE token_hash = ?'),
  deleteSession: db.prepare('DELETE FROM auth_sessions WHERE token_hash = ?'),
  deleteExpiredSessions: db.prepare('DELETE FROM auth_sessions WHERE expires_at <= ?'),
  createState: db.prepare('INSERT INTO workout_states (user_id,state_json,updated_at) VALUES (?,?,?)'),
  readState: db.prepare('SELECT state_json FROM workout_states WHERE user_id = ?'),
  saveState: db.prepare('INSERT INTO workout_states (user_id,state_json,updated_at) VALUES (?,?,?) ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at')
};

const mime = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.woff2': 'font/woff2'
};

const emptyState = (weight = null) => ({ sessions: [], weights: weight ? [{ date: new Date().toISOString().slice(0, 10), value: weight }] : [], logs: {} });
const hashToken = token => createHash('sha256').update(token).digest('hex');
const hashPassword = (password, salt) => scryptSync(password, salt, 64).toString('hex');
const publicUser = user => ({ id: user.id, name: user.name, login: user.login, avatar: user.avatar, height: user.height, goal: user.goal, createdAt: user.created_at });

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

function sendJson(res, status, payload, extraHeaders = {}) {
  securityHeaders(res);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders });
  res.end(JSON.stringify(payload));
}

function readJson(req) {
  return new Promise((resolveBody, reject) => {
    let raw = '';
    req.setEncoding('utf8');
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1_000_000) reject(Object.assign(new Error('Слишком большой запрос.'), { status: 413 }));
    });
    req.on('end', () => {
      try { resolveBody(raw ? JSON.parse(raw) : {}); }
      catch { reject(Object.assign(new Error('Некорректный JSON.'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

function sessionToken(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/(?:^|;\s*)forma_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

function currentUser(req) {
  const token = sessionToken(req);
  if (!token) return null;
  const session = statements.findSession.get(hashToken(token));
  if (!session || session.expires_at <= new Date().toISOString()) return null;
  return statements.findUserById.get(session.user_id) || null;
}

function issueSession(res, userId) {
  const token = randomBytes(32).toString('base64url');
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 86400_000);
  statements.createSession.run(hashToken(token), userId, now.toISOString(), expires.toISOString());
  res.setHeader('Set-Cookie', `forma_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}`);
}

function validState(value) {
  return value && Array.isArray(value.sessions) && Array.isArray(value.weights) && value.logs && typeof value.logs === 'object' && !Array.isArray(value.logs);
}

async function handleApi(req, res, pathname) {
  if (pathname === '/api/register' && req.method === 'POST') {
    const body = await readJson(req);
    const name = String(body.name || '').trim();
    const login = String(body.login || '').trim().toLowerCase();
    const password = String(body.password || '');
    const avatar = Math.max(0, Math.min(5, Number(body.avatar) || 0));
    const height = body.height ? Number(body.height) : null;
    const weight = body.weight ? Number(body.weight) : null;
    const goal = body.goal ? Number(body.goal) : null;
    if (name.length < 2 || name.length > 40) return sendJson(res, 400, { error: 'Укажи имя: от 2 до 40 символов.' });
    if (!/^[a-zа-яё0-9._-]{3,30}$/i.test(login)) return sendJson(res, 400, { error: 'Логин должен содержать 3-30 допустимых символов.' });
    if (password.length < 8 || password.length > 128) return sendJson(res, 400, { error: 'Пароль должен содержать от 8 до 128 символов.' });
    if ((height && (height < 120 || height > 230)) || (weight && (weight < 30 || weight > 300)) || (goal && (goal < 30 || goal > 300))) return sendJson(res, 400, { error: 'Проверь введённые параметры тела.' });
    if (statements.findUserByLogin.get(login)) return sendJson(res, 409, { error: 'Такой логин уже зарегистрирован.' });
    const id = randomUUID();
    const salt = randomBytes(16).toString('hex');
    const now = new Date().toISOString();
    const workoutState = emptyState(weight);
    db.exec('BEGIN IMMEDIATE');
    try {
      statements.createUser.run(id, name, login, hashPassword(password, salt), salt, avatar, height, goal, now);
      statements.createState.run(id, JSON.stringify(workoutState), now);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      if (String(error.message).includes('UNIQUE')) return sendJson(res, 409, { error: 'Такой логин уже зарегистрирован.' });
      throw error;
    }
    const user = statements.findUserById.get(id);
    issueSession(res, id);
    return sendJson(res, 201, { user: publicUser(user), state: workoutState });
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    const body = await readJson(req);
    const user = statements.findUserByLogin.get(String(body.login || '').trim().toLowerCase());
    if (!user) return sendJson(res, 401, { error: 'Неверный логин или пароль.' });
    const actual = Buffer.from(hashPassword(String(body.password || ''), user.password_salt), 'hex');
    const expected = Buffer.from(user.password_hash, 'hex');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return sendJson(res, 401, { error: 'Неверный логин или пароль.' });
    issueSession(res, user.id);
    const row = statements.readState.get(user.id);
    return sendJson(res, 200, { user: publicUser(user), state: row ? JSON.parse(row.state_json) : emptyState() });
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    const token = sessionToken(req);
    if (token) statements.deleteSession.run(hashToken(token));
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': 'forma_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  }

  if (pathname === '/api/session' && req.method === 'GET') {
    const user = currentUser(req);
    if (!user) return sendJson(res, 401, { error: 'Сессия не найдена.' });
    const row = statements.readState.get(user.id);
    return sendJson(res, 200, { user: publicUser(user), state: row ? JSON.parse(row.state_json) : emptyState() });
  }

  if (pathname === '/api/state' && req.method === 'PUT') {
    const user = currentUser(req);
    if (!user) return sendJson(res, 401, { error: 'Нужно войти в профиль.' });
    const body = await readJson(req);
    if (!validState(body.state)) return sendJson(res, 400, { error: 'Некорректные данные тренировок.' });
    const serialized = JSON.stringify(body.state);
    if (serialized.length > 750_000) return sendJson(res, 413, { error: 'История тренировок слишком большая.' });
    statements.saveState.run(user.id, serialized, new Date().toISOString());
    return sendJson(res, 200, { ok: true });
  }

  return sendJson(res, 404, { error: 'API-метод не найден.' });
}

function serveStatic(req, res, pathname) {
  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = normalize(join(publicDir, relative));
  if (!filePath.startsWith(publicDir)) return sendJson(res, 403, { error: 'Доступ запрещён.' });
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) throw new Error('not a file');
    securityHeaders(res);
    res.writeHead(200, { 'Content-Type': mime[extname(filePath).toLowerCase()] || 'application/octet-stream', 'Cache-Control': relative === 'index.html' ? 'no-cache' : 'public, max-age=86400' });
    res.end(readFileSync(filePath));
  } catch {
    sendJson(res, 404, { error: 'Страница не найдена.' });
  }
}

statements.deleteExpiredSessions.run(new Date().toISOString());
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) await handleApi(req, res, url.pathname);
    else serveStatic(req, res, decodeURIComponent(url.pathname));
  } catch (error) {
    console.error(error);
    if (!res.headersSent) sendJson(res, error.status || 500, { error: error.status ? error.message : 'Внутренняя ошибка сервера.' });
    else res.end();
  }
});

server.listen(port, '127.0.0.1', () => console.log(`FORMA: http://localhost:${port}`));

