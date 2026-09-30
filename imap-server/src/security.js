/**
 * Security reporting for the IMAP port.
 *
 * - Events (connections, logins, failed passwords, throttling) are sent to the mail service,
 *   which stores them in the shared security log and sends alert emails. Fire and forget:
 *   a slow or missing mail service never delays a mail app.
 * - Connected mail apps are listed in the `imap_sessions` collection so the web app can show
 *   who is connected right now, and can ask for a session to be ended ("kick").
 * - The IP block list (set on the web app's Security page) is read from MongoDB every 20 s.
 */
const net = require('net');
const crypto = require('crypto');
const { getDb } = require('./mongo');

const MAIL_SERVICE_URL = (process.env.MAIL_SERVICE_URL || 'http://mail-service:8080').replace(/\/+$/, '');
const API_KEY = process.env.SECURITY_API_KEY || process.env.API_KEY || '';
const HEARTBEAT_MS = 30 * 1000;
const BLOCK_REFRESH_MS = 20 * 1000;

function isInternal(ip) {
  const addr = String(ip || '').replace(/^::ffff:/, '');
  if (!net.isIP(addr)) return true;
  if (net.isIPv6(addr)) return addr === '::1' || /^(fc|fd|fe80)/i.test(addr);
  const [a, b] = addr.split('.').map(Number);
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function cleanIp(ip) {
  return String(ip || '').replace(/^::ffff:/, '').slice(0, 64);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

function report(kind, { ip = '', user = '', detail = '', aggregate } = {}) {
  ip = cleanIp(ip);
  if (!API_KEY || typeof fetch !== 'function') return;
  const body = { source: 'imap', kind, ip, user: String(user || '').slice(0, 320), detail: String(detail || '').slice(0, 300) };
  if (typeof aggregate === 'boolean') body.aggregate = aggregate;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  fetch(`${MAIL_SERVICE_URL}/admin/security/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${API_KEY}` },
    body: JSON.stringify(body),
    signal: controller.signal,
  }).catch(() => {}).finally(() => clearTimeout(timer));
}

// ---------------------------------------------------------------------------
// Block list
// ---------------------------------------------------------------------------

let blockList = new net.BlockList();
let blockLoadedAt = 0;
let loading = null;

async function refreshBlockList() {
  const fresh = new net.BlockList();
  const now = new Date();
  const docs = await getDb().collection('ip_blocklist').find({}, { projection: { ip: 1, expires_at: 1 } }).toArray();
  for (const doc of docs) {
    if (doc.expires_at && new Date(doc.expires_at) < now) continue;
    const value = String(doc.ip || '');
    try {
      if (value.includes('/')) {
        const [base, prefix] = value.split('/');
        fresh.addSubnet(base, Number(prefix), net.isIPv6(base) ? 'ipv6' : 'ipv4');
      } else if (net.isIP(value)) {
        fresh.addAddress(value, net.isIPv6(value) ? 'ipv6' : 'ipv4');
      }
    } catch { /* skip malformed entries */ }
  }
  blockList = fresh;
  blockLoadedAt = Date.now();
}

function isBlocked(ip) {
  const addr = cleanIp(ip);
  if (Date.now() - blockLoadedAt > BLOCK_REFRESH_MS && !loading) {
    loading = refreshBlockList().catch(() => {}).finally(() => { loading = null; });
  }
  if (!net.isIP(addr)) return false;
  try {
    return blockList.check(addr, net.isIPv6(addr) ? 'ipv6' : 'ipv4');
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Connected mail apps
// ---------------------------------------------------------------------------

const live = new Map(); // session id -> ImapConnection

function newSessionId() {
  return crypto.randomBytes(12).toString('hex');
}

async function sessionStarted(conn) {
  if (!conn.sessionId) conn.sessionId = newSessionId();
  live.set(conn.sessionId, conn);
  const now = new Date();
  try {
    await getDb().collection('imap_sessions').updateOne(
      { _id: conn.sessionId },
      { $set: { user: conn.user.address, ip: cleanIp(conn.remoteAddr), client: conn.clientName || '', folder: '', idle: false, last_seen: now, login_at: now } },
      { upsert: true },
    );
  } catch { /* the list is informational */ }
}

function sessionUpdate(conn, fields) {
  if (!conn.sessionId || !live.has(conn.sessionId)) return;
  getDb().collection('imap_sessions')
    .updateOne({ _id: conn.sessionId }, { $set: { ...fields, last_seen: new Date() } })
    .catch(() => {});
}

function sessionEnded(conn) {
  if (!conn.sessionId || !live.has(conn.sessionId)) return;
  live.delete(conn.sessionId);
  getDb().collection('imap_sessions').deleteOne({ _id: conn.sessionId }).catch(() => {});
}

async function heartbeat() {
  if (!live.size) return;
  const ids = [...live.keys()];
  const db = getDb();
  try {
    await db.collection('imap_sessions').updateMany({ _id: { $in: ids } }, { $set: { last_seen: new Date() } });
    const kicked = await db.collection('imap_sessions').find({ _id: { $in: ids }, kick: true }, { projection: { _id: 1 } }).toArray();
    for (const { _id } of kicked) {
      const conn = live.get(_id);
      if (!conn) continue;
      report('session_kicked', { ip: conn.remoteAddr, user: conn.user && conn.user.address });
      conn.kick();
    }
  } catch { /* try again next beat */ }
}

async function start() {
  try {
    // Sessions from before a restart are gone.
    await getDb().collection('imap_sessions').deleteMany({});
    await getDb().collection('imap_sessions').createIndex({ last_seen: 1 });
  } catch { /* not fatal */ }
  refreshBlockList().catch(() => {});
  setInterval(() => { heartbeat(); }, HEARTBEAT_MS).unref();
  setInterval(() => { refreshBlockList().catch(() => {}); }, BLOCK_REFRESH_MS).unref();
}

module.exports = {
  report, isBlocked, isInternal, cleanIp, sessionStarted, sessionUpdate, sessionEnded, start,
  _setBlockList: (list) => { blockList = list; blockLoadedAt = Date.now(); },
  _live: live,
};
