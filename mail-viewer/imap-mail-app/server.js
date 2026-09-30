const express = require('express');
const path = require('path');
const { simpleParser } = require('mailparser');
const MailClient = require('./client');
const { fromPreset, PRESETS, autoDetect } = require('./config');
const { prepareHtmlForRender } = require('./sanitize');
const { createAccountStore } = require('./accountStore');

const app = express();
app.use(express.json({ limit: '1mb' }));

// Only the web app (which holds the token) may call the bridge API.
const crypto = require('crypto');
const BRIDGE_TOKEN = process.env.BRIDGE_TOKEN || '';
if (!BRIDGE_TOKEN) console.warn('WARNING: BRIDGE_TOKEN is not set; bridge API is unauthenticated.');
app.use('/api', (req, res, next) => {
  if (!BRIDGE_TOKEN) return next();
  const got = Buffer.from(String(req.get('x-bridge-token') || ''));
  const want = Buffer.from(BRIDGE_TOKEN);
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// Multi-account mode: the web app says whose request this is (X-Bridge-User), and every account belongs
// to the person who added it. Admins (and single-password mode) share the "__admin__" space. The
// header can only come from the web app, because the bridge refuses requests without the token.
const ADMIN_OWNER = '__admin__';
function ownerOf(req) {
  const v = String(req.get('x-bridge-user') || '').trim().toLowerCase();
  return v && v.length <= 320 ? v : ADMIN_OWNER;
}
function accountOwner(client) {
  return (client.account && client.account.owner) || ADMIN_OWNER;
}
function mine(req, client) {
  return accountOwner(client) === ownerOf(req);
}
// The account in the URL, only if it belongs to whoever is asking (otherwise it looks like it does not exist).
function ownClient(req) {
  const client = clients.get(parseInt(req.params.id, 10));
  return client && mine(req, client) ? client : undefined;
}

// Block connections to private/loopback addresses (SSRF) unless allowed.
const net = require('net');
function isPrivateHost(h) {
  h = String(h || '').toLowerCase().trim();
  if (h === 'localhost' || h.endsWith('.local') || h.endsWith('.internal')) return true;
  if (!net.isIP(h)) return !h.includes('.');
  if (net.isIPv6(h)) return h === '::1' || /^(fc|fd|fe80)/.test(h);
  const [a, b] = h.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}
app.use(express.static(path.join(__dirname, 'public')));

const clients = new Map();
let clientId = 0;

// Report account connections to BearerMail's security log (Setup > Security). Fire and forget.
const MAIL_SERVICE_URL = (process.env.MAIL_SERVICE_URL || 'http://mail-service:8080').replace(/\/+$/, '');
function reportEvent(kind, detail = '', user = '') {
  if (!BRIDGE_TOKEN || typeof fetch !== 'function') return;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  fetch(`${MAIL_SERVICE_URL}/admin/security/events`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${BRIDGE_TOKEN}` },
    body: JSON.stringify({ source: 'bridge', kind, user: String(user || '').slice(0, 320), detail: String(detail || '').slice(0, 300), aggregate: kind === 'account_connected' }),
    signal: controller.signal,
  }).catch(() => {}).finally(() => clearTimeout(timer));
}
function newClient(account) {
  return new MailClient(account, {
    onEvent: (kind, mc, detail) => reportEvent(kind, `${mc.account.host}:${mc.account.port}${detail ? ' - ' + detail : ''}`, mc.account.auth.user),
  });
}

const ACCOUNTS_FILE = process.env.ACCOUNTS_FILE || path.join(__dirname, 'accounts.json');
const accountStore = createAccountStore({
  filePath: ACCOUNTS_FILE,
  encryptionKey: process.env.IMAP_ACCOUNT_ENCRYPTION_KEY || '',
  mode: process.env.IMAP_ACCOUNT_PERSISTENCE || 'encrypted',
  logger: console,
});

function saveAccounts() {
  return accountStore.save(clients);
}

async function restoreAccounts() {
  const data = accountStore.load();
  if (!Array.isArray(data) || data.length === 0) return;

  console.log(`Restoring ${data.length} saved account(s)...`);
  for (const item of data) {
    const client = newClient(item.account);
    try {
      await client.connect();
      const id = ++clientId;
      clients.set(id, client);
      console.log(`  ✓ ${item.account.auth.user} restored`);
    } catch (err) {
      console.log(`  ✗ ${item.account.auth.user} restore failed: ${err.message}`);
    }
  }
  saveAccounts();
}

app.get('/api/presets', (req, res) => {
  res.json(Object.keys(PRESETS));
});

app.post('/api/accounts', async (req, res) => {
  const { preset, host, port, email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Enter the email address and password' });
  }

  let account;
  if (preset && preset !== 'custom') {
    try {
      account = fromPreset(preset, email, password);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
  } else {
    if (!host) return res.status(400).json({ error: 'Custom setup needs a server address' });
    if (process.env.ALLOW_PRIVATE_IMAP_HOSTS !== '1' && isPrivateHost(host)) {
      return res.status(400).json({ error: 'Private or local server addresses are not allowed' });
    }
    account = {
      name: email.split('@')[1] || 'custom',
      host,
      port: parseInt(port, 10) || 993,
      secure: true,
      auth: { user: email, pass: password },
    };
  }

  account.owner = ownerOf(req);
  for (const [existingId, existing] of clients) {
    if (existing.account.auth.user === email && mine(req, existing)) {
      return res.json({ id: existingId, name: existing.account.name, email, exists: true });
    }
  }

  const client = newClient(account);
  try {
    await client.connect();
    const id = ++clientId;
    clients.set(id, client);
    saveAccounts();
    reportEvent('account_added', `${account.host}:${account.port}`, account.auth.user);
    res.json({ id, name: account.name, email: account.auth.user });
  } catch (err) {
    res.status(500).json({ error: `Connection failed: ${err.message}` });
  }
});

app.get('/api/accounts', (req, res) => {
  const list = [];
  clients.forEach((c, id) => {
    if (!mine(req, c)) return;
    list.push({ id, name: c.account.name, email: c.account.auth.user });
  });
  res.json(list);
});

// Connection health of every external account (for the web app's Security page). No passwords.
app.get('/api/status', (req, res) => {
  const list = [];
  clients.forEach((c, id) => list.push({ ...c.describe(id), owner: accountOwner(c) === ADMIN_OWNER ? 'admin' : accountOwner(c) }));
  res.json({ accounts: list, persistence: process.env.IMAP_ACCOUNT_PERSISTENCE || 'encrypted' });
});

app.delete('/api/accounts/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const client = clients.get(id) && mine(req, clients.get(id)) ? clients.get(id) : undefined;
  if (!client) return res.status(404).json({ error: 'Account not found' });
  try { await client.disconnect(); } catch {}
  clients.delete(id);
  saveAccounts();
  reportEvent('account_removed', `${client.account.host}:${client.account.port}`, client.account.auth.user);
  res.json({ ok: true });
});

app.get('/api/accounts/:id/folders', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });
  try {
    await client.ensureConnected();
    const folders = await client.client.list();
    res.json(folders.map(f => ({
      path: f.path,
      name: f.name,
      noselect: f.flags?.has('\\Noselect') || false,
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/:id/mails', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const count = parseInt(req.query.count, 10) || 20;
  const before = req.query.before ? parseInt(req.query.before, 10) : null;

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      const status = await client.client.status(folder, { messages: true, unseen: true });
      const total = status.messages;
      if (total === 0) {
        return res.json({ total: 0, unseen: status.unseen, mails: [], hasMore: false });
      }

      let startSeq, endSeq;
      if (before) {
        endSeq = before - 1;
        if (endSeq < 1) {
          return res.json({ total, unseen: status.unseen, mails: [], hasMore: false });
        }
        startSeq = Math.max(1, endSeq - count + 1);
      } else {
        endSeq = total;
        startSeq = Math.max(1, total - count + 1);
      }

      const mails = [];

      for await (const msg of client.client.fetch(`${startSeq}:${endSeq}`, {
        envelope: true,
        flags: true,
        uid: true,
      })) {
        mails.push({
          uid: msg.uid,
          seq: msg.seq,
          date: msg.envelope.date,
          from: msg.envelope.from?.[0]
            ? { name: msg.envelope.from[0].name || '', address: msg.envelope.from[0].address }
            : { name: '', address: '(unknown)' },
          to: msg.envelope.to?.map(t => ({ name: t.name || '', address: t.address })) || [],
          subject: msg.envelope.subject || '(no subject)',
          seen: msg.flags?.has('\\Seen') || false,
          flagged: msg.flags?.has('\\Flagged') || false,
        });
      }

      mails.sort((a, b) => new Date(b.date) - new Date(a.date));
      res.json({ total, unseen: status.unseen, mails, hasMore: startSeq > 1 });
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/:id/mails/:uid', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const uid = req.params.uid;

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      const source = await client.client.download(uid, undefined, { uid: true });
      const parsed = await simpleParser(source.content);

      await client.client.messageFlagsAdd(uid, ['\\Seen'], { uid: true });

      res.json({
        subject: parsed.subject || '(no subject)',
        from: parsed.from?.text || '',
        to: parsed.to?.text || '',
        cc: parsed.cc?.text || '',
        date: parsed.date,
        text: parsed.text || '',
        html: parsed.html ? prepareHtmlForRender(parsed.html) : '',
        attachments: (parsed.attachments || []).map((a, i) => ({
          index: i,
          filename: a.filename || `attachment_${i}`,
          size: a.size,
          contentType: a.contentType,
        })),
      });
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/:id/mails/:uid/attachments/:index', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const index = parseInt(req.params.index, 10);
  const uid = req.params.uid;

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      const source = await client.client.download(uid, undefined, { uid: true });
      const parsed = await simpleParser(source.content);

      const att = parsed.attachments?.[index];
      if (!att) return res.status(404).json({ error: 'Attachment not found' });

      const filename = att.filename || `attachment_${index}`;
      res.setHeader('Content-Type', att.contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
      res.send(att.content);
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/:id/search', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const keyword = req.query.q || '';
  const field = req.query.field || 'subject';
  if (!keyword) return res.status(400).json({ error: 'Enter a search keyword' });

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      let searchQuery;
      if (field === 'all') {
        searchQuery = { or: [{ subject: keyword }, { from: keyword }, { body: keyword }] };
      } else if (['from', 'body', 'subject'].includes(field)) {
        searchQuery = { [field]: keyword };
      } else {
        searchQuery = { subject: keyword };
      }
      const uids = await client.client.search(searchQuery, { uid: true });
      if (uids.length === 0) return res.json([]);

      const mails = [];
      for await (const msg of client.client.fetch(uids.slice(0, 30), {
        envelope: true,
        flags: true,
        uid: true,
      }, { uid: true })) {
        mails.push({
          uid: msg.uid,
          date: msg.envelope.date,
          from: msg.envelope.from?.[0]
            ? { name: msg.envelope.from[0].name || '', address: msg.envelope.from[0].address }
            : { name: '', address: '(unknown)' },
          subject: msg.envelope.subject || '(no subject)',
          seen: msg.flags?.has('\\Seen') || false,
        });
      }
      mails.sort((a, b) => new Date(b.date) - new Date(a.date));
      res.json(mails);
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/accounts/:id/mails/:uid', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const uid = req.params.uid;

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      await client.client.messageDelete(uid, { uid: true });
      res.json({ ok: true });
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const ALLOWED_FLAGS = new Set(['\\Seen', '\\Flagged', '\\Answered', '\\Draft', '\\Deleted']);

app.put('/api/accounts/:id/mails/:uid/flags', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const uid = req.params.uid;
  const { action, flags } = req.body || {};

  if (!action || !Array.isArray(flags) || flags.length === 0) {
    return res.status(400).json({ error: 'action and flags are required' });
  }
  if (!['add', 'remove', 'set'].includes(action)) {
    return res.status(400).json({ error: 'action must be add / remove / set' });
  }
  const safeFlags = flags.filter(f => ALLOWED_FLAGS.has(f));
  if (safeFlags.length === 0) {
    return res.status(400).json({ error: 'No valid flag' });
  }

  const methods = { add: 'messageFlagsAdd', remove: 'messageFlagsRemove', set: 'messageFlagsSet' };

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      await client.client[methods[action]](uid, safeFlags, { uid: true });
      res.json({ ok: true });
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/accounts/:id/mails/:uid/move', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const uid = req.params.uid;
  const { destination } = req.body || {};

  if (!destination) {
    return res.status(400).json({ error: 'destination is required' });
  }

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      await client.client.messageMove(uid, destination, { uid: true });
      res.json({ ok: true });
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/accounts/:id/batch', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  const folder = req.query.folder || 'INBOX';
  const { uids, action, destination } = req.body || {};

  if (!Array.isArray(uids) || uids.length === 0 || !action) {
    return res.status(400).json({ error: 'uids and action are required' });
  }

  const uidRange = uids.join(',');

  try {
    await client.ensureConnected();
    const lock = await client.client.getMailboxLock(folder);
    try {
      switch (action) {
        case 'delete':
          await client.client.messageDelete(uidRange, { uid: true });
          break;
        case 'read':
          await client.client.messageFlagsAdd(uidRange, ['\\Seen'], { uid: true });
          break;
        case 'unread':
          await client.client.messageFlagsRemove(uidRange, ['\\Seen'], { uid: true });
          break;
        case 'flag':
          await client.client.messageFlagsAdd(uidRange, ['\\Flagged'], { uid: true });
          break;
        case 'unflag':
          await client.client.messageFlagsRemove(uidRange, ['\\Flagged'], { uid: true });
          break;
        case 'move':
          if (!destination) return res.status(400).json({ error: 'Move needs a destination' });
          await client.client.messageMove(uidRange, destination, { uid: true });
          break;
        default:
          return res.status(400).json({ error: `Unknown action: ${action}` });
      }
      res.json({ ok: true, count: uids.length });
    } finally {
      lock.release();
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/:id/folders/status', async (req, res) => {
  const client = ownClient(req);
  if (!client) return res.status(404).json({ error: 'Account not found' });

  try {
    await client.ensureConnected();
    const folders = await client.client.list();
    const selectable = folders.filter(f => !f.flags?.has('\\Noselect')).slice(0, 20);

    const statuses = [];
    for (const f of selectable) {
      try {
        const st = await client.client.status(f.path, { messages: true, unseen: true });
        statuses.push({ path: f.path, name: f.name, messages: st.messages, unseen: st.unseen });
      } catch {
        statuses.push({ path: f.path, name: f.name, messages: 0, unseen: 0 });
      }
    }
    res.json(statuses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/accounts/batch', async (req, res) => {
  const { lines } = req.body;
  if (!lines || !lines.length) {
    return res.status(400).json({ error: 'Provide an account list' });
  }

  const results = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const sepIdx = trimmed.indexOf(':');
    if (sepIdx === -1) {
      results.push({ email: trimmed, ok: false, error: 'Wrong format, expected email:password' });
      continue;
    }

    const email = trimmed.substring(0, sepIdx).trim();
    const password = trimmed.substring(sepIdx + 1).trim();
    if (!email || !password) {
      results.push({ email: email || '(empty)', ok: false, error: 'Email or password is empty' });
      continue;
    }

    let alreadyExists = false;
    for (const [existingId, existing] of clients) {
      if (existing.account.auth.user === email && mine(req, existing)) {
        results.push({ id: existingId, email, ok: true, exists: true });
        alreadyExists = true;
        break;
      }
    }
    if (alreadyExists) continue;

    try {
      const account = autoDetect(email, password);
      account.owner = ownerOf(req);
      const client = newClient(account);
      await client.connect();
      const id = ++clientId;
      clients.set(id, client);
      results.push({ id, email, ok: true });
    } catch (err) {
      results.push({ email, ok: false, error: err.message });
    }
  }

  if (results.some(r => r.ok)) saveAccounts();
  res.json(results);
});

const PORT = process.env.PORT || 3939;

async function startServer() {
  await restoreAccounts();
  return app.listen(PORT, () => {
    console.log(`IMAP Mail Client started: http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startServer().catch((err) => {
    console.error(`IMAP Mail Client failed to start: ${err.message}`);
    process.exit(1);
  });
}

module.exports = { app, clients, saveAccounts, restoreAccounts, startServer };
