const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const DUMMY_HASH = bcrypt.hashSync('dummy-password-for-timing', 10);
const { getDb } = require('./mongo');

// App passwords (My account > App passwords in the web app) are shown as "abcd efgh jkmn pqrs";
// spaces and capitals do not matter. Only a SHA-256 hash is stored, the same way the mail service does it.
function normalizeAppPassword(value) {
  return String(value || '').replace(/\s+/g, '').toLowerCase();
}

function appPasswordHash(value) {
  return crypto.createHash('sha256').update('bearermail-relay:' + normalizeAppPassword(value)).digest('hex');
}

/**
 * Check a mail app's sign-in. Accepts the mailbox password, or one of the mailbox's app passwords.
 * When app passwords are required (for this mailbox or for everyone) the mailbox password is refused.
 * `info` receives how it went: info.method ('password' | 'app password'), info.label, info.reason.
 */
async function authenticate(username, password, info = {}) {
  // Only plain strings are accepted, so an object can never end up inside the query filter.
  if (typeof username !== 'string' || typeof password !== 'string') return null;
  if (username.length > 320 || password.length > 1024) return null;
  const address = username.trim().toLowerCase();
  if (!address || !password) return null;
  const db = getDb();

  const account = await db.collection('accounts').findOne({
    address,
    is_active: true,
  });
  if (!account) {
    await bcrypt.compare(password, DUMMY_HASH); // equalise timing
    return null;
  }
  const user = { id: account._id.toHexString(), address: account.address };

  const app = await db.collection('relay_keys').findOne({
    owner: account.address, kind: 'app_password', secret_hash: appPasswordHash(password),
  });
  if (app) {
    if (app.revoked_at) {
      info.reason = 'revoked app password';
      return null;
    }
    info.method = 'app password';
    info.label = app.label || '';
    db.collection('relay_keys').updateOne({ _id: app._id },
      { $set: { last_used_at: new Date(), last_ip: String(info.ip || '').slice(0, 64) } }).catch(() => {});
    return user;
  }

  const valid = await bcrypt.compare(password, account.password_hash);
  if (!valid) return null;
  const settings = await db.collection('settings').findOne({ _id: 'auth' });
  if (account.app_passwords_only || (settings && settings.app_passwords_required)) {
    info.reason = 'mailbox password refused, app passwords are required';
    return null;
  }
  info.method = 'password';
  return user;
}

module.exports = { authenticate, appPasswordHash, normalizeAppPassword };
