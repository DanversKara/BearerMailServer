const test = require('node:test');
const assert = require('node:assert');
const bcrypt = require('bcryptjs');

// A tiny stand-in for the MongoDB collections auth.js reads.
const data = { accounts: [], relay_keys: [], settings: [] };
const match = (doc, q) => Object.entries(q).every(([k, v]) => doc[k] === v);
const fakeDb = {
  collection: (name) => ({
    findOne: async (q) => data[name].find((d) => match(d, q)) || null,
    updateOne: async (q, u) => { const d = data[name].find((x) => match(x, q)); if (d) Object.assign(d, u.$set); },
  }),
};
const mongo = require('../src/mongo');
mongo.getDb = () => fakeDb;
const { authenticate, appPasswordHash } = require('../src/auth');

const ID = { toHexString: () => 'a1' };
data.accounts.push({ _id: ID, address: 'jane@x.test', is_active: true, password_hash: bcrypt.hashSync('real-pass-123', 4) });

test('app password hash matches the mail service (spaces and capitals ignored)', () => {
  // Same value Python computes for sha256("bearermail-relay:abcdefghjkmnpqrs")
  const expected = require('crypto').createHash('sha256').update('bearermail-relay:abcdefghjkmnpqrs').digest('hex');
  assert.strictEqual(appPasswordHash('ABCD efgh JKMN pqrs'), expected);
});

test('mailbox password and app passwords both work, revoked ones do not', async () => {
  data.relay_keys.push({ _id: 'k1', owner: 'jane@x.test', kind: 'app_password', label: 'Phone', secret_hash: appPasswordHash('abcd efgh jkmn pqrs'), revoked_at: null });
  data.relay_keys.push({ _id: 'k2', owner: 'jane@x.test', kind: 'app_password', label: 'Old', secret_hash: appPasswordHash('zzzz zzzz zzzz zzzz'), revoked_at: new Date() });
  let info = {};
  assert.ok(await authenticate('jane@x.test', 'real-pass-123', info));
  assert.strictEqual(info.method, 'password');
  info = { ip: '198.51.100.3' };
  assert.ok(await authenticate('Jane@x.test', 'abcdefghjkmnpqrs', info));
  assert.strictEqual(info.method, 'app password');
  assert.strictEqual(info.label, 'Phone');
  assert.strictEqual(data.relay_keys[0].last_ip, '198.51.100.3');
  info = {};
  assert.strictEqual(await authenticate('jane@x.test', 'zzzz zzzz zzzz zzzz', info), null);
  assert.match(info.reason, /revoked/);
  assert.strictEqual(await authenticate('jane@x.test', 'wrong', {}), null);
});

test('app passwords only: the mailbox password is refused', async () => {
  data.accounts[0].app_passwords_only = true;
  const info = {};
  assert.strictEqual(await authenticate('jane@x.test', 'real-pass-123', info), null);
  assert.match(info.reason, /app passwords are required/);
  assert.ok(await authenticate('jane@x.test', 'abcd efgh jkmn pqrs', {}));
  data.accounts[0].app_passwords_only = false;
  data.settings.push({ _id: 'auth', app_passwords_required: true });
  assert.strictEqual(await authenticate('jane@x.test', 'real-pass-123', {}), null);
  data.settings.length = 0;
});
