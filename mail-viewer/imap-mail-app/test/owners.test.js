const test = require('node:test');
const assert = require('node:assert');

process.env.BRIDGE_TOKEN = 'tok';
process.env.IMAP_ACCOUNT_PERSISTENCE = 'disabled';
const { app, clients } = require('../server');

function fake(user, owner) {
  return { account: { name: 'x', host: 'imap.example', port: 993, auth: { user, pass: 'p' }, owner },
    client: { usable: true }, ensureConnected: async () => {}, disconnect: async () => {},
    describe: (id) => ({ id, email: user }) };
}

test('each person only sees and opens their own external accounts', async () => {
  clients.set(101, fake('alice@gmail.com', 'alice@bearer.test'));
  clients.set(102, fake('boss@outlook.com', undefined)); // added before multi-account mode: admins only
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = (path, user) => fetch(base + path, { headers: { 'x-bridge-token': 'tok', ...(user ? { 'x-bridge-user': user } : {}) } });
  try {
    const alice = await (await get('/api/accounts', 'alice@bearer.test')).json();
    assert.deepStrictEqual(alice.map((a) => a.email), ['alice@gmail.com']);
    const admin = await (await get('/api/accounts')).json();
    assert.deepStrictEqual(admin.map((a) => a.email), ['boss@outlook.com']);
    assert.strictEqual((await get('/api/accounts/102/folders', 'alice@bearer.test')).status, 404);
    assert.strictEqual((await get('/api/accounts/101/folders', 'bob@bearer.test')).status, 404);
    const status = await (await get('/api/status')).json();
    assert.strictEqual(status.accounts.length, 2);
  } finally {
    server.close();
    clients.clear();
  }
});
