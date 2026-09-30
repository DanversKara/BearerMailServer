const test = require('node:test');
const assert = require('node:assert');
const net = require('net');

const security = require('../src/security');
const { parseIdParams, describeClient } = require('../src/connection');
const { buildMessage } = require('../src/rfc2822');

test('block list matches single addresses and ranges', () => {
  const list = new net.BlockList();
  list.addAddress('203.0.113.7', 'ipv4');
  list.addSubnet('198.51.100.0', 24, 'ipv4');
  security._setBlockList(list);
  assert.strictEqual(security.isBlocked('203.0.113.7'), true);
  assert.strictEqual(security.isBlocked('::ffff:198.51.100.42'), true);
  assert.strictEqual(security.isBlocked('192.0.2.1'), false);
  assert.strictEqual(security.isBlocked('not-an-ip'), false);
});

test('internal addresses are recognised', () => {
  assert.ok(security.isInternal('172.18.0.3'));
  assert.ok(security.isInternal('::ffff:192.168.1.10'));
  assert.ok(!security.isInternal('203.0.113.9'));
});

test('ID command parsing names the mail app', () => {
  const params = parseIdParams('("name" "Thunderbird" "version" "128.3.1" "os" "Windows")');
  assert.strictEqual(describeClient(params), 'Thunderbird 128.3.1 (Windows)');
  assert.deepStrictEqual(parseIdParams('NIL'), {});
  assert.strictEqual(describeClient(parseIdParams('("name" "K-9 \\"Mail\\"")')), 'K-9 "Mail"');
});

test('stored sender checks appear as Authentication-Results', () => {
  const raw = buildMessage({
    _id: 'abc', from: { address: 'a@b.example', name: '' }, to: [{ address: 'me@x.example' }], subject: 's', text: 'hi',
    reply_to: 'r@c.example',
    auth: { spf: 'fail', spf_domain: 'b.example', dkim: 'none', dmarc: 'fail', header_from_domain: 'b.example' },
  }, false);
  assert.match(raw, /Authentication-Results: [^;]+;\r\n spf=fail smtp\.mailfrom=b\.example;\r\n dkim=none;\r\n dmarc=fail header\.from=b\.example/);
  assert.match(raw, /Reply-To: r@c\.example/);
  const local = buildMessage({ _id: 'abc', from: { address: 'a@b.example' }, to: [], subject: 's', text: 'hi', auth: { skipped: true } }, false);
  assert.doesNotMatch(local, /Authentication-Results/);
});
