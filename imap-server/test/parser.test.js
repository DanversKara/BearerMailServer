const assert = require('node:assert');
const test = require('node:test');

const { parseLine, tokenize, parseFetchItems, parseSequenceSet, isInSequenceSet } = require('../src/parser');
const { getFolder } = require('../src/folders');

test('parseLine and tokenize handle basic IMAP commands', () => {
  assert.deepStrictEqual(parseLine('A1 LOGIN "user@example.com" "p a s s"'), {
    tag: 'A1',
    command: 'LOGIN',
    args: '"user@example.com" "p a s s"',
  });
  assert.deepStrictEqual(tokenize('"user@example.com" "p a s s"'), ['user@example.com', 'p a s s']);
});

test('parseFetchItems handles common client requests', () => {
  const items = parseFetchItems('UID FLAGS BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT)]');
  assert.deepStrictEqual(items[0], { type: 'UID' });
  assert.deepStrictEqual(items[1], { type: 'FLAGS' });
  assert.strictEqual(items[2].type, 'BODY_SECTION');
  assert.strictEqual(items[2].peek, true);
  assert.strictEqual(items[2].section, 'HEADER.FIELDS');
  assert.deepStrictEqual(items[2].fields, ['FROM', 'TO', 'SUBJECT']);
});

test('sequence set supports ranges and wildcard', () => {
  const ranges = parseSequenceSet('1,3:5,10:*');
  assert.strictEqual(isInSequenceSet(1, ranges), true);
  assert.strictEqual(isInSequenceSet(4, ranges), true);
  assert.strictEqual(isInSequenceSet(9, ranges), false);
  assert.strictEqual(isInSequenceSet(999, ranges), true);
});

test('folder mappings protect per-account mailbox boundaries', () => {
  assert.deepStrictEqual(getFolder('inbox').filter('u@example.com'), {
    to_addresses: 'u@example.com',
    is_deleted: { $ne: true },
  });
  assert.deepStrictEqual(getFolder('Sent').filter('u@example.com'), {
    $or: [{ from_address: 'u@example.com' }, { owner: 'u@example.com' }],
  });
  assert.strictEqual(getFolder('Unknown'), null);
});

test('login throttle blocks an address after repeated failures and clears on success', () => {
  process.env.IMAP_MAX_AUTH_FAILURES = '3';
  delete require.cache[require.resolve('../src/throttle')];
  const t = require('../src/throttle');
  const ip = '203.0.113.9';
  assert.strictEqual(t.isBlocked(ip), false);
  assert.strictEqual(t.recordFailure(ip), false);
  assert.strictEqual(t.recordFailure(ip), false);
  assert.strictEqual(t.recordFailure(ip), true);
  assert.strictEqual(t.isBlocked(ip), true);
  assert.strictEqual(t.isBlocked('203.0.113.10'), false);
  t.recordSuccess(ip);
  assert.strictEqual(t.isBlocked(ip), false);
});

test('authenticate refuses non-string credentials before touching the database', async () => {
  const { authenticate } = require('../src/auth');
  assert.strictEqual(await authenticate({ $gt: '' }, 'x'), null);
  assert.strictEqual(await authenticate('a@b.c', { $ne: null }), null);
  assert.strictEqual(await authenticate('a@b.c', ''), null);
  assert.strictEqual(await authenticate('a'.repeat(400), 'x'), null);
});
