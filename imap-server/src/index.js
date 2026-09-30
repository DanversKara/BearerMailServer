const tls = require('tls');
const net = require('net');
const fs = require('fs');
const { connect, close } = require('./mongo');
const ImapConnection = require('./connection');
const security = require('./security');

const IMAP_PORT = parseInt(process.env.IMAP_PORT || '993');
const TLS_CERT = process.env.TLS_CERT || '';
const TLS_KEY = process.env.TLS_KEY || '';

function loadTlsOptions() {
  if (!TLS_CERT || !TLS_KEY) return null;
  try {
    return { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY), minVersion: 'TLSv1.2' };
  } catch (err) {
    console.error(`Could not read TLS certificate (${TLS_CERT}): ${err.message}`);
    return null;
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ALLOW_INSECURE = ['1', 'true', 'yes', 'on'].includes((process.env.IMAP_ALLOW_INSECURE || '').toLowerCase());

async function main() {
  await connect();
  console.log('MongoDB connected');

  // Mail apps send your password, so plaintext IMAP is refused unless IMAP_ALLOW_INSECURE=1
  // (local testing only). Without a certificate we wait and retry, which also covers first
  // start while a certificate is still being issued.
  let tlsOptions = loadTlsOptions();
  if (!tlsOptions && !ALLOW_INSECURE) {
    console.error('IMAP is waiting for a TLS certificate (TLS_CERT / TLS_KEY). See the README section "TLS certificates".');
    while (!tlsOptions) {
      await sleep(15000);
      tlsOptions = loadTlsOptions();
    }
  }
  if (tlsOptions) console.log('TLS certificates loaded');

  const MAX_CONN_PER_IP = parseInt(process.env.IMAP_MAX_CONN_PER_IP || '20', 10);
  const active = new Map();
  await security.start();
  const onConnection = (socket) => {
    const addr = socket.remoteAddress || 'unknown';
    if (security.isBlocked(addr)) {
      security.report('blocked', { ip: addr });
      socket.destroy();
      return;
    }
    const n = (active.get(addr) || 0) + 1;
    if (n > MAX_CONN_PER_IP) {
      security.report('too_many_connections', { ip: addr, detail: `more than ${MAX_CONN_PER_IP} at once` });
      socket.destroy();
      return;
    }
    active.set(addr, n);
    socket.on('close', () => {
      const c = (active.get(addr) || 1) - 1;
      if (c <= 0) active.delete(addr); else active.set(addr, c);
    });
    console.log(`[IMAP] Connection from ${addr}`);
    if (!security.isInternal(addr)) security.report('connect', { ip: addr });
    const conn = new ImapConnection(socket);
    conn.start();
  };

  if (tlsOptions) {
    // IMAPS — implicit TLS on port 993
    const server = tls.createServer(tlsOptions, onConnection);
    server.on('error', (err) => console.error(`TLS server error: ${err.message}`));
    // Scanners and old clients that fail the TLS handshake never reach onConnection.
    server.on('tlsClientError', (err, socket) => {
      const addr = socket && socket.remoteAddress;
      if (addr && !security.isInternal(addr)) security.report('tls_error', { ip: addr, detail: String(err && err.code || err && err.message || '').slice(0, 120) });
    });
    server.listen(IMAP_PORT, '0.0.0.0', () => {
      console.log(`IMAP server (TLS) listening on port ${IMAP_PORT}`);
    });
    // Pick up renewed certificates without a restart
    setInterval(() => {
      const fresh = loadTlsOptions();
      if (fresh) server.setSecureContext(fresh);
    }, 6 * 60 * 60 * 1000).unref();
  } else {
    // Plain IMAP — for development/testing without TLS
    console.warn('WARNING: No TLS certs configured — running plain IMAP (insecure)');
    const server = net.createServer(onConnection);
    server.on('error', (err) => console.error(`Server error: ${err.message}`));
    server.listen(IMAP_PORT, '0.0.0.0', () => {
      console.log(`IMAP server (plain) listening on port ${IMAP_PORT}`);
    });
  }

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    console.log('Shutting down...');
    await close();
    process.exit(0);
  });
}

main().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
