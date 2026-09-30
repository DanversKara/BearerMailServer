const { ImapFlow } = require('imapflow');

/**
 * One external IMAP account (Gmail, Outlook, ...). The server uses the ImapFlow client in
 * `this.client` directly; this wrapper keeps it connected and records its health so the
 * web app's Security page can show which external accounts are connected.
 *
 * (Earlier versions also had command-line helpers here that printed message subjects and
 * bodies to the log. They were unused by the web app and have been removed, so no email
 * content ends up in the container logs.)
 */
class MailClient {
  constructor(account, { onEvent } = {}) {
    this.account = account;
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.status = {
      connectedAt: null,
      lastOkAt: null,
      lastError: '',
      lastErrorAt: null,
      reconnects: 0,
      failures: 0,
    };
    this.client = this._newClient();
  }

  _newClient() {
    const client = new ImapFlow({
      host: this.account.host,
      port: this.account.port,
      secure: this.account.secure,
      auth: this.account.auth,
      logger: false,
    });
    client.on('error', (err) => {
      this._failed(err);
      console.error(`[${this.account.name}] connection error: ${err.message}`);
    });
    return client;
  }

  _failed(err) {
    this.status.lastError = String((err && err.message) || err || 'unknown error').slice(0, 200);
    this.status.lastErrorAt = new Date().toISOString();
    this.status.failures += 1;
  }

  _connected() {
    const now = new Date().toISOString();
    this.status.connectedAt = now;
    this.status.lastOkAt = now;
  }

  async connect() {
    try {
      await this.client.connect();
    } catch (err) {
      this._failed(err);
      this.onEvent('account_failed', this, err.message);
      throw err;
    }
    this._connected();
    this.onEvent('account_connected', this, '');
    console.log(`[${this.account.name}] connected ${this.account.auth.user}`);
  }

  async ensureConnected() {
    if (!this.client.usable) {
      console.log(`[${this.account.name}] connection lost, reconnecting...`);
      this.status.reconnects += 1;
      this.client = this._newClient();
      await this.connect();
      console.log(`[${this.account.name}] reconnected`);
    } else {
      this.status.lastOkAt = new Date().toISOString();
    }
  }

  async disconnect() {
    await this.client.logout();
    console.log(`[${this.account.name}] disconnected`);
  }

  /** Public view for the Security page. Never includes the password. */
  describe(id) {
    return {
      id,
      name: this.account.name,
      email: this.account.auth.user,
      host: this.account.host,
      port: this.account.port,
      secure: !!this.account.secure,
      connected: !!(this.client && this.client.usable),
      ...this.status,
    };
  }
}

module.exports = MailClient;
