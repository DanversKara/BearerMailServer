/* BearerMail Setup > Security
 *
 * Overview  - what reached each port in the last day, who is connected right now (mail apps, web
 *             sessions, external accounts), suspicious addresses with a Block button.
 * Activity  - the full security log with filters, and the IP block list.
 * Sign-in   - two-factor sign-in for the web app, active web sessions.
 * Privacy   - remote images, trusted senders, link protection.
 * Alerts    - email alerts for new sign-ins and password guessing.
 * DMARC     - the daily reports from Gmail, Microsoft... about mail sent as your domains.
 */
(function () {
  'use strict';

  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toast = (msg, type) => (window.showToast ? window.showToast(msg, { type: type || 'success' }) : alert(msg));
  const fail = (msg) => (window.toastError ? window.toastError(msg) : alert(msg));

  const S = { view: 'overview', hours: 24, filter: { source: '', level: '', ip: '' }, timer: null, setup: null, codes: null };
  let host = null;

  async function call(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res; let data = {};
    try { res = await fetch(url, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || 'Request failed');
    return data;
  }
  const admin = (method, path, body) => call(method, '/api/admin/security/' + path, body);
  async function run(fn) { try { return await fn(); } catch (e) { fail(e.message); return null; } }

  const ago = (iso) => {
    if (!iso) return '-';
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + new Date(iso).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  };
  const PORT = {
    smtp: ['Port 25', 'Incoming mail', 'bi-mailbox'],
    imap: ['Port 993', 'Mail apps (IMAP)', 'bi-phone'],
    relay: ['587/465', 'Sending with SMTP keys', 'bi-send-check'],
    web: ['Web app', 'This website', 'bi-globe2'],
    bridge: ['External', 'Gmail, Outlook...', 'bi-diagram-3'],
    system: ['System', 'Settings', 'bi-gear'],
  };
  const portBadge = (src) => `<span class="sec-port sec-port-${esc(src)}" title="${esc((PORT[src] || [])[1] || '')}">${esc((PORT[src] || [src])[0])}</span>`;
  const levelDot = (lvl) => `<span class="sec-dot sec-dot-${esc(lvl)}" title="${esc(lvl)}"></span>`;
  const empty = (text) => `<div class="text-muted small py-2">${text}</div>`;
  const isPrivate = (ip) => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|f[cd])/i.test(ip || '');
  const lookup = (ip) => ip && isPrivate(ip) ? `<span title="Private / local address">${esc(ip)}</span>` : ip ? `<a class="small" href="https://ipinfo.io/${encodeURIComponent(ip)}" target="_blank" rel="noopener noreferrer" title="Who owns this address (opens ipinfo.io)">${esc(ip)}</a>` : '';

  const VIEWS = [['overview', 'bi-speedometer2', 'Overview'], ['activity', 'bi-list-ul', 'Activity'], ['signin', 'bi-key', 'Sign-in'], ['privacy', 'bi-eye-slash', 'Privacy'], ['alerts', 'bi-bell', 'Alerts'], ['dmarc', 'bi-envelope-check', 'DMARC reports']];

  function render(el) {
    host = el || host;
    if (!host) return;
    clearInterval(S.timer); S.timer = null;
    host.innerHTML = `<div class="sec-nav" role="tablist">${VIEWS.map(([id, icon, label]) => `<button type="button" class="sec-nav-btn${S.view === id ? ' active' : ''}" data-sec-view="${id}"><i class="bi ${icon}"></i><span>${label}</span></button>`).join('')}</div><div class="sec-body"><div class="text-muted py-4 text-center"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div></div>`;
    const body = host.querySelector('.sec-body');
    ({ overview: viewOverview, activity: viewActivity, signin: viewSignin, privacy: viewPrivacy, alerts: viewAlerts, dmarc: viewDmarc })[S.view](body);
  }

  /* ------------------------------ overview ------------------------------ */
  async function viewOverview(body) {
    const [sum, imap, web, ext] = await Promise.all([
      run(() => admin('GET', `summary?hours=${S.hours}`)), run(() => admin('GET', 'imap-sessions')),
      run(() => call('GET', '/api/security/overview')), run(() => call('GET', '/api/security/external-accounts')),
    ]);
    if (!body.isConnected) return;
    const src = (sum && sum.sources) || {};
    const k = (s, kind) => ((src[s] || {}).kinds || {})[kind] || 0;
    const tile = (s, lines) => `<div class="sec-tile"><div class="sec-tile-head"><i class="bi ${PORT[s][2]}"></i><div><div class="fw-semibold">${PORT[s][0]}</div><div class="small text-muted">${PORT[s][1]}</div></div></div>
      <ul class="sec-tile-list">${(() => { const shown = lines.filter((l, i) => l && (i === 0 || l[0])); return shown.map(([n, label, bad]) => `<li class="${bad && n ? 'is-bad' : ''}"><b>${n}</b> ${label}</li>`).join('') + (shown.length < lines.length ? '<li class="sec-quiet">nothing else</li>' : ''); })()}</ul></div>`;
    const tiles = [
      tile('smtp', [[k('smtp', 'connect'), 'connections'], [k('smtp', 'message_received'), 'messages delivered'],
        [k('smtp', 'relay_attempt'), 'relay attempts', true], [k('smtp', 'auth_attempt'), 'password-guessing attempts', true],
        [k('smtp', 'forged_sender'), 'messages with a fake sender', true], [k('smtp', 'blocked'), 'blocked connections']]),
      tile('imap', [[k('imap', 'connect'), 'connections'], [k('imap', 'login_ok'), 'sign-ins'], [k('imap', 'login_failed'), 'wrong passwords', true],
        [k('imap', 'throttled'), 'addresses throttled', true], [k('imap', 'tls_error'), 'broken TLS (scanners)'], [k('imap', 'blocked'), 'blocked connections']]),
      tile('relay', [[k('relay', 'sent'), 'messages sent with keys'], [k('relay', 'login_ok'), 'key sign-ins'],
        [k('relay', 'auth_failed'), 'wrong keys', true], [k('relay', 'revoked_key_used'), 'revoked keys tried', true],
        [k('relay', 'sender_refused'), 'tried to send as someone else', true], [k('relay', 'blocked'), 'blocked connections']]),
      tile('web', [[k('web', 'login_ok'), 'sign-ins'], [k('web', 'login_failed'), 'wrong passwords', true], [k('web', 'login_2fa_failed'), 'wrong two-factor codes', true],
        [k('web', 'rate_limited'), 'times rate limited', true], [k('web', 'blocked'), 'blocked requests']]),
      tile('bridge', [[(ext && ext.accounts || []).length, 'external accounts'], [(ext && ext.accounts || []).filter((a) => a.connected).length, 'connected'],
        [k('bridge', 'account_failed'), 'connection failures', true]]),
    ].join('');

    const sessions = (imap && imap.sessions) || [];
    const imapRows = sessions.length ? sessions.map((s) => `<div class="sec-row">
        <div class="sec-row-main"><div class="fw-semibold text-truncate">${esc(s.user)}</div>
          <div class="small text-muted">${esc(s.client || 'Unknown mail app')} &middot; ${lookup(s.ip)}${s.folder ? ` &middot; ${esc(s.folder)}` : ''}${s.idle ? ' &middot; waiting for new mail' : ''}</div>
          <div class="small text-muted">signed in ${ago(s.login_at)}</div></div>
        <button type="button" class="btn btn-sm btn-outline-danger" data-sec-kick="${esc(s.id)}">End</button></div>`).join('')
      : empty('No mail apps are connected right now.');

    const webSessions = (web && web.sessions) || [];
    const webRows = webSessions.map((s) => `<div class="sec-row">
        <div class="sec-row-main"><div class="fw-semibold">${esc(s.device || 'Browser')} ${s.current ? '<span class="badge text-bg-success ms-1">this device</span>' : ''}</div>
          <div class="small text-muted">${s.user ? `<b>${esc(s.user)}</b> &middot; ` : ''}${lookup(s.ip)} &middot; ${esc(s.method || 'password')} &middot; active ${ago(s.last_seen)}</div></div>
        ${s.current ? '' : `<button type="button" class="btn btn-sm btn-outline-danger" data-sec-endweb="${esc(s.id)}">Sign out</button>`}</div>`).join('') || empty('None.');

    const accounts = (ext && ext.accounts) || [];
    const extRows = accounts.length ? accounts.map((a) => `<div class="sec-row">
        <div class="sec-row-main"><div class="fw-semibold text-truncate">${esc(a.email)}</div>
          <div class="small text-muted">${esc(a.host)}:${esc(a.port)} &middot; ${a.connected ? '<span class="text-success">connected</span>' : '<span class="text-danger">not connected</span>'}${a.lastOkAt ? ` &middot; last used ${ago(a.lastOkAt)}` : ''}</div>
          ${a.lastError ? `<div class="small text-danger text-truncate">Last error ${ago(a.lastErrorAt)}: ${esc(a.lastError)}</div>` : ''}</div></div>`).join('')
      : empty('No external accounts. Add Gmail, Outlook and others under <b>External accounts</b>.');

    const sus = (sum && sum.suspicious_ips) || [];
    const susRows = sus.length ? sus.map((x) => `<div class="sec-row">
        <div class="sec-row-main"><div class="fw-semibold">${lookup(x.ip)} <span class="badge text-bg-light border ms-1">${x.count}&times;</span></div>
          <div class="small text-muted">${x.sources.map(portBadge).join(' ')} ${esc(x.kinds.join(', ').replace(/_/g, ' '))}${x.users.length ? ` &middot; tried ${esc(x.users.join(', '))}` : ''}</div></div>
        ${x.blocked ? '<span class="badge text-bg-secondary">blocked</span>' : `<button type="button" class="btn btn-sm btn-outline-danger" data-sec-block="${esc(x.ip)}">Block</button>`}</div>`).join('')
      : empty('Nothing suspicious in this period.');

    body.innerHTML = `
      <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
        <div class="small text-muted">What reached BearerMail's ports. Your address right now: <b>${esc((web && web.your_ip) || '?')}</b></div>
        <div class="d-flex gap-2 align-items-center"><select class="form-select form-select-sm" data-sec-hours style="width:auto">
          ${[[24, 'Last 24 hours'], [168, 'Last 7 days'], [720, 'Last 30 days']].map(([h, l]) => `<option value="${h}"${S.hours === h ? ' selected' : ''}>${l}</option>`).join('')}</select>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-sec-refresh title="Refresh"><i class="bi bi-arrow-clockwise"></i></button></div></div>
      <div class="sec-tiles mb-4">${tiles}</div>
      <div class="row g-3">
        <div class="col-lg-6"><div class="card h-100"><div class="card-header"><i class="bi bi-phone me-1"></i>Mail apps connected now (port 993)</div><div class="card-body">${imapRows}</div></div></div>
        <div class="col-lg-6"><div class="card h-100"><div class="card-header"><i class="bi bi-globe2 me-1"></i>Web app sessions</div><div class="card-body">${webRows}
          ${webSessions.length > 1 ? '<button type="button" class="btn btn-sm btn-outline-danger mt-2" data-sec-endothers>Sign out all other sessions</button>' : ''}</div></div></div>
        <div class="col-lg-6"><div class="card h-100"><div class="card-header"><i class="bi bi-diagram-3 me-1"></i>External accounts (outgoing IMAP connections)</div><div class="card-body">${extRows}</div></div></div>
        <div class="col-lg-6"><div class="card h-100"><div class="card-header"><i class="bi bi-exclamation-triangle me-1"></i>Suspicious addresses</div><div class="card-body">${susRows}</div></div></div>
      </div>
      <div class="alert alert-secondary small mt-3 mb-0"><b>Other ports on this server</b> (SSH, your router, anything outside BearerMail) are not visible to BearerMail's containers.
        To see every port that is open, connected or being probed, run this on the server: <code>sudo ./tools/port_report.sh</code></div>`;
    S.timer = setInterval(() => { if (S.view === 'overview' && body.isConnected && document.visibilityState === 'visible') viewOverview(body); else clearInterval(S.timer); }, 30000);
  }

  /* ------------------------------ activity ------------------------------ */
  async function viewActivity(body) {
    const f = S.filter;
    const qs = new URLSearchParams({ hours: String(S.hours), limit: '300' });
    if (f.source) qs.set('source', f.source);
    if (f.level) qs.set('level', f.level);
    if (f.ip) qs.set('ip', f.ip);
    const [ev, bl] = await Promise.all([run(() => admin('GET', 'events?' + qs.toString())), run(() => admin('GET', 'blocklist'))]);
    if (!body.isConnected) return;
    const events = (ev && ev.events) || [];
    const rows = events.length ? events.map((e) => `<tr>
        <td data-label="When" class="text-nowrap small">${ago(e.last)}${e.count > 1 ? `<div class="text-muted">${e.count}&times; since ${ago(e.first)}</div>` : ''}</td>
        <td data-label="Where">${portBadge(e.source)}</td>
        <td data-label="What">${levelDot(e.level)} ${esc(e.label)}${e.detail ? `<div class="small text-muted text-break">${esc(e.detail)}</div>` : ''}</td>
        <td data-label="Who" class="small">${lookup(e.ip)}${e.user ? `<div class="text-muted text-break">${esc(e.user)}</div>` : ''}</td>
        <td class="text-end">${e.ip && e.source !== 'system' ? `<button type="button" class="btn btn-sm btn-link p-0" data-sec-filterip="${esc(e.ip)}" title="Only this address"><i class="bi bi-funnel"></i></button>` : ''}</td></tr>`).join('')
      : `<tr><td colspan="5">${empty('No events match.')}</td></tr>`;
    const blocks = (bl && bl.blocklist) || [];
    const blockRows = blocks.length ? blocks.map((b) => `<div class="sec-row"><div class="sec-row-main"><div class="fw-semibold">${esc(b.ip)}</div>
        <div class="small text-muted">${esc(b.reason || 'no reason given')} &middot; since ${ago(b.created_at)}${b.expires_at ? ` &middot; until ${new Date(b.expires_at).toLocaleString()}` : ' &middot; permanent'}</div></div>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-sec-unblock="${esc(b.ip)}">Remove</button></div>`).join('') : empty('No addresses are blocked.');
    body.innerHTML = `
      <div class="sec-filters mb-2">
        <select class="form-select form-select-sm" data-sec-f="source"><option value="">All ports</option>${Object.entries(PORT).map(([id, p]) => `<option value="${id}"${f.source === id ? ' selected' : ''}>${p[0]} (${p[1]})</option>`).join('')}</select>
        <select class="form-select form-select-sm" data-sec-f="level"><option value="">Everything</option><option value="warn"${f.level === 'warn' ? ' selected' : ''}>Warnings and alerts</option><option value="alert"${f.level === 'alert' ? ' selected' : ''}>Alerts only</option></select>
        <select class="form-select form-select-sm" data-sec-hours>${[[24, '24 hours'], [168, '7 days'], [720, '30 days']].map(([h, l]) => `<option value="${h}"${S.hours === h ? ' selected' : ''}>${l}</option>`).join('')}</select>
        <div class="input-group input-group-sm"><input class="form-control" placeholder="IP address" value="${esc(f.ip)}" data-sec-ipinput><button type="button" class="btn btn-outline-secondary" data-sec-applyip><i class="bi bi-search"></i></button>${f.ip ? '<button type="button" class="btn btn-outline-secondary" data-sec-clearip><i class="bi bi-x-lg"></i></button>' : ''}</div>
      </div>
      <div class="small text-muted mb-2">Repeated events from the same address are grouped per hour. Kept for ${esc(String((ev && ev.retention_days) || 30))} days.</div>
      <div class="table-responsive"><table class="table table-sm align-middle table-stack sec-table"><thead><tr><th>When</th><th>Where</th><th>What</th><th>Who</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="card mt-4"><div class="card-header"><i class="bi bi-slash-circle me-1"></i>Blocked addresses</div><div class="card-body">
        <p class="small text-muted">Blocked addresses cannot connect to port 25, port 993 or the web app. Your own current address and private network addresses cannot be blocked.</p>
        ${blockRows}
        <div class="row g-2 mt-2 align-items-end">
          <div class="col-md-4"><label class="form-label small mb-1">IP address or range</label><input class="form-control form-control-sm" data-sec-newblock placeholder="203.0.113.7 or 203.0.113.0/24"></div>
          <div class="col-md-4"><label class="form-label small mb-1">Reason (optional)</label><input class="form-control form-control-sm" data-sec-newreason placeholder="password guessing"></div>
          <div class="col-md-2"><label class="form-label small mb-1">For</label><select class="form-select form-select-sm" data-sec-newhours><option value="">Always</option><option value="1">1 hour</option><option value="24">1 day</option><option value="168">1 week</option></select></div>
          <div class="col-md-2"><button type="button" class="btn btn-sm btn-danger w-100" data-sec-addblock>Block</button></div>
        </div></div></div>`;
  }

  /* ------------------------------ sign-in ------------------------------ */
  async function viewSignin(body) {
    const web = await run(() => call('GET', '/api/security/overview'));
    if (!body.isConnected || !web) return;
    const tf = web.two_factor || {};
    const multi = (window.BM_USER || {}).mode === 'multi';
    let twoFactor;
    if (S.codes) {
      twoFactor = `<div class="alert alert-warning"><b>Save these recovery codes now.</b> Each one works once, if you lose your phone. They will not be shown again.</div>
        <div class="sec-codes">${S.codes.map((c) => `<code>${esc(c)}</code>`).join('')}</div>
        <div class="d-flex gap-2 mt-2"><button type="button" class="btn btn-sm btn-outline-secondary" data-sec-copycodes><i class="bi bi-clipboard me-1"></i>Copy</button>
        <button type="button" class="btn btn-sm btn-primary" data-sec-codesdone>I saved them</button></div>`;
    } else if (tf.enabled) {
      twoFactor = `<p><span class="badge text-bg-success">On</span> Signing in needs your password <b>and</b> a code from your authenticator app. Recovery codes left: <b>${tf.recovery_codes_left}</b>.</p>
        <div class="row g-2 align-items-end">
          <div class="col-sm-4"><label class="form-label small mb-1">Web app password</label><input type="password" class="form-control form-control-sm" data-sec-pw autocomplete="current-password"></div>
          <div class="col-sm-4"><label class="form-label small mb-1">Current code (or a recovery code)</label><input class="form-control form-control-sm" data-sec-code inputmode="numeric" autocomplete="one-time-code"></div>
          <div class="col-sm-4 d-flex gap-2"><button type="button" class="btn btn-sm btn-outline-secondary" data-sec-newcodes>New recovery codes</button><button type="button" class="btn btn-sm btn-outline-danger" data-sec-tfaoff>Turn off</button></div>
        </div>`;
    } else if (S.setup) {
      twoFactor = `<ol class="small ps-3"><li>Open an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Aegis, 1Password, Bitwarden...).</li>
          <li>Scan this code, or type the key by hand.</li><li>Enter the 6-digit code it shows and your web app password.</li></ol>
        <div class="sec-qr">${S.setup.qr_svg || ''}</div>
        <div class="small mb-2">Key: <code class="user-select-all">${esc(S.setup.secret.replace(/(.{4})/g, '$1 ').trim())}</code></div>
        <div class="row g-2 align-items-end">
          <div class="col-sm-4"><label class="form-label small mb-1">6-digit code</label><input class="form-control" data-sec-code inputmode="numeric" autocomplete="one-time-code" maxlength="8"></div>
          <div class="col-sm-4"><label class="form-label small mb-1">Web app password</label><input type="password" class="form-control" data-sec-pw autocomplete="current-password"></div>
          <div class="col-sm-4 d-flex gap-2"><button type="button" class="btn btn-primary" data-sec-tfaon>Turn on</button><button type="button" class="btn btn-outline-secondary" data-sec-tfacancel>Cancel</button></div>
        </div>`;
    } else {
      twoFactor = `<p><span class="badge text-bg-secondary">Off</span> Anyone who learns the web app password can sign in. With two-factor sign-in they also need your phone.</p>
        <button type="button" class="btn btn-primary btn-sm" data-sec-tfasetup><i class="bi bi-shield-lock me-1"></i>Set up two-factor sign-in</button>`;
    }
    const sessions = (web.sessions || []).map((s) => `<div class="sec-row">
        <div class="sec-row-main"><div class="fw-semibold">${esc(s.device || 'Browser')} ${s.current ? '<span class="badge text-bg-success ms-1">this device</span>' : ''}</div>
          <div class="small text-muted">${s.user ? `<b>${esc(s.user)}</b> &middot; ` : ''}${lookup(s.ip)} &middot; ${esc(s.method)} &middot; signed in ${ago(s.created)} &middot; active ${ago(s.last_seen)}</div></div>
        ${s.current ? '' : `<button type="button" class="btn btn-sm btn-outline-danger" data-sec-endweb="${esc(s.id)}">Sign out</button>`}</div>`).join('');
    body.innerHTML = `
      ${multi ? `<div class="alert alert-info small">Personal accounts are on. Each person sets up their own two-factor under <b>My account</b>; admins can turn it off for someone who lost their phone under <b>Users</b>. The setting below only protects the emergency admin sign-in (ACCESS_PASSWORD).</div>` : ''}
      <div class="card mb-3"><div class="card-header"><i class="bi bi-shield-lock me-1"></i>${multi ? 'Two-factor for the emergency admin sign-in' : 'Two-factor sign-in (web app)'}</div><div class="card-body">${twoFactor}</div></div>
      <div class="card mb-3"><div class="card-header d-flex justify-content-between align-items-center"><span><i class="bi bi-laptop me-1"></i>Signed-in browsers</span>
        ${(web.sessions || []).length > 1 ? '<button type="button" class="btn btn-sm btn-outline-danger" data-sec-endothers>Sign out all others</button>' : ''}</div>
        <div class="card-body">${sessions || empty('None.')}<div class="small text-muted mt-2">A sign-in lasts ${esc(String(web.session_hours))} hours (SESSION_HOURS). Signing out here ends it on the server, so a copied cookie stops working too.</div></div></div>
      <div class="alert alert-secondary small mb-0"><b>Mail app passwords</b> (Thunderbird, phones) are separate: each mailbox has its own, changed under Setup &gt; Mailboxes &gt; Reset password.
        The web app password is <code>ACCESS_PASSWORD</code> in <code>.env</code>.</div>`;
  }

  /* ------------------------------ privacy ------------------------------ */
  async function viewPrivacy(body) {
    const s = await run(() => admin('GET', 'settings'));
    if (!body.isConnected || !s) return;
    const p = s.privacy || {};
    const toggle = (key, title, text) => `<div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="sec-${key}" data-sec-privacy="${key}"${p[key] ? ' checked' : ''}>
      <label class="form-check-label" for="sec-${key}"><b>${title}</b><div class="small text-muted">${text}</div></label></div>`;
    const trusted = (p.trusted_senders || []);
    body.innerHTML = `
      <div class="card mb-3"><div class="card-header"><i class="bi bi-eye-slash me-1"></i>Reading email</div><div class="card-body">
        ${toggle('block_remote_images', 'Hide remote images until I click "Show images"', 'Pictures loaded from the internet tell the sender when (and that) you opened a message. Tracking pixels stay blocked even after you show images.')}
        ${toggle('confirm_suspicious_links', 'Ask before opening suspicious links', 'Links whose text shows one website but lead to another, raw IP addresses, look-alike domains and link shorteners.')}
        ${toggle('strip_link_tracking', 'Remove tracking from links', 'Strips utm_*, fbclid, gclid and similar tags so websites learn less about where you came from.')}
        <div class="small text-muted">These apply to the web app. Thunderbird and phone apps have their own setting: in Thunderbird, Settings &gt; Privacy &amp; Security &gt; untick "Allow remote content in messages".</div>
      </div></div>
      <div class="card"><div class="card-header"><i class="bi bi-person-check me-1"></i>Always show images from</div><div class="card-body">
        ${trusted.length ? trusted.map((t) => `<span class="badge rounded-pill text-bg-light border me-1 mb-1 p-2">${esc(t)} <button type="button" class="btn btn-sm p-0 ms-1" data-sec-untrust="${esc(t)}" aria-label="Remove"><i class="bi bi-x-lg"></i></button></span>`).join('') : empty('Nobody yet. Use "Always from this sender" on a message, or add one here.')}
        <div class="input-group input-group-sm mt-2" style="max-width:420px"><input class="form-control" data-sec-newtrust placeholder="news@example.com or @example.com"><button type="button" class="btn btn-outline-primary" data-sec-addtrust>Add</button></div>
        <div class="small text-muted mt-2">Senders that fail the sender check (a forged From address) never get images shown automatically.</div>
      </div></div>`;
  }

  /* ------------------------------ DMARC reports ------------------------------ */
  S.dmarcDays = 30;
  async function viewDmarc(body) {
    const [sum, settings, reps] = await Promise.all([
      run(() => call('GET', `/api/admin/dmarc/summary?days=${S.dmarcDays}`)), run(() => admin('GET', 'settings')),
      run(() => call('GET', '/api/admin/dmarc/reports?limit=30')),
    ]);
    if (!body.isConnected || !sum) return;
    const keep = !!((settings || {}).dmarc || {}).keep_in_inbox;
    const pct = sum.total ? Math.round(sum.passed * 100 / sum.total) : 0;
    const status = { ok: ['success', 'passes'], partly: ['warning', 'partly fails'], failing: ['danger', 'fails'] };
    const who = (s) => s.name || (s.host ? s.host : 'Unknown server');
    const rows = (sum.sources || []).map((s) => `<tr class="${s.status === 'failing' ? 'table-danger' : s.status === 'partly' ? 'table-warning' : ''}">
        <td data-label="Server"><div class="fw-semibold">${esc(who(s))}</div><div class="small text-muted">${lookup(s.ip)}${s.host && s.name ? ' &middot; ' + esc(s.host) : ''}</div></td>
        <td data-label="Messages">${s.total}</td>
        <td data-label="Result"><span class="badge text-bg-${status[s.status][0]}">${status[s.status][1]}</span>
          <div class="small text-muted">DKIM ${s.dkim_pass}/${s.total} &middot; SPF ${s.spf_pass}/${s.total}</div></td>
        <td data-label="As" class="small">${esc(s.header_from.join(', '))}</td>
        <td data-label="Reported by" class="small">${esc(s.reporters.join(', '))}${s.unverified_only ? ' <span class="badge text-bg-secondary" title="The report email itself could not be verified">unverified</span>' : ''}</td></tr>`).join('');
    const doms = (sum.domains || []).map((d) => `<div class="sec-row"><div class="sec-row-main"><div class="fw-semibold">${esc(d.domain)} <span class="badge text-bg-light border">policy p=${esc((d.policy || {}).p || '?')}</span></div>
        <div class="small text-muted">${d.passed} of ${d.total} message(s) passed</div>${d.advice ? `<div class="small mt-1"><i class="bi bi-lightbulb me-1"></i>${esc(d.advice)}</div>` : ''}</div></div>`).join('');
    const reportList = ((reps && reps.reports) || []).map((r) => `<details class="mb-1"><summary class="small">${esc(new Date(r.end).toLocaleDateString())} &middot; ${esc(r.org_name)} &middot; ${esc(r.domain)} &middot; ${r.total} message(s)${r.failed ? ` <span class="text-danger">(${r.failed} failed)</span>` : ''}${r.verified ? '' : ' <span class="badge text-bg-secondary">unverified</span>'}</summary>
        <div class="table-responsive"><table class="table table-sm small mb-2"><thead><tr><th>Server</th><th>Count</th><th>DKIM</th><th>SPF</th><th>From</th><th>Action taken</th></tr></thead><tbody>
        ${r.records.map((x) => `<tr><td>${esc(x.source_ip)}</td><td>${x.count}</td><td>${esc(x.dkim)}</td><td>${esc(x.spf)}</td><td>${esc(x.header_from)}</td><td>${esc(x.disposition)}</td></tr>`).join('')}</tbody></table></div></details>`).join('');
    body.innerHTML = `
      <div class="card mb-3"><div class="card-body">
        <p class="small text-muted mb-2">Your domains' DMARC record asks Gmail, Microsoft, Yahoo and others to send a daily report about the mail they received
          <b>claiming to be from your domains</b>: which servers sent it and whether it passed the checks. BearerMail reads those reports and files
          them here instead of in someone's inbox. Green rows are your own servers (for example your SMTP provider). <b>Red rows</b> are servers that sent mail
          as your domain and failed: someone faking your address, or a service you use but did not set up (add it to SPF/DKIM).</p>
        <div class="d-flex flex-wrap gap-2 align-items-center">
          <select class="form-select form-select-sm" style="width:auto" data-sec-dmarcdays>${[7, 30, 90, 365].map((d) => `<option value="${d}"${S.dmarcDays === d ? ' selected' : ''}>Last ${d} days</option>`).join('')}</select>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-sec-dmarcimport title="Find reports that already landed in mailboxes and file them here"><i class="bi bi-inbox me-1"></i>Collect reports from mailboxes</button>
          <div class="form-check form-switch ms-2 mb-0"><input class="form-check-input" type="checkbox" id="dm-keep" data-sec-dmarckeep${keep ? ' checked' : ''}>
            <label class="form-check-label small" for="dm-keep">Also keep the report emails in the inbox</label></div>
        </div></div></div>
      ${sum.total ? `<div class="sec-tiles mb-3">
          <div class="sec-tile"><div class="fw-semibold fs-4">${sum.total}</div><div class="small text-muted">messages reported</div></div>
          <div class="sec-tile"><div class="fw-semibold fs-4 ${pct === 100 ? 'text-success' : pct < 90 ? 'text-danger' : ''}">${pct}%</div><div class="small text-muted">passed</div></div>
          <div class="sec-tile"><div class="fw-semibold fs-4 ${sum.failed ? 'text-danger' : ''}">${sum.failed}</div><div class="small text-muted">failed</div></div>
          <div class="sec-tile"><div class="fw-semibold fs-4">${sum.reports}</div><div class="small text-muted">reports from ${esc((sum.reporters || []).map((r) => r.name).join(', ') || '-')}</div></div></div>
        <div class="card mb-3"><div class="card-header"><i class="bi bi-globe me-1"></i>Your domains</div><div class="card-body">${doms}</div></div>
        <div class="card mb-3"><div class="card-header"><i class="bi bi-hdd-network me-1"></i>Servers that sent mail as your domains</div><div class="card-body">
          <div class="table-responsive"><table class="table table-sm align-middle table-stack mb-0"><thead><tr><th>Server</th><th>Messages</th><th>Result</th><th>As</th><th>Reported by</th></tr></thead><tbody>${rows}</tbody></table></div></div></div>
        <div class="card"><div class="card-header"><i class="bi bi-file-earmark-text me-1"></i>Latest reports</div><div class="card-body">${reportList}</div></div>`
      : empty(`No reports in the last ${S.dmarcDays} days. They arrive once a day from each big provider that received mail from your domain, to the address in your DMARC record (rua=mailto:...). If some already landed in a mailbox, press "Collect reports from mailboxes".`)}`;
    body.querySelector('[data-sec-dmarcdays]').onchange = (ev) => { S.dmarcDays = parseInt(ev.target.value, 10); render(); };
    body.querySelector('[data-sec-dmarckeep]').onchange = (ev) => run(async () => { await admin('PATCH', 'settings', { dmarc: { keep_in_inbox: ev.target.checked } }); toast(ev.target.checked ? 'Report emails will also stay in the inbox' : 'Report emails only go here'); });
    body.querySelector('[data-sec-dmarcimport]').onclick = () => run(async () => {
      const r = await call('POST', '/api/admin/dmarc/import', { keep: keep });
      toast(r.imported ? `Filed ${r.imported} report(s)${r.moved_to_trash ? `, moved ${r.moved_to_trash} email(s) to Trash` : ''}` : 'No reports found in the mailboxes');
      render();
    });
  }

  /* ------------------------------ alerts ------------------------------ */
  async function viewAlerts(body) {
    const [s, accounts, aliases] = await Promise.all([run(() => admin('GET', 'settings')), run(() => call('GET', '/api/admin/accounts')), run(() => call('GET', '/api/admin/aliases'))]);
    if (!body.isConnected || !s) return;
    const a = s.alerts || {};
    const senders = ((accounts && accounts.accounts) || []).map((x) => x.address).concat(((aliases && aliases.aliases) || []).filter((x) => x.enabled).map((x) => x.address));
    const check = (key, text) => `<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="al-${key}" data-sec-alert="${key}"${a[key] ? ' checked' : ''}><label class="form-check-label" for="al-${key}">${text}</label></div>`;
    body.innerHTML = `<div class="card"><div class="card-header"><i class="bi bi-bell me-1"></i>Email alerts</div><div class="card-body">
      <p class="small text-muted">BearerMail can email you when something happens. Alerts are sent through your 3rd-party SMTP provider, so set that up first. Send them to an address outside this server (for example your phone's email) so you still get them if this server is the problem.</p>
      <div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="al-enabled" data-sec-alert="enabled"${a.enabled ? ' checked' : ''}><label class="form-check-label fw-semibold" for="al-enabled">Send alerts</label></div>
      <div class="row g-2 mb-3">
        <div class="col-md-6"><label class="form-label small mb-1">Send alerts to</label><input class="form-control form-control-sm" data-sec-alertval="to" value="${esc(a.to)}" placeholder="you@gmail.com"></div>
        <div class="col-md-6"><label class="form-label small mb-1">Send from</label><select class="form-select form-select-sm" data-sec-alertval="from"><option value="">Choose a mailbox or alias...</option>${senders.map((x) => `<option value="${esc(x)}"${x === a.from ? ' selected' : ''}>${esc(x)}</option>`).join('')}</select></div>
      </div>
      ${check('new_web_login', 'Someone signs in to the web app from a new address')}
      ${check('new_imap_login', 'A mail app signs in to a mailbox from a new address')}
      ${check('brute_force', 'Someone keeps guessing passwords (web app or port 993)')}
      ${check('forged_sender', 'A message with a fake sender arrives')}
      <div class="d-flex gap-2 mt-3"><button type="button" class="btn btn-primary btn-sm" data-sec-savealerts>Save</button><button type="button" class="btn btn-outline-secondary btn-sm" data-sec-testalert>Send a test alert</button></div>
    </div></div>`;
  }

  /* ------------------------------ events ------------------------------ */
  function val(sel) { const el = host.querySelector(sel); return el ? el.value.trim() : ''; }

  async function block(ip, reason, hours) {
    await admin('POST', 'blocklist', { ip, reason: reason || '', hours: hours ? Number(hours) : null });
    toast(`${ip} blocked`);
  }

  document.addEventListener('click', (ev) => {
    if (!host || !host.contains(ev.target)) return;
    const t = ev.target.closest('[data-sec-view],[data-sec-refresh],[data-sec-kick],[data-sec-endweb],[data-sec-endothers],[data-sec-block],[data-sec-unblock],[data-sec-addblock],[data-sec-filterip],[data-sec-applyip],[data-sec-clearip],[data-sec-tfasetup],[data-sec-tfacancel],[data-sec-tfaon],[data-sec-tfaoff],[data-sec-newcodes],[data-sec-codesdone],[data-sec-copycodes],[data-sec-untrust],[data-sec-addtrust],[data-sec-savealerts],[data-sec-testalert]');
    if (!t) return;
    const d = t.dataset;
    if (d.secView) { S.view = d.secView; S.setup = null; render(); return; }
    if (d.secRefresh !== undefined) { render(); return; }
    if (d.secKick) return run(async () => { const r = await admin('POST', `imap-sessions/${d.secKick}/kick`, {}); toast(r.message || 'Ending session'); setTimeout(render, 1500); });
    if (d.secEndweb) return run(async () => { await call('DELETE', `/api/security/sessions/${encodeURIComponent(d.secEndweb)}`); toast('Signed out'); render(); });
    if (d.secEndothers !== undefined) return window.showConfirm({ title: 'Sign out everywhere else?', message: 'Every other browser signed in to this web app will be signed out.', okLabel: 'Sign out others', onConfirm: () => run(async () => { const r = await call('POST', '/api/security/sessions/revoke-others', {}); toast(`${r.ended} session(s) signed out`); render(); }) });
    if (d.secBlock) return window.showConfirm({ title: `Block ${d.secBlock}?`, message: 'It will not be able to connect to port 25, port 993 or the web app. You can remove the block later under Activity.', okLabel: 'Block', onConfirm: () => run(async () => { await block(d.secBlock, 'blocked from the Security overview'); render(); }) });
    if (d.secUnblock) return run(async () => { await admin('DELETE', `blocklist/${d.secUnblock}`); toast('Block removed'); render(); });
    if (d.secAddblock !== undefined) return run(async () => { const ip = val('[data-sec-newblock]'); if (!ip) throw new Error('Enter an IP address'); await block(ip, val('[data-sec-newreason]'), val('[data-sec-newhours]')); render(); });
    if (d.secFilterip) { S.filter.ip = d.secFilterip; render(); return; }
    if (d.secApplyip !== undefined) { S.filter.ip = val('[data-sec-ipinput]'); render(); return; }
    if (d.secClearip !== undefined) { S.filter.ip = ''; render(); return; }
    if (d.secTfasetup !== undefined) return run(async () => { S.setup = await call('POST', '/api/security/2fa/setup', {}); render(); });
    if (d.secTfacancel !== undefined) { S.setup = null; render(); return; }
    if (d.secTfaon !== undefined) return run(async () => { const r = await call('POST', '/api/security/2fa/enable', { code: val('[data-sec-code]'), password: val('[data-sec-pw]') }); S.setup = null; S.codes = r.recovery_codes; toast('Two-factor sign-in is on'); render(); });
    if (d.secTfaoff !== undefined) return window.showConfirm({ title: 'Turn off two-factor sign-in?', message: 'Signing in will only need the password again.', okLabel: 'Turn off', onConfirm: () => run(async () => { await call('POST', '/api/security/2fa/disable', { code: val('[data-sec-code]'), password: val('[data-sec-pw]') }); toast('Two-factor sign-in is off'); render(); }) });
    if (d.secNewcodes !== undefined) return run(async () => { const r = await call('POST', '/api/security/2fa/recovery-codes', { password: val('[data-sec-pw]') }); S.codes = r.recovery_codes; render(); });
    if (d.secCodesdone !== undefined) { S.codes = null; render(); return; }
    if (d.secCopycodes !== undefined) { if (window.copyText) window.copyText((S.codes || []).join('\n'), ev); return; }
    if (d.secUntrust) return run(async () => { const list = (window.BearerPrivacy.settings.trusted_senders || []).filter((x) => x !== d.secUntrust); await window.BearerPrivacy.saveSettings({ trusted_senders: list }); render(); });
    if (d.secAddtrust !== undefined) return run(async () => {
      const v = val('[data-sec-newtrust]').toLowerCase();
      if (!/^(@[a-z0-9.-]+\.[a-z]{2,}|[^\s@]+@[a-z0-9.-]+\.[a-z]{2,})$/.test(v)) throw new Error('Enter an address like news@example.com, or @example.com for the whole domain');
      await window.BearerPrivacy.loadSettings(true);
      await window.BearerPrivacy.saveSettings({ trusted_senders: (window.BearerPrivacy.settings.trusted_senders || []).concat([v]) }); render();
    });
    if (d.secSavealerts !== undefined) return run(async () => {
      const alerts = {};
      host.querySelectorAll('[data-sec-alert]').forEach((el) => { alerts[el.dataset.secAlert] = el.checked; });
      host.querySelectorAll('[data-sec-alertval]').forEach((el) => { alerts[el.dataset.secAlertval] = el.value.trim(); });
      if (alerts.enabled && (!alerts.to || !alerts.from)) throw new Error('Choose where to send alerts and which address sends them');
      await admin('PATCH', 'settings', { alerts }); toast('Alert settings saved');
    });
    if (d.secTestalert !== undefined) return run(async () => { const r = await admin('POST', 'test-alert', {}); toast(r.message || 'Test alert sent'); });
  });

  document.addEventListener('change', (ev) => {
    if (!host || !host.contains(ev.target)) return;
    const t = ev.target;
    if (t.dataset.secHours !== undefined) { S.hours = Number(t.value) || 24; render(); return; }
    if (t.dataset.secF) { S.filter[t.dataset.secF] = t.value; render(); return; }
    if (t.dataset.secPrivacy) {
      run(async () => { await window.BearerPrivacy.saveSettings({ [t.dataset.secPrivacy]: t.checked }); toast('Saved'); });
    }
  });
  document.addEventListener('keydown', (ev) => {
    if (!host || !host.contains(ev.target) || ev.key !== 'Enter') return;
    if (ev.target.matches('[data-sec-ipinput]')) { S.filter.ip = ev.target.value.trim(); render(); }
    if (ev.target.matches('[data-sec-code]') && S.setup) host.querySelector('[data-sec-tfaon]').click();
  });

  window.BearerSecurity = { render, open(view) { if (view) S.view = view; } };
})();
