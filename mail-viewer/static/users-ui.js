/* BearerMail personal accounts (multi-account mode).
 *
 *  Users       (admin)  turn personal accounts on/off, pick the admin, add users and set what each may do
 *  My account  (users)  change password, two-factor sign-in, signed-in browsers
 *  My aliases  (users)  disposable addresses that deliver into their own mailbox
 *  Sending     (users)  which SMTP providers they may send through, and their own if allowed
 */
(function () {
  'use strict';

  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toast = (msg, type) => (window.showToast ? window.showToast(msg, { type: type || 'success' }) : alert(msg));
  const fail = (msg) => (window.toastError ? window.toastError(msg) : alert(msg));
  const ME = window.BM_USER || { role: 'admin', kind: 'single', mode: 'single' };

  async function call(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res; let data = {};
    try { res = await fetch(url, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || 'Request failed');
    return data;
  }
  async function run(fn) { try { return await fn(); } catch (e) { fail(e.message); return null; } }
  const empty = (text) => `<div class="text-muted small py-2">${text}</div>`;
  const ago = (iso) => {
    if (!iso) return 'never';
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  };
  function genPass(n) {
    const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const r = new Uint32Array(n || 16); crypto.getRandomValues(r);
    return Array.from(r, (x) => a[x % a.length]).join('');
  }

  let host = null;
  const U = { users: null, domains: [], openUser: null, setup: null, codes: null, view: null, aliasInfo: null, sending: null, presets: [] };

  function rerender() {
    if (!host || !host.isConnected) return;
    ({ users: renderUsers, account: renderAccount, aliases: () => renderMyAliases(host), smtp: renderMySending })[U.view](host);
  }

  /* ================================================================== Users (admin) */
  const PERMS = [
    ['send', 'Send mail'],
    ['own_smtp', 'Add their own SMTP provider'],
    ['aliases', 'Create disposable aliases'],
    ['external_accounts', 'Add external accounts (Gmail, Outlook...)'],
    ['change_password', 'Change their own password'],
    ['smtp_keys', 'Create their own SMTP keys (for scripts)'],
    ['share_links', 'Make public share links (Drive files, events)'],
  ];

  async function renderUsers(el) {
    host = el; U.view = 'users';
    el.innerHTML = '<div class="text-muted py-3"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div>';
    const [users, domains] = await Promise.all([run(() => call('GET', '/api/users')), run(() => call('GET', '/api/admin/domains'))]);
    if (!users || !el.isConnected) return;
    U.users = users; U.domains = ((domains && domains.domains) || []).filter((d) => d.is_active !== false).map((d) => d.domain);
    const multi = users.mode === 'multi';
    const list = users.users || [];
    const shared = users.shared_smtp_providers || [];

    const modeCard = multi ? `
      <div class="mode-switch mb-4">
        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2">
          <div><div class="fw-semibold"><i class="bi bi-people-fill me-1 text-success"></i>Personal accounts are on</div>
            <div class="small text-muted">Everyone signs in with their own email, mailbox password and (if they set it up) two-factor code.
            ${ME.emergency_admin ? 'Emergency admin sign-in is <b>on</b> (<code>ALLOW_EMERGENCY_ADMIN=1</code>): email <code>admin</code> + ACCESS_PASSWORD.' : 'Emergency admin sign-in is off. To enable it for a lockout, set <code>ALLOW_EMERGENCY_ADMIN=1</code> in .env.'}</div></div>
          <button type="button" class="btn btn-sm btn-outline-danger" data-u-single>Switch back to one shared password</button>
        </div>
      </div>` : `
      <div class="mode-switch mb-4">
        <div class="fw-semibold mb-1"><i class="bi bi-person-lock me-1"></i>Sign-in: one shared password (now)</div>
        <p class="small text-muted mb-3">Turn on <b>personal accounts</b> to give each person their own login, like Gmail: they sign in with their mailbox
          address and its password (the same one their mail apps use), set up their own two-factor, and only see their own mail.
          You choose what each person may do below.</p>
        ${list.length ? `<div class="row g-2 align-items-end">
          <div class="col-md-4"><label class="form-label small mb-1">Admin mailbox (you)</label><select class="form-select form-select-sm" data-u-admin>${list.filter((u) => u.is_active).map((u) => `<option value="${esc(u.address)}">${esc(u.address)}</option>`).join('')}</select></div>
          <div class="col-md-4"><label class="form-label small mb-1">New password for that mailbox <span class="text-muted">(optional, 10+)</span></label>
            <div class="input-group input-group-sm"><input class="form-control" data-u-adminpw autocomplete="new-password" placeholder="keep its current password"><button type="button" class="btn btn-outline-secondary" data-u-gen="[data-u-adminpw]">New</button></div></div>
          <div class="col-md-4"><label class="form-label small mb-1">Current web app password</label><input type="password" class="form-control form-control-sm" data-u-confirm autocomplete="current-password" placeholder="ACCESS_PASSWORD"></div>
          <div class="col-12"><button type="button" class="btn btn-primary btn-sm" data-u-multi><i class="bi bi-people me-1"></i>Turn on personal accounts</button>
            <span class="small text-muted ms-2">Everyone is signed out. Then sign in with the admin mailbox's address and password.</span></div>
        </div>` : '<div class="alert alert-warning small mb-0">Create at least one mailbox first (Mailboxes tab). It becomes the admin account.</div>'}
      </div>`;

    const requiredCard = `<div class="mode-switch mb-4"><div class="form-check form-switch mb-0">
        <input class="form-check-input" type="checkbox" id="u-required" data-u-required${users.app_passwords_required ? ' checked' : ''}>
        <label class="form-check-label" for="u-required"><b>Mail apps must use app passwords (everyone).</b>
          <span class="small text-muted d-block">Thunderbird and phones then need an app password (My account > App passwords) instead of the mailbox password,
          for reading (993) and sending (587/465). The web app is not affected. People with mail apps already set up must switch them over.</span></label></div></div>`;

    const providerChecks = (u) => shared.length ? shared.map((p) => {
      const all = u.permissions.smtp_providers === 'all';
      const on = all || (u.permissions.smtp_providers || []).includes(p.id);
      return `<div class="form-check"><input class="form-check-input" type="checkbox" data-u-prov="${esc(p.id)}"${on ? ' checked' : ''}${u.role === 'admin' ? ' disabled' : ''}><label class="form-check-label small">${esc(p.name)}</label></div>`;
    }).join('') : '<div class="small text-muted">No shared SMTP providers yet (3rd-party SMTP tab).</div>';

    const domainChecks = (u) => {
      const own = u.address.split('@')[1];
      const granted = Array.isArray(u.permissions.domains) ? u.permissions.domains : [];
      if (u.role === 'admin') return '<div class="small text-muted">Admins can use every domain.</div>';
      return `<div class="d-flex flex-wrap gap-3">${U.domains.map((d) => `<div class="form-check"><input class="form-check-input" type="checkbox" data-u-dom="${esc(d)}"${d === own || granted.includes(d) ? ' checked' : ''}${d === own ? ' disabled' : ''}>
        <label class="form-check-label small">${esc(d)}${d === own ? ' <span class="text-muted">(their mailbox)</span>' : ''}</label></div>`).join('')}</div>
        <div class="small text-muted">They only ever see the domains ticked here, never your other domains.</div>`;
    };

    const cards = list.map((u) => {
      const open = U.openUser === u.address;
      const isAdmin = u.role === 'admin';
      return `<div class="user-card${isAdmin ? ' is-admin' : ''}${u.is_active ? '' : ' is-disabled'}" data-u-card="${esc(u.address)}">
        <div class="user-card-head">
          <div class="text-break"><span class="fw-semibold">${esc(u.address)}</span>
            ${isAdmin ? '<span class="badge text-bg-primary ms-1">admin</span>' : ''}
            ${u.is_active ? '' : '<span class="badge text-bg-secondary ms-1">disabled</span>'}
            ${u.two_factor ? '<span class="badge text-bg-success ms-1" title="Two-factor sign-in on"><i class="bi bi-shield-lock"></i> 2FA</span>' : ''}
            <div class="small text-muted">${u.display_name ? esc(u.display_name) + ' &middot; ' : ''}last sign-in ${ago(u.last_login)} &middot; ${u.aliases} alias${u.aliases === 1 ? '' : 'es'}${u.own_smtp_providers ? ` &middot; ${u.own_smtp_providers} own SMTP` : ''}</div></div>
          <div class="d-flex flex-wrap gap-1 justify-content-end">
            ${multi && !isAdmin && u.is_active && u.address !== ME.address ? `<button type="button" class="btn btn-sm btn-outline-dark" data-u-stealth="${esc(u.address)}" title="Open this mailbox read-only without the person being notified"><i class="bi bi-incognito me-1"></i>Stealth sign-in</button>` : ''}
            <button type="button" class="btn btn-sm btn-outline-secondary" data-u-keys="${esc(u.address)}" title="SMTP keys of this mailbox"><i class="bi bi-key"></i></button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-u-toggle="${esc(u.address)}">${open ? 'Close' : 'Manage'}</button>
          </div>
        </div>
        ${open ? `<div class="mt-3">
          <div class="row g-2 mb-2">
            <div class="col-sm-6"><label class="form-label small mb-1">Name shown</label><input class="form-control form-control-sm" data-u-name value="${esc(u.display_name)}"></div>
            <div class="col-sm-6"><label class="form-label small mb-1">Role</label><select class="form-select form-select-sm" data-u-role>
              <option value="user"${isAdmin ? '' : ' selected'}>User (own mailbox only)</option><option value="admin"${isAdmin ? ' selected' : ''}>Admin (everything)</option></select></div>
          </div>
          ${isAdmin ? '<div class="small text-muted mb-2">Admins can do everything; the options below apply to users.</div>' : ''}
          <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" data-u-apponly${u.app_passwords_only ? ' checked' : ''}><label class="form-check-label small">Mail apps: app passwords only (their mailbox password stops working in mail apps)</label></div>
          <div class="user-perms mb-2">${PERMS.map(([k, label]) => `<div class="form-check form-switch"><input class="form-check-input" type="checkbox" data-u-perm="${k}"${u.permissions[k] ? ' checked' : ''}${isAdmin ? ' disabled' : ''}><label class="form-check-label small">${label}</label></div>`).join('')}</div>
          <div class="row g-2 mb-2">
            <div class="col-sm-4"><label class="form-label small mb-1">Storage (MB)</label><input type="number" min="0" class="form-control form-control-sm" data-u-quota value="${u.quota_mb == null ? '' : esc(u.quota_mb)}" placeholder="default ${esc(users.default_quota_mb)}" title="Mail + Drive. Empty = the default, 0 = unlimited"></div>
            <div class="col-sm-4"><label class="form-label small mb-1">Most aliases</label><input type="number" min="0" max="10000" class="form-control form-control-sm" data-u-max value="${esc(u.permissions.max_aliases)}"${isAdmin ? ' disabled' : ''}></div>
            <div class="col-12"><label class="form-label small mb-1">May send through (shared providers)</label>${providerChecks(u)}</div>
            <div class="col-12"><label class="form-label small mb-1">Domains they may use (aliases, share links)</label>${domainChecks(u)}</div>
          </div>
          <div class="d-flex flex-wrap gap-2 mt-2">
            <button type="button" class="btn btn-sm btn-primary" data-u-save="${esc(u.address)}">Save</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-u-resetpw="${esc(u.address)}">Reset password</button>
            ${u.two_factor ? `<button type="button" class="btn btn-sm btn-outline-secondary" data-u-reset2fa="${esc(u.address)}">Turn off their 2FA</button>` : ''}
            <button type="button" class="btn btn-sm btn-outline-${u.is_active ? 'warning' : 'success'}" data-u-active="${esc(u.address)}" data-u-to="${u.is_active ? '0' : '1'}">${u.is_active ? 'Disable' : 'Enable'}</button>
            <button type="button" class="btn btn-sm btn-outline-danger" data-u-delete="${esc(u.address)}"><i class="bi bi-trash"></i></button>
          </div></div>` : ''}
      </div>`;
    }).join('');

    el.innerHTML = `${modeCard}${requiredCard}
      <div class="d-flex justify-content-between align-items-center mb-2"><h6 class="mb-0">Users (${list.length})</h6></div>
      ${cards || empty('No mailboxes yet.')}
      <div class="card mt-3"><div class="card-header"><i class="bi bi-person-plus me-1"></i>Add a user</div><div class="card-body">
        <p class="small text-muted">Creates their mailbox. Give them the address and password; they can change the password and set up two-factor themselves.</p>
        <div class="row g-2 align-items-end">
          <div class="col-md-3"><label class="form-label small mb-1">Name</label><input class="form-control form-control-sm" data-u-newlocal placeholder="jane"></div>
          <div class="col-md-3"><label class="form-label small mb-1">Domain</label><select class="form-select form-select-sm" data-u-newdomain>${U.domains.map((d) => `<option>${esc(d)}</option>`).join('')}</select></div>
          <div class="col-md-3"><label class="form-label small mb-1">Password</label><div class="input-group input-group-sm"><input class="form-control" data-u-newpw value="${genPass(16)}" autocomplete="off"><button type="button" class="btn btn-outline-secondary" data-u-gen="[data-u-newpw]">New</button></div></div>
          <div class="col-md-3"><label class="form-label small mb-1">Display name</label><input class="form-control form-control-sm" data-u-newname placeholder="Jane Doe"></div>
          <div class="col-12"><button type="button" class="btn btn-sm btn-primary" data-u-add><i class="bi bi-person-plus me-1"></i>Create user</button>
            <span class="small text-muted ms-2">New users can send and create aliases; change that with Manage.</span></div>
        </div></div></div>`;
  }

  function cardValues(card) {
    const q = (sel) => card.querySelector(sel);
    const perms = {};
    card.querySelectorAll('[data-u-perm]').forEach((c) => { perms[c.dataset.uPerm] = c.checked; });
    const max = parseInt(q('[data-u-max]').value, 10);
    if (!Number.isNaN(max)) perms.max_aliases = max;
    const doms = [...card.querySelectorAll('[data-u-dom]')];
    if (doms.length) perms.domains = doms.filter((c) => c.checked && !c.disabled).map((c) => c.dataset.uDom);
    const provs = [...card.querySelectorAll('[data-u-prov]')];
    if (provs.length) perms.smtp_providers = provs.every((c) => c.checked) ? 'all' : provs.filter((c) => c.checked).map((c) => c.dataset.uProv);
    const quota = q('[data-u-quota]') ? q('[data-u-quota]').value.trim() : '';
    return { display_name: q('[data-u-name]').value.trim(), role: q('[data-u-role]').value, permissions: perms,
      quota_mb: quota === '' ? null : parseInt(quota, 10),
      app_passwords_only: !!(q('[data-u-apponly]') && q('[data-u-apponly]').checked) };
  }

  /* ================================================================== My account (users) */
  async function renderAccount(el) {
    host = el; U.view = 'account';
    const [me, sess, apps] = await Promise.all([run(() => call('GET', '/api/me')), run(() => call('GET', '/api/me/sessions')),
      run(() => call('GET', '/api/me/app-passwords'))]);
    if (!me || !el.isConnected) return;
    const perms = me.permissions || {};
    let tf;
    if (U.codes) {
      tf = `<div class="alert alert-warning"><b>Save these recovery codes now.</b> Each works once if you lose your phone. They will not be shown again.</div>
        <div class="sec-codes">${U.codes.map((c) => `<code>${esc(c)}</code>`).join('')}</div>
        <div class="d-flex gap-2 mt-2"><button type="button" class="btn btn-sm btn-outline-secondary" data-m-copycodes><i class="bi bi-clipboard me-1"></i>Copy</button><button type="button" class="btn btn-sm btn-primary" data-m-codesdone>I saved them</button></div>`;
    } else if (me.two_factor) {
      tf = `<p><span class="badge text-bg-success">On</span> Signing in needs your password and a code from your app. Recovery codes left: <b>${esc(me.recovery_codes_left)}</b>.</p>
        <div class="row g-2 align-items-end"><div class="col-sm-4"><label class="form-label small mb-1">Your password</label><input type="password" class="form-control form-control-sm" data-m-pw autocomplete="current-password"></div>
        <div class="col-sm-4"><label class="form-label small mb-1">Current code (or a recovery code)</label><input class="form-control form-control-sm" data-m-code inputmode="numeric" autocomplete="one-time-code"></div>
        <div class="col-sm-4 d-flex gap-2"><button type="button" class="btn btn-sm btn-outline-secondary" data-m-newcodes>New recovery codes</button><button type="button" class="btn btn-sm btn-outline-danger" data-m-tfaoff>Turn off</button></div></div>`;
    } else if (U.setup) {
      tf = `<ol class="small ps-3"><li>Open an authenticator app (Google/Microsoft Authenticator, Aegis, 1Password, Bitwarden...).</li><li>Scan this code, or type the key.</li><li>Enter the 6-digit code and your password.</li></ol>
        <div class="sec-qr">${U.setup.qr_svg || ''}</div><div class="small mb-2">Key: <code class="user-select-all">${esc(U.setup.secret.replace(/(.{4})/g, '$1 ').trim())}</code></div>
        <div class="row g-2 align-items-end"><div class="col-sm-4"><label class="form-label small mb-1">6-digit code</label><input class="form-control" data-m-code inputmode="numeric" autocomplete="one-time-code" maxlength="8"></div>
        <div class="col-sm-4"><label class="form-label small mb-1">Your password</label><input type="password" class="form-control" data-m-pw autocomplete="current-password"></div>
        <div class="col-sm-4 d-flex gap-2"><button type="button" class="btn btn-primary" data-m-tfaon>Turn on</button><button type="button" class="btn btn-outline-secondary" data-m-tfacancel>Cancel</button></div></div>`;
    } else {
      tf = `<p><span class="badge text-bg-secondary">Off</span> Anyone who learns your password can sign in to the web app. With two-factor they also need your phone.</p>
        <button type="button" class="btn btn-primary btn-sm" data-m-tfasetup><i class="bi bi-shield-lock me-1"></i>Set up two-factor sign-in</button>`;
    }
    const sessions = ((sess && sess.sessions) || []).map((s) => `<div class="sec-row"><div class="sec-row-main">
        <div class="fw-semibold">${esc(s.device || 'Browser')} ${s.current ? '<span class="badge text-bg-success ms-1">this device</span>' : ''}</div>
        <div class="small text-muted">${esc(s.ip)} &middot; ${esc(s.method)} &middot; active ${ago(s.last_seen)}</div></div>
        ${s.current ? '' : `<button type="button" class="btn btn-sm btn-outline-danger" data-m-endsess="${esc(s.id)}">Sign out</button>`}</div>`).join('');
    el.innerHTML = `
      <div class="d-flex align-items-center gap-3 mb-3"><div class="detail-avatar" style="flex-basis:48px;height:48px">${esc((me.display_name || me.address || '?')[0].toUpperCase())}</div>
        <div><div class="fw-semibold">${esc(me.display_name || me.address)}</div><div class="small text-muted">${esc(me.address)} &middot; ${me.role === 'admin' ? 'admin' : 'user'} &middot; last sign-in ${ago(me.last_login)}</div></div></div>
      <div class="card mb-3"><div class="card-header"><i class="bi bi-key me-1"></i>Password</div><div class="card-body">
        ${perms.change_password ? `<p class="small text-muted">Your web app password. Mail apps that still use it (instead of an app password) need the new one too. Other browsers are signed out.</p>
        <div class="row g-2 align-items-end"><div class="col-sm-4"><label class="form-label small mb-1">Current password</label><input type="password" class="form-control form-control-sm" data-m-cur autocomplete="current-password"></div>
          <div class="col-sm-4"><label class="form-label small mb-1">New password (10+)</label><input type="password" class="form-control form-control-sm" data-m-new autocomplete="new-password"></div>
          <div class="col-sm-4"><label class="form-label small mb-1">New password again</label><input type="password" class="form-control form-control-sm" data-m-new2 autocomplete="new-password"></div>
          <div class="col-12"><button type="button" class="btn btn-sm btn-primary" data-m-changepw>Change password</button></div></div>`
        : '<div class="small text-muted">Ask your admin to change your password.</div>'}</div></div>
      ${appPasswordsCard(me, apps)}
      <div class="card mb-3"><div class="card-header"><i class="bi bi-shield-lock me-1"></i>Two-factor sign-in</div><div class="card-body">${tf}
        <div class="small text-muted mt-2">Two-factor protects the web app. Mail apps (Thunderbird, phones) cannot ask for a code: give them an app password instead (above).</div></div></div>
      <div class="card"><div class="card-header d-flex justify-content-between align-items-center"><span><i class="bi bi-laptop me-1"></i>Signed-in browsers</span>
        ${((sess && sess.sessions) || []).length > 1 ? '<button type="button" class="btn btn-sm btn-outline-danger" data-m-endothers>Sign out all others</button>' : ''}</div>
        <div class="card-body">${sessions || empty('None.')}</div></div>`;
  }

  function appPasswordsCard(me, apps) {
    if (!apps) return '';
    const list = apps.app_passwords || [];
    const fresh = U.newApp ? `<div class="alert alert-success">
        <div class="fw-semibold mb-1"><i class="bi bi-key-fill me-1"></i>App password for "${esc(U.newApp.label)}"</div>
        <div class="small mb-2">Type it in the app's password field, with or without the spaces. It is shown only once.</div>
        <div class="d-flex flex-wrap align-items-center gap-2"><span class="key-secret fs-4 fw-semibold user-select-all">${esc(U.newApp.password)}</span>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-copy="${esc(U.newApp.password)}"><i class="bi bi-clipboard"></i></button></div>
        <div class="small mt-2">Username: <b>${esc(me.address)}</b>. Works for incoming mail (IMAP, port 993) and outgoing mail (SMTP${apps.submission && apps.submission.enabled ? `, port ${esc(apps.submission.starttls_port || apps.submission.tls_port)}` : ''}).</div>
        <button type="button" class="btn btn-sm btn-success mt-2" data-m-appdone>Done</button></div>` : '';
    const rows = list.map((k) => `<div class="key-row${k.revoked ? ' is-revoked' : ''}"><div style="flex:1 1 240px">
        <div class="fw-semibold">${esc(k.label)} ${k.revoked ? '<span class="badge text-bg-secondary">revoked</span>' : ''}</div>
        <div class="small text-muted">created ${esc(new Date(k.created_at).toLocaleDateString())}${k.created_by && k.created_by !== 'self' ? ` by ${esc(k.created_by)}` : ''} &middot; ${k.last_used_at ? `last used ${ago(k.last_used_at)}${k.last_ip ? ` from ${esc(k.last_ip)}` : ''}` : 'never used'}${k.sent_count ? ` &middot; ${k.sent_count} sent` : ''}</div></div>
        ${k.revoked ? '' : `<button type="button" class="btn btn-sm btn-outline-danger" data-m-apprevoke="${esc(k.id)}" data-m-applabel="${esc(k.label)}">Revoke</button>`}</div>`).join('');
    const onlyOn = apps.only || apps.required;
    return `<div class="card mb-3"><div class="card-header"><i class="bi bi-phone me-1"></i>App passwords</div><div class="card-body">
      <p class="small text-muted">Like Gmail: give Thunderbird, your phone's mail app or any other program an <b>app password</b> instead of your real
        password. Your username stays your email address. One app password works for reading and sending. Make one per app or device;
        if a device is lost or an app looks shady, revoke just that one.</p>
      ${fresh}
      <div class="row g-2 align-items-end mb-2"><div class="col-sm-8"><input class="form-control form-control-sm" data-m-applabel-in placeholder="What is it for? e.g. Thunderbird laptop, Pixel phone"></div>
        <div class="col-sm-4"><button type="button" class="btn btn-sm btn-primary w-100" data-m-appadd><i class="bi bi-plus-lg me-1"></i>Create app password</button></div></div>
      ${rows || empty('No app passwords yet.')}
      <div class="form-check form-switch mt-3"><input class="form-check-input" type="checkbox" data-m-apponly${onlyOn ? ' checked' : ''}${apps.required ? ' disabled' : ''} id="m-apponly">
        <label class="form-check-label small" for="m-apponly"><b>Mail apps must use an app password.</b> Your real password then only works here in the web app (with two-factor), so a mail app or a leaked app password can never reveal it.</label></div>
      ${apps.required ? '<div class="small text-muted">Your admin requires app passwords for everyone.</div>' : ''}
      <div class="row g-2 align-items-end mt-1 d-none" data-m-appoff><div class="col-sm-6"><input type="password" class="form-control form-control-sm" data-m-appoff-pw placeholder="Your password, to allow it in mail apps again" autocomplete="current-password"></div>
        <div class="col-sm-3"><button type="button" class="btn btn-sm btn-outline-danger w-100" data-m-appoffok>Allow my password</button></div>
        <div class="col-sm-3"><button type="button" class="btn btn-sm btn-outline-secondary w-100" data-m-appoffcancel>Cancel</button></div></div>
    </div></div>`;
  }

  /* ================================================================== My aliases (users) */
  async function renderMyAliases(el) {
    host = el; U.view = 'aliases';
    const info = await run(() => call('GET', '/api/me/aliases'));
    if (!info || !el.isConnected) return;
    U.aliasInfo = info;
    const items = info.aliases || [];
    const perms = (window.BM_USER || {}).permissions || {};
    const rows = items.map((a) => `<div class="sec-row${a.enabled ? '' : ' text-muted'}"><div class="sec-row-main">
        <div class="fw-semibold text-break">${esc(a.address)} ${a.enabled ? '' : '<span class="badge text-bg-secondary">off</span>'}</div>
        <div class="small text-muted">${esc(a.label || 'no label')} &middot; ${a.received || 0} message${a.received === 1 ? '' : 's'}</div></div>
        <div class="d-flex flex-wrap gap-1 justify-content-end">
          <button type="button" class="btn btn-sm btn-outline-secondary" data-copy="${esc(a.address)}" title="Copy"><i class="bi bi-clipboard"></i></button>
          <button type="button" class="btn btn-sm btn-outline-primary" data-openbox="${esc(a.address)}">Open</button>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-a-toggle="${esc(a.address)}" data-a-to="${a.enabled ? '0' : '1'}">${a.enabled ? 'Disable' : 'Enable'}</button>
          <button type="button" class="btn btn-sm btn-outline-danger" data-a-delete="${esc(a.address)}"><i class="bi bi-trash"></i></button></div></div>`).join('');
    el.innerHTML = `<p class="text-muted">An alias is an extra address like <code>shop-x7k2@${esc(info.domain)}</code>. Mail sent to it lands in your inbox, and you can reply from it. Turn it off when it starts getting spam.</p>
      ${perms.aliases ? (info.can_create ? `<div class="card mb-3" style="background:var(--soft-bg)"><div class="card-body"><div class="row g-2 align-items-end">
        <div class="col-md-4"><label class="form-label small mb-1">Name <span class="text-muted">(blank = random)</span></label><div class="input-group input-group-sm"><input class="form-control" data-a-local placeholder="shop"><span class="input-group-text">@</span>
          ${(info.domains || []).length > 1 ? `<select class="form-select" data-a-domain>${info.domains.map((d) => `<option${d === info.domain ? ' selected' : ''}>${esc(d)}</option>`).join('')}</select>` : `<span class="input-group-text">${esc(info.domain)}</span>`}</div></div>
        <div class="col-md-4"><label class="form-label small mb-1">What is it for?</label><input class="form-control form-control-sm" data-a-label placeholder="Amazon"></div>
        <div class="col-md-4 d-flex gap-2"><button type="button" class="btn btn-sm btn-primary" data-a-add>Create</button><button type="button" class="btn btn-sm btn-outline-primary" data-a-random><i class="bi bi-dice-5 me-1"></i>Random</button></div>
        </div><div class="small text-muted mt-2">${items.length} of ${info.max_aliases} used.</div></div></div>`
        : `<div class="alert alert-secondary small">You have reached your limit of ${info.max_aliases} aliases. Delete one to make a new one.</div>`)
        : '<div class="alert alert-secondary small">Your admin has not allowed creating aliases.</div>'}
      ${rows || empty('No aliases yet.')}`;
  }

  /* ================================================================== Sending (users) */
  async function renderMySending(el) {
    host = el; U.view = 'smtp';
    const [info, presets] = await Promise.all([run(() => call('GET', '/api/me/smtp-providers')), run(() => call('GET', '/api/me/smtp-presets'))]);
    if (!info || !el.isConnected) return;
    U.sending = info; U.presets = (presets && presets.presets) || [];
    const usable = info.usable || [];
    const own = (info.own || []).map((p) => `<div class="sec-row"><div class="sec-row-main"><div class="fw-semibold">${esc(p.name)}</div>
        <div class="small text-muted">${esc(p.host)}:${esc(p.port)} &middot; ${esc(String(p.security).toUpperCase())} &middot; user ${esc(p.username || '-')} &middot; password ${p.has_password ? 'saved' : 'not set'}</div></div>
        <div class="d-flex gap-1"><button type="button" class="btn btn-sm btn-outline-success" data-s-test="${esc(p.id)}">Test</button><button type="button" class="btn btn-sm btn-outline-danger" data-s-delete="${esc(p.id)}"><i class="bi bi-trash"></i></button></div></div>`).join('');
    el.innerHTML = `
      <div class="card mb-3"><div class="card-header"><i class="bi bi-send-check me-1"></i>How your mail is sent</div><div class="card-body">
        ${!info.can_send ? '<div class="alert alert-warning small mb-0">Your admin has not allowed sending mail from this account.</div>'
          : usable.length ? `<p class="small text-muted">Mail you send goes out through ${usable[0].own ? 'your own provider' : 'a provider your admin set up'}. Available to you:</p>
            <ul class="mb-0">${usable.map((p) => `<li>${esc(p.name)} ${p.own ? '<span class="badge text-bg-info">yours</span>' : ''}</li>`).join('')}</ul>`
          : '<div class="alert alert-warning small mb-0">No SMTP provider is available to you yet. Ask your admin.</div>'}
      </div></div>
      ${info.can_add ? `<div class="card"><div class="card-header"><i class="bi bi-plus-circle me-1"></i>Your own SMTP provider</div><div class="card-body">
        <p class="small text-muted">Your admin allows you to send through your own account at Mailjet, SendGrid, Brevo, Gmail SMTP and similar. It is private: nobody else's mail uses it. The password is stored encrypted.</p>
        ${own || empty('None yet.')}
        <div class="row g-2 mt-2 align-items-end">
          <div class="col-md-4"><label class="form-label small mb-1">Provider</label><select class="form-select form-select-sm" data-s-preset>${U.presets.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></div>
          <div class="col-md-4"><label class="form-label small mb-1">SMTP server</label><input class="form-control form-control-sm" data-s-host placeholder="smtp.example.com"></div>
          <div class="col-md-2"><label class="form-label small mb-1">Port</label><input type="number" class="form-control form-control-sm" data-s-port value="587"></div>
          <div class="col-md-2"><label class="form-label small mb-1">Security</label><select class="form-select form-select-sm" data-s-sec><option value="starttls">STARTTLS</option><option value="ssl">SSL/TLS</option></select></div>
          <div class="col-md-4"><label class="form-label small mb-1">Username / API key</label><input class="form-control form-control-sm" data-s-user autocomplete="off"></div>
          <div class="col-md-4"><label class="form-label small mb-1">Password / secret</label><input type="password" class="form-control form-control-sm" data-s-pass autocomplete="new-password"></div>
          <div class="col-md-4"><button type="button" class="btn btn-sm btn-primary w-100" data-s-add>Add provider</button></div>
        </div></div></div>` : ''}`;
    presetFill();
  }

  function presetFill() {
    const sel = host && host.querySelector('[data-s-preset]');
    if (!sel) return;
    const p = U.presets.find((x) => x.id === sel.value);
    if (!p) return;
    host.querySelector('[data-s-host]').value = p.host || '';
    host.querySelector('[data-s-port]').value = p.port || 587;
    host.querySelector('[data-s-sec]').value = p.security === 'ssl' ? 'ssl' : 'starttls';
  }

  /* ================================================================== events */
  const val = (sel) => { const e = host && host.querySelector(sel); return e ? e.value.trim() : ''; };
  const sidebar = () => { if (window.BearerSetup) window.BearerSetup.refreshSidebar(); };

  document.addEventListener('change', (ev) => {
    if (host && host.contains(ev.target) && ev.target.matches('[data-s-preset]')) presetFill();
    if (host && host.contains(ev.target) && ev.target.matches('[data-m-apponly]')) {
      if (ev.target.checked) {
        run(async () => { await call('POST', '/api/me/app-passwords-only', { only: true }); toast('Mail apps now need an app password'); await renderAccount(host); });
      } else {
        ev.target.checked = true;  // stays on until the password is confirmed
        host.querySelector('[data-m-appoff]').classList.remove('d-none');
      }
    }
    if (host && host.contains(ev.target) && ev.target.matches('[data-u-required]')) {
      const on = ev.target.checked;
      run(async () => { await call('POST', '/api/users/app-passwords-required', { required: on }); toast(on ? 'Mail apps now need app passwords for everyone' : 'Each person decides again'); await renderUsers(host); });
    }
  });

  document.addEventListener('click', (ev) => {
    if (!host || !host.contains(ev.target)) return;
    const t = ev.target.closest('button');
    if (!t) return;
    const d = t.dataset;
    const confirm = window.showConfirm;

    // ---- Users (admin)
    if (d.uGen) { const i = host.querySelector(d.uGen); if (i) i.value = genPass(16); return; }
    if (d.uToggle) { U.openUser = U.openUser === d.uToggle ? null : d.uToggle; rerender(); return; }
    if (d.uStealth) { if (window.startStealth) window.startStealth(d.uStealth); return; }
    if (d.uKeys) { if (window.BearerKeys) window.BearerKeys.filter = d.uKeys; if (window.BearerSetup) window.BearerSetup.open('apis'); return; }
    if (d.uMulti !== undefined) {
      const admin = val('[data-u-admin]'); const password = val('[data-u-adminpw]'); const conf = host.querySelector('[data-u-confirm]').value;
      return confirm({ title: 'Turn on personal accounts?', message: `${admin} becomes the admin. Everyone is signed out and must sign in with their own email and mailbox password.${password ? `\n\nThe admin mailbox's new password: ${password}\nWrite it down before continuing.` : '\n\nMake sure you know that mailbox\'s password.'}`,
        okLabel: 'Turn on', onConfirm: () => run(async () => { await call('POST', '/api/users/mode', { mode: 'multi', admin, password, confirm: conf }); window.location.href = '/login'; }) });
    }
    if (d.uSingle !== undefined) {
      return confirm({ title: 'Back to one shared password?', message: 'Personal sign-ins stop working. Everyone who knows ACCESS_PASSWORD gets full admin access again. Everyone is signed out.',
        okLabel: 'Switch back', onConfirm: () => run(async () => { await call('POST', '/api/users/mode', { mode: 'single' }); window.location.href = '/login'; }) });
    }
    if (d.uSave) {
      const card = t.closest('[data-u-card]');
      return run(async () => { await call('PATCH', `/api/users/${encodeURIComponent(d.uSave)}`, cardValues(card)); toast('Saved'); await renderUsers(host); });
    }
    if (d.uResetpw) {
      const pw = window.prompt(`New password for ${d.uResetpw} (8+ characters). Tell them the new password; their mail apps need it too.`, genPass(16));
      if (!pw) return;
      return run(async () => { await call('PATCH', `/api/admin/accounts/${encodeURIComponent(d.uResetpw)}`, { password: pw }); toast('Password changed'); });
    }
    if (d.uReset2fa) return confirm({ title: 'Turn off their two-factor?', message: `${d.uReset2fa} will sign in with just the password until they set it up again. Use this when they lost their phone.`, okLabel: 'Turn off',
      onConfirm: () => run(async () => { await call('PATCH', `/api/users/${encodeURIComponent(d.uReset2fa)}`, { reset_two_factor: true }); toast('Two-factor turned off'); await renderUsers(host); }) });
    if (d.uActive) return run(async () => { await call('PATCH', `/api/users/${encodeURIComponent(d.uActive)}`, { is_active: d.uTo === '1' }); toast(d.uTo === '1' ? 'Enabled' : 'Disabled and signed out'); await renderUsers(host); });
    if (d.uDelete) return confirm({ title: 'Delete this user?', message: `Delete ${d.uDelete}, its mailbox and aliases? Stored mail becomes unreachable. This cannot be undone.`, okLabel: 'Delete',
      onConfirm: () => run(async () => { await call('DELETE', `/api/admin/accounts/${encodeURIComponent(d.uDelete)}`); toast('Deleted'); await renderUsers(host); sidebar(); }) });
    if (d.uAdd !== undefined) return run(async () => {
      const local = val('[data-u-newlocal]').toLowerCase(); const domain = val('[data-u-newdomain]'); const password = val('[data-u-newpw]');
      if (!local) throw new Error('Enter a name for the address');
      const address = `${local}@${domain}`;
      await call('POST', '/api/admin/accounts', { address, password });
      const name = val('[data-u-newname]');
      if (name) await call('PATCH', `/api/users/${encodeURIComponent(address)}`, { display_name: name });
      window.alert(`User created.\n\nEmail: ${address}\nPassword: ${password}\n\nGive these to the person. They can change the password under My account.`);
      U.openUser = address; await renderUsers(host); sidebar();
    });

    // ---- My account
    if (d.mChangepw !== undefined) return run(async () => {
      const cur = host.querySelector('[data-m-cur]').value; const n = host.querySelector('[data-m-new]').value; const n2 = host.querySelector('[data-m-new2]').value;
      if (n !== n2) throw new Error('The two new passwords are different');
      const r = await call('POST', '/api/me/password', { current: cur, new: n }); toast(r.message || 'Password changed'); await renderAccount(host);
    });
    if (d.mTfasetup !== undefined) return run(async () => { U.setup = await call('POST', '/api/me/2fa/setup', {}); await renderAccount(host); });
    if (d.mTfacancel !== undefined) { U.setup = null; renderAccount(host); return; }
    if (d.mTfaon !== undefined) return run(async () => { const r = await call('POST', '/api/me/2fa/enable', { code: val('[data-m-code]'), password: host.querySelector('[data-m-pw]').value }); U.setup = null; U.codes = r.recovery_codes; toast('Two-factor sign-in is on'); await renderAccount(host); });
    if (d.mTfaoff !== undefined) return confirm({ title: 'Turn off two-factor sign-in?', message: 'Signing in will only need your password again.', okLabel: 'Turn off',
      onConfirm: () => run(async () => { await call('POST', '/api/me/2fa/disable', { code: val('[data-m-code]'), password: host.querySelector('[data-m-pw]').value }); toast('Two-factor sign-in is off'); await renderAccount(host); }) });
    if (d.mNewcodes !== undefined) return run(async () => { const r = await call('POST', '/api/me/2fa/recovery-codes', { password: host.querySelector('[data-m-pw]').value }); U.codes = r.recovery_codes; await renderAccount(host); });
    if (d.mCodesdone !== undefined) { U.codes = null; renderAccount(host); return; }
    if (d.mCopycodes !== undefined) { if (window.copyText) window.copyText((U.codes || []).join('\n'), ev); return; }
    if (d.mEndsess) return run(async () => { await call('DELETE', `/api/me/sessions/${encodeURIComponent(d.mEndsess)}`); toast('Signed out'); await renderAccount(host); });
    if (d.mEndothers !== undefined) return run(async () => { const r = await call('POST', '/api/me/sessions/revoke-others', {}); toast(`${r.ended} session(s) signed out`); await renderAccount(host); });

    // ---- App passwords
    if (d.mAppadd !== undefined) return run(async () => {
      const label = val('[data-m-applabel-in]') || 'Mail app';
      const r = await call('POST', '/api/me/app-passwords', { label }); U.newApp = { label, password: r.password }; await renderAccount(host);
    });
    if (d.mAppdone !== undefined) { U.newApp = null; renderAccount(host); return; }
    if (d.mApprevoke) return confirm({ title: 'Revoke app password?', message: `"${d.mApplabel}" stops working at once. Apps using it must be given a new one.`, okLabel: 'Revoke',
      onConfirm: () => run(async () => { await call('POST', `/api/me/app-passwords/${d.mApprevoke}/revoke`, {}); toast('Revoked'); await renderAccount(host); }) });
    if (d.mAppoffok !== undefined) return run(async () => {
      await call('POST', '/api/me/app-passwords-only', { only: false, password: host.querySelector('[data-m-appoff-pw]').value }); toast('Mail apps may use your password again'); await renderAccount(host);
    });
    if (d.mAppoffcancel !== undefined) { renderAccount(host); return; }

    // ---- My aliases
    if (d.aAdd !== undefined || d.aRandom !== undefined) return run(async () => {
      const local = d.aRandom !== undefined ? '' : val('[data-a-local]').toLowerCase();
      const a = await call('POST', '/api/me/aliases', { local, random: !local, label: val('[data-a-label]'), domain: val('[data-a-domain]') || undefined });
      toast(`Created ${a.address}`); if (window.copyText) window.copyText(a.address);
      await refreshMe(); await renderMyAliases(host);
    });
    if (d.aToggle) return run(async () => { await call('PATCH', `/api/me/aliases/${encodeURIComponent(d.aToggle)}`, { enabled: d.aTo === '1' }); await renderMyAliases(host); sidebar(); });
    if (d.aDelete) return confirm({ title: 'Delete alias?', message: `Delete ${d.aDelete}? Mail sent to it will bounce.`, okLabel: 'Delete',
      onConfirm: () => run(async () => { await call('DELETE', `/api/me/aliases/${encodeURIComponent(d.aDelete)}`); await refreshMe(); await renderMyAliases(host); }) });

    // ---- Sending
    if (d.sAdd !== undefined) return run(async () => {
      const preset = val('[data-s-preset]'); const p = U.presets.find((x) => x.id === preset) || {};
      await call('POST', '/api/me/smtp-providers', { name: p.name || 'My SMTP', preset, host: val('[data-s-host]'), port: val('[data-s-port]'), security: val('[data-s-sec]'), username: val('[data-s-user]'), password: host.querySelector('[data-s-pass]').value });
      toast('Provider added. Use Test to check it.'); await renderMySending(host);
    });
    if (d.sTest) return run(async () => {
      const to = window.prompt('Send a test email to (leave blank to only test the login):', ''); if (to === null) return;
      const r = await call('POST', `/api/me/smtp-providers/${encodeURIComponent(d.sTest)}/test`, { to: to.trim() });
      (r.message && /fail|error|could not/i.test(r.message) ? fail : toast)(r.message || 'Done');
    });
    if (d.sDelete) return confirm({ title: 'Delete provider?', message: 'Your mail will use a provider your admin allows instead.', okLabel: 'Delete',
      onConfirm: () => run(async () => { await call('DELETE', `/api/me/smtp-providers/${encodeURIComponent(d.sDelete)}`); await renderMySending(host); }) });
  });

  async function refreshMe() {
    // New aliases change which addresses this person may open and send from.
    try {
      const me = await call('GET', '/api/me');
      if (window.BM_USER) window.BM_USER.addresses = me.addresses;
    } catch (e) { /* ignore */ }
    sidebar();
  }

  window.BearerUsers = { renderUsers, renderAccount, renderMyAliases, renderMySending };
})();
