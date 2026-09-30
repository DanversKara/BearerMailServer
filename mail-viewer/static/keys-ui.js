/* BearerMail SMTP keys ("APIs").
 *
 * A key lets one mailbox send through the admin's SMTP providers (Mailjet, Brevo...) from a mail app
 * (ports 587 / 465) or a script (POST /api/v1/send), without the provider's real secret ever being shown.
 * Revoking a key stops only that key.
 *
 *   renderAdmin(el)  Setup > APIs: every key, create for any mailbox, revoke
 *   renderMine(el)   Connect a mail app: the signed-in person's own keys
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
  const ago = (iso) => {
    if (!iso) return 'never used';
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 60) return 'used just now';
    if (s < 3600) return `used ${Math.round(s / 60)} min ago`;
    if (s < 86400) return `used ${Math.round(s / 3600)} h ago`;
    return 'used ' + new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  };
  const copy = (text) => `<button type="button" class="btn btn-sm btn-outline-secondary" data-copy="${esc(text)}" title="Copy"><i class="bi bi-clipboard"></i></button>`;

  const KIND = {
    app_password: '<span class="badge text-bg-info">app password</span>',
    mailbox_password: '<span class="badge text-bg-light border">mailbox password</span>',
  };
  const K = { filter: '', created: null, admin: null, mine: null, host: null, view: null };

  const portText = (sub) => [sub.starttls_port ? `port <b>${esc(sub.starttls_port)}</b> with <b>STARTTLS</b>` : '', sub.tls_port ? `port <b>${esc(sub.tls_port)}</b> with <b>SSL/TLS</b>` : ''].filter(Boolean).join(' or ');

  /* One-time box shown right after a key is made: the password is never shown again. */
  function createdBox(sub) {
    const c = K.created;
    if (!c) return '';
    const s = sub || c.submission || {};
    const line = (label, value, secret) => `<div class="d-flex align-items-center gap-2 mb-1"><span class="text-muted small" style="min-width:120px">${label}</span>
      <span class="${secret ? 'key-secret fw-semibold' : 'key-secret'}">${esc(value)}</span>${copy(value)}</div>`;
    return `<div class="alert alert-success">
      <div class="fw-semibold mb-2"><i class="bi bi-key-fill me-1"></i>${c.app_password ? 'App password' : 'Key'} created for ${esc((c.key || c.app_password).owner)}. Copy the password now: it is shown only once.</div>
      ${line('Username', c.username)}${line('Password', c.password, true)}
      ${s.host ? line('SMTP server', s.host) : ''}
      <div class="small mt-2">${c.app_password ? 'Works for incoming mail (IMAP, port 993) and outgoing mail. ' : ''}${s.enabled ? `Sending from mail apps: ${portText(s)}, "Normal password". ` : ''}Scripts: <code>POST ${esc(location.origin)}/api/v1/send</code> with <code>Authorization: Bearer USERNAME:PASSWORD</code>.</div>
      <button type="button" class="btn btn-sm btn-success mt-2" data-k-done>I saved it</button></div>`;
  }

  function statusCard(sub) {
    const on = sub && sub.enabled;
    return `<div class="card mb-3"><div class="card-header fw-semibold"><i class="bi bi-hdd-network me-1"></i>Where keys sign in</div><div class="card-body small">
      <div class="mb-2">${on
        ? `<span class="badge text-bg-success">On</span> Mail apps: server <b>${esc(sub.host || 'your mail hostname')}</b>, ${portText(sub)}.`
        : `<span class="badge text-bg-secondary">Off</span> The sending ports for mail apps are not running: ${esc((sub && sub.reason) || 'unknown')}. Scripts can still use the web API below.`}</div>
      <div class="mb-2">Scripts and apps: <code>POST ${esc(location.origin)}/api/v1/send</code> ${copy(location.origin + '/api/v1/send')}</div>
      <details><summary>Example</summary><pre class="small mt-2 mb-0" style="white-space:pre-wrap">curl ${esc(location.origin)}/api/v1/send \\
  -H "Authorization: Bearer USERNAME:PASSWORD" \\
  -H "Content-Type: application/json" \\
  -d '{"from": "you@yourdomain.com", "to": ["friend@example.com"], "subject": "Hello", "text": "Sent with my BearerMail key"}'</pre></details>
      <div class="text-muted mt-2">Each key can only send from its own mailbox and that mailbox's aliases, through the providers that mailbox may use, at most ${esc((sub && sub.hourly_limit) || 100)} messages an hour (unless you set another limit), ${esc((sub && sub.max_recipients) || 50)} recipients per message.</div>
    </div></div>`;
  }

  function keyRow(k, admin) {
    const meta = [admin ? `<b>${esc(k.owner)}</b>` : '', `user <span class="key-secret">${esc(k.username)}</span>`, `password ends in ...${esc(k.hint)}`,
      k.provider ? `via ${esc(k.provider)}` : 'via the default provider', `${k.sent_count} sent`, ago(k.last_used_at) + (k.last_ip ? ` from ${esc(k.last_ip)}` : ''),
      admin && k.hourly_limit ? `${k.hourly_limit}/hour` : ''].filter(Boolean).join(' &middot; ');
    return `<div class="key-row${k.revoked ? ' is-revoked' : ''}"><div class="text-break" style="flex:1 1 280px">
        <div class="fw-semibold">${esc(k.label)} ${KIND[k.kind] || ''} ${k.revoked ? '<span class="badge text-bg-secondary">revoked</span>' : '<span class="badge text-bg-success">active</span>'}</div>
        <div class="small text-muted">${meta}</div>
        <div class="small text-muted">created ${esc(new Date(k.created_at).toLocaleDateString())}${admin ? ` by ${esc(k.created_by)}` : ''}${k.revoked ? ` &middot; revoked by ${esc(k.revoked_by)}` : ''}</div></div>
      <div class="d-flex gap-1">${k.revoked
        ? (admin ? `<button type="button" class="btn btn-sm btn-outline-danger" data-k-delete="${esc(k.id)}" title="Remove from the list"><i class="bi bi-trash"></i></button>` : '')
        : `<button type="button" class="btn btn-sm btn-outline-danger" data-k-revoke="${esc(k.id)}" data-k-label="${esc(k.label)}">Revoke</button>`}</div></div>`;
  }

  /* ================================================================== admin */
  async function renderAdmin(el) {
    K.host = el; K.view = 'admin';
    el.innerHTML = '<div class="text-muted py-3"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div>';
    const [data, accounts] = await Promise.all([
      run(() => call('GET', '/api/admin/relay-keys' + (K.filter ? `?owner=${encodeURIComponent(K.filter)}` : ''))),
      run(() => call('GET', '/api/admin/accounts')),
    ]);
    if (!data || !el.isConnected) return;
    K.admin = data;
    const boxes = ((accounts && accounts.accounts) || []).map((a) => a.address);
    const provs = data.providers || [];
    const keys = data.keys || [];
    const active = keys.filter((k) => !k.revoked).length;
    el.innerHTML = `<p class="text-muted"><b>App passwords</b> (Gmail style: email address + generated password) are what mail apps should use for reading and sending;
      people make their own under My account. <b>SMTP keys</b> (username <code>bm-...</code>) are for scripts and programs that only send.
      Either way BearerMail sends through your provider (${provs.length ? provs.map((p) => esc(p.name)).join(', ') : 'none set up yet'}) for them.
      The provider's real API key and secret are never shown to anyone. If someone misuses one, <b>revoke it</b>: only that one stops, nobody else has to change anything.
      "Mailbox password" rows appear when someone sends from a mail app with their real password; revoking that row stops it.</p>
      ${createdBox(data.submission)}
      ${statusCard(data.submission)}
      <div class="card mb-3" style="background:var(--soft-bg)"><div class="card-body"><div class="fw-semibold mb-2">Create a key</div><div class="row g-2 align-items-end">
        <div class="col-md-12"><div class="btn-group btn-group-sm" role="group">
          <input type="radio" class="btn-check" name="k-kind" id="k-kind-key" value="key"${K.kind !== 'app' ? ' checked' : ''} data-k-kind><label class="btn btn-outline-primary" for="k-kind-key">SMTP key (scripts, sending only)</label>
          <input type="radio" class="btn-check" name="k-kind" id="k-kind-app" value="app"${K.kind === 'app' ? ' checked' : ''} data-k-kind><label class="btn btn-outline-primary" for="k-kind-app">App password (mail apps: email + password, reading and sending)</label></div></div>
        <div class="col-md-4"><label class="form-label small mb-1">For mailbox</label><select class="form-select form-select-sm" data-k-owner>${boxes.map((b) => `<option value="${esc(b)}"${b === K.filter ? ' selected' : ''}>${esc(b)}</option>`).join('')}</select></div>
        <div class="col-md-3"><label class="form-label small mb-1">Label</label><input class="form-control form-control-sm" data-k-label-in placeholder="Thunderbird, phone, website..."></div>
        <div class="col-md-3"><label class="form-label small mb-1">Send through</label><select class="form-select form-select-sm" data-k-prov><option value="">What the mailbox is allowed (default)</option>${provs.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></div>
        <div class="col-md-2"><label class="form-label small mb-1">Per hour</label><input type="number" min="1" max="100000" class="form-control form-control-sm" data-k-limit placeholder="${esc((data.submission || {}).hourly_limit || 100)}"></div>
        <div class="col-12"><button type="button" class="btn btn-sm btn-primary" data-k-create${boxes.length ? '' : ' disabled'}><i class="bi bi-key me-1"></i>Create key</button></div>
      </div></div></div>
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
        <div class="fw-semibold">Keys <span class="text-muted small">(${active} active)</span></div>
        <div class="d-flex gap-2 align-items-center"><select class="form-select form-select-sm" data-k-filter style="max-width:260px"><option value="">All mailboxes</option>${boxes.map((b) => `<option value="${esc(b)}"${b === K.filter ? ' selected' : ''}>${esc(b)}</option>`).join('')}</select>
          ${K.filter && active ? `<button type="button" class="btn btn-sm btn-outline-danger text-nowrap" data-k-revokeall="${esc(K.filter)}">Revoke all</button>` : ''}</div></div>
      <div>${keys.length ? keys.map((k) => keyRow(k, true)).join('') : '<div class="text-muted small py-2">No keys yet.</div>'}</div>`;
  }

  /* ================================================================== the signed-in person's own keys */
  async function renderMine(el) {
    K.host = el; K.view = 'mine';
    const data = await run(() => call('GET', '/api/me/relay-keys'));
    if (!data || !el.isConnected) return;
    K.mine = data;
    const keys = data.keys || [];
    const provs = data.providers || [];
    const readOnly = !!ME.stealth;
    el.innerHTML = `${createdBox(data.submission)}
      <p class="small text-muted mb-2">For scripts and programs that send mail (a website contact form, a backup job): an SMTP key has its own username and password, and only sends. Mail apps should use an app password instead.</p>
      ${!data.can_send ? '<div class="alert alert-warning small">Your admin has not allowed sending mail from this account.</div>'
        : data.can_create && !readOnly ? `<div class="row g-2 align-items-end mb-2">
          <div class="col-md-5"><input class="form-control form-control-sm" data-k-label-in placeholder="Name it: Thunderbird, phone..."></div>
          ${provs.length > 1 ? `<div class="col-md-4"><select class="form-select form-select-sm" data-k-prov><option value="">Default provider</option>${provs.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('')}</select></div>` : ''}
          <div class="col-md-3"><button type="button" class="btn btn-sm btn-primary w-100" data-k-create><i class="bi bi-key me-1"></i>Create key</button></div></div>`
        : !data.self_service ? '<div class="alert alert-secondary small">Your admin creates SMTP keys for you. Ask them for one.</div>'
        : readOnly ? '' : `<div class="alert alert-secondary small">You have ${data.max_keys} active keys, the most allowed. Revoke one to make a new one.</div>`}
      ${keys.length ? keys.map((k) => keyRow(k, false)).join('') : '<div class="text-muted small">No keys yet.</div>'}`;
  }

  function rerender() {
    if (!K.host || !K.host.isConnected) return;
    (K.view === 'admin' ? renderAdmin : renderMine)(K.host);
  }

  document.addEventListener('change', (ev) => {
    if (!K.host || !K.host.contains(ev.target)) return;
    if (ev.target.matches('[data-k-filter]')) { K.filter = ev.target.value; rerender(); }
    if (ev.target.matches('[data-k-kind]')) {
      K.kind = ev.target.value;
      K.host.querySelectorAll('[data-k-prov], [data-k-limit]').forEach((e) => { e.disabled = K.kind === 'app'; });
    }
  });

  document.addEventListener('click', (ev) => {
    if (!K.host || !K.host.contains(ev.target)) return;
    const t = ev.target.closest('button');
    if (!t) return;
    const d = t.dataset;
    const q = (sel) => { const e = K.host.querySelector(sel); return e ? e.value.trim() : ''; };
    if (d.kDone !== undefined) { K.created = null; rerender(); return; }
    if (d.kCreate !== undefined) return run(async () => {
      const body = { label: q('[data-k-label-in]'), provider_id: q('[data-k-prov]') || null };
      if (K.view === 'admin' && K.kind === 'app') {
        K.created = await call('POST', `/api/admin/users/${encodeURIComponent(q('[data-k-owner]'))}/app-passwords`, { label: body.label });
      } else if (K.view === 'admin') {
        body.owner = q('[data-k-owner]');
        const lim = q('[data-k-limit]'); if (lim) body.hourly_limit = parseInt(lim, 10);
        K.created = await call('POST', '/api/admin/relay-keys', body);
      } else {
        K.created = await call('POST', '/api/me/relay-keys', body);
      }
      rerender();
    });
    if (d.kRevoke) return window.showConfirm({ title: 'Revoke this key?', message: `"${d.kLabel}" stops working at once, even in a mail app that is signed in right now. Other keys keep working.`, okLabel: 'Revoke',
      onConfirm: () => run(async () => { await call('POST', K.view === 'admin' ? `/api/admin/relay-keys/${d.kRevoke}/revoke` : `/api/me/relay-keys/${d.kRevoke}/revoke`, {}); toast('Key revoked'); rerender(); }) });
    if (d.kRevokeall) return window.showConfirm({ title: 'Revoke all keys?', message: `Every key of ${d.kRevokeall} stops working at once.`, okLabel: 'Revoke all',
      onConfirm: () => run(async () => { const r = await call('POST', '/api/admin/relay-keys/revoke-all', { owner: d.kRevokeall }); toast(`${r.revoked} key(s) revoked`); rerender(); }) });
    if (d.kDelete) return run(async () => { await call('DELETE', `/api/admin/relay-keys/${d.kDelete}`); rerender(); });
  });

  window.BearerKeys = { renderAdmin, renderMine, set filter(v) { K.filter = v || ''; } };
})();
