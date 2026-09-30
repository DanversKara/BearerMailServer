/* BearerMail Setup screens: domains + DNS, mailboxes, aliases, SMTP providers, connect a mail app. */
(function () {
  'use strict';

  const S = { domains: [], accounts: [], aliases: [], providers: [], presets: [], tab: 'start', dnsOpen: null, dnsData: {}, dnsCheck: {}, editProvider: null };
  const root = () => document.getElementById('setup-root');

  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toast = (msg, type) => (window.showToast ? window.showToast(msg, { type: type || 'success' }) : alert(msg));
  const fail = (msg) => (window.toastError ? window.toastError(msg) : alert(msg));

  async function api(method, path, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res, data = {};
    try { res = await fetch('/api/admin/' + path, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || 'Request failed');
    return data;
  }

  async function run(fn) { try { return await fn(); } catch (e) { fail(e.message); return null; } }

  const ME = window.BM_USER || { role: 'admin', kind: 'single' };
  const isAdmin = () => ME.role === 'admin';
  // With personal accounts, "Your addresses", the mailbox picker and "Send as" only ever list your own
  // mailbox and the aliases that deliver into it, admins included. Other people's mailboxes are reached
  // only through Stealth sign-in (Setup > Users or Mailboxes).
  const multi = () => ME.mode === 'multi';
  const mineBox = (address) => !multi() || (!!ME.address && address === ME.address);
  const ownMailboxes = () => S.accounts.filter((a) => mineBox(a.address));
  const ownAliases = () => S.aliases.filter((a) => a.enabled && (!multi() || (!!ME.address && a.deliver_to === ME.address) || !isAdmin()));

  async function me(method, path, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res, data = {};
    try { res = await fetch('/api/me' + path, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || 'Request failed');
    return data;
  }

  async function load() {
    if (!isAdmin()) {
      // A personal account only loads what belongs to it.
      const al = await me('GET', '/aliases');
      S.accounts = [{ address: ME.address, messages: '', aliases: (al.aliases || []).length }];
      S.aliases = al.aliases || []; S.myAliasInfo = al; S.domains = [{ domain: al.domain }];
      return;
    }
    const [d, a, al, p, pr] = await Promise.all([
      api('GET', 'domains'), api('GET', 'accounts'), api('GET', 'aliases'), api('GET', 'smtp-providers'), api('GET', 'smtp-presets'),
    ]);
    S.domains = (d.domains || []).filter((x) => x.is_active !== false);
    S.accounts = a.accounts || []; S.aliases = al.aliases || []; S.providers = p.providers || []; S.presets = pr.presets || [];
  }

  function copyBtn(text, label) {
    return `<button type="button" class="btn btn-sm btn-outline-secondary copy-btn" data-copy="${esc(text)}"><i class="bi bi-clipboard me-1"></i>${esc(label || 'Copy')}</button>`;
  }
  function badge(kind, text) { return `<span class="badge bg-${kind}">${esc(text)}</span>`; }
  function domainOptions(sel) { return S.domains.map((d) => `<option value="${esc(d.domain)}"${d.domain === sel ? ' selected' : ''}>${esc(d.domain)}</option>`).join(''); }
  function mailboxOptions(sel) { return S.accounts.map((a) => `<option value="${esc(a.address)}"${a.address === sel ? ' selected' : ''}>${esc(a.address)}</option>`).join(''); }
  function providerOptions(sel, blank) {
    return `<option value="">${esc(blank || 'Use the default provider')}</option>` + S.providers.map((p) => `<option value="${esc(p.id)}"${p.id === sel ? ' selected' : ''}>${esc(p.name)}${p.is_default ? ' (default)' : ''}</option>`).join('');
  }
  const emptyNote = (icon, text) => `<div class="text-center text-muted py-4"><i class="bi ${icon}" style="font-size:2rem;opacity:.35"></i><div class="mt-2">${text}</div></div>`;

  /* ------------------------------ shell ------------------------------ */
  const ADMIN_TABS = [
    ['start', 'bi-rocket-takeoff', 'Get started'], ['domains', 'bi-globe', 'Domains & DNS'], ['mailboxes', 'bi-person-badge', 'Mailboxes'],
    ['aliases', 'bi-shuffle', 'Disposable aliases'], ['smtp', 'bi-send-check', '3rd-party SMTP'], ['apis', 'bi-key', 'APIs'], ['connect', 'bi-phone', 'Connect a mail app'], ['users', 'bi-people', 'Users'], ['security', 'bi-shield-lock', 'Security'], ['appearance', 'bi-palette', 'Appearance'],
  ];
  const USER_TABS = [
    ['account', 'bi-person-circle', 'My account'], ['aliases', 'bi-shuffle', 'My aliases'], ['smtp', 'bi-send-check', 'Sending'],
    ['connect', 'bi-phone', 'Connect a mail app'], ['appearance', 'bi-palette', 'Appearance'],
  ];
  function tabs() {
    if (!isAdmin()) return USER_TABS;
    // An admin with a personal account (multi-account mode) also gets "My account" for their own password and 2FA.
    return ME.kind === 'user' ? [['account', 'bi-person-circle', 'My account']].concat(ADMIN_TABS) : ADMIN_TABS;
  }

  function render() {
    const TABS = tabs();
    if (!TABS.some(([id]) => id === S.tab)) S.tab = TABS[0][0];
    const nav = TABS.map(([id, icon, label]) => `<li class="nav-item"><button class="nav-link${S.tab === id ? ' active' : ''}" data-tab="${id}"><i class="bi ${icon} me-1"></i>${label}</button></li>`).join('');
    root().innerHTML = `<div class="card"><div class="card-header setup-nav-wrap"><ul class="nav nav-pills setup-nav gap-1">${nav}</ul></div><div class="card-body" id="setup-body"></div></div>`;
    const body = document.getElementById('setup-body');
    const viewSecurity = (el) => (window.BearerSecurity ? window.BearerSecurity.render(el) : (el.textContent = 'Security page failed to load'));
    const U = window.BearerUsers;
    const views = { connect: viewConnect, appearance: viewAppearance, account: (el) => U.renderAccount(el) };
    if (isAdmin()) Object.assign(views, { start: viewStart, domains: viewDomains, mailboxes: viewMailboxes, aliases: viewAliases, smtp: viewSmtp, security: viewSecurity, users: (el) => U.renderUsers(el), apis: (el) => window.BearerKeys.renderAdmin(el) });
    else Object.assign(views, { aliases: (el) => U.renderMyAliases(el, S), smtp: (el) => U.renderMySending(el) });
    views[S.tab](body);
    const active = root().querySelector('.setup-nav .nav-link.active');
    if (active && active.scrollIntoView) active.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    renderSidebar();
  }

  /* --------------------------- get started --------------------------- */
  function viewStart(el) {
    const steps = [
      [S.domains.length > 0, 'Add your domain', 'The domain you want to receive mail on.', 'domains', 'Add domain'],
      [S.domains.length > 0 && S.dnsAllOk, 'Publish the DNS records (MX, SPF, DKIM, DMARC)', 'Copy the records shown for your domain into your DNS provider, then press Check DNS.', 'domains', 'Show DNS records'],
      [S.accounts.length > 0, 'Create your main mailbox', 'This is the real inbox. Its password is what you use in Thunderbird or Android.', 'mailboxes', 'Create mailbox'],
      [S.providers.length > 0, 'Add a 3rd-party SMTP provider (to send mail)', 'Mailjet, SendGrid, Brevo... needed for sending and replying.', 'smtp', 'Add provider'],
      [S.aliases.length > 0, 'Create a disposable alias', 'Catch-all style addresses that land in your main mailbox and can also send.', 'aliases', 'Create alias'],
      [S.accounts.length > 0, 'Connect your phone or desktop mail app', 'IMAP settings for Thunderbird, FairEmail, K-9...', 'connect', 'Show settings'],
    ];
    el.innerHTML = `<h5 class="mb-1">Welcome to BearerMail</h5>
      <p class="text-muted">Follow these steps once. Mail sent to <b>anything@your-domain</b> is stored on this server; aliases forward into your main mailbox.</p>
      <ol class="list-group list-group-numbered">${steps.map(([done, title, desc, tab, btn]) => `
        <li class="list-group-item d-flex justify-content-between align-items-start gap-3">
          <div class="me-auto"><div class="fw-semibold"><i class="bi ${done ? 'bi-check-circle-fill step-done' : 'bi-circle step-todo'} me-1"></i>${title}</div><div class="small text-muted">${desc}</div></div>
          <button class="btn btn-sm ${done ? 'btn-outline-secondary' : 'btn-primary'}" data-goto="${tab}">${btn}</button>
        </li>`).join('')}</ol>
      <div class="alert alert-info mt-3 mb-0 small"><b>How it fits together:</b> Incoming mail arrives on port 25 (MX record) and is stored per mailbox. <b>Aliases</b> deliver into a mailbox of your choice. <b>Sending</b> goes out through the 3rd-party SMTP provider you set up, using the alias or mailbox as the From address.</div>`;
  }

  /* ---------------------------- domains ---------------------------- */
  function viewDomains(el) {
    if (S.dnsOpen && !S.dnsData[S.dnsOpen]) { const dom = S.dnsOpen; run(() => ensureDns(dom)).then(() => { if (S.tab === 'domains') render(); }); }
    el.innerHTML = `<div class="row g-2 align-items-end mb-3">
        <div class="col-md-8"><label class="form-label">Add a domain</label><input id="sd-new" class="form-control" placeholder="example.com"></div>
        <div class="col-md-4"><button class="btn btn-primary w-100" id="sd-add"><i class="bi bi-plus-lg me-1"></i>Add domain</button></div></div>
      ${S.domains.length ? S.domains.map(domainCard).join('') : emptyNote('bi-globe', 'No domains yet. Add the domain you own above.')}`;
  }

  function domainCard(d) {
    const open = S.dnsOpen === d.domain;
    return `<div class="card mb-3"><div class="card-body">
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-2">
        <div><span class="fw-semibold fs-5">${esc(d.domain)}</span>
          ${d.catch_all_to ? badge('success', 'catch-all on') : ''}</div>
        <div class="d-flex gap-2">
          <button class="btn btn-sm btn-primary" data-dns="${esc(d.domain)}"><i class="bi bi-diagram-3 me-1"></i>${open ? 'Hide' : 'Show'} DNS records</button>
          <button class="btn btn-sm btn-outline-danger" data-deldomain="${esc(d.domain)}"><i class="bi bi-trash"></i></button></div></div>
      <div class="row g-2 mt-2 align-items-end">
        <div class="col-md-8"><label class="form-label small mb-1">Catch-all: deliver mail sent to <i>any</i> unknown address @${esc(d.domain)} into</label>
          <select class="form-select form-select-sm" data-catchall="${esc(d.domain)}"><option value="">Nothing (reject unknown addresses)</option>${mailboxOptions(d.catch_all_to)}</select></div>
        <div class="col-md-4"><label class="form-label small mb-1">Send domain mail via</label>
          <select class="form-select form-select-sm" data-domsend="${esc(d.domain)}">${providerOptions(d.send_via, 'Default provider')}</select></div>
        <div class="col-md-8"><label class="form-label small mb-1">Web address for share links <span class="text-muted">(optional: people with this domain get links like https://mail.${esc(d.domain)}/s/...)</span></label>
          <div class="input-group input-group-sm"><input class="form-control" data-webhost-in="${esc(d.domain)}" value="${esc(d.web_host || '')}" placeholder="https://mail.${esc(d.domain)}">
          <button class="btn btn-outline-primary" data-webhost="${esc(d.domain)}">Save</button></div>
          <div class="small text-muted mt-1">That address must reach this web app (for example a Cloudflare Tunnel hostname). Empty = PUBLIC_URL from .env.</div></div></div>
      ${open ? `<div class="mt-3">${dnsPanel(d.domain)}</div>` : ''}</div></div>`;
  }

  function dnsPanel(domain) {
    const data = S.dnsData[domain];
    if (!data) return '<div class="text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Loading records...</div>';
    const chk = S.dnsCheck[domain] || {};
    const status = (id) => {
      const r = chk[id]; if (!r) return '';
      const map = { ok: ['success', 'Found and correct'], mismatch: ['warning', 'Found but different'], missing: ['danger', 'Not found yet'], error: ['secondary', 'Lookup error'] };
      const [k, t] = map[r.status] || ['secondary', r.status];
      return `${badge(k, t)}${r.found && r.found.length && r.status !== 'ok' ? `<div class="small text-muted mt-1">Currently: ${esc(r.found.join(' | ')).slice(0, 160)}</div>` : ''}`;
    };
    const rows = data.records.map((r) => `<tr>
        <td data-label="Type"><b>${esc(r.type)}</b>${r.priority != null ? `<div class="small text-muted">priority ${r.priority}</div>` : ''}</td>
        <td data-label="Host"><span class="dns-value">${esc(r.name)}</span>${copyBtn(r.name, 'Host')}</td>
        <td data-label="Value"><span class="dns-value">${esc(r.value)}</span>${copyBtn(r.value, 'Value')}</td>
        <td data-label="What it does" class="small">${esc(r.purpose)}${r.note ? `<div class="text-muted">${esc(r.note)}</div>` : ''}</td>
        <td data-label="Status">${status(r.id)}</td></tr>`).join('');
    const extra = (data.provider_records || []).map((r) => `<tr><td><b>${esc(r.type)}</b></td><td><span class="dns-value">${esc(r.name)}</span></td><td><span class="dns-value">${esc(r.value)}</span>${copyBtn(r.value, 'Value')}</td><td class="small text-muted">${esc(r.note)}</td><td><button class="btn btn-sm btn-outline-danger" data-delextra="${esc(domain)}|${esc(r.name)}|${esc(r.value)}"><i class="bi bi-x"></i></button></td></tr>`).join('');
    return `<div class="d-flex flex-wrap justify-content-between align-items-center mb-2 gap-2">
        <div class="small text-muted">Add these at your DNS provider (Cloudflare, Namecheap, GoDaddy...). "Host" is the name field; <code>@</code> means the bare domain. ${data.server_ip ? '' : '<b class="text-danger">Set SERVER_IP in .env so the A record and SPF show your real IP.</b>'}</div>
        <button class="btn btn-sm btn-success" data-checkdns="${esc(domain)}"><i class="bi bi-arrow-repeat me-1"></i>Check DNS now</button></div>
      ${data.mail_host_warning ? `<div class="alert alert-warning small">${esc(data.mail_host_warning)}</div>` : ''}
      <div class="row g-2 align-items-end mb-2"><div class="col-md-8"><label class="form-label small mb-1">Mail server name for this domain (MX and A record)</label>
        <div class="input-group input-group-sm"><input class="form-control" data-mailhost-in="${esc(domain)}" value="${esc(data.mail_host !== data.mail_host_default ? data.mail_host : '')}" placeholder="${esc(data.mail_host_default)} (from .env)">
        <button class="btn btn-outline-primary" data-mailhost="${esc(domain)}">Save</button></div>
        <div class="small text-muted mt-1">Leave empty to use ${esc(data.mail_host_default)}. Use your own, e.g. <code>mail.${esc(domain)}</code>, to keep each domain independent. Mail apps connect to this name, so the TLS certificate (IMAP_CERTS_PATH) must include it.</div></div></div>
      <div class="table-responsive"><table class="table table-sm align-middle table-stack"><thead><tr><th>Type</th><th>Host</th><th>Value</th><th>What it does</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table></div>
      <h6 class="mt-3">Records from your SMTP provider (sending)</h6>
      <p class="small text-muted mb-2">When you add a domain in Mailjet / SendGrid / Brevo they show their own DKIM/SPF/verification records. Paste them here so everything lives in one place.</p>
      ${extra ? `<div class="table-responsive"><table class="table table-sm align-middle"><tbody>${extra}</tbody></table></div>` : ''}
      <div class="row g-2 align-items-end">
        <div class="col-md-2"><select class="form-select form-select-sm" id="px-type"><option>TXT</option><option>CNAME</option><option>MX</option></select></div>
        <div class="col-md-3"><input class="form-control form-control-sm" id="px-name" placeholder="Host, e.g. mailjet._domainkey"></div>
        <div class="col-md-4"><input class="form-control form-control-sm" id="px-value" placeholder="Value"></div>
        <div class="col-md-3"><button class="btn btn-sm btn-outline-primary w-100" data-addextra="${esc(domain)}">Save provider record</button></div></div>`;
  }

  /* ---------------------------- mailboxes ---------------------------- */
  function genPass() {
    const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const r = new Uint32Array(16); crypto.getRandomValues(r);
    return Array.from(r, (n) => a[n % a.length]).join('');
  }

  function viewMailboxes(el) {
    if (!S.domains.length) { el.innerHTML = emptyNote('bi-globe', 'Add a domain first (Domains & DNS tab).'); return; }
    el.innerHTML = `<p class="text-muted">A <b>mailbox</b> is a real inbox with its own password. Use it in the webmail here and in Thunderbird / Android over IMAP.</p>
      <div class="row g-2 align-items-end mb-3">
        <div class="col-md-3"><label class="form-label">Name</label><input id="mb-local" class="form-control" placeholder="you"></div>
        <div class="col-md-3"><label class="form-label">Domain</label><select id="mb-domain" class="form-select">${domainOptions()}</select></div>
        <div class="col-md-4"><label class="form-label">Password (8+ chars)</label><div class="input-group"><input id="mb-pass" class="form-control" type="text" value="${genPass()}" autocomplete="off"><button class="btn btn-outline-secondary" data-genpass="mb-pass" type="button">New</button></div></div>
        <div class="col-md-2"><button class="btn btn-primary w-100" id="mb-add">Create</button></div></div>
      <div class="alert alert-warning small py-2">Save the password now. It is stored hashed and cannot be shown again (you can reset it).</div>
      ${S.accounts.length ? `<div class="table-responsive"><table class="table align-middle table-stack"><thead><tr><th>Mailbox</th><th>Messages</th><th>Aliases</th><th></th></tr></thead><tbody>${S.accounts.map((a) => `<tr>
        <td class="fw-semibold stack-title">${esc(a.address)}${a.is_active === false ? ' ' + badge('secondary', 'disabled') : ''}</td><td data-label="Messages">${a.messages}</td><td data-label="Aliases">${a.aliases}</td>
        <td class="text-end text-nowrap stack-actions">${mineBox(a.address) ? `<button class="btn btn-sm btn-outline-primary" data-openbox="${esc(a.address)}">Open inbox</button>` : `<button class="btn btn-sm btn-outline-dark" data-stealth="${esc(a.address)}" title="Open read-only; not listed under Your addresses and the person is not notified"><i class="bi bi-incognito me-1"></i>Stealth sign-in</button>`}
          <button class="btn btn-sm btn-outline-secondary" data-resetpw="${esc(a.address)}">Reset password</button>
          <button class="btn btn-sm btn-outline-danger" data-delbox="${esc(a.address)}"><i class="bi bi-trash"></i></button></td></tr>`).join('')}</tbody></table></div>` : emptyNote('bi-person-badge', 'No mailboxes yet.')}`;
  }

  /* ----------------------------- aliases ----------------------------- */
  function viewAliases(el) {
    if (!S.domains.length || !S.accounts.length) { el.innerHTML = emptyNote('bi-shuffle', 'Add a domain and a main mailbox first. Aliases deliver into a mailbox.'); return; }
    el.innerHTML = `<p class="text-muted">A <b>disposable alias</b> is an extra address (like <code>shop-x7k2@${esc(S.domains[0].domain)}</code>). Everything sent to it lands in the mailbox you choose, and you can <b>reply from it</b>. Disable or delete it any time.</p>
      <div class="card mb-3" style="background:var(--soft-bg)"><div class="card-body"><div class="row g-2 align-items-end">
        <div class="col-md-3"><label class="form-label">Alias name <span class="text-muted small">(blank = random)</span></label><input id="al-local" class="form-control" placeholder="shop"></div>
        <div class="col-md-3"><label class="form-label">Domain</label><select id="al-domain" class="form-select">${domainOptions()}</select></div>
        <div class="col-md-3"><label class="form-label">Deliver into</label><select id="al-to" class="form-select">${mailboxOptions()}</select></div>
        <div class="col-md-3"><label class="form-label">Label (what is it for?)</label><input id="al-label" class="form-control" placeholder="Amazon"></div>
        <div class="col-md-3"><label class="form-label">Sender name</label><input id="al-name" class="form-control" placeholder="Shown when you reply"></div>
        <div class="col-md-3"><label class="form-label">Send via</label><select id="al-via" class="form-select">${providerOptions('')}</select></div>
        <div class="col-md-6 d-flex gap-2"><button class="btn btn-primary" id="al-add">Create alias</button><button class="btn btn-outline-primary" id="al-rand"><i class="bi bi-dice-5 me-1"></i>Create random</button></div></div></div></div>
      ${S.aliases.length ? `<div class="table-responsive"><table class="table align-middle table-stack"><thead><tr><th>Alias</th><th>Label</th><th>Delivers to</th><th>Send via</th><th>Mail</th><th></th></tr></thead><tbody>${S.aliases.map((a) => `<tr class="${a.enabled ? '' : 'text-muted'}">
        <td class="fw-semibold stack-title">${esc(a.address)} ${copyBtn(a.address, '')}${a.enabled ? '' : ' ' + badge('secondary', 'off')}</td><td data-label="Label">${esc(a.label)}</td><td data-label="Delivers to">${esc(a.deliver_to)}</td>
        <td data-label="Send via"><select class="form-select form-select-sm" data-aliasvia="${esc(a.address)}">${providerOptions(a.send_via)}</select></td><td data-label="Mail">${a.received || 0}</td>
        <td class="text-end text-nowrap stack-actions">${mineBox(a.deliver_to) ? `<button class="btn btn-sm btn-outline-primary" data-openbox="${esc(a.address)}">Open</button>
          <button class="btn btn-sm btn-outline-secondary" data-compose="${esc(a.address)}">Send from</button>` : `<button class="btn btn-sm btn-outline-dark" data-stealth="${esc(a.deliver_to)}" title="Stealth sign-in to ${esc(a.deliver_to)}"><i class="bi bi-incognito"></i></button>`}
          <button class="btn btn-sm btn-outline-secondary" data-togglealias="${esc(a.address)}">${a.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-sm btn-outline-danger" data-delalias="${esc(a.address)}"><i class="bi bi-trash"></i></button></td></tr>`).join('')}</tbody></table></div>` : emptyNote('bi-shuffle', 'No aliases yet.')}`;
  }

  /* ------------------------------ smtp ------------------------------ */
  function viewSmtp(el) {
    const ed = S.editProvider;
    const list = S.providers.length ? S.providers.map((p) => `<div class="card mb-2"><div class="card-body d-flex flex-wrap justify-content-between align-items-center gap-2">
        <div><span class="fw-semibold">${esc(p.name)}</span> ${p.is_default ? badge('primary', 'default') : ''} ${p.sign_dkim ? badge('info', 'DKIM signing') : ''}
          <div class="small text-muted">${esc(p.host)}:${p.port} · ${esc(p.security.toUpperCase())} · user ${esc(p.username || '-')} · password ${p.has_password ? 'saved' : 'not set'}</div></div>
        <div class="text-nowrap"><button class="btn btn-sm btn-outline-success" data-testprov="${esc(p.id)}">Test</button>
          <button class="btn btn-sm btn-outline-secondary" data-editprov="${esc(p.id)}">Edit</button>
          <button class="btn btn-sm btn-outline-danger" data-delprov="${esc(p.id)}"><i class="bi bi-trash"></i></button></div></div></div>`).join('') : emptyNote('bi-send-check', 'No SMTP provider yet. Add one below to be able to send and reply.');
    el.innerHTML = `<p class="text-muted">To <b>send</b> mail, BearerMail relays through a 3rd-party SMTP provider such as Mailjet. Enter its SMTP credentials here. The password is stored encrypted and never shown again.</p>${list}
      <h6 class="mt-4">${ed ? 'Edit provider' : 'Add a provider'}</h6><div id="prov-form">${providerForm(ed)}</div>`;
  }

  function providerForm(ed) {
    const cur = ed ? S.providers.find((p) => p.id === ed) : null;
    const preset = (id) => S.presets.find((p) => p.id === id);
    const selPreset = cur ? cur.preset || 'custom' : 'mailjet';
    const pr = preset(selPreset) || {};
    return `<div class="row g-2">
      <div class="col-md-4"><label class="form-label">Provider</label><select id="pv-preset" class="form-select">${S.presets.map((p) => `<option value="${esc(p.id)}"${p.id === selPreset ? ' selected' : ''}>${esc(p.name)}</option>`).join('')}</select></div>
      <div class="col-md-4"><label class="form-label">Name</label><input id="pv-name" class="form-control" value="${esc(cur ? cur.name : pr.name || '')}"></div>
      <div class="col-md-4"><label class="form-label">SMTP server</label><input id="pv-host" class="form-control" value="${esc(cur ? cur.host : pr.host || '')}" placeholder="smtp.example.com"></div>
      <div class="col-md-2"><label class="form-label">Port</label><input id="pv-port" class="form-control" type="number" value="${cur ? cur.port : pr.port || 587}"></div>
      <div class="col-md-3"><label class="form-label">Security</label><select id="pv-sec" class="form-select">${[['starttls', 'STARTTLS (587)'], ['ssl', 'SSL/TLS (465)'], ['none', 'None (not recommended)']].map(([v, l]) => `<option value="${v}"${(cur ? cur.security : pr.security || 'starttls') === v ? ' selected' : ''}>${l}</option>`).join('')}</select></div>
      <div class="col-md-3"><label class="form-label" id="pv-ulabel">${esc(pr.username_label || 'Username / API key')}</label><input id="pv-user" class="form-control" value="${esc(cur ? cur.username : '')}" autocomplete="off"></div>
      <div class="col-md-4"><label class="form-label" id="pv-plabel">${esc(pr.password_label || 'Password / Secret')}</label><input id="pv-pass" class="form-control" type="password" placeholder="${cur && cur.has_password ? 'Saved, leave blank to keep' : ''}" autocomplete="new-password"></div>
      <div class="col-md-4"><label class="form-label">SPF include <span class="text-muted small">(adds to your SPF record)</span></label><input id="pv-spf" class="form-control" value="${esc(cur ? cur.spf_include : pr.spf_include || '')}"></div>
      <div class="col-md-8 d-flex flex-wrap gap-3 align-items-center pt-4">
        <div class="form-check"><input type="checkbox" class="form-check-input" id="pv-default"${!cur || cur.is_default ? ' checked' : ''}><label class="form-check-label" for="pv-default">Use as default</label></div>
        <div class="form-check"><input type="checkbox" class="form-check-input" id="pv-dkim"${cur && cur.sign_dkim ? ' checked' : ''}><label class="form-check-label" for="pv-dkim">Sign mail with my domain's DKIM key</label></div></div>
      <div class="col-12"><div class="alert alert-secondary small mb-2" id="pv-help">${esc(pr.help || '')}</div></div>
      <div class="col-12"><button class="btn btn-primary" id="pv-save">${cur ? 'Save changes' : 'Add provider'}</button>${cur ? ' <button class="btn btn-outline-secondary" id="pv-cancel">Cancel</button>' : ''}</div></div>`;
  }

  /* ----------------------------- connect ----------------------------- */
  async function viewConnect(el) {
    el.innerHTML = '<div class="text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div>';
    const info = await run(async () => { const r = await fetch('/api/me/connect-info'); const j = await r.json(); if (!r.ok || j.success === false) throw new Error(j.message || 'Could not load'); return j; });
    if (!info) return;
    const i = info.imap;
    const sub = info.submission || {};
    const row = (k, v, copy) => `<tr><th class="text-nowrap" style="width:180px">${k}</th><td><span class="dns-value d-inline-block">${esc(v)}</span> ${copy ? copyBtn(v, '') : ''}</td></tr>`;
    el.innerHTML = `<p class="text-muted">Read your BearerMail inboxes in <b>Thunderbird</b> (desktop) or on <b>Android</b> (Thunderbird for Android, FairEmail, K-9 Mail, Gmail app "Other" account). BearerMail speaks <b>IMAP</b> (JMAP is not supported).</p>
      <div class="row g-3"><div class="col-lg-6"><div class="card h-100"><div class="card-header fw-semibold"><i class="bi bi-inbox me-1"></i>Incoming mail (IMAP)</div><div class="card-body">
        <table class="table table-sm mb-2"><tbody>${row('Server / host', i.host, true)}${row('Port', String(i.port), true)}${row('Security', i.security)}${row('Authentication', i.auth)}${row('Username', 'your full address, e.g. ' + (info.mailboxes[0] || 'you@yourdomain.com'), false)}${row('Password', 'an app password (My account > App passwords), or the mailbox password', false)}</tbody></table>
        <div class="small text-muted">Mailboxes you can log in with:${info.mailboxes.length ? '<ul class="mb-0">' + info.mailboxes.map((m) => `<li>${esc(m)}</li>`).join('') + '</ul>' : ' none yet (create one under Mailboxes).'}</div>
        <div class="alert alert-info small mt-3 mb-0">Mail sent to your <b>aliases</b> shows up in the main mailbox's inbox, so one IMAP login covers everything. The "To" line shows which alias it was sent to.</div></div></div></div>
      <div class="col-lg-6"><div class="card h-100"><div class="card-header fw-semibold"><i class="bi bi-send me-1"></i>Outgoing mail (SMTP)</div><div class="card-body">
        ${sub.enabled ? `<table class="table table-sm mb-2"><tbody>${row('Server / host', sub.host || i.host, true)}${row('Port', String(sub.starttls_port || sub.tls_port || ''), true)}${row('Security', sub.starttls_port ? 'STARTTLS' : 'SSL/TLS')}${sub.starttls_port && sub.tls_port ? row('Or', `port ${sub.tls_port} with SSL/TLS`) : ''}${row('Authentication', 'Normal password')}${row('Username', 'your full address (same as incoming)')}${row('Password', 'the same app password (or the mailbox password)')}</tbody></table>
          <p class="small text-muted mb-2">Scripts and programs can instead use an SMTP key (username <code>bm-...</code>) and the web API <code>POST /api/v1/send</code>.</p>
          <p class="small text-muted mb-2">BearerMail sends it on through ${isAdmin() ? 'your 3rd-party provider' : (info.provider_names || []).length ? esc(info.provider_names.join(' or ')) : 'the provider your admin set up'}; ${isAdmin() ? 'people never see the provider\'s password' : 'you never need the provider\'s own password'}.</p>`
          : `<div class="alert alert-secondary small">${isAdmin() ? `Ports 587/465 for mail apps are off: ${esc(sub.reason || 'unknown')}. See the README, "SMTP keys".` : 'Sending from mail apps is not set up on this server yet. Send from the webmail here (Compose), or ask your admin.'}</div>`}
        ${isAdmin() ? `<div class="d-flex flex-wrap gap-2 align-items-center mb-2"><button class="btn btn-sm btn-primary" data-goto="apis"><i class="bi bi-key me-1"></i>Manage SMTP keys</button><span class="small text-muted">Give each person their own key.</span></div>
          ${info.smtp_providers.length ? `<details class="small"><summary>Your providers (admins only)</summary>${info.smtp_providers.map((p) => `<table class="table table-sm mb-2 mt-2"><tbody>${row('Provider', p.name + (p.is_default ? ' (default)' : ''))}${row('Server', p.host, true)}${row('Port', String(p.port), true)}${row('Security', p.security)}${row('Username', p.username || '-', true)}</tbody></table>`).join('')}</details>` : '<div class="text-muted small">No provider added yet. See the 3rd-party SMTP tab.</div>'}`
          : '<div class="alert alert-info small py-2"><b>Tip:</b> make an <a href="#" data-goto="account">app password</a> for each mail app instead of typing your real password.</div><div class="fw-semibold small mb-1">SMTP keys for scripts</div><div id="connect-keys"></div>'}
      </div></div></div></div>
      <div class="card mt-3"><div class="card-header fw-semibold"><i class="bi bi-list-check me-1"></i>Step by step</div><div class="card-body"><div class="row"><div class="col-md-6">
        <h6>Thunderbird (desktop)</h6><ol class="small"><li>Account Settings, then Account Actions, then Add Mail Account.</li><li>Enter your address and password, then choose <b>Configure manually</b>.</li><li>Incoming: <b>IMAP</b>, host <code>${esc(i.host)}</code>, port <code>${i.port}</code>, <b>SSL/TLS</b>, authentication <b>Normal password</b>, username = full address.</li><li>Outgoing: ${sub.enabled ? `host <code>${esc(sub.host || i.host)}</code>, port <code>${esc(sub.starttls_port || sub.tls_port)}</code>, <b>${sub.starttls_port ? 'STARTTLS' : 'SSL/TLS'}</b>, <b>Normal password</b>, with your SMTP key's username and password` : 'send from the webmail here'}.</li></ol></div>
        <div class="col-md-6"><h6>Android</h6><ol class="small"><li>Install <b>Thunderbird for Android</b>, <b>FairEmail</b> or <b>K-9 Mail</b>.</li><li>Add account, choose manual / IMAP setup.</li><li>Use the same incoming settings as above (IMAP, port ${i.port}, SSL/TLS).</li>${sub.enabled ? `<li>Outgoing (SMTP): the same host, port ${esc(sub.starttls_port || sub.tls_port)} with ${sub.starttls_port ? 'STARTTLS' : 'SSL/TLS'}, and an SMTP key (make a separate key for the phone).</li>` : ''}<li>Requires a valid TLS certificate for <code>${esc(i.host)}</code> on the server (see the README, "TLS certificates").</li></ol></div></div></div></div>`;
    const keysBox = el.querySelector('#connect-keys');
    if (keysBox && window.BearerKeys) window.BearerKeys.renderMine(keysBox);
  }

  /* --------------------------- left sidebar --------------------------- */
  /* ---------------------------- appearance --------------------------- */
  const LOGO_SLOTS = [
    ['app_light', 'Signed-in header, light themes'], ['app_dark', 'Signed-in header, dark themes'],
    ['login_light', 'Login page, light themes'], ['login_dark', 'Login page, dark themes'],
  ];

  function notifyBlock() {
    const N = window.BearerNotify;
    if (!N) return '';
    const perm = N.permission();
    let state;
    if (perm === 'unsupported') state = '<span class="text-muted">Not available here. Notifications need HTTPS and a browser that supports them.</span>';
    else if (perm === 'denied') state = '<span class="text-danger">Blocked in this browser. Allow notifications for this site in the browser\'s site settings, then reload.</span>';
    else state = N.enabled() ? '<span class="badge bg-success">On</span>' : '<span class="badge bg-secondary">Off</span>';
    return `<h5 class="mb-1">New mail alerts</h5>
      <p class="text-muted small">Shows a pop-up notification and plays a short sound when new mail arrives in the mailbox you have open. Works while BearerMail is open in a browser tab (it checks every 20 seconds). Set per browser.</p>
      <div class="d-flex flex-wrap gap-2 align-items-center mb-4">${state}
        ${perm === 'denied' || perm === 'unsupported' ? '' : (N.enabled()
          ? '<button class="btn btn-outline-secondary btn-sm" data-notify="off">Turn off</button>'
          : '<button class="btn btn-primary btn-sm" data-notify="on">Turn on notifications</button>')}
        ${N.enabled() ? '<button class="btn btn-outline-primary btn-sm" data-notify="test"><i class="bi bi-bell me-1"></i>Send a test</button>' : ''}
        <div class="form-check form-switch ms-2 mb-0"><input class="form-check-input" type="checkbox" id="notify-sound" data-notify-sound="1"${N.soundOn() ? ' checked' : ''}><label class="form-check-label small" for="notify-sound">Play a sound</label></div>
      </div>`;
  }

  async function viewAppearance(el) {
    const cur = window.BearerTheme ? window.BearerTheme.get() : 'mint';
    const themes = window.BearerTheme ? window.BearerTheme.list : [];
    let have = {};
    if (isAdmin()) { try { have = (await (await fetch('/api/branding')).json()).slots || {}; } catch (e) { /* ignore */ } }
    const v = Date.now();
    const slot = ([id, label]) => `<div class="col-md-6"><div class="p-3 rounded h-100" style="background:var(--soft-bg)">
        <div class="fw-semibold small mb-2">${esc(label)}</div>
        ${have[id] ? `<div class="mb-2 p-2 rounded text-center" style="background:${id.endsWith('_dark') ? '#1b1216' : '#ffffff'}"><img src="/branding/logo/${id}?t=${v}" alt="" style="max-height:48px;max-width:100%;object-fit:contain"></div>` : '<div class="small text-muted mb-2">Not set. Uses the closest other logo, or the text name.</div>'}
        <div class="d-flex gap-2"><input type="file" class="form-control form-control-sm" data-logo-file="${id}" accept="image/png,image/jpeg,image/webp,image/gif,image/svg+xml">
          <button class="btn btn-primary btn-sm" data-logo-upload="${id}"><i class="bi bi-upload"></i></button>
          ${have[id] ? `<button class="btn btn-outline-danger btn-sm" data-logo-remove="${id}"><i class="bi bi-trash"></i></button>` : ''}</div></div></div>`;
    el.innerHTML = `<h5 class="mb-1">Theme</h5><p class="text-muted small">Saved in this browser. The login page has its own colour dots in the top right corner.</p>
      <div class="theme-grid mb-4">${themes.map((t) => `<button type="button" class="theme-card${t.id === cur ? ' active' : ''}" data-theme-pick="${esc(t.id)}">
        <div class="theme-swatch" style="background:linear-gradient(90deg, ${esc(t.swatch[0])} 0 60%, ${esc(t.swatch[1])} 60% 100%)"></div>
        <div class="small fw-semibold">${esc(t.name)}</div></button>`).join('')}</div>
      ${isAdmin() ? `<h5 class="mb-1">Logos</h5>
      <p class="text-muted small">A logo replaces the "BearerMail" text. Upload one for each place and theme so it never looks off: for example a light-coloured logo for dark themes. Any slot you leave empty falls back to the closest logo you did upload. PNG, JPG, WebP, GIF or SVG, up to 512 KB; about 40 to 50 px tall works best. Shared by everyone who signs in.</p>
      <div class="row g-3 mb-4">${LOGO_SLOTS.map(slot).join('')}</div>` : ''}
      ${notifyBlock()}`;
  }

  async function uploadLogo(id) {
    const f = document.querySelector(`[data-logo-file="${id}"]`);
    if (!f || !f.files[0]) return fail('Choose an image file first.');
    if (f.files[0].size > 512 * 1024) return fail('Logo is too large (max 512 KB).');
    const fd = new FormData(); fd.append('logo', f.files[0]);
    const res = await fetch('/api/branding/logo/' + id, { method: 'POST', body: fd });
    let data = {}; try { data = await res.json(); } catch (e) { /* ignore */ }
    if (!res.ok || data.success === false) return fail(data.message || 'Upload failed');
    location.reload();
  }
  async function removeLogo(id) {
    const res = await fetch('/api/branding/logo/' + id, { method: 'DELETE' });
    if (!res.ok) return fail('Could not remove the logo');
    location.reload();
  }
  async function notifyAction(kind) {
    const N = window.BearerNotify;
    if (kind === 'on') { await N.enable(); N.test(); }
    else if (kind === 'off') N.disable();
    else if (kind === 'test') N.test();
    render();
  }

  function renderSidebar() {
    renderChooser();
    const box = document.getElementById('mine-list'); if (!box) return;
    const boxes = ownMailboxes(), aliases = ownAliases();
    if (!boxes.length && !aliases.length) {
      box.innerHTML = multi() && !ME.address
        ? 'The emergency admin has no mailbox. Use <a href="#" data-goto="users">Stealth sign-in</a> to look into one.'
        : 'Nothing yet. Open <a href="#" data-goto="mailboxes">Setup</a> to create a mailbox.';
      return;
    }
    const chips = (list, icon) => list.map((a) => `<span class="badge rounded-pill text-bg-light border addr-chip me-1 mb-1" data-openbox="${esc(a)}"><i class="bi ${icon} me-1"></i>${esc(a)}</span>`).join('');
    box.innerHTML = `${chips(boxes.map((a) => a.address), 'bi-person-badge')}${chips(aliases.map((a) => a.address), 'bi-shuffle')}`;
  }

  /* Big buttons in the (empty) message list, so a phone user can open a mailbox with one tap. */
  function renderChooser() {
    const box = document.getElementById('mailbox-chooser'); if (!box) return;
    const boxes = ownMailboxes();
    if (!boxes.length) {
      box.innerHTML = multi() && !ME.address
        ? '<button type="button" data-goto="users"><i class="bi bi-incognito"></i><span>Stealth sign-in to a mailbox</span></button>'
        : '<button type="button" data-goto="mailboxes"><i class="bi bi-plus-circle"></i><span>Create your first mailbox</span></button>';
      return;
    }
    const item = (addr, icon, note) => `<button type="button" data-openbox="${esc(addr)}"><i class="bi ${icon}"></i><span class="text-truncate">${esc(addr)}</span>${note ? `<span class="ms-auto small text-muted">${esc(note)}</span>` : ''}</button>`;
    box.innerHTML = boxes.map((a) => item(a.address, 'bi-person-badge', a.messages ? `${a.messages}` : '')).join('')
      + ownAliases().slice(0, 6).map((a) => item(a.address, 'bi-shuffle', a.label || 'alias')).join('');
  }

  function openInbox(address) {
    const [local, domain] = address.split('@');
    if (typeof switchTab === 'function') switchTab('inbox');
    const sel = document.getElementById('inbox-domain');
    if (sel && ![...sel.options].some((o) => o.value === domain)) sel.add(new Option(domain, domain));
    if (sel) { sel.value = domain; sel.dispatchEvent(new Event('change')); }
    document.getElementById('inbox-prefix').value = local;
    if (typeof queryInbox === 'function') queryInbox();
  }

  /* ---------------------------- compose bits ---------------------------- */
  function fillSenderPicker() {
    const sel = document.getElementById('compose-from-pick'); if (!sel) return;
    const opts = ownMailboxes().map((a) => a.address).concat(ownAliases().map((a) => a.address));
    sel.innerHTML = '<option value="">Choose a mailbox or alias...</option>' + opts.map((a) => `<option value="${esc(a)}">${esc(a)}</option>`).join('');
    const cur = document.getElementById('compose-from-prefix').value + '@' + document.getElementById('compose-from-domain').value;
    if (opts.includes(cur)) sel.value = cur;
  }
  function pickSender(address) {
    if (!address) return;
    const [local, domain] = address.split('@');
    const dsel = document.getElementById('compose-from-domain');
    if (![...dsel.options].some((o) => o.value === domain)) dsel.add(new Option(domain, domain));
    dsel.value = domain; document.getElementById('compose-from-prefix').value = local;
  }

  /* ------------------------------ events ------------------------------ */
  async function refresh(keep) { await run(load); render(); if (keep) keep(); }

  async function ensureDns(domain) {
    if (!S.dnsData[domain]) S.dnsData[domain] = await api('GET', `domains/${encodeURIComponent(domain)}/dns`);
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-tab],[data-goto],[data-copy],[data-openbox],[data-stealth],button[id],[data-dns],[data-checkdns],[data-deldomain],[data-addextra],[data-delextra],[data-genpass],[data-resetpw],[data-delbox],[data-delalias],[data-togglealias],[data-compose],[data-testprov],[data-editprov],[data-delprov],[data-theme-pick],[data-logo-upload],[data-logo-remove],[data-notify],[data-webhost],[data-mailhost]');
    if (!t) return;
    const d = t.dataset;
    if (d.tab || d.goto) { ev.preventDefault(); S.tab = d.tab || d.goto; if (typeof switchTab === 'function' && d.goto) switchTab('setup'); render(); return; }
    if (d.themePick) { window.BearerTheme.set(d.themePick); render(); return; }
    if (d.copy !== undefined) { if (window.copyText) window.copyText(d.copy, ev); return; }
    if (d.openbox) { ev.preventDefault(); openInbox(d.openbox); return; }
    if (d.stealth) { ev.preventDefault(); if (window.startStealth) window.startStealth(d.stealth); return; }
    if (d.genpass) { document.getElementById(d.genpass).value = genPass(); return; }
    if (d.compose) { if (typeof openCompose === 'function') { openCompose(); pickSender(d.compose); const p = document.getElementById('compose-from-pick'); if (p) p.value = d.compose; } return; }
    if (!root() || !root().contains(t)) return;
    if (d.logoUpload) return run(() => uploadLogo(d.logoUpload));
    if (d.logoRemove) return run(() => removeLogo(d.logoRemove));
    if (d.notify) return run(() => notifyAction(d.notify));

    if (d.mailhost) return run(async () => {
      const v = document.querySelector(`[data-mailhost-in="${d.mailhost}"]`).value.trim();
      await api('PATCH', `domains/${encodeURIComponent(d.mailhost)}`, { mail_host: v });
      delete S.dnsData[d.mailhost]; delete S.dnsCheck[d.mailhost]; await ensureDns(d.mailhost); render();
      toast('Saved. Update the MX and A records at your DNS provider, then press Check DNS now.');
    });
    if (d.webhost) return run(async () => {
      const v = document.querySelector(`[data-webhost-in="${d.webhost}"]`).value.trim();
      const r = await api('PATCH', `domains/${encodeURIComponent(d.webhost)}`, { web_host: v });
      toast(r.web_host ? `Share links for ${d.webhost} use ${r.web_host}` : 'Share links use PUBLIC_URL'); await refresh();
    });
    if (d.dns) return run(async () => { S.dnsOpen = S.dnsOpen === d.dns ? null : d.dns; render(); if (S.dnsOpen) { await ensureDns(d.dns); render(); } });
    if (d.checkdns) return run(async () => {
      t.disabled = true; t.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Checking...';
      const res = await api('POST', `domains/${encodeURIComponent(d.checkdns)}/dns/check`, {});
      S.dnsCheck[d.checkdns] = Object.fromEntries(res.results.map((r) => [r.id, r])); S.dnsAllOk = res.all_ok; render();
      toast(res.all_ok ? 'All records look correct' : 'Some records are missing or different. DNS can take a few minutes to update.', res.all_ok ? 'success' : undefined);
    });
    if (d.deldomain) return window.showConfirm({ title: 'Remove domain?', message: `Stop receiving mail for ${d.deldomain}? Existing mail is kept.`, okLabel: 'Remove', onConfirm: () => run(async () => { const r = await fetch('/api/domains/' + encodeURIComponent(d.deldomain), { method: 'DELETE' }); if (!r.ok) throw new Error('Could not remove domain'); if (window.loadDomains) window.loadDomains(); await refresh(); }) });
    if (d.addextra) return run(async () => {
      const dom = d.addextra, name = document.getElementById('px-name').value.trim(), value = document.getElementById('px-value').value.trim();
      if (!name || !value) throw new Error('Enter the host and value from your provider');
      const cur = (S.dnsData[dom].provider_records || []).concat([{ type: document.getElementById('px-type').value, name, value, note: '' }]);
      await api('PATCH', `domains/${encodeURIComponent(dom)}`, { extra_dns_records: cur }); delete S.dnsData[dom]; await ensureDns(dom); render();
    });
    if (d.delextra) return run(async () => {
      const [dom, name, value] = d.delextra.split('|');
      const cur = (S.dnsData[dom].provider_records || []).filter((r) => !(r.name === name && r.value === value));
      await api('PATCH', `domains/${encodeURIComponent(dom)}`, { extra_dns_records: cur }); delete S.dnsData[dom]; await ensureDns(dom); render();
    });
    if (d.resetpw) { const pw = window.prompt(`New password for ${d.resetpw} (8+ characters):`, genPass()); if (!pw) return; return run(async () => { await api('PATCH', `accounts/${encodeURIComponent(d.resetpw)}`, { password: pw }); toast('Password changed'); }); }
    if (d.delbox) return window.showConfirm({ title: 'Delete mailbox?', message: `Delete ${d.delbox} and its aliases? Stored mail becomes unreachable.`, okLabel: 'Delete', onConfirm: () => run(async () => { await api('DELETE', `accounts/${encodeURIComponent(d.delbox)}`); await refresh(); }) });
    if (d.delalias) return window.showConfirm({ title: 'Delete alias?', message: `Delete ${d.delalias}? Mail sent to it will bounce.`, okLabel: 'Delete', onConfirm: () => run(async () => { await api('DELETE', `aliases/${encodeURIComponent(d.delalias)}`); await refresh(); }) });
    if (d.togglealias) return run(async () => { const a = S.aliases.find((x) => x.address === d.togglealias); await api('PATCH', `aliases/${encodeURIComponent(a.address)}`, { enabled: !a.enabled }); await refresh(); });
    if (d.delprov) return window.showConfirm({ title: 'Delete provider?', message: 'Aliases using it will fall back to the default provider.', okLabel: 'Delete', onConfirm: () => run(async () => { await api('DELETE', `smtp-providers/${d.delprov}`); S.editProvider = null; await refresh(); }) });
    if (d.editprov) { S.editProvider = d.editprov; render(); return; }
    if (d.testprov) return run(async () => {
      const to = window.prompt('Send a test email to (leave blank to only test the login):', ''); if (to === null) return;
      let from_email = ''; if (to) { from_email = window.prompt('Send it from which address (must be verified at your provider)?', (S.accounts[0] || {}).address || ''); if (!from_email) return; }
      t.disabled = true; const res = await api('POST', `smtp-providers/${d.testprov}/test`, { to: to.trim(), from_email: (from_email || '').trim() }); t.disabled = false;
      (res.success ? toast : fail)(res.message);
    });

    switch (t.id) {
      case 'sd-add': return run(async () => {
        const v = document.getElementById('sd-new').value.trim().toLowerCase(); if (!v) throw new Error('Enter a domain');
        const r = await fetch('/api/domains', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ domain: v }) }); const j = await r.json();
        if (!j.success) throw new Error(j.message || 'Could not add domain');
        if (window.loadDomains) window.loadDomains(); S.dnsOpen = v; await refresh(); await ensureDns(v); render(); toast('Domain added. Now publish the DNS records below.');
      });
      case 'mb-add': return run(async () => {
        const local = document.getElementById('mb-local').value.trim().toLowerCase(); if (!local) throw new Error('Enter a name');
        const address = `${local}@${document.getElementById('mb-domain').value}`, password = document.getElementById('mb-pass').value;
        await api('POST', 'accounts', { address, password }); await refresh();
        window.alert(`Mailbox created.\n\nAddress: ${address}\nPassword: ${password}\n\nSave the password now.`);
      });
      case 'al-add': case 'al-rand': return run(async () => {
        const local = document.getElementById('al-local').value.trim().toLowerCase(), random = t.id === 'al-rand' || !local;
        const body = { random, prefix: local, address: random ? '' : `${local}@${document.getElementById('al-domain').value}`, domain: document.getElementById('al-domain').value,
          deliver_to: document.getElementById('al-to').value, label: document.getElementById('al-label').value, from_name: document.getElementById('al-name').value, send_via: document.getElementById('al-via').value || null };
        const a = await api('POST', 'aliases', body); await refresh(); toast(`Created ${a.address}`);
        if (window.copyText) window.copyText(a.address);
      });
      case 'pv-save': return run(async () => {
        const body = { name: document.getElementById('pv-name').value, preset: document.getElementById('pv-preset').value, host: document.getElementById('pv-host').value, port: document.getElementById('pv-port').value,
          security: document.getElementById('pv-sec').value, username: document.getElementById('pv-user').value, spf_include: document.getElementById('pv-spf').value,
          is_default: document.getElementById('pv-default').checked, sign_dkim: document.getElementById('pv-dkim').checked };
        const pw = document.getElementById('pv-pass').value; if (pw) body.password = pw;
        if (S.editProvider) await api('PATCH', `smtp-providers/${S.editProvider}`, body); else await api('POST', 'smtp-providers', body);
        S.editProvider = null; S.dnsData = {}; await refresh(); toast('Provider saved. Use Test to check the login.');
      });
      case 'pv-cancel': S.editProvider = null; render(); return;
    }
  });

  document.addEventListener('change', (ev) => {
    const t = ev.target; if (!root() || !root().contains(t)) return;
    if (t.dataset.catchall !== undefined) return run(async () => { await api('PATCH', `domains/${encodeURIComponent(t.dataset.catchall)}`, { catch_all_to: t.value || null }); await refresh(); toast(t.value ? 'Catch-all enabled' : 'Catch-all disabled'); });
    if (t.dataset.domsend !== undefined) return run(async () => { await api('PATCH', `domains/${encodeURIComponent(t.dataset.domsend)}`, { send_via: t.value || null }); S.dnsData = {}; toast('Saved'); });
    if (t.dataset.aliasvia !== undefined) return run(async () => { await api('PATCH', `aliases/${encodeURIComponent(t.dataset.aliasvia)}`, { send_via: t.value || null }); toast('Saved'); });
    if (t.id === 'pv-preset') {
      const p = S.presets.find((x) => x.id === t.value); if (!p) return;
      document.getElementById('pv-name').value = p.name; document.getElementById('pv-host').value = p.host; document.getElementById('pv-port').value = p.port;
      document.getElementById('pv-sec').value = p.security; document.getElementById('pv-spf').value = p.spf_include;
      document.getElementById('pv-ulabel').textContent = p.username_label; document.getElementById('pv-plabel').textContent = p.password_label; document.getElementById('pv-help').textContent = p.help;
    }
  });

  window.BearerSetup = {
    async open(tab) {
      if (tab) S.tab = tab;
      root().innerHTML = '<div class="text-center text-muted py-5"><span class="spinner-border me-2"></span>Loading...</div>';
      await run(load); render();
    },
    fillSenderPicker, pickSender, reload: refresh, get state() { return S; },
    async refreshSidebar() { await run(load); renderSidebar(); },
  };

  document.addEventListener('change', (ev) => {
    if (ev.target && ev.target.dataset && ev.target.dataset.notifySound && window.BearerNotify) window.BearerNotify.setSound(ev.target.checked);
  });

  document.addEventListener('DOMContentLoaded', () => { window.BearerSetup.refreshSidebar(); });
})();
