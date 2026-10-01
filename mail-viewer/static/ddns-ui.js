/* Setup > Domains & DNS: "Dynamic IP & Cloudflare" card, and "Apply to Cloudflare" on each domain's DNS records. */
(function () {
  'use strict';
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toast = (m) => (window.showToast ? window.showToast(m, { type: 'success' }) : alert(m));
  const fail = (m) => (window.toastError ? window.toastError(m) : alert(m));
  const D = { data: null, loading: false, open: false };

  async function api(method, path, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res, data = {};
    try { res = await fetch('/api/admin/' + path, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || data.detail || 'Request failed');
    return data;
  }

  const when = (iso) => {
    if (!iso) return 'never';
    const d = new Date(iso); if (isNaN(d)) return iso;
    const mins = Math.round((Date.now() - d) / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins} min ago`;
    if (mins < 1440) return `${Math.round(mins / 60)} h ago`;
    return d.toLocaleString();
  };

  function cardHtml() {
    const s = D.data;
    if (!s) return `<div class="card mb-3"><div class="card-body small text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Loading dynamic IP settings…</div></div>`;
    const state = !s.enabled ? '<span class="badge text-bg-secondary">Off</span>'
      : s.last_error ? '<span class="badge text-bg-warning">Problem</span>' : '<span class="badge text-bg-success">Watching</span>';
    return `<div class="card mb-3 ddns-card"><div class="card-body">
      <div class="d-flex flex-wrap justify-content-between align-items-center gap-2">
        <div><span class="fw-semibold"><i class="bi bi-arrow-repeat me-1"></i>Dynamic IP &amp; Cloudflare</span> ${state}
          <div class="small text-muted">This server's IP: <b>${esc(s.current_ip || 'unknown')}</b>${s.enabled ? ` · checked ${esc(when(s.last_check))}` : ''}${s.last_change ? ` · last changed ${esc(when(s.last_change))}` : ''}</div></div>
        <button class="btn btn-sm btn-outline-secondary" data-ddns-toggle>${D.open ? 'Close' : 'Set up'}</button>
      </div>
      ${s.last_error ? `<div class="alert alert-warning small mt-2 mb-0">${esc(s.last_error)}</div>` : ''}
      ${s.last_result ? `<div class="small mt-1 ${s.last_result.failed ? 'text-danger' : 'text-success'}"><i class="bi ${s.last_result.failed ? 'bi-x-circle' : 'bi-check-circle'} me-1"></i>${esc(s.last_result.summary)} (${esc(when(s.last_result.at))})</div>` : ''}
      ${D.open ? `<hr>
      <p class="small text-muted mb-2">When your internet provider gives you a new IP, BearerMail updates every Cloudflare A record that pointed at the old one and the <code>ip4:</code> in your SPF records,
        and uses the new IP on this page right away (no restart). MX, DKIM and DMARC don't depend on the IP.</p>
      <div class="row g-2 align-items-end">
        <div class="col-md-7"><label class="form-label small mb-1">Cloudflare API token ${s.has_token ? `<span class="badge text-bg-light border">saved ${esc(s.token_hint)}</span>` : ''}</label>
          <div class="input-group input-group-sm"><input type="password" class="form-control" data-ddns-token autocomplete="off" placeholder="${s.has_token ? 'Paste a new token to replace it' : 'Paste your token'}">
          <button class="btn btn-outline-primary" data-ddns-savetoken>Save</button>
          ${s.has_token ? '<button class="btn btn-outline-danger" data-ddns-deltoken title="Remove token"><i class="bi bi-trash"></i></button>' : ''}</div>
          <div class="small text-muted mt-1">Cloudflare → My Profile → API Tokens → Create Token → <b>Edit zone DNS</b> template, Zone Resources: your zones
            (permissions <i>Zone · DNS · Edit</i> and <i>Zone · Zone · Read</i>). Stored encrypted.</div></div>
        <div class="col-md-5">
          <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="ddns-en" data-ddns-enabled ${s.enabled ? 'checked' : ''} ${s.has_token ? '' : 'disabled'}>
            <label class="form-check-label small" for="ddns-en">Watch this server's public IP</label></div>
          <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="ddns-auto" data-ddns-auto ${s.auto_update ? 'checked' : ''}>
            <label class="form-check-label small" for="ddns-auto">Update Cloudflare automatically when it changes</label></div>
          <div class="d-flex align-items-center gap-2 small mt-1">Check every
            <select class="form-select form-select-sm w-auto" data-ddns-interval>${[2, 5, 10, 15, 30, 60].map((m) => `<option value="${m}" ${+s.interval_min === m ? 'selected' : ''}>${m} min</option>`).join('')}</select></div>
        </div>
      </div>
      <div class="d-flex flex-wrap gap-2 mt-3">
        <button class="btn btn-sm btn-outline-primary" data-ddns-preview ${s.has_token ? '' : 'disabled'}><i class="bi bi-search me-1"></i>Check IP &amp; preview</button>
        <button class="btn btn-sm btn-primary" data-ddns-apply ${s.has_token ? '' : 'disabled'}><i class="bi bi-cloud-upload me-1"></i>Update Cloudflare now</button>
      </div>
      <div data-ddns-out class="mt-2"></div>
      <div class="small text-muted mt-2">Reverse DNS (PTR) belongs to your internet provider and can't be changed from here.
        ${s.env_ip && s.current_ip && s.env_ip !== s.current_ip ? `SERVER_IP in .env (${esc(s.env_ip)}) is now only the starting value; you can update it whenever convenient.` : ''}</div>` : ''}
    </div></div>`;
  }

  function changesTable(changes) {
    if (!changes.length) return '<div class="small text-success"><i class="bi bi-check-circle me-1"></i>Nothing to change. Cloudflare already matches.</div>';
    return `<div class="table-responsive"><table class="table table-sm small align-middle mb-1"><thead><tr><th></th><th>Type</th><th>Name</th><th>Now</th><th>Will be</th></tr></thead><tbody>
      ${changes.map((c) => `<tr><td>${c.ok === false ? `<i class="bi bi-x-circle text-danger" title="${esc(c.error)}"></i>` : c.ok ? '<i class="bi bi-check-circle text-success"></i>' : (c.action === 'create' ? '<span class="badge text-bg-success">new</span>' : '<span class="badge text-bg-primary">edit</span>')}</td>
        <td>${esc(c.type)}</td><td class="text-break">${esc(c.name)}${c.why ? `<div class="text-muted">${esc(c.why)}</div>` : ''}${c.proxied ? ' <span class="badge text-bg-warning">proxied</span>' : ''}</td>
        <td class="text-break text-muted">${esc(c.old || '—').slice(0, 120)}</td><td class="text-break">${esc(c.new).slice(0, 160)}${c.error ? `<div class="text-danger">${esc(c.error)}</div>` : ''}</td></tr>`).join('')}
    </tbody></table></div>`;
  }

  async function load() {
    if (D.loading) return;
    D.loading = true;
    try { D.data = await api('GET', 'ddns'); } catch (e) { D.data = null; } finally { D.loading = false; }
  }

  async function mount(el) {
    if (!el) return;
    el.innerHTML = cardHtml();
    if (!D.data) { await load(); const again = document.getElementById('ddns-card'); if (again && D.data) again.innerHTML = cardHtml(); }
  }

  const rerender = () => { const el = document.getElementById('ddns-card'); if (el) el.innerHTML = cardHtml(); };

  async function save(body, msg) {
    try { D.data = await api('PATCH', 'ddns', body); rerender(); if (msg) toast(msg); } catch (e) { fail(e.message); rerender(); }
  }

  async function check(apply, btn) {
    const out = document.querySelector('[data-ddns-out]');
    if (btn) { btn.disabled = true; btn.dataset.label = btn.innerHTML; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Working…'; }
    try {
      const r = await api('POST', `ddns/check?preview=${apply ? 0 : 1}`, {});
      D.data = r.settings; rerender();
      const o = document.querySelector('[data-ddns-out]');
      if (!r.ok) { o.innerHTML = `<div class="alert alert-warning small mb-0">${esc(r.error)}</div>`; return; }
      const plan = r.plan || { changes: [], not_on_cloudflare: [] };
      const rows = r.results || plan.changes;
      o.innerHTML = `<div class="small mb-1">Public IP right now: <b>${esc(r.ip)}</b>${r.changed ? ` (was ${esc(r.previous_ip)})` : ''}</div>
        ${changesTable(rows)}
        ${plan.not_on_cloudflare && plan.not_on_cloudflare.length ? `<div class="small text-muted">Not in a zone this token can edit: ${esc(plan.not_on_cloudflare.join(', '))}</div>` : ''}`;
      if (apply) {
        const bad = rows.filter((x) => x.ok === false).length;
        bad ? fail(`${bad} record(s) could not be updated`) : toast(rows.length ? `Updated ${rows.length} record(s) at Cloudflare` : 'Cloudflare already matches');
      }
    } catch (e) {
      if (out) out.innerHTML = `<div class="alert alert-danger small mb-0">${esc(e.message)}</div>`;
    } finally {
      const b = btn && document.body.contains(btn) ? btn : null;
      if (b) { b.disabled = false; b.innerHTML = b.dataset.label; }
    }
  }

  async function pushDomain(domain) {
    if (!D.data) await load();
    if (!D.data || !D.data.has_token) {
      return window.bmDialog({ title: 'Apply to Cloudflare', html: '<p class="small mb-0">Add a Cloudflare API token first, in the <b>Dynamic IP &amp; Cloudflare</b> card at the top of this page.</p>', buttons: [{ label: 'OK', cls: 'btn-primary' }] });
    }
    let plan;
    try { plan = await api('POST', `domains/${encodeURIComponent(domain)}/cloudflare`, {}); } catch (e) { return fail(e.message); }
    const notes = (plan.notes || []).map((n) => `<div class="alert alert-warning small py-2 mb-2">${esc(n)}</div>`).join('');
    window.bmDialog({
      title: `Cloudflare DNS for ${domain}`, size: 'modal-lg',
      html: `<p class="small text-muted">These records make mail work for <b>${esc(domain)}</b>. Nothing is deleted; your DMARC policy and other SPF senders are kept.</p>${notes}${changesTable(plan.changes)}`,
      buttons: plan.changes.length ? [{ label: 'Cancel' }, {
        label: `Apply ${plan.changes.length} change${plan.changes.length === 1 ? '' : 's'}`, cls: 'btn-primary', onClick: async (body) => {
          const r = await api('POST', `domains/${encodeURIComponent(domain)}/cloudflare?apply=1`, {});
          body.innerHTML = `${(r.notes || []).map((n) => `<div class="alert alert-warning small py-2 mb-2">${esc(n)}</div>`).join('')}${changesTable(r.results || [])}
            <p class="small text-muted mt-2 mb-0">Cloudflare usually answers with the new records within a minute. Press <b>Check DNS now</b> to confirm.</p>`;
          const bad = (r.results || []).filter((x) => !x.ok).length;
          bad ? fail(`${bad} record(s) failed`) : toast('Cloudflare updated');
          document.getElementById('bmDialogFooter').innerHTML = '<button type="button" class="btn btn-primary" data-bs-dismiss="modal">Done</button>';
          return false;
        },
      }] : [{ label: 'Close', cls: 'btn-primary' }],
    });
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target.closest('[data-ddns-toggle],[data-ddns-savetoken],[data-ddns-deltoken],[data-ddns-preview],[data-ddns-apply],[data-cfpush]');
    if (!t) return;
    const d = t.dataset;
    if (d.ddnsToggle !== undefined) { D.open = !D.open; rerender(); return; }
    if (d.ddnsSavetoken !== undefined) {
      const v = document.querySelector('[data-ddns-token]').value.trim();
      if (!v) return fail('Paste the token first');
      t.disabled = true;
      return save({ token: v }, 'Token saved. Cloudflare accepted it.');
    }
    if (d.ddnsDeltoken !== undefined) return save({ token: '' }, 'Token removed; IP watching is off');
    if (d.ddnsPreview !== undefined) return check(false, t);
    if (d.ddnsApply !== undefined) return check(true, t);
    if (d.cfpush) return pushDomain(d.cfpush);
  });
  document.addEventListener('change', (ev) => {
    const t = ev.target;
    if (t.matches('[data-ddns-enabled]')) return save({ enabled: t.checked }, t.checked ? 'Watching the public IP' : 'IP watching off');
    if (t.matches('[data-ddns-auto]')) return save({ auto_update: t.checked });
    if (t.matches('[data-ddns-interval]')) return save({ interval_min: +t.value });
  });

  window.BearerDdns = { mount, pushDomain };
})();
