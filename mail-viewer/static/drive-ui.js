/* BearerMail Drive: folders, uploads (with progress), downloads, previews, share links, and the Compose picker. */
(function () {
  'use strict';

  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toast = (msg, type) => window.showToast(msg, { type: type || 'success' });
  const fail = (msg) => window.toastError(msg);
  const size = (n) => window._formatSize(n) || '0 KB';
  const root = () => document.getElementById('drive-root');
  const D = { folder: '/', data: null, view: 'files', uploads: [], shares: null };

  async function call(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res; let data = {};
    try { res = await fetch(url, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || 'Request failed');
    return data;
  }
  const q = (params) => window.driveQuery(params);
  const body = (extra) => window.drivePayload(extra);

  const ICONS = [
    [/^image\//, 'bi-file-earmark-image'], [/pdf/, 'bi-file-earmark-pdf'], [/word|document/, 'bi-file-earmark-word'],
    [/sheet|excel|csv/, 'bi-file-earmark-spreadsheet'], [/presentation|powerpoint/, 'bi-file-earmark-slides'],
    [/zip|compressed|tar|7z|rar/, 'bi-file-earmark-zip'], [/^audio\//, 'bi-file-earmark-music'], [/^video\//, 'bi-file-earmark-play'],
    [/rfc822/, 'bi-envelope-paper'], [/calendar/, 'bi-calendar-event'], [/^text\//, 'bi-file-earmark-text'],
  ];
  const iconFor = (ctype) => (ICONS.find(([rx]) => rx.test(ctype || '')) || [null, 'bi-file-earmark'])[1];
  const PREVIEW = /^(image\/(png|jpeg|gif|webp)|application\/pdf|text\/plain)/;
  const when = (iso) => iso ? new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' }) : '';

  /* ------------------------------------------------------------ main view */
  async function open(folder) {
    if (folder) D.folder = folder;
    const el = root();
    if (!window.driveReady()) {
      el.innerHTML = `<div class="card"><div class="card-body text-center text-muted py-5"><i class="bi bi-hdd" style="font-size:2.4rem;opacity:.4"></i>
        <p class="mt-2 mb-0">Open a mailbox first. Each mailbox has its own Drive.</p></div></div>`;
      return;
    }
    if (D.view === 'links') return renderLinks();
    if (!D.data) el.innerHTML = '<div class="card"><div class="card-body text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div></div>';
    try {
      D.data = await call('GET', '/api/drive' + q({ folder: D.folder }));
    } catch (e) {
      el.innerHTML = `<div class="card"><div class="card-body text-danger">${esc(e.message)}</div></div>`;
      return;
    }
    render();
  }

  function render() {
    const d = D.data;
    const s = d.storage;
    const readOnly = !!(window.BM_USER && BM_USER.stealth);
    const crumbs = d.breadcrumbs.map((c, i) => `${i ? '<i class="bi bi-chevron-right small text-muted"></i>' : ''}<button type="button" data-d-folder="${esc(c.path)}">${i ? '' : '<i class="bi bi-hdd me-1"></i>'}${esc(c.name)}</button>`).join('');
    const folders = d.folders.map((f) => `<button type="button" class="drive-folder" data-d-folder="${esc(f.path)}"><i class="bi bi-folder-fill"></i><span class="text-truncate">${esc(f.name)}</span></button>`).join('');
    const files = d.files.map((f) => `<div class="drive-file">
        <i class="bi ${iconFor(f.content_type)} file-icon"></i>
        <div class="file-main"><div class="file-name" title="${esc(f.name)}">${esc(f.name)} ${f.shared ? '<i class="bi bi-link-45deg text-primary" title="Has a share link"></i>' : ''}</div>
          <div class="small text-muted">${size(f.size)} &middot; ${when(f.updated_at)}${f.source !== 'upload' ? ` &middot; from ${f.source === 'message' ? 'an email' : 'an attachment'}` : ''}</div></div>
        <div class="d-flex gap-1 flex-shrink-0">
          ${PREVIEW.test(f.content_type) ? `<a class="btn btn-sm btn-outline-secondary" href="/api/drive/files/${f.id}/content${q({ inline: 1 })}" target="_blank" rel="noopener" title="Open"><i class="bi bi-eye"></i></a>` : ''}
          <a class="btn btn-sm btn-outline-secondary" href="/api/drive/files/${f.id}/content${q()}" title="Download"><i class="bi bi-download"></i></a>
          <div class="dropdown"><button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="dropdown" aria-label="More"><i class="bi bi-three-dots"></i></button>
            <ul class="dropdown-menu dropdown-menu-end">
              ${readOnly ? '' : `<li><button class="dropdown-item" type="button" data-d-share="${f.id}"><i class="bi bi-link-45deg me-2"></i>Share link</button></li>
              <li><button class="dropdown-item" type="button" data-d-email="${f.id}"><i class="bi bi-envelope me-2"></i>Email as attachment</button></li>
              <li><button class="dropdown-item" type="button" data-d-rename="${f.id}"><i class="bi bi-pencil me-2"></i>Rename</button></li>
              <li><button class="dropdown-item" type="button" data-d-move="${f.id}"><i class="bi bi-folder-symlink me-2"></i>Move</button></li>
              <li><hr class="dropdown-divider"></li>
              <li><button class="dropdown-item text-danger" type="button" data-d-delete="${f.id}"><i class="bi bi-trash me-2"></i>Delete</button></li>`}
            </ul></div></div></div>`).join('');
    const uploads = D.uploads.map((u) => `<div class="drive-progress mb-1"><div class="d-flex justify-content-between"><span class="text-truncate">${esc(u.name)}</span><span>${u.error ? `<span class="text-danger">${esc(u.error)}</span>` : u.done ? 'done' : u.pct + '%'}</span></div>
        <div class="progress" style="height:4px"><div class="progress-bar${u.error ? ' bg-danger' : ''}" style="width:${u.error ? 100 : u.pct}%"></div></div></div>`).join('');
    const pct = s.unlimited ? 0 : Math.min(100, s.percent);
    root().innerHTML = `<div class="card" id="drive-card"><div class="card-header drive-toolbar">
        <div class="drive-crumbs">${crumbs}</div>
        <div class="d-flex flex-wrap gap-2">
          ${readOnly ? '' : `<button type="button" class="btn btn-sm btn-primary" data-d-upload><i class="bi bi-upload me-1"></i>Upload</button>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-d-newfolder><i class="bi bi-folder-plus me-1"></i>New folder</button>`}
          <button type="button" class="btn btn-sm btn-outline-secondary" data-d-links><i class="bi bi-link-45deg me-1"></i>Shared links</button>
          ${d.folder !== '/' && !readOnly ? `<div class="dropdown"><button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="dropdown" aria-label="Folder actions"><i class="bi bi-three-dots"></i></button>
            <ul class="dropdown-menu dropdown-menu-end"><li><button class="dropdown-item" type="button" data-d-renamefolder><i class="bi bi-pencil me-2"></i>Rename folder</button></li>
            <li><button class="dropdown-item text-danger" type="button" data-d-delfolder><i class="bi bi-trash me-2"></i>Delete folder</button></li></ul></div>` : ''}
        </div></div>
      <div class="card-body">
        <div class="d-flex flex-wrap align-items-center gap-2 small text-muted mb-3">
          <div class="progress flex-grow-1" style="height:6px;max-width:260px"><div class="progress-bar${pct >= 95 ? ' bg-danger' : pct >= 80 ? ' bg-warning' : ''}" style="width:${s.unlimited ? 0 : Math.max(pct, 1)}%"></div></div>
          <span>${s.unlimited ? `${size(s.used)} used (no limit)` : `${size(s.used)} of ${size(s.quota)} used`} &middot; mail ${size(s.mail)}, Drive ${size(s.drive)}</span>
          <span>&middot; files up to ${esc(d.max_file_mb)} MB</span></div>
        ${uploads}
        ${folders ? `<div class="drive-grid mb-3">${folders}</div>` : ''}
        ${files || (folders ? '' : `<div class="text-center text-muted py-5"><i class="bi bi-cloud-arrow-up" style="font-size:2.4rem;opacity:.4"></i>
          <p class="mt-2 mb-0">${readOnly ? 'This folder is empty.' : 'Drop files here, or press Upload. In an email you can also use ... &gt; Save to Drive.'}</p></div>`)}
      </div></div>
      <input type="file" multiple class="d-none" id="drive-file-input">`;
  }

  /* ------------------------------------------------------------ uploads */
  function uploadFiles(fileList) {
    const folder = D.folder;
    Array.from(fileList || []).forEach((file) => {
      const u = { name: file.name, pct: 0, done: false, error: '' };
      D.uploads.push(u);
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/api/drive/upload' + q({ folder, name: file.name }));
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      xhr.setRequestHeader('X-File-Type', file.type || 'application/octet-stream');
      xhr.upload.onprogress = (ev) => { if (ev.lengthComputable) { u.pct = Math.round(ev.loaded * 100 / ev.total); if (D.data && D.view === 'files') render(); } };
      xhr.onload = () => {
        let res = {};
        try { res = JSON.parse(xhr.responseText); } catch (e) { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300 && res.success) { u.done = true; u.pct = 100; } else { u.error = res.message || `Upload failed (${xhr.status})`; }
        finishUpload(u);
      };
      xhr.onerror = () => { u.error = 'Connection lost'; finishUpload(u); };
      xhr.send(file);
    });
    if (D.data) render();
  }

  function finishUpload(u) {
    if (u.error) fail(`${u.name}: ${u.error}`);
    setTimeout(() => { D.uploads = D.uploads.filter((x) => x !== u); if (D.view === 'files') render(); }, u.error ? 6000 : 1500);
    open();
    if (window.refreshStorage) window.refreshStorage();
  }

  /* ------------------------------------------------------------ share links */
  function shareDialog(kind, targetId, name, afterCreate) {
    window.bmDialog({
      title: `Share "${name}"`,
      html: `<p class="small text-muted">Anyone with the link can ${kind === 'file' ? 'download the file' : 'see the event and add it to their calendar'}. Add a password for private things.</p>
        <label class="form-label small mb-1">Password (optional)</label><input type="text" class="form-control mb-2" data-s-pw autocomplete="off" placeholder="No password">
        <label class="form-label small mb-1">Link works for</label>
        <select class="form-select" data-s-exp><option value="">Until I turn it off</option><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option><option value="365">1 year</option></select>
        <div data-s-hosts></div>
        <div data-s-result class="mt-3"></div>`,
      onShown: async (b) => {
        try {
          const h = await call('GET', '/api/drive/share-hosts' + q());
          if ((h.hosts || []).length > 1) {
            b.querySelector('[data-s-hosts]').innerHTML = `<label class="form-label small mb-1 mt-2">Link address</label><select class="form-select" data-s-domain>${h.hosts.map((x) => `<option value="${esc(x.domain)}"${x.domain === h.default ? ' selected' : ''}>${esc(x.web_host)}/s/...</option>`).join('')}</select>`;
          }
        } catch (e) { /* only the default address */ }
      },
      buttons: [{ label: 'Close' }, { label: 'Create link', cls: 'btn-primary', onClick: async (b) => {
        const pw = b.querySelector('[data-s-pw]').value.trim();
        const exp = b.querySelector('[data-s-exp]').value;
        const dsel = b.querySelector('[data-s-domain]');
        const r = await call('POST', '/api/drive/shares', body({ kind, target_id: targetId, password: pw || null, expires_days: exp ? parseInt(exp, 10) : null, domain: dsel ? dsel.value : null }));
        b.querySelector('[data-s-result]').innerHTML = `<div class="alert alert-success mb-0"><div class="small fw-semibold mb-1">Link ready${pw ? ' (password protected)' : ''}</div>
          <div class="input-group input-group-sm"><input class="form-control" value="${esc(r.url)}" readonly><button type="button" class="btn btn-outline-secondary" data-copy="${esc(r.url)}"><i class="bi bi-clipboard"></i></button></div>
          <button type="button" class="btn btn-sm btn-primary mt-2" data-s-email><i class="bi bi-envelope me-1"></i>Email this link</button></div>
          ${/:\/\/(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|your-|example\./.test(r.url) ? `<div class="alert alert-warning small mt-2 mb-0">This link uses a local or example address, so people outside your network cannot open it. Your admin should set <code>PUBLIC_URL=https://your-real-web-address</code> in <code>.env</code> and run <code>docker compose up -d mail-viewer</code>.</div>` : ''}`;
        b.querySelector('[data-s-email]').onclick = () => { window.bmAfterClose(() => emailLink(r.url, name, pw)); bootstrap.Modal.getInstance(document.getElementById('bmDialog')).hide(); };
        if (afterCreate) afterCreate(r);
        return false;  // keep the dialog open to show the link
      } }],
    });
  }

  function emailLink(url, name, pw) {
    window.openCompose();
    const s = document.getElementById('compose-subject');
    if (!s.value) s.value = name;
    setTimeout(() => {
      window.composeInsertLink(url, name);
      if (pw) toast('Send the link password separately, for example by text message.');
    }, 150);
  }

  async function renderLinks() {
    const el = root();
    el.innerHTML = '<div class="card"><div class="card-body text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div></div>';
    let data;
    try { data = await call('GET', '/api/drive/shares' + q()); } catch (e) { el.innerHTML = `<div class="card"><div class="card-body text-danger">${esc(e.message)}</div></div>`; return; }
    const rows = (data.shares || []).map((s) => `<div class="drive-file">
        <i class="bi ${s.kind === 'file' ? 'bi-file-earmark' : 'bi-calendar-event'} file-icon"></i>
        <div class="file-main"><div class="file-name">${esc(s.name || '(deleted)')}</div>
          <div class="small text-muted">${s.has_password ? '<i class="bi bi-lock me-1"></i>password &middot; ' : ''}${s.expired ? '<span class="text-danger">expired</span>' : s.expires_at ? 'until ' + esc(when(s.expires_at)) : 'no expiry'}
            &middot; ${s.views} view${s.views === 1 ? '' : 's'}, ${s.downloads} download${s.downloads === 1 ? '' : 's'}</div>
          <div class="small"><a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.url)}</a></div></div>
        <div class="d-flex gap-1"><button type="button" class="btn btn-sm btn-outline-secondary" data-copy="${esc(s.url)}" title="Copy"><i class="bi bi-clipboard"></i></button>
          <button type="button" class="btn btn-sm btn-outline-danger" data-d-unshare="${esc(s.code)}">Turn off</button></div></div>`).join('');
    el.innerHTML = `<div class="card"><div class="card-header drive-toolbar"><div class="fw-semibold"><i class="bi bi-link-45deg me-1"></i>Shared links</div>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-d-files><i class="bi bi-arrow-left me-1"></i>Back to files</button></div>
      <div class="card-body">${rows || '<div class="text-muted">No share links yet. Use ... &gt; Share link on a file, or Share on a calendar event.</div>'}</div></div>`;
  }

  /* ------------------------------------------------------------ Compose picker */
  async function pickForCompose() {
    if (!window.driveReady()) return fail('Open a mailbox first');
    const dlg = window.bmDialog({
      title: 'From Drive', size: 'modal-lg',
      html: `<input type="search" class="form-control mb-2" placeholder="Search your files" data-p-search>
        <div class="pick-list" data-p-list><div class="text-muted small"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div></div>
        <div class="small text-muted mt-2">Attach sends a copy of the file. Link inserts a share link into the message instead (better for big files).</div>`,
      buttons: [{ label: 'Done', cls: 'btn-primary' }],
    });
    const list = dlg.body.querySelector('[data-p-list]');
    const load = async (term) => {
      try {
        const r = await call('GET', '/api/drive/all' + q({ q: term || '' }));
        list.innerHTML = (r.files || []).map((f) => `<div class="drive-file"><i class="bi ${iconFor(f.content_type)} file-icon"></i>
            <div class="file-main"><div class="file-name">${esc(f.name)}</div><div class="small text-muted">${esc(f.folder)} &middot; ${size(f.size)}</div></div>
            <div class="d-flex gap-1"><button type="button" class="btn btn-sm btn-outline-primary" data-p-attach="${f.id}">Attach</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" data-p-link="${f.id}">Link</button></div></div>`).join('') || '<div class="text-muted small">No files found.</div>';
        list.querySelectorAll('[data-p-attach]').forEach((b) => { b.onclick = () => { const f = r.files.find((x) => x.id === b.dataset.pAttach); window.composeAddDriveFile(f); b.textContent = 'Attached'; b.disabled = true; }; });
        list.querySelectorAll('[data-p-link]').forEach((b) => { b.onclick = async () => {
          const f = r.files.find((x) => x.id === b.dataset.pLink);
          try { const s = await call('POST', '/api/drive/shares', body({ kind: 'file', target_id: f.id, expires_days: 30 })); window.composeInsertLink(s.url, f.name); b.textContent = 'Linked'; b.disabled = true; } catch (e) { fail(e.message); }
        }; });
      } catch (e) { list.innerHTML = `<div class="text-danger small">${esc(e.message)}</div>`; }
    };
    let t = null;
    dlg.body.querySelector('[data-p-search]').oninput = (ev) => { clearTimeout(t); t = setTimeout(() => load(ev.target.value), 250); };
    load('');
  }

  /* ------------------------------------------------------------ events */
  document.addEventListener('click', (ev) => {
    const el = root();
    if (!el || !el.contains(ev.target)) return;
    const t = ev.target.closest('button');
    if (!t) return;
    const d = t.dataset;
    const file = (id) => (D.data.files || []).find((f) => f.id === id);
    const run = async (fn) => { try { await fn(); } catch (e) { fail(e.message); } };
    if (d.dFolder) { D.folder = d.dFolder; D.view = 'files'; open(); return; }
    if (d.dUpload !== undefined) { const input = document.getElementById('drive-file-input'); input.onchange = () => { uploadFiles(input.files); input.value = ''; }; input.click(); return; }
    if (d.dNewfolder !== undefined) {
      const name = window.prompt('New folder name:'); if (!name) return;
      return run(async () => { const r = await call('POST', '/api/drive/folders', body({ folder: D.folder, name })); D.folder = r.path; await open(); });
    }
    if (d.dRenamefolder !== undefined) {
      const cur = D.folder.split('/').pop(); const name = window.prompt('Rename folder to:', cur); if (!name || name === cur) return;
      return run(async () => { const r = await call('POST', '/api/drive/folders/rename', body({ path: D.folder, name })); D.folder = r.path; await open(); });
    }
    if (d.dDelfolder !== undefined) {
      return window.showConfirm({ title: 'Delete folder?', message: `Delete ${D.folder} and every file in it? This cannot be undone.`, okLabel: 'Delete',
        onConfirm: () => run(async () => { await call('DELETE', '/api/drive/folders' + q({ path: D.folder, recursive: 1 })); D.folder = D.folder.split('/').slice(0, -1).join('/') || '/'; await open(); window.refreshStorage(); }) });
    }
    if (d.dLinks !== undefined) { D.view = 'links'; renderLinks(); return; }
    if (d.dFiles !== undefined) { D.view = 'files'; open(); return; }
    if (d.dUnshare) return run(async () => { await call('DELETE', `/api/drive/shares/${d.dUnshare}` + q()); toast('Link turned off'); renderLinks(); });
    if (d.dShare) { const f = file(d.dShare); return shareDialog('file', f.id, f.name, () => { f.shared = true; }); }
    if (d.dEmail) { const f = file(d.dEmail); window.openCompose(); window.composeAddDriveFile(f); return; }
    if (d.dRename) {
      const f = file(d.dRename); const name = window.prompt('Rename to:', f.name); if (!name || name === f.name) return;
      return run(async () => { await call('PATCH', `/api/drive/files/${f.id}`, body({ name })); await open(); });
    }
    if (d.dMove) {
      const f = file(d.dMove); const folder = window.prompt('Move to folder (for example /Invoices/2026, or / for My Drive):', f.folder); if (!folder || folder === f.folder) return;
      return run(async () => { await call('PATCH', `/api/drive/files/${f.id}`, body({ folder })); await open(); toast('Moved'); });
    }
    if (d.dDelete) {
      const f = file(d.dDelete);
      return window.showConfirm({ title: 'Delete file?', message: `Delete ${f.name}? Its share links stop working. This cannot be undone.`, okLabel: 'Delete',
        onConfirm: () => run(async () => { await call('DELETE', `/api/drive/files/${f.id}` + q()); await open(); window.refreshStorage(); }) });
    }
  });

  // Drag and drop files onto the Drive panel
  ['dragover', 'dragenter'].forEach((type) => document.addEventListener(type, (ev) => {
    const card = document.getElementById('drive-card');
    if (!card || !card.contains(ev.target) || !ev.dataTransfer || ![...ev.dataTransfer.types].includes('Files')) return;
    ev.preventDefault(); card.classList.add('drive-drop');
  }));
  document.addEventListener('dragleave', (ev) => { const card = document.getElementById('drive-card'); if (card && !card.contains(ev.relatedTarget)) card.classList.remove('drive-drop'); });
  document.addEventListener('drop', (ev) => {
    const card = document.getElementById('drive-card');
    if (!card || !card.contains(ev.target) || !ev.dataTransfer || !ev.dataTransfer.files.length) return;
    ev.preventDefault(); card.classList.remove('drive-drop');
    if (!(window.BM_USER && BM_USER.stealth)) uploadFiles(ev.dataTransfer.files);
  });

  window.BearerDrive = { open: (folder) => { D.view = 'files'; return open(folder); }, pickForCompose, shareDialog, emailLink };
})();
