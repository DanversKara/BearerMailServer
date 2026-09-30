/* BearerMail Calendar: month and list views, event editor, import from email, invitations and share links. */
(function () {
  'use strict';

  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const toast = (msg, type, extra) => window.showToast(msg, { type: type || 'success', ...(extra || {}) });
  const fail = (msg) => window.toastError(msg);
  const root = () => document.getElementById('calendar-root');
  const today = () => { const d = new Date(); d.setHours(0, 0, 0, 0); return d; };
  const C = { view: 'month', cursor: (() => { const d = today(); d.setDate(1); return d; })(), events: [] };
  const COLORS = ['blue', 'green', 'red', 'orange', 'purple', 'teal', 'gray'];
  const readOnly = () => !!(window.BM_USER && BM_USER.stealth);

  async function call(method, url, body) {
    const opt = { method, headers: {} };
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    let res; let data = {};
    try { res = await fetch(url, opt); data = await res.json(); } catch (e) { throw new Error('Could not reach the server'); }
    if (!res.ok || data.success === false) throw new Error(data.message || 'Request failed');
    return data;
  }
  const q = (params) => window.driveQuery(params);
  const payload = (extra) => window.drivePayload(extra);

  /* ---------- dates ---------- */
  const pad = (n) => String(n).padStart(2, '0');
  const ymd = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  const hm = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate() + n); return x; };
  // All-day events are stored as UTC midnights; show them on that calendar date wherever you are.
  const allDayLocal = (iso) => { const u = new Date(iso); return new Date(u.getUTCFullYear(), u.getUTCMonth(), u.getUTCDate()); };
  function span(e) {
    if (e.all_day) return [allDayLocal(e.start), allDayLocal(e.end)];
    return [new Date(e.start), new Date(e.end)];
  }
  function onDay(e, day) {
    const [s, en] = span(e);
    const next = addDays(day, 1);
    return s < next && (en > day || (+en === +s && s >= day));
  }
  const timeLabel = (e) => e.all_day ? 'All day' : new Date(e.start).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  function whenLabel(e) {
    const [s, en] = span(e);
    if (e.all_day) {
      const last = addDays(en, -1);
      const f = { weekday: 'short', month: 'short', day: 'numeric' };
      return s.toLocaleDateString([], f) + (last > s ? ' – ' + last.toLocaleDateString([], f) : '') + ', all day';
    }
    const same = s.toDateString() === en.toDateString();
    return s.toLocaleString([], { weekday: 'short', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) + ' – '
      + (same ? en.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : en.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }));
  }

  /* ---------- views ---------- */
  function range() {
    if (C.view === 'list') { const s = today(); return [s, addDays(s, 90)]; }
    const first = new Date(C.cursor);
    const start = addDays(first, -first.getDay());
    return [start, addDays(start, 42)];
  }

  async function open(date) {
    if (date) { C.cursor = new Date(date.getFullYear(), date.getMonth(), 1); }
    const el = root();
    if (!window.driveReady()) {
      el.innerHTML = `<div class="card"><div class="card-body text-center text-muted py-5"><i class="bi bi-calendar3" style="font-size:2.4rem;opacity:.4"></i>
        <p class="mt-2 mb-0">Open a mailbox first. Each mailbox has its own calendar.</p></div></div>`;
      return;
    }
    const [s, e] = range();
    try {
      C.events = (await call('GET', '/api/calendar' + q({ start: s.toISOString(), end: e.toISOString() }))).events || [];
    } catch (err) {
      el.innerHTML = `<div class="card"><div class="card-body text-danger">${esc(err.message)}</div></div>`;
      return;
    }
    render();
  }

  function render() {
    const title = C.view === 'list' ? 'Upcoming' : C.cursor.toLocaleDateString([], { month: 'long', year: 'numeric' });
    const header = `<div class="card-header drive-toolbar">
        <div class="d-flex align-items-center gap-2">
          ${C.view === 'month' ? `<button type="button" class="btn btn-sm btn-outline-secondary" data-c-nav="-1" aria-label="Previous month"><i class="bi bi-chevron-left"></i></button>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-c-today>Today</button>
          <button type="button" class="btn btn-sm btn-outline-secondary" data-c-nav="1" aria-label="Next month"><i class="bi bi-chevron-right"></i></button>` : ''}
          <span class="fw-semibold ms-1">${esc(title)}</span></div>
        <div class="d-flex gap-2">
          <div class="btn-group btn-group-sm"><button type="button" class="btn ${C.view === 'month' ? 'btn-primary' : 'btn-outline-secondary'}" data-c-view="month">Month</button>
            <button type="button" class="btn ${C.view === 'list' ? 'btn-primary' : 'btn-outline-secondary'}" data-c-view="list">List</button></div>
          ${readOnly() ? '' : '<button type="button" class="btn btn-sm btn-primary" data-c-new><i class="bi bi-plus-lg me-1"></i>New event</button>'}
        </div></div>`;
    root().innerHTML = `<div class="card">${header}<div class="card-body">${C.view === 'month' ? monthHtml() : listHtml()}</div></div>`;
  }

  function monthHtml() {
    const [start] = range();
    const t0 = today();
    const heads = Array.from({ length: 7 }, (_, i) => `<div class="cal-head">${addDays(start, i).toLocaleDateString([], { weekday: 'short' })}</div>`).join('');
    const days = Array.from({ length: 42 }, (_, i) => {
      const day = addDays(start, i);
      const evs = C.events.filter((e) => onDay(e, day)).sort((a, b) => (b.all_day - a.all_day) || (new Date(a.start) - new Date(b.start)));
      const shown = evs.slice(0, 3).map((e) => `<button type="button" class="cal-ev c-${esc(e.color)}" data-c-ev="${esc(e.id)}" title="${esc(timeLabel(e) + ' ' + e.title)}">${e.all_day ? '' : esc(timeLabel(e)) + ' '}${esc(e.title)}</button>`).join('');
      return `<div class="cal-day${day.getMonth() !== C.cursor.getMonth() ? ' other' : ''}${+day === +t0 ? ' today' : ''}" data-c-day="${ymd(day)}">
        <span class="num">${day.getDate()}</span>${shown}${evs.length > 3 ? `<div class="cal-more">+${evs.length - 3} more</div>` : ''}</div>`;
    }).join('');
    return `<div class="cal-grid">${heads}${days}</div>`;
  }

  function listHtml() {
    if (!C.events.length) return '<div class="text-muted py-4 text-center">Nothing in the next 90 days.</div>';
    const groups = {};
    C.events.forEach((e) => { const k = ymd(span(e)[0] < today() ? today() : span(e)[0]); (groups[k] = groups[k] || []).push(e); });
    return Object.keys(groups).sort().map((k) => {
      const [y, m, d] = k.split('-').map(Number);
      return `<div class="cal-list-day">${new Date(y, m - 1, d).toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric' })}</div>`
        + groups[k].map((e) => `<div class="cal-list-item" data-c-ev="${esc(e.id)}"><span class="cal-dot cal-ev c-${esc(e.color)}"></span>
            <div class="min-w-0"><div class="fw-semibold">${esc(e.title)}</div><div class="small text-muted">${esc(whenLabel(e))}${e.location ? ' &middot; ' + esc(e.location) : ''}</div></div></div>`).join('');
    }).join('');
  }

  /* ---------- editor ---------- */
  function formHtml(e) {
    const [s, en] = e.id ? span(e) : [e._start, e._end];
    const endShown = e.all_day ? addDays(en, -1) : en;
    const dis = readOnly() ? ' disabled' : '';
    return `<div class="row g-2">
      <div class="col-12"><label class="form-label small mb-1">Title</label><input class="form-control" data-f="title" value="${esc(e.title || '')}"${dis}></div>
      <div class="col-12"><div class="form-check form-switch"><input class="form-check-input" type="checkbox" data-f="all_day" id="c-allday"${e.all_day ? ' checked' : ''}${dis}><label class="form-check-label" for="c-allday">All day</label></div></div>
      <div class="col-7"><label class="form-label small mb-1">Starts</label><input type="date" class="form-control" data-f="sd" value="${ymd(s)}"${dis}></div>
      <div class="col-5" data-time><label class="form-label small mb-1">&nbsp;</label><input type="time" class="form-control" data-f="st" value="${hm(s)}"${dis}></div>
      <div class="col-7"><label class="form-label small mb-1">Ends</label><input type="date" class="form-control" data-f="ed" value="${ymd(endShown)}"${dis}></div>
      <div class="col-5" data-time><label class="form-label small mb-1">&nbsp;</label><input type="time" class="form-control" data-f="et" value="${hm(en)}"${dis}></div>
      <div class="col-12"><label class="form-label small mb-1">Location</label><input class="form-control" data-f="location" value="${esc(e.location || '')}"${dis}></div>
      <div class="col-12"><label class="form-label small mb-1">Guests (emails, for invitations)</label><input class="form-control" data-f="attendees" value="${esc((e.attendees || []).join(', '))}"${dis}></div>
      <div class="col-12"><label class="form-label small mb-1">Notes</label><textarea class="form-control" rows="3" data-f="description"${dis}>${esc(e.description || '')}</textarea></div>
      <div class="col-12 d-flex flex-wrap gap-2 align-items-center"><span class="small text-muted">Colour</span>${COLORS.map((c) => `<label class="d-inline-flex align-items-center gap-1 small"><input type="radio" name="c-color" value="${c}"${(e.color || 'blue') === c ? ' checked' : ''}${dis}><span class="cal-dot cal-ev c-${c}" style="margin:0"></span></label>`).join('')}</div>
      ${e.id && e.source === 'email' ? '<div class="col-12 small text-muted"><i class="bi bi-envelope me-1"></i>Imported from an email invitation.</div>' : ''}
    </div>`;
  }

  function readForm(b) {
    const v = (k) => b.querySelector(`[data-f="${k}"]`).value;
    const allDay = b.querySelector('[data-f="all_day"]').checked;
    const out = { title: v('title').trim(), all_day: allDay, location: v('location'), description: v('description'), attendees: v('attendees'),
      color: (b.querySelector('input[name="c-color"]:checked') || {}).value || 'blue' };
    if (!out.title) throw new Error('Give the event a title');
    if (allDay) {
      out.start = v('sd');
      const [y, m, d] = v('ed').split('-').map(Number);
      out.end = ymd(addDays(new Date(y, m - 1, d), 1));
    } else {
      const s = new Date(`${v('sd')}T${v('st') || '09:00'}`), e = new Date(`${v('ed')}T${v('et') || '10:00'}`);
      if (isNaN(s) || isNaN(e)) throw new Error('Check the start and end');
      if (e < s) throw new Error('The event ends before it starts');
      out.start = s.toISOString(); out.end = e.toISOString();
    }
    return out;
  }

  function editor(e) {
    const isNew = !e.id;
    const buttons = [];
    if (!isNew) {
      buttons.push({ label: 'Download .ics', onClick: () => { window.location.href = `/api/calendar/${e.id}/ics` + q(); return false; } });
      if (!readOnly()) {
        buttons.push({ label: 'Delete', cls: 'btn-outline-danger', onClick: () => new Promise((resolve) => {
          window.showConfirm({ title: 'Delete event?', message: `Delete "${e.title}"? Share links to it stop working.`, okLabel: 'Delete',
            onConfirm: async () => { try { await call('DELETE', `/api/calendar/${e.id}` + q()); toast('Event deleted'); open(); resolve(true); } catch (err) { fail(err.message); resolve(false); } } });
        }) });
        buttons.push({ label: 'Share', onClick: () => { window.bmAfterClose(() => window.BearerDrive.shareDialog('event', e.id, e.title)); } });
        buttons.push({ label: 'Email invitation', onClick: () => { window.bmAfterClose(() => emailInvite(e)); } });
      }
    }
    if (!readOnly()) buttons.push({ label: isNew ? 'Create' : 'Save', cls: 'btn-primary', onClick: async (b) => {
      const data = readForm(b);
      const saved = isNew ? await call('POST', '/api/calendar', payload(data)) : await call('PATCH', `/api/calendar/${e.id}`, payload(data));
      toast(isNew ? 'Event created' : 'Saved');
      if (e._after) e._after(saved);
      if (document.body.dataset.activeTab === 'calendar') open(new Date(saved.start));
    } });
    const dlg = window.bmDialog({ title: isNew ? 'New event' : e.title, html: formHtml(e), buttons, onShown: (b) => {
      const sync = () => b.querySelectorAll('[data-time]').forEach((x) => { x.classList.toggle('d-none', b.querySelector('[data-f="all_day"]').checked); });
      b.querySelector('[data-f="all_day"]').onchange = sync; sync();
      // Moving the start keeps the length of the event
      const sd = b.querySelector('[data-f="sd"]'), ed = b.querySelector('[data-f="ed"]');
      sd.onchange = () => { if (ed.value < sd.value) ed.value = sd.value; };
      if (isNew) b.querySelector('[data-f="title"]').focus();
    } });
    return dlg;
  }

  function newEvent(prefill = {}) {
    const base = prefill.date || addDays(today(), prefill.date === undefined && !prefill.title ? 0 : 1);
    const s = new Date(base); s.setHours(9, 0, 0, 0);
    const en = new Date(s); en.setHours(10);
    return editor({ title: '', all_day: false, color: 'blue', attendees: [], ...prefill, _start: s, _end: en });
  }

  function emailInvite(e) {
    window.openCompose();
    window.composeSetEvent(e);
    const subj = document.getElementById('compose-subject');
    if (!subj.value) subj.value = `Invitation: ${e.title}`;
    if (e.attendees && e.attendees.length && window.setRecipients) window.setRecipients(e.attendees);
  }

  /* ---------- from an email / for Compose ---------- */
  async function fromMessage(messageId) {
    try {
      const r = await call('POST', '/api/calendar/from-message', payload({ message_id: messageId }));
      if (r.imported && r.imported.length) {
        const first = r.imported[0];
        toast(`Added to your calendar: ${first.title}${r.imported.length > 1 ? ` (+${r.imported.length - 1})` : ''}`, 'success',
          { actionLabel: 'Open', onAction: () => { window.switchTab('calendar'); open(new Date(first.start)); } });
        return;
      }
      const s = r.suggestion || {};
      newEvent({ title: s.title || '', description: s.description || '', attendees: (s.attendees || []).filter(Boolean) });
    } catch (e) { fail(e.message); }
  }

  async function pickForCompose() {
    if (!window.driveReady()) return fail('Open a mailbox first');
    const s = today();
    let events = [];
    try { events = (await call('GET', '/api/calendar' + q({ start: s.toISOString(), end: addDays(s, 180).toISOString() }))).events || []; } catch (e) { return fail(e.message); }
    const html = `<p class="small text-muted">The invitation is attached as an .ics file: Gmail, Outlook and phone calendars show Accept / Decline. Recipients are added to the event's guests.</p>
      <div class="pick-list">${events.map((e) => `<div class="cal-list-item" data-pick="${esc(e.id)}"><span class="cal-dot cal-ev c-${esc(e.color)}"></span>
        <div><div class="fw-semibold">${esc(e.title)}</div><div class="small text-muted">${esc(whenLabel(e))}</div></div></div>`).join('') || '<div class="text-muted small">No upcoming events.</div>'}</div>`;
    const dlg = window.bmDialog({ title: 'Attach an invitation', html, buttons: [{ label: 'Cancel' }, { label: 'New event', cls: 'btn-primary', onClick: () => {
      window.bmAfterClose(() => newEvent({ _after: (saved) => { attach(saved); } }));
    } }] });
    const attach = (e) => {
      window.composeSetEvent(e);
      const subj = document.getElementById('compose-subject');
      if (subj && !subj.value) subj.value = `Invitation: ${e.title}`;
    };
    dlg.body.querySelectorAll('[data-pick]').forEach((row) => { row.onclick = () => { attach(events.find((x) => x.id === row.dataset.pick)); dlg.close(); }; });
  }

  /* ---------- events ---------- */
  document.addEventListener('click', (ev) => {
    const el = root();
    if (!el || !el.contains(ev.target)) return;
    const evBtn = ev.target.closest('[data-c-ev]');
    if (evBtn) { ev.stopPropagation(); const e = C.events.find((x) => x.id === evBtn.dataset.cEv); if (e) editor(e); return; }
    const t = ev.target.closest('[data-c-nav],[data-c-today],[data-c-view],[data-c-new],[data-c-day]');
    if (!t) return;
    const d = t.dataset;
    if (d.cNav) { C.cursor = new Date(C.cursor.getFullYear(), C.cursor.getMonth() + Number(d.cNav), 1); open(); return; }
    if (d.cToday !== undefined) { open(today()); return; }
    if (d.cView) { C.view = d.cView; open(); return; }
    if (d.cNew !== undefined) { newEvent({ date: today() }); return; }
    if (d.cDay && !readOnly()) { const [y, m, dd] = d.cDay.split('-').map(Number); newEvent({ date: new Date(y, m - 1, dd) }); }
  });

  window.BearerCalendar = { open, fromMessage, pickForCompose, newEvent };
})();
