/* Inbox tabs: Primary / Favorites / Security / Promotions / Social / Updates / Forums / Work / School + your own.
   The mail service sorts each email when it arrives; "Move to" puts an email (and optionally everything
   from that sender or domain, now and later) in another tab. A flood of email shows a warning, because
   floods are used to bury "your password / SIM / phone number was changed" alerts. */
(function () {
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const S = { email: '', current: 'primary', data: null, dismissedFlood: {} };
    const store = {
        get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
        set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } },
    };
    const readOnly = () => !!(window.BM_USER && BM_USER.stealth);

    async function post(url, body) {
        const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: S.email, ...body }) });
        const data = await r.json().catch(() => ({ success: false, message: 'Request failed' }));
        if (!data.success) throw new Error(data.message || 'Request failed');
        return data;
    }

    function onMailbox(email) {
        if (email === S.email) return;
        S.email = email;
        S.data = null;
        S.current = store.get('bm-tab:' + email) || 'primary';
    }

    // The tab to ask the server for ('' = no tabs, everything in one list).
    function current() {
        if (S.data && !S.data.enabled) return '';
        return S.current || 'primary';
    }

    function tabById(id) { return (S.data?.tabs || []).find(t => t.id === id); }

    async function refresh() {
        if (!S.email) return;
        try {
            S.data = await post('/api/inbox/tabs', {});
            // A tab that was removed or hidden falls back to Primary.
            const t = tabById(S.current);
            if (S.current !== 'all' && (!t || t.hidden)) { S.current = 'primary'; }
        } catch (e) { /* keep the last good state */ }
        render();
    }

    function visibleTabs() {
        return (S.data?.tabs || []).filter(t => !t.hidden && (t.id === 'primary' || t.total > 0 || t.id === S.current));
    }

    /* ---------------- dragging: reorder tabs, or drop emails on a tab to move them ---------------- */
    const D = { kind: null, tab: null, mail: [] };

    function clearDropMarks() {
        document.querySelectorAll('.drop-before,.drop-after,.drop-mail,.dragging').forEach(el => el.classList.remove('drop-before', 'drop-after', 'drop-mail', 'dragging'));
    }

    function wireDrag(container, selector, key, horizontal) {
        container.querySelectorAll(selector).forEach(el => {
            const id = el.dataset[key];
            if (!readOnly() && id !== 'all') {
                el.draggable = true;
                el.ondragstart = e => {
                    D.kind = 'tab'; D.tab = id;
                    e.dataTransfer.effectAllowed = 'move';
                    try { e.dataTransfer.setData('text/plain', id); } catch (err) { /* old browsers */ }
                    el.classList.add('dragging');
                };
                el.ondragend = dragEnd;
            }
            el.ondragover = e => {
                if (D.kind === 'tab' && id !== 'all' && id !== D.tab) {
                    e.preventDefault();
                    const r = el.getBoundingClientRect();
                    const after = horizontal ? e.clientX > r.left + r.width / 2 : e.clientY > r.top + r.height / 2;
                    el.classList.toggle('drop-after', after);
                    el.classList.toggle('drop-before', !after);
                } else if (D.kind === 'mail' && id !== 'all') {
                    e.preventDefault();
                    e.dataTransfer.dropEffect = 'move';
                    el.classList.add('drop-mail');
                }
            };
            el.ondragleave = () => el.classList.remove('drop-before', 'drop-after', 'drop-mail');
            el.ondrop = e => {
                e.preventDefault();
                const after = el.classList.contains('drop-after');
                const kind = D.kind, from = D.tab, ids = D.mail.slice();
                dragEnd();
                if (kind === 'tab' && from && from !== id && id !== 'all') reorder(from, id, after);
                else if (kind === 'mail' && ids.length && id !== 'all') moveMail(ids, id);
            };
        });
    }

    function dragEnd() {
        D.kind = null; D.tab = null; D.mail = [];
        clearDropMarks();
        const card = document.getElementById('tabs-card');
        if (card) card.classList.remove('tabs-drop-ready');
        const box = document.getElementById('inbox-tabs');
        if (box) box.classList.remove('tabs-drop-ready');
    }

    async function saveOrder(ids) {
        try { S.data = await post('/api/inbox/tabs/settings', { order: ids }); } catch (e) { toastError(e.message); }
        render();
    }

    function reorder(from, to, after) {
        const ids = S.data.tabs.map(t => t.id).filter(t => t !== from);
        let at = ids.indexOf(to);
        if (at < 0) return;
        if (after) at += 1;
        ids.splice(at, 0, from);
        // Show the new order right away, then save it.
        S.data.tabs = ids.map(tid => tabById(tid)).filter(Boolean);
        render();
        saveOrder(ids);
    }

    // Called by each email in the list (index.html): drag one email, or all ticked ones if it is ticked.
    function dragMail(e, id) {
        if (readOnly() || !S.data || !S.data.enabled) return;
        const ticked = typeof getSelectedIds === 'function' ? getSelectedIds() : [];
        D.kind = 'mail';
        D.mail = ticked.includes(id) ? ticked : [id];
        e.dataTransfer.effectAllowed = 'move';
        try { e.dataTransfer.setData('text/plain', D.mail.join(',')); } catch (err) { /* old browsers */ }
        const card = document.getElementById('tabs-card');
        if (card) card.classList.add('tabs-drop-ready');
        const box = document.getElementById('inbox-tabs');
        if (box) box.classList.add('tabs-drop-ready');
    }

    async function moveMail(ids, tab) {
        const senders = _sendersOf(ids);
        try {
            S.data = await post('/api/inbox/tabs/move', { message_ids: ids, tab });
        } catch (e) { return toastError(e.message); }
        const t = tabById(tab);
        const n = ids.length;
        showToast(`Moved ${n} email${n === 1 ? '' : 's'} to ${t ? t.name : 'tab'}`, {
            type: 'success',
            actionLabel: senders.length ? 'Always for ' + (senders.length === 1 ? 'this sender' : 'these senders') : undefined,
            onAction: senders.length ? async () => {
                try {
                    S.data = await post('/api/inbox/tabs/move', { message_ids: ids, tab, rule: 'sender', senders });
                    showToast(`Future email from ${senders.length === 1 ? senders[0] : 'those senders'} goes to ${t ? t.name : 'that tab'}`, { type: 'success' });
                    queryInbox(true);
                } catch (e) { toastError(e.message); }
            } : undefined,
        });
        if (window._currentDetailMsg && ids.includes(window._currentDetailMsg.id) && S.current !== 'all' && tab !== S.current) resetMailDetail();
        queryInbox(true);
    }

    // Left column (computers): every tab with its count, at the top.
    function renderSide() {
        const card = document.getElementById('tabs-card');
        const list = document.getElementById('tabs-card-list');
        if (!card || !list) return;
        const show = !!currentEmail && currentEmail === S.email && S.data && S.data.enabled;
        card.classList.toggle('d-none', !show);
        if (!show) { list.innerHTML = ''; return; }
        const onInbox = currentTab === 'inbox' && !isSearchMode;
        const fmt = n => n > 9999 ? Math.round(n / 1000) + 'k' : String(n);
        const row = t => {
            const alert = t.id === 'security' && t.unread > 0;
            return `<button type="button" class="tabs-side-item ${onInbox && t.id === S.current ? 'active' : ''} ${alert ? 'tabs-side-alert' : ''}" data-side-tab="${esc(t.id)}"
                title="${esc(t.name)}: ${t.total} email${t.total === 1 ? '' : 's'}, ${t.unread} unread">
                <i class="bi ${esc(t.icon)}"></i><span class="tabs-side-name">${esc(t.name)}</span>
                ${t.unread ? `<span class="tabs-side-unread">${fmt(t.unread)}</span>` : ''}<span class="tabs-side-total">${fmt(t.total)}</span></button>`;
        };
        const tabs = S.data.tabs.filter(t => !t.hidden);
        const all = tabs.reduce((a, t) => ({ total: a.total + t.total, unread: a.unread + t.unread }), { total: 0, unread: 0 });
        list.innerHTML = tabs.map(row).join('') + row({ id: 'all', name: 'All mail', icon: 'bi-collection', total: all.total, unread: all.unread });
        list.querySelectorAll('[data-side-tab]').forEach(b => b.onclick = () => {
            if (currentTab !== 'inbox') { S.current = b.dataset.sideTab; store.set('bm-tab:' + S.email, S.current); switchTab('inbox'); queryInbox(); }
            else select(b.dataset.sideTab);
            if (typeof closeLeftDrawer === 'function') closeLeftDrawer();
        });
        wireDrag(list, '[data-side-tab]', 'sideTab', false);
        const gear = document.getElementById('tabs-card-manage');
        if (gear) gear.onclick = manage;
    }

    function render() {
        renderSide();
        const box = document.getElementById('inbox-tabs');
        const flood = document.getElementById('flood-banner');
        if (!box) return;
        const show = currentTab === 'inbox' && !!currentEmail && currentEmail === S.email && S.data && S.data.enabled && !isSearchMode;
        box.classList.toggle('d-none', !show);
        if (!show) { box.innerHTML = ''; if (flood) flood.innerHTML = ''; return; }
        const chip = t => {
            const alert = t.id === 'security' && t.unread > 0;
            return `<button type="button" class="inbox-tab ${t.id === S.current ? 'active' : ''} ${alert ? 'inbox-tab-alert' : ''}" data-tab="${esc(t.id)}" title="${esc(t.name)}: ${t.total} email(s), ${t.unread} unread">
                <i class="bi ${esc(t.icon)}"></i><span>${esc(t.name)}</span>${t.unread ? `<span class="inbox-tab-count">${t.unread > 999 ? '999+' : t.unread}</span>` : ''}</button>`;
        };
        box.innerHTML = visibleTabs().map(chip).join('')
            + `<button type="button" class="inbox-tab ${S.current === 'all' ? 'active' : ''}" data-tab="all" title="Every email in one list"><i class="bi bi-collection"></i><span>All</span></button>`
            + `<button type="button" class="inbox-tab inbox-tab-gear" data-tabs-manage title="Manage tabs and sorting rules" aria-label="Manage tabs"><i class="bi bi-gear"></i></button>`;
        box.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => select(b.dataset.tab));
        wireDrag(box, '[data-tab]', 'tab', true);
        box.querySelector('[data-tabs-manage]').onclick = manage;
        const active = box.querySelector('.inbox-tab.active');
        if (active && active.scrollIntoView) active.scrollIntoView({ block: 'nearest', inline: 'nearest' });

        const f = S.data.flood;
        if (flood) {
            const key = S.email + ':' + (f ? Math.floor(f.count / 25) : 0);
            if (f && !S.dismissedFlood[key]) {
                const sec = tabById('security');
                flood.innerHTML = `<div class="flood-banner" role="alert">
                    <i class="bi bi-exclamation-octagon-fill"></i>
                    <div class="flex-grow-1"><b>Mail flood:</b> ${f.count} emails in the last hour from ${f.senders} senders.
                    Floods are used to hide real alerts (password changes, new sign-ins, SIM or phone-number changes, orders).
                    ${sec && !sec.hidden ? `<a href="#" data-flood-security>${f.security ? `Check ${f.security} security email${f.security === 1 ? '' : 's'}` : 'Security tab is clear'}</a>` : ''}</div>
                    <button type="button" class="btn-close btn-sm" aria-label="Dismiss" data-flood-close></button></div>`;
                const link = flood.querySelector('[data-flood-security]');
                if (link) link.onclick = e => { e.preventDefault(); select('security'); };
                flood.querySelector('[data-flood-close]').onclick = () => { S.dismissedFlood[key] = true; flood.innerHTML = ''; };
            } else {
                flood.innerHTML = '';
            }
        }
    }

    function select(id) {
        S.current = id;
        store.set('bm-tab:' + S.email, id);
        render();
        queryInbox();
    }

    function emptyText() {
        if (!S.data || !S.data.enabled || S.current === 'all') return null;
        if (S.current === 'security') return 'No security alerts. Password changes, new sign-ins and codes show up here.';
        if (S.current === 'favorites') return 'No favorites yet. Open an email and use Move → Favorites to always see that sender here.';
        const t = tabById(S.current);
        return t ? `Nothing in ${t.name}.` : null;
    }

    function _sendersOf(ids) {
        const all = [...(currentMessages || []), window._currentDetailMsg].filter(Boolean);
        const set = new Set();
        ids.forEach(id => {
            const m = all.find(x => x && (x.id === id));
            const a = (m?.from?.address || '').toLowerCase();
            if (a) set.add(a);
        });
        return [...set];
    }

    async function moveDialog(ids) {
        if (readOnly()) return toastError('Stealth view is read-only.');
        if (!S.data) await refresh();
        if (!S.data) return toastError('Could not load tabs');
        const senders = _sendersOf(ids);
        const domains = [...new Set(senders.map(s => s.split('@')[1]).filter(Boolean))];
        const msg = window._currentDetailMsg && ids.length === 1 && window._currentDetailMsg.id === ids[0] ? window._currentDetailMsg : null;
        const nowTab = msg?.tab || (currentMessages || []).find(m => m.id === ids[0])?.tab || '';
        const one = senders.length === 1;
        const tabs = S.data.tabs.filter(t => !t.hidden);
        const html = `
            <div class="small text-muted mb-2">${ids.length === 1 ? 'Move this email to:' : `Move ${ids.length} emails to:`}</div>
            <div class="move-tab-grid">
                ${tabs.map(t => `<label class="move-tab-opt"><input type="radio" name="mv-tab" value="${esc(t.id)}" ${t.id === nowTab ? 'checked' : ''}>
                    <span><i class="bi ${esc(t.icon)}"></i>${esc(t.name)}</span></label>`).join('')}
                <label class="move-tab-opt"><input type="radio" name="mv-tab" value="__new"><span><i class="bi bi-plus-lg"></i>New tab</span></label>
            </div>
            <input type="text" class="form-control form-control-sm mt-2 d-none" maxlength="30" placeholder="Name, e.g. Taxes, Kids, Travel" data-mv-newname>
            <div class="mt-3 small fw-semibold">Future email</div>
            <div class="form-check small"><input class="form-check-input" type="radio" name="mv-rule" id="mv-r-s" value="sender" ${senders.length ? 'checked' : 'disabled'}>
                <label class="form-check-label" for="mv-r-s">Always put email from <b>${one ? esc(senders[0]) : `these ${senders.length} senders`}</b> here (also moves their older email)</label></div>
            <div class="form-check small"><input class="form-check-input" type="radio" name="mv-rule" id="mv-r-d" value="domain" ${domains.length ? '' : 'disabled'}>
                <label class="form-check-label" for="mv-r-d">Always put email from anyone at <b>${domains.length === 1 ? '@' + esc(domains[0]) : 'those domains'}</b> here</label></div>
            <div class="form-check small"><input class="form-check-input" type="radio" name="mv-rule" id="mv-r-n" value="" ${senders.length ? '' : 'checked'}>
                <label class="form-check-label" for="mv-r-n">Only ${ids.length === 1 ? 'this email' : 'these emails'}</label></div>`;
        bmDialog({
            title: 'Move to tab', html,
            onShown(body) {
                const name = body.querySelector('[data-mv-newname]');
                body.querySelectorAll('input[name=mv-tab]').forEach(r => r.onchange = () => {
                    name.classList.toggle('d-none', r.value !== '__new' || !r.checked);
                    if (r.value === '__new' && r.checked) name.focus();
                });
            },
            buttons: [
                { label: 'Cancel' },
                {
                    label: 'Move', cls: 'btn-primary', onClick: async body => {
                        let tab = body.querySelector('input[name=mv-tab]:checked')?.value;
                        if (!tab) { toastError('Pick a tab'); return false; }
                        if (tab === '__new') {
                            const name = body.querySelector('[data-mv-newname]').value.trim();
                            if (!name) { toastError('Give the new tab a name'); return false; }
                            tab = (await post('/api/inbox/tabs/settings', { add_tab: name })).tab_id;
                        }
                        const rule = body.querySelector('input[name=mv-rule]:checked')?.value || '';
                        const res = await post('/api/inbox/tabs/move', { message_ids: ids, tab, rule, senders });
                        S.data = res;
                        const t = tabById(tab);
                        const who = rule === 'domain' ? (domains.length === 1 ? '@' + domains[0] : 'those domains') : (one ? senders[0] : 'those senders');
                        showToast(`Moved to ${t ? t.name : 'tab'}` + (rule ? `. Future email from ${who} goes there too.` : '.'));
                        if (msg && S.current !== 'all' && tab !== S.current) resetMailDetail();
                        else if (msg) msg.tab = tab;
                        queryInbox(true);
                    },
                },
            ],
        });
    }

    function _manageHtml() {
        const d = S.data;
        const tabs = d.tabs;
        const name = id => tabById(id)?.name || 'Primary (tab removed)';
        return `
            <div class="form-check form-switch mb-3">
                <input class="form-check-input" type="checkbox" id="tabs-enabled" ${d.enabled ? 'checked' : ''} ${readOnly() ? 'disabled' : ''}>
                <label class="form-check-label" for="tabs-enabled"><b>Sort my inbox into tabs</b><div class="small text-muted">Off = every email in one list.</div></label>
            </div>
            <div class="fw-semibold small mb-1">Tabs <span class="fw-normal text-muted">(arrows or drag in the tab list to change the order)</span></div>
            <div class="list-group mb-2">
                ${tabs.map((t, i) => `<div class="list-group-item d-flex align-items-center gap-2 py-2">
                    <div class="btn-group-vertical btn-group-sm tab-order-btns">
                        <button type="button" class="btn btn-link p-0 lh-1" data-tab-up="${esc(t.id)}" title="Move up" aria-label="Move ${esc(t.name)} up" ${i === 0 || readOnly() ? 'disabled' : ''}><i class="bi bi-chevron-up"></i></button>
                        <button type="button" class="btn btn-link p-0 lh-1" data-tab-down="${esc(t.id)}" title="Move down" aria-label="Move ${esc(t.name)} down" ${i === tabs.length - 1 || readOnly() ? 'disabled' : ''}><i class="bi bi-chevron-down"></i></button>
                    </div>
                    <i class="bi ${esc(t.icon)}"></i>
                    ${t.builtin ? `<span class="flex-grow-1">${esc(t.name)}${t.auto ? ' <span class="badge text-bg-light border fw-normal">auto</span>' : ''}</span>`
                        : `<input class="form-control form-control-sm flex-grow-1" value="${esc(t.name)}" maxlength="30" data-tab-rename="${esc(t.id)}" ${readOnly() ? 'disabled' : ''}>`}
                    <span class="small text-muted">${t.total}</span>
                    ${t.id === 'primary' ? '<span class="small text-muted" style="width:62px">always</span>' : `<div class="form-check form-switch mb-0" title="Show this tab (off = its email goes to Primary)">
                        <input class="form-check-input" type="checkbox" data-tab-show="${esc(t.id)}" ${t.hidden ? '' : 'checked'} ${readOnly() ? 'disabled' : ''}></div>`}
                    ${t.builtin ? '' : `<button type="button" class="btn btn-sm btn-outline-danger" data-tab-remove="${esc(t.id)}" title="Remove tab (its email goes back to automatic sorting)" ${readOnly() ? 'disabled' : ''}><i class="bi bi-trash"></i></button>`}
                </div>`).join('')}
            </div>
            <div class="input-group input-group-sm mb-3">
                <input type="text" class="form-control" maxlength="30" placeholder="New tab, e.g. Taxes, Kids, Travel" data-tab-add-name ${readOnly() ? 'disabled' : ''}>
                <button class="btn btn-outline-primary" type="button" data-tab-add ${readOnly() ? 'disabled' : ''}><i class="bi bi-plus-lg me-1"></i>Add</button>
            </div>
            <div class="fw-semibold small mb-1">Sorting rules</div>
            ${d.rules.length ? `<div class="list-group mb-2">${d.rules.map(r => `<div class="list-group-item d-flex align-items-center gap-2 py-2 small">
                <span class="text-truncate flex-grow-1"><b>${esc(r.match)}</b> → ${esc(name(r.tab))}</span>
                <button type="button" class="btn btn-sm btn-outline-secondary" data-rule-remove="${esc(r.match)}" ${readOnly() ? 'disabled' : ''}><i class="bi bi-x-lg"></i></button></div>`).join('')}</div>`
                : '<div class="small text-muted mb-2">None yet. Open an email and use <b>Move</b> to add one.</div>'}
            <div class="small text-muted">Security holds password changes, new sign-ins, verification codes and SIM / phone-number changes,
            so a flood of junk mail can't hide them. Senders that fail the forgery checks never land there.</div>`;
    }

    function _wireManage(body) {
        const apply = async payload => {
            try { S.data = await post('/api/inbox/tabs/settings', payload); } catch (e) { toastError(e.message); }
            body.innerHTML = _manageHtml();
            _wireManage(body);
            render();
        };
        const en = body.querySelector('#tabs-enabled');
        if (en) en.onchange = () => apply({ enabled: en.checked });
        body.querySelectorAll('[data-tab-show]').forEach(c => c.onchange = () => {
            const hidden = [...body.querySelectorAll('[data-tab-show]')].filter(x => !x.checked).map(x => x.dataset.tabShow);
            apply({ hidden });
        });
        body.querySelectorAll('[data-tab-rename]').forEach(i => i.onchange = () => apply({ rename_tab: { id: i.dataset.tabRename, name: i.value } }));
        body.querySelectorAll('[data-tab-remove]').forEach(b => b.onclick = () => apply({ remove_tab: b.dataset.tabRemove }));
        body.querySelectorAll('[data-rule-remove]').forEach(b => b.onclick = () => apply({ remove_rule: b.dataset.ruleRemove }));
        const shift = (id, by) => {
            const ids = S.data.tabs.map(t => t.id);
            const i = ids.indexOf(id), j = i + by;
            if (i < 0 || j < 0 || j >= ids.length) return;
            [ids[i], ids[j]] = [ids[j], ids[i]];
            apply({ order: ids });
        };
        body.querySelectorAll('[data-tab-up]').forEach(b => b.onclick = () => shift(b.dataset.tabUp, -1));
        body.querySelectorAll('[data-tab-down]').forEach(b => b.onclick = () => shift(b.dataset.tabDown, 1));
        const add = body.querySelector('[data-tab-add]');
        const addName = body.querySelector('[data-tab-add-name]');
        if (add) add.onclick = () => addName.value.trim() && apply({ add_tab: addName.value.trim() });
        if (addName) addName.onkeydown = e => { if (e.key === 'Enter') add.click(); };
    }

    async function manage() {
        if (!S.data) await refresh();
        if (!S.data) return;
        bmDialog({
            title: 'Inbox tabs', html: _manageHtml(),
            onShown: body => _wireManage(body),
            buttons: [{ label: 'Done', cls: 'btn-primary', onClick: () => { queryInbox(); } }],
        });
    }

    window.BearerTabs = { onMailbox, current, refresh, render, select, moveDialog, manage, emptyText, dragMail, dragEnd, state: S };
})();
