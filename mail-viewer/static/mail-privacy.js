/* BearerMail: privacy and safety display for an opened email.
 *
 * - Remote images are held back by the server (data-bm-src, no src). "Show images" loads them for
 *   this message only; tracking pixels (data-bm-tracker) stay blocked either way.
 * - Sender check (SPF / DKIM / DMARC) banner, Reply-To and display-name tricks, read-receipt requests.
 * - Attachment risk badges; opening a risky attachment asks first.
 * - Links flagged by the server (data-bm-warn) ask before opening and show where they really go.
 */
(function () {
  'use strict';

  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const DEFAULTS = { block_remote_images: true, trusted_senders: [], confirm_suspicious_links: true, strip_link_tracking: true };
  let settings = Object.assign({}, DEFAULTS);
  let loaded = null;

  async function loadSettings(force) {
    if (loaded && !force) return loaded;
    loaded = (async () => {
      try {
        const res = await fetch('/api/admin/security/settings');
        const data = await res.json();
        if (data && data.privacy) settings = Object.assign({}, DEFAULTS, data.privacy);
      } catch (e) { /* keep the safe defaults */ }
      return settings;
    })();
    return loaded;
  }

  async function saveSettings(privacy) {
    const res = await fetch('/api/admin/security/settings', {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ privacy }),
    });
    const data = await res.json();
    if (!res.ok || data.success === false) throw new Error(data.message || 'Could not save');
    settings = Object.assign({}, DEFAULTS, data.privacy || {});
    loaded = Promise.resolve(settings);
    return settings;
  }

  function senderAddress(msg) { return String((msg && msg.from && msg.from.address) || '').toLowerCase(); }
  function senderDomain(msg) { const a = senderAddress(msg); return a.includes('@') ? a.split('@')[1] : ''; }

  function isTrusted(msg) {
    const list = (settings.trusted_senders || []).map((s) => String(s).toLowerCase());
    const addr = senderAddress(msg), dom = senderDomain(msg);
    // Only trust a sender whose From address passed the sender check (a forged "From" must not unlock images).
    const verdict = msg && msg.auth ? verdictOf(msg.auth) : '';
    if (verdict === 'fail') return false;
    return !!addr && (list.includes(addr) || (dom && list.includes('@' + dom)));
  }

  function shouldShowImages(msg, isSent) {
    if (isSent) return true;
    if (!settings.block_remote_images) return true;
    return isTrusted(msg);
  }

  /* ------------------------------ sender check ------------------------------ */
  function verdictOf(auth) {
    if (!auth || auth.skipped) return '';
    if (auth.dmarc === 'fail') return 'fail';
    if (auth.spf === 'fail' && auth.dkim !== 'pass') return 'fail';
    if (auth.dmarc === 'pass' || auth.dkim === 'pass' || auth.spf === 'pass') return 'pass';
    return 'warn';
  }

  const RESULT_TEXT = {
    pass: 'passed', fail: 'failed', softfail: 'soft fail', neutral: 'neutral', none: 'not set up',
    temperror: 'could not check', permerror: 'broken record',
  };

  function authChips(auth) {
    const chip = (name, value) => {
      const v = String(value || 'none');
      const kind = v === 'pass' ? 'success' : (v === 'fail' || v === 'softfail' || v === 'permerror') ? 'danger' : 'secondary';
      return `<span class="badge text-bg-${kind} me-1" title="${esc(name)}: ${esc(RESULT_TEXT[v] || v)}">${esc(name)} ${esc(RESULT_TEXT[v] || v)}</span>`;
    };
    return chip('SPF', auth.spf) + chip('DKIM', auth.dkim) + chip('DMARC', auth.dmarc);
  }

  function displayNameTrick(msg) {
    const name = String((msg.from && msg.from.name) || '');
    const m = name.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    if (m && m[0].toLowerCase() !== senderAddress(msg)) return m[0];
    return '';
  }

  function banners(msg, isSent) {
    if (isSent || !msg) return '';
    const out = [];
    const auth = msg.auth;
    const verdict = verdictOf(auth);
    const domain = (auth && auth.header_from_domain) || senderDomain(msg);
    if (verdict === 'fail') {
      out.push(`<div class="bm-banner bm-danger" role="alert"><i class="bi bi-shield-exclamation"></i><div>
        <b>This sender could not be verified.</b> The message says it is from <b>${esc(domain)}</b>, but it was not sent by that domain's mail servers.
        Treat links, attachments and requests for passwords or payment as fake.
        <div class="bm-chips mt-1">${authChips(auth)}</div></div></div>`);
    } else if (verdict === 'warn') {
      out.push(`<div class="bm-banner bm-warn"><i class="bi bi-shield"></i><div>
        <b>Sender not verified.</b> ${esc(domain)} does not prove who sends its mail, so this message could come from anyone.
        <div class="bm-chips mt-1">${authChips(auth)}</div></div></div>`);
    }
    const shown = displayNameTrick(msg);
    if (shown) {
      out.push(`<div class="bm-banner bm-danger"><i class="bi bi-person-exclamation"></i><div>
        The sender's <b>name</b> shows <b>${esc(shown)}</b>, but the real address is <b>${esc(senderAddress(msg))}</b>.</div></div>`);
    }
    const replyTo = String(msg.replyTo || '').toLowerCase();
    if (replyTo && replyTo.includes('@') && replyTo.split('@')[1] !== senderDomain(msg)) {
      out.push(`<div class="bm-banner bm-info"><i class="bi bi-reply"></i><div>
        Replies go to <b>${esc(replyTo)}</b>, not to the sender's own domain.</div></div>`);
    }
    const links = ((msg.privacy && msg.privacy.link_warnings) || []).filter((w) => w.level === 'high');
    if (links.length) {
      out.push(`<div class="bm-banner bm-danger"><i class="bi bi-link-45deg"></i><div>
        <b>${links.length} deceptive link${links.length === 1 ? '' : 's'}</b> (outlined in red below): ${esc(links[0].reasons[0] || '')}${links.length > 1 ? ', ...' : ''}.
        BearerMail will show the real address and ask before opening ${links.length === 1 ? 'it' : 'them'}.</div></div>`);
    }
    const receipt = msg.scan && msg.scan.read_receipt_to;
    if (receipt) {
      out.push(`<div class="bm-banner bm-info"><i class="bi bi-envelope-check"></i><div>
        The sender asked for a <b>read receipt</b> (to ${esc(receipt)}). BearerMail never sends one, so they are not told you opened it.
        Mail apps such as Thunderbird may ask you; you can say no.</div></div>`);
    }
    return out.join('');
  }

  function verdictIcon(verdict, risky) {
    if (verdict === 'fail') return '<i class="bi bi-shield-exclamation text-danger ms-1" title="Sender could not be verified"></i>';
    if (risky) return '<i class="bi bi-exclamation-triangle text-warning ms-1" title="Has a risky attachment"></i>';
    return '';
  }

  /* ------------------------------ privacy bar ------------------------------ */
  function privacyBar(msg, isSent, showing) {
    const p = (msg && msg.privacy) || {};
    const images = p.remote_images || 0;
    const trackers = (p.trackers || []).length;
    const parts = [];
    if (trackers) parts.push(`<b>${trackers}</b> tracking pixel${trackers === 1 ? '' : 's'} blocked`);
    if (p.tracked_links) parts.push(`${p.tracked_links} tracked link${p.tracked_links === 1 ? '' : 's'}`);
    if (p.links_cleaned) parts.push(`tracking removed from ${p.links_cleaned} link${p.links_cleaned === 1 ? '' : 's'}`);
    if (p.css_blocked) parts.push(`${p.css_blocked} hidden style image${p.css_blocked === 1 ? '' : 's'} removed`);
    const attPhone = (msg.scan && msg.scan.attachments_phone_home) || 0;
    if (!images && !parts.length && !attPhone) return '';
    const remaining = images - trackers;
    let left;
    if (showing) {
      left = `<i class="bi bi-image"></i><span>Images shown${trackers ? ' (tracking pixels still blocked)' : ''}. Loading them lets the sender see that this message was opened.</span>`;
    } else if (remaining > 0) {
      left = `<i class="bi bi-eye-slash"></i><span><b>Images hidden</b> so the sender cannot tell you opened this${parts.length ? '. ' : ''}${parts.join(', ')}</span>`;
    } else {
      left = `<i class="bi bi-shield-check"></i><span>${parts.join(', ') || 'Nothing in this message can tell the sender you opened it'}</span>`;
    }
    const attNote = attPhone
      ? `<div class="bm-privacy-note"><i class="bi bi-paperclip"></i> ${attPhone} attachment${attPhone === 1 ? '' : 's'} can contact the internet when opened, which would tell the sender you opened ${attPhone === 1 ? 'it' : 'them'}.</div>` : '';
    const buttons = !showing && remaining > 0 && !isSent
      ? `<div class="bm-privacy-actions"><button type="button" class="btn btn-sm btn-outline-secondary" data-bm-show-images>Show images</button>
         ${senderAddress(msg) && verdictOf(msg.auth) !== 'fail' ? `<button type="button" class="btn btn-sm btn-link" data-bm-trust="${esc(senderAddress(msg))}">Always from this sender</button>` : ''}</div>` : '';
    return `<div class="bm-privacy ${showing ? 'is-showing' : ''}"><div class="bm-privacy-main">${left}</div>${buttons}</div>${attNote}`;
  }

  /* ------------------------------ attachments ------------------------------ */
  function attachmentsHtml(attachments, urlFor, formatSize) {
    if (!attachments || !attachments.length) return '';
    const items = attachments.map((att, index) => {
      const name = att.filename || `attachment_${index}`;
      const size = formatSize ? formatSize(att.size) : '';
      const risk = att.risk || 'info';
      const reasons = (att.reasons || []).join('; ');
      const icon = risk === 'high' ? 'bi-exclamation-octagon-fill text-danger' : risk === 'medium' ? 'bi-exclamation-triangle-fill text-warning' : 'bi-download';
      const phone = att.phonesHome ? ' <span class="badge text-bg-warning" title="Opening it contacts the internet, which tells the sender you opened it">phones home</span>' : '';
      const note = reasons ? `<div class="bm-att-reason">${esc(reasons)}</div>` : '';
      return `<div class="bm-att bm-att-${risk}">
        <a class="bm-att-link" href="${esc(urlFor(att, index))}" download data-bm-risk="${esc(risk)}" data-bm-reasons="${esc(reasons)}" data-bm-name="${esc(name)}">
          <i class="bi ${icon}"></i><span class="bm-att-name">${esc(name)}</span>${size ? `<span class="text-muted small">${esc(size)}</span>` : ''}${phone}</a>${note}</div>`;
    }).join('');
    return `<div class="bm-atts mb-3"><div class="small fw-semibold mb-1"><i class="bi bi-paperclip me-1"></i>Attachments</div>${items}</div>`;
  }

  /* ------------------------------ in the email frame ------------------------------ */
  function loadImages(doc) {
    let count = 0;
    doc.querySelectorAll('img[data-bm-src]').forEach((img) => {
      if (img.hasAttribute('data-bm-tracker')) return;
      const src = img.getAttribute('data-bm-src');
      if (src && src.startsWith('/api/image-proxy')) { img.setAttribute('src', src); count += 1; }
    });
    return count;
  }

  function hostOf(href) { try { return new URL(href).hostname; } catch (e) { return ''; } }

  function wireLinks(doc, confirmFn) {
    doc.querySelectorAll('a[href]').forEach((a) => {
      a.setAttribute('target', '_blank');
      a.setAttribute('rel', 'noopener noreferrer');
      const warn = a.getAttribute('data-bm-warn');
      if (warn) a.classList.add('bm-link-' + (a.getAttribute('data-bm-level') || 'medium'));
      a.addEventListener('click', (ev) => {
        const href = a.getAttribute('href') || '';
        if (!/^https?:/i.test(href)) return;
        if (warn && settings.confirm_suspicious_links !== false) {
          ev.preventDefault();
          confirmFn({
            title: 'Open this link?',
            message: `This link goes to ${hostOf(href)}.\n\nWarning: ${warn}.\n\nFull address:\n${href}`,
            okLabel: 'Open anyway',
            onConfirm: () => window.open(href, '_blank', 'noopener,noreferrer'),
          });
        }
      });
    });
    doc.querySelectorAll('a[data-bm-warn]:not([href])').forEach((a) => { a.title = a.getAttribute('data-bm-warn'); });
  }

  const FRAME_CSS = 'img[data-bm-src]:not([src]):not([data-bm-tracker]){display:inline-block;min-width:24px;min-height:18px;background:repeating-linear-gradient(45deg,#eef2f1,#eef2f1 6px,#e3e9e7 6px,#e3e9e7 12px);border-radius:3px;}'
    + 'img[data-bm-tracker]{display:none!important;}'
    + 'a.bm-link-high{outline:2px dashed #c76b6b;outline-offset:1px;}a.bm-link-medium{outline:1px dashed #c4a35a;outline-offset:1px;}';

  window.BearerPrivacy = {
    loadSettings, saveSettings, get settings() { return settings; },
    isTrusted, shouldShowImages, verdictOf, verdictIcon, banners, privacyBar, attachmentsHtml,
    loadImages, wireLinks, FRAME_CSS, authChips,
  };
})();
