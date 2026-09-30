/**
 * Email HTML sanitizer & image proxy rewriter for IMAP bridge.
 * Uses htmlparser2 ecosystem (transitive deps of mailparser — zero new packages).
 * Mirrors the whitelist from mail-viewer/app.py for consistency.
 */

const htmlparser2 = require('htmlparser2');
const { DomHandler } = require('domhandler');
const { render: domSerializer } = require('dom-serializer');
const DomUtils = require('domutils');

// ---------------------------------------------------------------------------
// Whitelists (mirror app.py _EMAIL_ALLOWED_*)
// ---------------------------------------------------------------------------

const ALLOWED_TAGS = new Set([
  'a', 'abbr', 'b', 'blockquote', 'br', 'code', 'div', 'em', 'font',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li', 'ol',
  'p', 'pre', 'span', 'strong', 'table', 'tbody', 'td', 'th', 'thead',
  'tr', 'u', 'ul',
]);

const REMOVE_WITH_CONTENT = new Set([
  'script', 'style', 'iframe', 'object', 'embed', 'form', 'input',
  'textarea', 'select', 'button', 'applet', 'link', 'meta', 'noscript',
]);

const ALLOWED_ATTRS = {
  '*': new Set(['align', 'valign']),
  'a': new Set(['href', 'title', 'target', 'rel', 'style']),
  'div': new Set(['style']),
  'font': new Set(['color', 'size', 'face']),
  'img': new Set(['src', 'alt', 'title', 'width', 'height', 'style']),
  'p': new Set(['style']),
  'span': new Set(['style']),
  'table': new Set(['border', 'cellpadding', 'cellspacing', 'width', 'style']),
  'tbody': new Set(['style']),
  'thead': new Set(['style']),
  'tr': new Set(['style']),
  'td': new Set(['colspan', 'rowspan', 'width', 'height', 'style']),
  'th': new Set(['colspan', 'rowspan', 'width', 'height', 'style']),
};

const ALLOWED_CSS_PROPS = new Set([
  'background', 'background-color', 'border', 'border-bottom', 'border-collapse',
  'border-left', 'border-right', 'border-spacing', 'border-top', 'color',
  'display', 'font', 'font-family', 'font-size', 'font-style', 'font-weight',
  'height', 'letter-spacing', 'line-height', 'margin', 'margin-bottom',
  'margin-left', 'margin-right', 'margin-top', 'max-width', 'min-width',
  'padding', 'padding-bottom', 'padding-left', 'padding-right', 'padding-top',
  'text-align', 'text-decoration', 'vertical-align', 'white-space', 'width',
  'word-break',
]);

const SAFE_URL_PROTOCOLS = new Set(['http:', 'https:', 'mailto:']);
const DANGEROUS_CSS_RE = /url\s*\(|expression\s*\(|behavior\s*:|javascript:|vbscript:|-moz-binding/i;

// ---------------------------------------------------------------------------
// CSS sanitizer
// ---------------------------------------------------------------------------

function sanitizeCss(raw) {
  if (!raw) return '';

  const declarations = raw.split(';');
  const safe = [];
  for (const decl of declarations) {
    const colonIdx = decl.indexOf(':');
    if (colonIdx === -1) continue;
    const prop = decl.substring(0, colonIdx).trim().toLowerCase();
    const value = decl.substring(colonIdx + 1).trim();
    if (!prop || !value) continue;
    if (!ALLOWED_CSS_PROPS.has(prop)) continue;
    if (DANGEROUS_CSS_RE.test(value)) continue;
    safe.push(`${prop}:${value}`);
  }
  return safe.join(';');
}

// ---------------------------------------------------------------------------
// Attribute filter
// ---------------------------------------------------------------------------

function filterAttrs(tagName, attribs) {
  const globalAllowed = ALLOWED_ATTRS['*'] || new Set();
  const tagAllowed = ALLOWED_ATTRS[tagName] || new Set();
  const result = {};

  for (const [key, value] of Object.entries(attribs)) {
    const lk = key.toLowerCase();
    // Block all event handlers
    if (lk.startsWith('on')) continue;
    if (!globalAllowed.has(lk) && !tagAllowed.has(lk)) continue;

    if (lk === 'href') {
      try {
        const url = new URL(value, 'https://placeholder.invalid');
        if (!SAFE_URL_PROTOCOLS.has(url.protocol)) continue;
      } catch {
        continue;
      }
    }

    if (lk === 'style') {
      const cleaned = sanitizeCss(value);
      if (cleaned) result[lk] = cleaned;
      continue;
    }

    result[lk] = value;
  }

  // Force safe link attributes
  if (tagName === 'a') {
    result.target = '_blank';
    result.rel = 'noopener noreferrer';
  }

  return result;
}

// ---------------------------------------------------------------------------
// DOM tree walker
// ---------------------------------------------------------------------------

function walkAndSanitize(nodes) {
  const result = [];
  for (const node of nodes) {
    if (node.type === 'text' || node.type === 'cdata') {
      result.push(node);
      continue;
    }

    if (node.type === 'comment') continue;

    if (node.type === 'tag' || node.type === 'script' || node.type === 'style') {
      const tag = (node.name || '').toLowerCase();

      // Remove dangerous tags and all their children
      if (REMOVE_WITH_CONTENT.has(tag)) continue;

      if (ALLOWED_TAGS.has(tag)) {
        node.attribs = filterAttrs(tag, node.attribs || {});
        if (node.children) {
          node.children = walkAndSanitize(node.children);
          for (const child of node.children) child.parent = node;
        }
        result.push(node);
      } else {
        // Tag not allowed — keep children (unwrap)
        if (node.children) {
          const sanitizedChildren = walkAndSanitize(node.children);
          result.push(...sanitizedChildren);
        }
      }
      continue;
    }

    // Other node types (directives, processing instructions) — skip
  }
  return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Sanitize email HTML using a whitelist approach.
 * Strips dangerous tags/attributes/CSS, keeps safe content.
 */
function sanitizeEmailHtml(html) {
  if (!html || typeof html !== 'string') return '';
  html = html.trim();
  if (!html) return '';

  // Extract <body> content if present
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  if (bodyMatch) html = bodyMatch[1];

  const handler = new DomHandler();
  const parser = new htmlparser2.Parser(handler);
  parser.write(html);
  parser.end();

  const sanitized = walkAndSanitize(handler.dom);
  return domSerializer(sanitized, { decodeEntities: false }).trim();
}

// Open-tracking detection (same rules as the web app's email_privacy.py, simplified).
const TRACKING_HOSTS = ['list-manage.com', 'mcsv.net', 'sendgrid.net', 'mandrillapp.com', 'sparkpostmail.com', 'exct.net',
  'rs6.net', 'hubspotemail.net', 'hubspotlinks.com', 'mailtrack.io', 'getnotify.com', 'bananatag.com', 'yesware.com',
  'streak.com', 'mixmax.com', 'superhuman.com', 'mjt.lu', 'sendibt3.com', 'awstrack.me', 'klaviyomail.com', 'emltrk.com',
  'convertkit-mail.com', 'mlsend.com', 'cmail19.com', 'cmail20.com', 'doubleclick.net', 'google-analytics.com',
  'customeriomail.com', 'pstmrk.it'];
const TRACKING_PATH_RE = /(?:\/(?:open|opens|track|tracking|pixel|beacon|imp|wf\/open|e\/o|o|oo)(?:\.gif|\.png|\.php)?(?:\/|\?|$))|[?&](?:open|track|pixel)=/i;

function trackerReason(tag, url) {
  const attr = (name) => { const m = tag.match(new RegExp('\\b' + name + '\\s*=\\s*["\']?([^"\'\\s>]+)', 'i')); return m ? m[1] : ''; };
  const small = (v) => /^\s*[0-3](?:\.\d+)?\s*(px)?\s*$/i.test(v || '');
  const w = attr('width'), h = attr('height');
  if ((small(w) && small(h)) || (small(w) && !h) || (small(h) && !w)) return 'invisible 1x1 image';
  if (/display\s*:\s*none|visibility\s*:\s*hidden/i.test(tag)) return 'hidden image';
  let host = '', path = '';
  try { const u = new URL(url); host = u.hostname.toLowerCase(); path = u.pathname + u.search; } catch { return ''; }
  if (TRACKING_HOSTS.some((m) => host === m || host.endsWith('.' + m))) return 'tracking service (' + host + ')';
  if (TRACKING_PATH_RE.test(path)) return 'open-tracking address (' + host + ')';
  return '';
}

/**
 * Remote images do not load by themselves: the proxied address goes into data-bm-src and the page
 * copies it to src only when you press "Show images". Tracking pixels are marked and never loaded.
 * Preserves data: and cid: URLs.
 */
function rewriteImageUrls(html) {
  if (!html || !/<img/i.test(html)) return html;

  return html.replace(/<img\b[^>]*>/gi, (tag) => {
    const m = tag.match(/\bsrc\s*=\s*(["'])([^"']+)\1/i);
    if (!m) return tag;
    const trimmed = m[2].trim().replace(/^\/\//, 'https://');
    if (!/^https?:\/\//i.test(trimmed)) return tag;
    const proxied = '/api/image-proxy?url=' + encodeURIComponent(trimmed);
    const reason = trackerReason(tag, trimmed);
    const marker = ' data-bm-src="' + proxied + '"' + (reason ? ' data-bm-tracker="' + reason.replace(/"/g, '') + '"' : '');
    return tag.replace(m[0], '').replace(/\s*\/?>$/, (end) => marker + end);
  });
}

/**
 * Full pipeline: sanitize HTML then rewrite image URLs.
 */
function prepareHtmlForRender(html) {
  return rewriteImageUrls(sanitizeEmailHtml(html));
}

module.exports = { sanitizeEmailHtml, rewriteImageUrls, prepareHtmlForRender, trackerReason };
