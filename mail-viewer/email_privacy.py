"""
Email privacy pass, run on every message after it has been sanitized.

* Remote images never load by themselves. Each <img> pointing at the internet keeps its address
  in data-bm-src (through the image proxy) and has no src, so nothing is fetched until you press
  "Show images" for that message (or the sender is on your trusted list).
* Tracking pixels are recognised (1x1 images, hidden images, known tracking services) and stay
  blocked even after "Show images".
* CSS in style="" attributes may not load anything (url(), image-set(), ...). Before this pass,
  a background image written that way loaded straight from your browser, bypassing the proxy.
* Links are checked: the text shows one site but goes to another, raw IP addresses, look-alike
  (punycode) domains, link shorteners, click trackers. Common tracking parameters (utm_*, fbclid,
  ...) can be removed from links.

Returns the rewritten HTML plus a report the web app shows above the message.
"""

import html as html_lib
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

# ---------------------------------------------------------------------------
# Tracker knowledge
# ---------------------------------------------------------------------------

# Hosts (or host suffixes) that exist to record opens/clicks. Services that also host newsletter
# pictures (gallery.mailchimp.com, image.exacttarget.com, img.en25.com, ...) are deliberately not
# listed by their image domains, so real pictures still appear after "Show images".
TRACKING_HOSTS = (
    "list-manage.com", "mcsv.net", "sendgrid.net", "mandrillapp.com", "sparkpostmail.com",
    "exct.net", "rs6.net", "hubspotemail.net", "hubspotlinks.com", "hs-analytics.net", "sidekickopen",
    "mailtrack.io", "getnotify.com", "bananatag.com", "yesware.com", "streak.com", "mixmax.com",
    "superhuman.com", "cirrusinsight.com", "outreach.io", "salesloft.com", "mjt.lu", "sendibt2.com",
    "sendibt3.com", "awstrack.me", "klaviyomail.com", "klclick.com", "emltrk.com",
    "convertkit-mail.com", "convertkit-mail2.com", "mlsend.com", "mktdns.com", "cmail19.com", "cmail20.com",
    "doubleclick.net", "google-analytics.com", "mixpanel.com", "customeriomail.com", "track.customer.io",
    "via.intercom.io", "pstmrk.it", "ct.sendgrid.net",
    "email.mg.", "click.pstmrk", "tracking.", "track.", "trk.", "pixel.", "beacon.", "open.",
)
_TRACKING_PATH_RE = re.compile(
    r"(?:/(?:open|opens|opened|track|tracking|pixel|beacon|imp|impression|wf/open|e/o|o|oo|mo|emimp|trk|t/o)"
    r"(?:\.gif|\.png|\.jpg|\.php|\.aspx)?(?:/|\?|$))|(?:[?&](?:open|track|pixel|opened|tracking)=)",
    re.I,
)
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "bl.ink", "short.io", "lnkd.in", "trib.al",
}
CLICK_TRACKER_RE = re.compile(
    r"(?:/ls/click|/track/click|/lnk/|/wf/click|/c/|/click|/redirect|/r/|/l/)(?:[/?]|$)", re.I,
)
TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "gclsrc", "msclkid", "yclid", "mc_eid", "mc_cid", "_hsenc", "_hsmi",
    "hsctatracking", "mkt_tok", "igshid", "oly_enc_id", "oly_anon_id", "vero_id", "vero_conv", "__s",
    "s_cid", "trk", "trkcampaign", "sc_campaign", "_ke", "ck_subscriber_id", "wickedid", "ttclid",
    "twclid", "li_fat_id", "rb_clickid", "spm", "ref_src", "mbid", "cmpid", "sfmc_id", "et_rid",
    "ml_subscriber", "ml_subscriber_hash", "_branch_match_id", "epik",
}

_SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(px)?\s*$", re.I)
_URL_LIKE_RE = re.compile(r"^\s*(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#]\S*)?\s*$", re.I)
_CSS_URL_RE = re.compile(r"(?:url|image-set|-webkit-image-set|image|cross-fade|element)\s*\(", re.I)
_CSS_DANGER_RE = re.compile(r"expression\s*\(|javascript\s*:|vbscript\s*:|behavior\s*:|-moz-binding|@import", re.I)


_COMMON_TLDS = {
    "com", "net", "org", "io", "co", "us", "uk", "de", "fr", "nl", "info", "biz", "app", "dev", "me", "ca",
    "au", "in", "eu", "gov", "edu", "mil", "ru", "cn", "jp", "br", "it", "es", "ch", "se", "no", "dk", "fi",
    "be", "at", "pl", "cz", "ie", "nz", "za", "mx", "ar", "tv", "xyz", "online", "site", "shop", "store",
    "top", "club", "live", "email", "support", "services", "bank", "pay", "link", "click", "cloud", "ai",
}


def _looks_like_web_address(text: str, host: str) -> bool:
    """Is the visible link text itself a web address (so a different destination is deceptive)?"""
    stripped = (text or "").strip().lower()
    if stripped.startswith(("http://", "https://", "www.")):
        return True
    return host.rsplit(".", 1)[-1].lower() in _COMMON_TLDS


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def _registrable(host: str) -> str:
    labels = [p for p in host.split(".") if p]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "ac", "gov", "edu", "or", "ne"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+", host or "")) or bool(re.fullmatch(r"0x[0-9a-f]+", host or "", re.I))


def tracker_reason(url: str, attrs: dict) -> str:
    """Why an image is a tracker, or '' if it looks like a normal picture."""
    width, height = attrs.get("width", ""), attrs.get("height", "")
    style = (attrs.get("style") or "").lower()
    for match in re.finditer(r"(?:^|;)\s*(width|height|max-width|max-height)\s*:\s*([^;]+)", style):
        size = _SIZE_RE.match(match.group(2))
        if size and float(size.group(1)) <= 3:
            if match.group(1) in ("width", "max-width"):
                width = width or size.group(1)
            else:
                height = height or size.group(1)
    tiny = [v for v in (width, height) if _SIZE_RE.match(str(v)) and float(_SIZE_RE.match(str(v)).group(1)) <= 3]
    if len(tiny) == 2 or (tiny and not (width and height)):
        return "invisible 1x1 image"
    if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)", style):
        return "hidden image"
    host = _host(url)
    if host:
        for marker in TRACKING_HOSTS:
            if marker.endswith(".") and (host.startswith(marker) or f".{marker}" in f".{host}"):
                if _TRACKING_PATH_RE.search(urlparse(url).path + "?" + (urlparse(url).query or "")):
                    return f"tracking service ({host})"
            elif host == marker or host.endswith("." + marker) or ("." not in marker and marker in host):
                return f"tracking service ({host})"
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    if _TRACKING_PATH_RE.search(parsed.path + ("?" + parsed.query if parsed.query else "")):
        return f"open-tracking address ({host})"
    return ""


def strip_tracking_params(url: str) -> tuple[str, int]:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url, 0
    if parsed.scheme not in ("http", "https") or not parsed.query:
        return url, 0
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if not (k.lower().startswith("utm_") or k.lower() in TRACKING_PARAMS)]
    removed = len(pairs) - len(kept)
    if not removed:
        return url, 0
    return urlunparse(parsed._replace(query=urlencode(kept, doseq=True))), removed


def link_findings(href: str, text: str) -> tuple[list, str, bool]:
    """(warnings, level, is_click_tracker). level is 'high', 'medium' or ''."""
    reasons, level = [], ""
    try:
        parsed = urlparse(href)
    except ValueError:
        return ["the address is malformed"], "high", False
    scheme = (parsed.scheme or "").lower()
    if scheme in ("mailto", "tel", "cid", ""):
        return [], "", False
    if scheme not in ("http", "https"):
        return [f"uses the unusual '{scheme}:' scheme"], "high", False
    host = (parsed.hostname or "").lower()
    if not host:
        return ["has no destination"], "high", False
    if _is_ip(host):
        reasons.append("goes to a numeric IP address instead of a named website")
        level = "high"
    if any(label.startswith("xn--") for label in host.split(".")):
        reasons.append(f"the address uses look-alike characters ({host})")
        level = "high"
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        reasons.append("hides the real destination after an '@' sign")
        level = "high"
    shown = _URL_LIKE_RE.match(text or "")
    if shown and _looks_like_web_address(text, shown.group(1)):
        shown_host = shown.group(1).lower().strip(".")
        if _registrable(shown_host) != _registrable(host):
            reasons.append(f"the text says {shown_host} but the link goes to {host}")
            level = "high"
    if host in SHORTENERS or _registrable(host) in SHORTENERS:
        reasons.append("shortened link: the real destination is hidden")
        level = level or "medium"
    tracker = bool(tracker_reason(href, {}) and not reasons) or bool(CLICK_TRACKER_RE.search(parsed.path or ""))
    if scheme == "http" and not reasons:
        pass  # plain http is common in newsletters; not worth a warning on its own
    return reasons, level, tracker


# ---------------------------------------------------------------------------
# Rewriter
# ---------------------------------------------------------------------------

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


def clean_inline_style(style: str) -> tuple[str, bool]:
    """Drop declarations that could load something or run script. Returns (style, changed)."""
    if not style:
        return style, False
    kept, changed = [], False
    for decl in style.split(";"):
        if not decl.strip():
            continue
        if _CSS_URL_RE.search(decl) or _CSS_DANGER_RE.search(decl):
            changed = True
            continue
        kept.append(decl.strip())
    return ";".join(kept), changed


class _Rewriter(HTMLParser):
    def __init__(self, proxy_url, strip_params):
        super().__init__(convert_charrefs=False)
        self.out = []
        self.proxy_url = proxy_url
        self.strip_params = strip_params
        self.report = {"remote_images": 0, "trackers": [], "tracked_links": 0, "link_warnings": [],
                       "links_cleaned": 0, "css_blocked": 0}
        self._link_stack = []  # [index in out, attrs, collected text]

    # -- helpers --
    @staticmethod
    def _attrs_to_str(attrs):
        parts = []
        for name, value in attrs:
            if value is None:
                parts.append(f" {name}")
            else:
                parts.append(f' {name}="{html_lib.escape(value, quote=True)}"')
        return "".join(parts)

    def _fix_style(self, attrs):
        fixed = []
        for name, value in attrs:
            if name == "style" and value:
                value, changed = clean_inline_style(value)
                if changed:
                    self.report["css_blocked"] += 1
                if not value:
                    continue
            if name == "background":  # legacy <td background=...>
                self.report["css_blocked"] += 1
                continue
            fixed.append((name, value))
        return fixed

    def _img(self, attrs):
        d = dict(attrs)
        src = (d.get("src") or "").strip()
        if src.startswith("//"):
            src = "https:" + src
        if not re.match(r"^https?://", src, re.I):
            return attrs  # data:, cid: and relative addresses load nothing from the internet
        self.report["remote_images"] += 1
        reason = tracker_reason(src, d)
        new = [(k, v) for k, v in attrs if k not in ("src", "srcset")]
        new.append(("data-bm-src", self.proxy_url(src)))
        if reason:
            if len(self.report["trackers"]) < 25:
                self.report["trackers"].append({"host": _host(src), "reason": reason})
            new.append(("data-bm-tracker", reason))
        return new

    def _open_link(self, attrs):
        d = dict(attrs)
        href = (d.get("href") or "").strip()
        new = [(k, v) for k, v in attrs if k not in ("href", "target", "rel")]
        if href:
            if self.strip_params:
                href, removed = strip_tracking_params(href)
                if removed:
                    self.report["links_cleaned"] += 1
            if href.lower().startswith(("data:", "javascript:", "vbscript:", "file:")):
                new.append(("data-bm-warn", "this link could run code, so it has been disabled"))
                new.append(("data-bm-level", "high"))
                href = ""
            if href:
                new.insert(0, ("href", href))
                new.append(("title", href[:300]))
        new += [("target", "_blank"), ("rel", "noopener noreferrer")]
        return new, href

    # -- parser callbacks --
    def handle_starttag(self, tag, attrs):
        attrs = self._fix_style(attrs)
        if tag == "img":
            attrs = self._img(attrs)
        if tag == "a":
            attrs, href = self._open_link(attrs)
            self.out.append(None)  # placeholder, filled at </a> once the link text is known
            self._link_stack.append([len(self.out) - 1, attrs, [], href])
            return
        self.out.append(f"<{tag}{self._attrs_to_str(attrs)}>")

    def handle_startendtag(self, tag, attrs):
        attrs = self._fix_style(attrs)
        if tag == "img":
            attrs = self._img(attrs)
        self.out.append(f"<{tag}{self._attrs_to_str(attrs)} />")

    def handle_endtag(self, tag):
        if tag == "a" and self._link_stack:
            self._close_link()
        self.out.append(f"</{tag}>")

    def _close_link(self):
        index, attrs, text_parts, href = self._link_stack.pop()
        if href:
            text = html_lib.unescape("".join(text_parts)).strip()
            reasons, level, tracker = link_findings(href, text)
            if tracker:
                self.report["tracked_links"] += 1
            if reasons:
                attrs = attrs + [("data-bm-warn", "; ".join(reasons)), ("data-bm-level", level)]
                if len(self.report["link_warnings"]) < 20:
                    self.report["link_warnings"].append({"text": text[:120], "host": _host(href), "reasons": reasons, "level": level})
        self.out[index] = f"<a{self._attrs_to_str(attrs)}>"

    def handle_data(self, data):
        for entry in self._link_stack:
            entry[2].append(data)
        self.out.append(data)

    def handle_entityref(self, name):
        for entry in self._link_stack:
            entry[2].append(f"&{name};")
        self.out.append(f"&{name};")

    def handle_charref(self, name):
        for entry in self._link_stack:
            entry[2].append(f"&#{name};")
        self.out.append(f"&#{name};")

    def handle_comment(self, data):
        pass  # comments are never needed to show an email

    def close(self):
        super().close()
        while self._link_stack:  # unclosed <a>
            self._close_link()


def default_proxy_url(src: str) -> str:
    return "/api/image-proxy?url=" + quote(src, safe="")


def protect_html(html: str, proxy_url=default_proxy_url, strip_params: bool = True) -> tuple[str, dict]:
    if not html:
        return "", {"remote_images": 0, "trackers": [], "tracked_links": 0, "link_warnings": [], "links_cleaned": 0, "css_blocked": 0}
    rewriter = _Rewriter(proxy_url, strip_params)
    try:
        rewriter.feed(html)
        rewriter.close()
    except Exception:  # pragma: no cover - never show unprotected HTML
        return html_lib.escape(re.sub(r"<[^>]+>", " ", html)), rewriter.report
    out = "".join(part for part in rewriter.out if part is not None)
    report = rewriter.report
    report["can_track_open"] = bool(report["remote_images"])
    return out, report
