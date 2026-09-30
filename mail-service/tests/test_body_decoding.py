"""Regression tests for byte-safe body decoding in handle_DATA.

History
-------
mail-service used to call part.get_content() directly and assign the result to
text_body / html_body. When that returned bytes instead of str, the very next
step

    intro = re.sub(r"\\s+", " ", (text_body or "")).strip()[:200]

raised "cannot use a string pattern on a bytes-like object". handle_DATA
aborted before the message was stored, the SMTP layer answered 451, and the
mail was lost. In production this silently discarded every Google DMARC
aggregate report - 38 messages in 26 hours - while ordinary mail was unaffected.

These tests pin the two guarantees that keep that from coming back:

  1. _part_text() always returns str and never raises, whatever the part says;
  2. the full body-extraction path, fed a message whose text part has an
     unresolvable charset, still produces str values for text and html.
"""

import base64
import re
from email import policy
from email.parser import BytesParser

import pytest

RCPT = "hello@example.test"


@pytest.fixture(scope="module")
def part_text():
    """Import app lazily: conftest's autouse fixture must patch pymongo first."""
    from app import _part_text

    return _part_text


def _message_with_body_part(content_type, cte, body):
    """Build a minimal multipart message and return it parsed."""
    raw = (
        f"From: sender@example.com\r\nTo: {RCPT}\r\n"
        "Subject: test\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        "--B\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Transfer-Encoding: {cte}\r\n\r\n"
    ).encode() + body + b"\r\n--B--\r\n"
    return BytesParser(policy=policy.default).parsebytes(raw)


def _text_part(message):
    for part in message.walk():
        if part.get_content_type() == "text/plain":
            return part
    return None


def _extract_like_handle_data(message, decode):
    """The body-extraction block exactly as handle_DATA runs it."""
    text_body = ""
    html_body = ""
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            ct = part.get_content_type()
            cd = part.get("Content-Disposition", "")
            if "attachment" in cd.lower() or bool(part.get_filename()):
                continue
            if ct == "text/plain" and not text_body:
                decoded = decode(part)
                if decoded:
                    text_body = decoded
            elif ct == "text/html" and not html_body:
                decoded = decode(part)
                if decoded:
                    html_body = decoded
    else:
        ct = message.get_content_type()
        content = decode(message)
        if ct == "text/html":
            html_body = content
        else:
            text_body = content
    return text_body, html_body


# --- _part_text always yields str -------------------------------------------

def test_part_text_returns_str_for_unknown_charset(part_text):
    """An unresolvable charset used to raise LookupError out of handle_DATA."""
    part = _message_with_body_part("text/plain; charset=unknown", "base64", b"aGVsbG8=")
    result = part_text(_text_part(part))
    assert isinstance(result, str)


def test_part_text_returns_str_for_missing_and_bogus_charsets(part_text):
    for charset in ("text/plain", "text/plain; charset=", "text/plain; charset=none",
                    "text/plain; charset=8bit", "text/plain; charset=x-bogus"):
        msg = _message_with_body_part(charset, "base64", b"aGVsbG8gd29ybGQ=")
        assert isinstance(part_text(_text_part(msg)), str), charset


def test_part_text_survives_malformed_base64(part_text):
    msg = _message_with_body_part("text/plain; charset=UTF-8", "base64", b"!!!not base64!!!")
    assert isinstance(part_text(_text_part(msg)), str)


def test_part_text_decodes_normal_mail(part_text):
    body = "入境医疗合作 · 客人在广州的空档".encode("utf-8")
    msg = _message_with_body_part(
        "text/plain; charset=UTF-8", "base64", base64.b64encode(body)
    )
    assert part_text(_text_part(msg)) == body.decode("utf-8")


# --- the full path must never hand bytes to re.sub ---------------------------

def test_intro_extraction_never_raises_on_odd_charset(part_text):
    """The exact production crash: re.sub() over a body that decoded to bytes."""
    msg = _message_with_body_part("text/plain; charset=unknown", "base64", b"aGVsbG8=")
    text_body, html_body = _extract_like_handle_data(msg, part_text)

    assert isinstance(text_body, str)
    assert isinstance(html_body, str)
    # This is the statement that used to raise TypeError.
    intro = re.sub(r"\s+", " ", (text_body or "")).strip()[:200]
    assert isinstance(intro, str)


def test_intro_extraction_still_reads_normal_dmarc_style_mail(part_text):
    body = b"Report domain: example.test"
    msg = _message_with_body_part(
        "text/plain; charset=UTF-8", "base64", base64.b64encode(body)
    )
    text_body, _ = _extract_like_handle_data(msg, part_text)
    assert text_body == body.decode()


def test_spam_normalisation_never_raises_on_bytes_body(part_text):
    """_detect_spam / the spam pass runs after this point with the same inputs."""
    msg = _message_with_body_part("text/plain; charset=unknown", "base64", b"aGVsbG8=")
    text_body, html_body = _extract_like_handle_data(msg, part_text)

    normalized = re.sub(r"\s+", " ", f"{text_body or ''} {html_body or ''}").strip().lower()
    assert isinstance(normalized, str)


# --- attachments must survive an unreadable body -----------------------------

def test_attachment_is_still_captured_when_body_is_undecodable(part_text):
    raw = (
        f"From: noreply-dmarc-support@google.com\r\nTo: {RCPT}\r\n"
        "Subject: Report domain: example.test\r\nMIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
        "--B\r\nContent-Type: text/plain; charset=unknown\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\nnot-valid-base64!!!\r\n"
        "--B\r\nContent-Type: application/gzip\r\n"
        'Content-Disposition: attachment; filename="report.xml.gz"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\nH4sIAAAAAAACAw==\r\n--B--\r\n"
    ).encode()
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    text_body, _ = _extract_like_handle_data(msg, part_text)
    attachments = [
        p for p in msg.walk()
        if "attachment" in (p.get("Content-Disposition") or "").lower()
    ]

    assert isinstance(text_body, str)
    assert len(attachments) == 1
    assert attachments[0].get_filename() == "report.xml.gz"
