"""DMARC reports are filed for the admins instead of landing in an inbox."""

import asyncio
import base64
import gzip
import io
import zipfile
from types import SimpleNamespace

import dmarc_ext

API = {"Authorization": "Bearer test-api-key"}

REPORT = """<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>846116234031826847{n}</report_id>
    <date_range><begin>1790640000</begin><end>1790726399</end></date_range>
  </report_metadata>
  <policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>87.253.232.1</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results><dkim><domain>{domain}</domain><result>pass</result><selector>mailjet</selector></dkim>
      <spf><domain>{domain}</domain><result>pass</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>203.0.113.66</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results><spf><domain>spammer.example</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>
"""


def zipped(domain="test.local", n=0):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"google.com!{domain}!1790640000!1790726399.xml", REPORT.format(domain=domain, n=n))
    return buf.getvalue()


def deliver_report(payload: bytes, filename="report.zip", ctype="application/zip", rcpt="me@test.local"):
    from app import MailHandler
    raw = (f"From: noreply-dmarc-support@google.com\r\nTo: {rcpt}\r\nSubject: Report domain: test.local Submitter: google.com\r\n"
           f"MIME-Version: 1.0\r\nContent-Type: {ctype}; name=\"{filename}\"\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\n"
           "Content-Transfer-Encoding: base64\r\n\r\n").encode() + base64.encodebytes(payload)
    envelope = SimpleNamespace(content=raw, rcpt_tos=[rcpt], mail_from="noreply-dmarc-support@google.com")
    session = SimpleNamespace(peer=("127.0.0.1", 25000), rcpt_count=1, mail_from=envelope.mail_from)
    return asyncio.run(MailHandler().handle_DATA(None, session, envelope))


def mailbox(client):
    client.post("/admin/accounts", json={"address": "me@test.local", "password": "supersecret1"}, headers=API)


def test_report_goes_to_security_not_the_inbox(client, mock_mongo):
    mailbox(client)
    assert deliver_report(zipped()).startswith("250")
    assert mock_mongo.messages.count_documents({}) == 0
    s = client.get("/admin/dmarc/summary", params={"days": 3650, "lookup": 0}, headers=API).json()
    assert s["total"] == 15 and s["passed"] == 12 and s["failed"] == 3 and s["reports"] == 1
    bad = s["sources"][0]
    assert bad["ip"] == "203.0.113.66" and bad["status"] == "failing"
    assert s["sources"][1]["status"] == "ok" and s["domains"][0]["domain"] == "test.local"
    # The same report twice is stored once
    deliver_report(zipped())
    assert client.get("/admin/dmarc/reports", headers=API).json()["reports"].__len__() == 1
    events = client.get("/admin/security/events", params={"source": "system"}, headers=API).json()["events"]
    assert any(e["kind"] == "dmarc_failures" for e in events)


def test_gzip_and_plain_xml_reports(client, mock_mongo):
    mailbox(client)
    deliver_report(gzip.compress(REPORT.format(domain="test.local", n=1).encode()), "r.xml.gz", "application/gzip")
    deliver_report(REPORT.format(domain="test.local", n=2).encode(), "r.xml", "text/xml")
    assert len(client.get("/admin/dmarc/reports", headers=API).json()["reports"]) == 2


def test_keep_a_copy_in_the_inbox(client, mock_mongo):
    mailbox(client)
    client.patch("/admin/security/settings", headers=API, json={"dmarc": {"keep_in_inbox": True}})
    deliver_report(zipped())
    assert mock_mongo.messages.count_documents({}) == 1
    assert len(client.get("/admin/dmarc/reports", headers=API).json()["reports"]) == 1


def test_reports_about_other_domains_are_normal_mail(client, mock_mongo):
    mailbox(client)
    deliver_report(zipped(domain="someone-else.example"))
    assert mock_mongo.messages.count_documents({}) == 1
    assert client.get("/admin/dmarc/reports", headers=API).json()["reports"] == []


def test_not_a_report_is_left_alone(client, mock_mongo):
    mailbox(client)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("photos.xml", "<gallery/>")
    deliver_report(buf.getvalue(), "photos.zip")
    assert mock_mongo.messages.count_documents({}) == 1


def test_hostile_xml_is_refused():
    bomb = b'<?xml version="1.0"?><!DOCTYPE feedback [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><feedback>&b;</feedback>'
    assert dmarc_ext.parse_report(bomb) is None


def test_import_reports_already_in_mailboxes(client, mock_mongo):
    mailbox(client)
    client.patch("/admin/security/settings", headers=API, json={"dmarc": {"keep_in_inbox": True}})
    deliver_report(zipped(n=5))
    client.patch("/admin/security/settings", headers=API, json={"dmarc": {"keep_in_inbox": False}})
    mock_mongo.dmarc_reports.delete_many({})
    r = client.post("/admin/dmarc/import", headers=API, json={}).json()
    assert r == {"imported": 1, "moved_to_trash": 1}
    assert mock_mongo.messages.find_one({})["is_deleted"] is True
    assert len(client.get("/admin/dmarc/reports", headers=API).json()["reports"]) == 1
