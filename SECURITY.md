# Security Policy

BearerMail listens for SMTP on a public port and renders untrusted HTML in the webmail viewer. Both are worth attacking, and both are worth reporting bugs against.

## Reporting a vulnerability

Report vulnerabilities privately to the maintainer of your deployment (the person who runs your BearerMail instance). Do not open public issues for security problems.

Please do not open a public issue for a security problem.

Include what you can:

- affected component — `mail-service`, `mail-viewer`, `imap-bridge`, or `imap-server`
- the commit you tested
- steps to reproduce, with the request or the message that triggers it
- what an attacker gains

Expect a first reply within 7 days. BearerMail is maintained in spare time, so a fix usually takes longer than the acknowledgement.

## In scope

- remote code execution, authentication bypass, privilege escalation
- XSS in the webmail viewer, including bypasses of the HTML and CSS sanitizer in `mail-viewer/app.py`
- SMTP relay abuse — getting the server to deliver mail it should refuse
- SSRF through the image proxy or the IMAP bridge
- reading another mailbox's messages or attachments
- leaking `DUCKMAIL_API_KEY`, `RESEND_API_KEY`, or mailbox credentials

## Out of scope

- a deployment that skipped [docs/production-hardening.md](docs/production-hardening.md)
- running with the placeholder `SECRET_KEY`, `ACCESS_PASSWORD` from `.env.example`
- spam and deliverability caused by DNS records (SPF, DKIM, DMARC) under your control
- denial of service through raw traffic volume
- scanner output with no working proof of concept

## Supported versions

Fixes land on `master`. There are no long-lived release branches, so run a recent commit.

## Before you expose an instance

Read [docs/production-hardening.md](docs/production-hardening.md). Set every secret in `.env`, keep `AUTO_CREATE_ACCOUNTS=0` in production, and put the viewer behind TLS.
