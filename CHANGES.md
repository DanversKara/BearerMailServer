# BearerMail changes

## Verification code banner

- Emails with a one-time / 2FA / verification code (4-8 digits, or a letter+digit code like `K7Q2PX`)
  now show a large **Verification code** box above the message with a **Copy code** button.
- Detection only triggers when the email reads like a code email ("verification code", "OTP", "2FA",
  "passcode", "PIN", "sign-in code", ...) and skips years, prices, phone numbers, times, zip codes
  and order/invoice numbers. The plain text part is searched first, then the HTML.

## Drive, Calendar, app passwords, storage and fixes

### Upgrade

```bash
cd ~/mailserver
cp .env .env.backup
unzip -o bearermail.zip -d /tmp/bm && cp -r /tmp/bm/bearermail/. ~/mailserver/
docker compose up -d --build
```

- Mail, users, keys and `.env` are kept. No `.env` changes are needed. Optional: `PUBLIC_URL=https://your-web-app-address`
  so share links use it (otherwise `CORS_ORIGINS`, then the address you browse with), and `DEFAULT_QUOTA_MB` (default 5 GB).
- The build takes a little longer once: the mail service now includes fonts (for PDFs) and three small libraries.

### Fixes

- **Sent:** messages can be deleted (tick them and press Delete, or Delete in the open message). Sent also has Forward.
- **Trash:** tick messages to **Restore** or **Delete forever**, and **Empty trash**.
- **Inbox:** the select bar now has **Read** and **Unread**.
- **"Unsent draft found":** the bar was always visible (even without a draft), so Restore and Discard seemed to do
  nothing. It now only appears when there is a draft, and Restore / Discard work.
- The External tab no longer reappears for people without that permission after switching tabs.
- The left column scrolls instead of squashing the Recent list.
- Mail that is only a file (like the daily DMARC reports from Google and Microsoft, which are a bare .zip) was shown as
  unreadable characters. It is now stored as an attachment. Reports that already arrived stay garbled; delete them.
- Share links: the share dialog warns when a link uses a local or example address, and `tools/check_production_config.py`
  now flags a missing or example `PUBLIC_URL` and any setting written twice in `.env` (Compose silently uses the last one).

### Domains per user and share-link addresses

- Setup > Users > Manage > **Domains they may use**: tick which of your domains a person may use for aliases and share
  links. They never see the others. Their own mailbox's domain is always included.
- Setup > Domains & DNS > **Web address for share links** per domain (e.g. `https://mail.newdomain.com`). Links use the
  web address of the person's domain (or a domain they choose, when they have several); removed domains fall back to
  `PUBLIC_URL`. So after moving to a new domain, links no longer show the old one.

- **Mail server name per domain** (Domains & DNS > Show DNS records): MX and A records can use e.g. `mail.newdomain.com`
  instead of `SMTP_HOSTNAME` for every domain. The page warns when the mail server name is on a domain that is no longer
  active (after moving domains). README: "Moving to (or adding) another domain".

### DMARC reports (Setup > Security > DMARC reports)

- The daily DMARC reports from Gmail, Microsoft, Yahoo... are now recognised on arrival and filed for the admins instead
  of landing in an inbox (a switch keeps copies in the inbox too).
- The page shows per sending server how much mail it sent as your domains and whether it passed; red rows are servers
  faking your address or a service you forgot to set up. Suggests when it is safe to tighten DMARC to `p=quarantine`.
- *Collect reports from mailboxes* files the ones that already arrived. Failures are also written to the security log.

### App passwords

- **My account > App passwords**: Gmail-style passwords for mail apps (email address + 16 letters). One works for reading
  (993) and sending (587/465). Revoke one without touching the others. Last use and address are shown.
- **Mail apps must use an app password** per person (they can switch it on; off needs their password) or for everyone
  (Setup > Users). The real password then only works in the web app, with two-factor.
- Sending on 587/465 also accepts the email address + mailbox password (unless app passwords are required), so a mail app
  can use the same login for incoming and outgoing mail. SMTP keys (`bm-...`) remain for scripts.

### Drive

- New **Drive** tab: upload (drag and drop, progress), folders, rename, move, delete, download, open images/PDFs/text.
- Save an email as **PDF, Word or .eml**, or an attachment, to Drive (... menu of a message; Save PDF on sent mail).
- **Compose > From Drive**: attach files, or insert a share link.
- **Share links** (`/s/Ab3dE9xY`) with optional password and expiry; a list of links with views/downloads; turn off any time.

### Calendar

- New **Calendar** tab: month and list views, events with time/all-day, place, guests, notes and colour.
- **Add to calendar** from an email imports the attached invitation (.ics), or prefills an event from the email.
- **Invitations**: Email invitation from an event, or Compose > Invite; recipients get a standard invite with Accept/Decline.
- Share an event with a link (optional password/expiry); download any event as .ics.

### Storage

- A quota per mailbox for mail + Drive (default 5 GB, per person under Setup > Users > Manage; 0 = unlimited).
- A bar under **Recent** shows the use. When full, Drive uploads stop; incoming mail is still accepted.

### Other

- On phones and tablets the bottom bar is Inbox, Sent, Drive, Calendar, Setup; Trash and External accounts are in the ⋮ menu.
- The web app now runs with threads, so a big upload or download never blocks everyone else.

## Privacy between accounts, stealth sign-in and SMTP keys

### Upgrade

```bash
cd ~/mailserver
cp .env .env.backup
unzip -o bearermail.zip -d /tmp/bm && cp -r /tmp/bm/bearermail/. ~/mailserver/
docker compose up -d --build
```

- Mail, mailboxes, users, SMTP providers and `.env` are kept. No `.env` changes are needed.
- **New ports 587 and 465** on the mail service (sending from mail apps with SMTP keys). They use the same certificate as
  IMAP. Forward 587 on your router if people should send from Thunderbird/phones outside your network. If
  `docker compose up` says the port is already in use, or you do not want them, set `SUBMISSION_BIND=127.0.0.1` in `.env`.

### Privacy between accounts

- **Recent** and unsent drafts are now kept **per account**. Before, people who used the same browser saw each other's
  recent addresses. The old shared list is removed once (in single-password mode it is kept).
- With personal accounts on, an admin's **Your addresses**, mailbox picker, **Recent** and **Send as** only list the
  admin's own mailbox and its aliases. Users' addresses no longer appear there.
- The server enforces it too: in personal-accounts mode nobody, admins included, can open or send from someone else's
  mailbox directly. The "Query Inbox" box (type any prefix) is only shown in single-password mode.

### Stealth sign-in (admins)

- **Setup > Users** and **Setup > Mailboxes** have **Stealth sign-in** instead of "Open inbox" for other people's mailboxes.
- Opens their mailbox **read-only** with a banner and **Return to my account**. Messages stay unread; sending, deleting,
  password, two-factor, keys and external accounts are blocked; their last sign-in, browser list and alerts are untouched.
- Each stealth sign-in and return is written to the admins' Security log. Admins cannot stealth into other admins.

### SMTP keys (Setup > APIs)

- New **APIs** tab: create a personal **SMTP key** for any mailbox (label, optional provider, optional hourly limit).
  The password is shown once and stored only as a hash. **Revoke** one key (or all keys of a mailbox) at any time;
  it stops at once, even mid-session, and nobody else is affected.
- Mail apps send with the key on **port 587 (STARTTLS)** or **465 (SSL/TLS)**; BearerMail relays through your provider,
  so users never see the Mailjet/Brevo API key or secret. Scripts use **`POST /api/v1/send`** with the same key.
- A key only sends from its own mailbox and aliases (envelope and From header), through providers that mailbox may use,
  within an hourly limit and a recipient limit. Wrong keys are throttled per address. Messages appear in Sent.
- Users see BearerMail's own SMTP settings and can create/revoke their own keys under **Connect a mail app** (new
  per-user permission *Create their own SMTP keys*, on by default). The provider's server and username are no longer
  shown to users.
- The Security page has a new **587/465** tile and log entries (keys used, wrong or revoked keys, sender refused).

### Header

- The Settings gear now opens the Setup area (it used to open a small "Quick domain list" pop-up, which is removed).
- The separate Security, My account and Appearance icons are gone from the top bar (they are tabs in Setup).
- **Compose** moved from the top bar to a large button at the top of the left column; phones and tablets keep the
  round Compose button.

## Security and mobile release

### Upgrade

```bash
cd ~/mailserver
cp .env .env.backup
unzip -o bearermail.zip -d /tmp/bm && cp -r /tmp/bm/bearermail/. ~/mailserver/
python3 tools/check_production_config.py
docker compose up -d --build
```

- Your mail, mailboxes, aliases, SMTP providers and `.env` are kept. No `.env` changes are required; the new
  settings (`CHECK_SENDER_AUTH`, `SMTP_ENFORCE_DMARC_REJECT`, `SECURITY_LOG_DAYS`) have safe defaults.
- **You will be signed out of the web app once** (sessions are now kept on the server). Sign in again.
- The config checker now also flags `.env` values that contain `$` without single quotes.
- Remote images in messages are now **hidden until you press "Show images"**. To keep the old behaviour, turn
  off "Hide remote images" under Setup > Security > Privacy.

### Personal accounts (Setup > Users)

- Optional **multi-account mode**, like Gmail for a family or team: everyone signs in with their own mailbox address,
  mailbox password and their own two-factor code, and only sees their own mailbox and aliases (enforced by the server).
- Admins pick who is admin and, per user, allow or block: sending, which shared SMTP providers, their own private SMTP
  provider, aliases (with a maximum), external accounts (kept private to each person) and changing their own password.
- Users get **My account** (password, two-factor, signed-in browsers), **My aliases** and **Sending**.
- Admins can reset passwords, turn off a user's two-factor, disable (signs out immediately) or delete accounts.
- The shared `ACCESS_PASSWORD` stops working in this mode, except as an emergency admin login when
  `ALLOW_EMERGENCY_ADMIN=1` (email `admin`). Switching back to a single password is one click.

### Email privacy and safety

- Remote images wait for "Show images" (per message), or "Always from this sender". Tracking pixels (1x1, hidden,
  known tracking services) stay blocked even then. A bar above each message says what was blocked.
- **Fixed a privacy leak:** a `style="background:url(...)"` in an email loaded straight from your browser,
  bypassing the image proxy and revealing your own IP address. Such styles are now removed.
- Incoming mail is checked with **SPF, DKIM and DMARC**. Forged senders get a red warning (and an icon in the
  list); verified senders a check mark. Also flagged: a display name containing a different address, a Reply-To
  on another domain. Mail apps receive the result as an `Authentication-Results` header.
  Optional: `SMTP_ENFORCE_DMARC_REJECT=1` refuses mail that fails DMARC with `p=reject`.
- **Links:** text that shows one site but links to another, raw IP addresses, look-alike (punycode) domains and
  shorteners are outlined and ask before opening. Tracking tags (`utm_*`, `fbclid`, ...) are removed from links.
- **Read-receipt requests** are pointed out (BearerMail never sends receipts).
- **Attachment scan:** programs/scripts, disguised names (`invoice.pdf.exe`), disk images, macro documents,
  password-protected archives, PDFs with JavaScript or auto-open links, and documents or web pages that contact
  the internet when opened (so the sender would learn you opened them). Risky files ask before downloading.
- The External accounts view (Gmail, Outlook...) hides remote images and blocks tracking pixels too.

### Sign-in security

- **Two-factor sign-in** (TOTP, any authenticator app) with 10 recovery codes. Turning it on or off asks for the
  password again.
- **Server-side sessions:** Sign out really ends the session; "Sign out all others"; list and end individual
  browser sessions.
- **Content-Security-Policy** and other security headers; Bootstrap, icons, Quill and fonts are now served by the
  web app itself (no requests to jsdelivr or Google Fonts).

### Security page (Setup > Security)

- Per-port activity for port 25 (connections, relay attempts, bots trying to log in, forged senders), port 993
  (mail-app sign-ins, wrong passwords, throttling, scanners), the web app and external accounts.
- **Connected right now:** mail apps on port 993 with their name ("Thunderbird 128"), address and folder, with an
  End button; web sessions; external IMAP accounts with their connection health and last error.
- Suspicious addresses with a **Block** button; an **IP block list** (addresses or ranges, timed or permanent)
  enforced on ports 25 and 993 and the web app.
- Activity log with filters, grouped per address per hour, kept `SECURITY_LOG_DAYS` days.
- **Email alerts** for new sign-in addresses (web and IMAP), password guessing and forged senders.
- `tools/port_report.sh`: every other port on the server (listening ports, live connections, firewall-blocked
  attempts, SSH sign-in attempts), which containers cannot see.

### Phone and tablet

- Phone: tabs at the bottom, round Compose button, one screen at a time with a Back button (and the phone's back
  gesture), full-screen Compose with Send always visible, compact dates, finger-sized buttons, Setup tables as
  cards, a mailbox picker in the empty list.
- Tablet: list and message side by side.
- The app reopens the mailbox you used last.

### Other

- IMAP server supports the `ID` command (mail apps identify themselves).
- The external-accounts bridge no longer contains command-line helpers that printed message subjects and bodies
  to the container log; its log messages are in English.
- CI now runs on the `main` branch (it was set to `master`, so it never ran) and a lint error in the tests was fixed.
