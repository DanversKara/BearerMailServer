# BearerMail

Self-hosted email for your own domain.

- Receive mail for your domain and read it in a web app.
- Create **mailboxes** and **disposable aliases** that deliver into a mailbox you choose.
- Read your mail in **Thunderbird** or on **Android** over **IMAP**.
- **Send** (and reply from an alias) through a 3rd-party SMTP provider such as **Mailjet**.
- **App passwords** (like Gmail's) for mail apps, and **SMTP keys** for scripts, so nobody ever needs the real password or the provider's secret.
- A personal **Drive** (upload, download, save emails as PDF/Word, share links with a password) and a **Calendar** (import invitations, send invitations, share events).
- A **storage quota** per mailbox, shown under Recent.
- See the exact **MX, SPF, DKIM and DMARC** records for each domain on screen, with a **Check DNS** button.

## Side Note:
- When sending large files by email, keep in mind that most email services have a file-size limit of around 20–25 MB.

Before sending the email, go to Drive and create a folder specifically for the email you’re about to send. Upload all the necessary files into that folder, then click Share and Create link.

Next, compose your email and include the Drive link instead of attaching the files directly. This makes it easier for the recipient to access the content without running into email attachment-size restrictions.

Once the recipient has finished accessing the files, you can delete the folder or set it to automatically expire/delete after a certain period.

## How it fits together

```
Internet ──25──► mail-service (SMTP receiver + API) ──► MongoDB ◄── imap-server ◄──993── Thunderbird / Android
Mail apps ─587/465─►    │  (SMTP keys) ──► your SMTP provider (Mailjet...) ──► Internet
                        ▲                                    
                  mail-viewer (web app, :5000) ◄── your reverse proxy (HTTPS) ◄── you
                        └──► imap-bridge (optional: read Gmail/Outlook etc. inside the web app)
```

| Port | Who can reach it | Purpose |
|---|---|---|
| **25** | Internet | Incoming mail |
| **993** | Internet | IMAP for Thunderbird / Android (needs a TLS certificate) |
| **587, 465** | Internet (optional) | Sending from mail apps with an SMTP key (same certificate as 993). `SUBMISSION_BIND=127.0.0.1` closes them. |
| **5000** | Your reverse proxy only | Web app. Never forward it on your router. |
| 8080, 3939 | This server / Docker network only | Internal API and bridge. Never expose them. |

Everything runs on your server. No mail, key or telemetry is sent to any third party; the only outbound mail goes through the SMTP provider you configure. Built on the MIT-licensed [ManyMail](https://github.com/margbug01/ManyMail) by margbug01, with an English UI and a new Setup area.

---

## 1. What you need

| Requirement | Notes |
|---|---|
| A server with a public IPv4 | Ubuntu/Debian is fine. |
| **Port 25 open inbound** | Many clouds block it by default. Ask your host to unblock it if needed. |
| Docker + Docker Compose | `docker compose version` must work. |
| A domain you control | You will add DNS records for it. |
| A TLS certificate for your mail hostname | Only needed for IMAP (Thunderbird / Android). `./setup.sh` can get one (section 4). |
| An SMTP provider account (optional, for sending) | Mailjet, SendGrid, Brevo, Mailgun, SES... |

## 2. Install

```bash
git clone <this repository> bearermail && cd bearermail
./setup.sh
```

The installer asks for your domain, mail hostname, server IP, the web app address and an admin password. It writes `.env` with fresh random secrets, optionally gets the TLS certificate for IMAP (section 4), checks the configuration and starts everything. It refuses placeholder values such as `yourdomain.com`.

Check that it is running:

```bash
docker compose ps
```

You should see `mail-mongodb`, `mail-service`, `mail-viewer`, `mail-imap-bridge` and `mail-imap-server`. The IMAP server waits until a certificate exists; the others start normally.

Then, once:
1. Forward **port 25** (and **993** for IMAP, **587** for sending from mail apps) on your router or firewall to this server.
2. In DNS, create `A mail.yourdomain.com -> your IP` and `MX yourdomain.com -> mail.yourdomain.com` (priority 10). If you use Cloudflare, set both to **DNS only** (grey cloud).

### 2.1 What is in `.env`

| Variable | What it does |
|---|---|
| `SMTP_HOSTNAME` / `IMAP_HOSTNAME` | Your mail hostname, e.g. `mail.yourdomain.com`. Shown on the Setup screen and used by mail apps. |
| `DOMAINS` | Your receiving domain(s), comma separated. More can be added on the Setup screen. |
| `SERVER_IP` | Your public IPv4. Shown in the A and SPF records on the Setup screen. |
| `ACCESS_PASSWORD` | The password on the web login page. |
| `SECRETS_KEY` | Encrypts saved SMTP passwords and DKIM keys. **Back it up.** If you lose or change it you must re-enter your SMTP passwords. |
| `API_KEY` / `DUCKMAIL_API_KEY` | Must be the **same value**. The internal admin key between the web app and the mail service (the name "DuckMail" is a leftover from the original project; it does not contact any DuckMail server). Also protects the external IMAP bridge. Never share it. |
| `ALLOW_PUBLIC_REGISTRATION` | Default `0`: creating mailboxes over the API needs the admin key. Leave it off. |
| `ALLOW_PRIVATE_IMAP_HOSTS` | Default `0`: the external IMAP bridge refuses private/local server addresses. |
| `TRUSTED_PROXY_COUNT` | Number of reverse proxies in front of the web app (see Login security). |
| `SESSION_HOURS` | How long a web login lasts (default 168). |
| `WEB_BIND` / `WEB_PORT` | Which address and port the web app listens on. `127.0.0.1` (default) means only this server; `0.0.0.0` opens it to your network (needed when the reverse proxy is on another machine). |
| `CORS_ORIGINS` | The public URL of the web app. |
| `CHECK_SENDER_AUTH` | `1` (default) checks SPF, DKIM and DMARC on incoming mail and warns about fake senders. |
| `SMTP_ENFORCE_DMARC_REJECT` | `1` refuses mail that fails DMARC when the sender's domain publishes `p=reject`. Default `0`: warn only. |
| `SECURITY_LOG_DAYS` | How long the security log is kept (default 30). |
| `ALLOW_EMERGENCY_ADMIN` | Personal-accounts mode only: `1` lets `ACCESS_PASSWORD` sign in as admin with the email `admin`. Keep `0` except when locked out. |
| `SUBMISSION_BIND` | Address for the sending ports 587/465 (SMTP keys). Default `0.0.0.0`; `127.0.0.1` closes them to the outside. |
| `SUBMISSION_ENABLED` | `0` turns the sending ports off completely. Default `1`. |
| `DEFAULT_QUOTA_MB` | Storage per mailbox (mail + Drive) in MB, default 5120. `0` = unlimited. Changeable per user. |
| `DRIVE_MAX_FILE_MB` / `ATTACH_FROM_DRIVE_MAX_MB` | Largest Drive upload (default 100 MB; a Cloudflare Tunnel allows at most 100 MB) and the most Drive files attached to one email (default 20 MB). |
| `PUBLIC_URL` | The web app's public address, used in share links. Defaults to `CORS_ORIGINS`. |
| `RELAY_HOURLY_LIMIT` / `RELAY_MAX_RCPTS` | Per SMTP key: messages per hour (default 100, can be changed per key) and recipients per message (default 50). |
| `MESSAGE_TTL_DAYS` | `0` keeps mail forever. A number (e.g. `3`) auto-deletes old mail, handy for pure disposable use. |
| `IMAP_CERTS_PATH`, `IMAP_TLS_CERT`, `IMAP_TLS_KEY` | Where the IMAP certificate lives (section 4). |

Keep `.env` private. After editing it, run `docker compose up -d` again. Values containing `$` must be in single quotes (`KEY='va$lue'`), because Docker Compose treats `$` as a variable. `python3 tools/check_production_config.py` checks it for mistakes.

To do the setup by hand instead, copy `.env.example` to `.env` and replace **every** example value.

### 2.2 Open the web app

The web app listens on port 5000. Put HTTPS in front of it with a reverse proxy:

- **Proxy on the same server** (Caddy, Nginx): forward to `127.0.0.1:5000`.
- **Proxy on another machine** (Nginx Proxy Manager, a Cloudflare Tunnel): set `WEB_BIND=0.0.0.0` in `.env`, forward to `http://<this server's LAN IP>:5000`, and do **not** forward port 5000 on your router.
- **Quick look, no proxy:** `ssh -L 5000:127.0.0.1:5000 user@your-server`, then open `http://localhost:5000`.

Sign in with `ACCESS_PASSWORD`. There is one shared admin password and no username.

## 3. First-time setup (in the web app)

Open the **Setup** tab and follow **Get started**:

1. **Domains & DNS.** Add your domain. Copy the records shown (A, MX, SPF, DKIM, DMARC) into your DNS provider, then press **Check DNS now**. Changes can take a few minutes.
2. **Mailboxes.** Create your main mailbox and save its password. This is what you use in Thunderbird and on Android.
3. **3rd-party SMTP.** Choose your provider, enter its SMTP login, press **Test**.
4. **Disposable aliases.** Create named or random addresses. Mail sent to an alias lands in the mailbox you chose. You can disable or delete an alias at any time.
5. **Connect a mail app.** Shows your IMAP settings and the outgoing (SMTP) settings for your SMTP keys.
6. **APIs.** Create SMTP keys for yourself and your users (section 6).

### Moving to (or adding) another domain

The DNS records for a domain point its **MX** at a *mail server name*. By default that is `SMTP_HOSTNAME` from `.env`
(for example `mail.olddomain.com`), for every domain. That keeps working while that name's DNS still points to your server.
To make a domain independent (or when you give the old domain up):

1. Setup > Domains & DNS > the domain > Show DNS records > **Mail server name for this domain**: e.g. `mail.newdomain.com`.
   The MX and A records shown change to that name; publish them and press Check DNS now.
2. Get a TLS certificate that covers the new name (`./setup.sh` again, or your own), because Thunderbird and phones connect
   to it on 993 and 587. The Connect-a-mail-app page shows each person the name for their domain.
3. When the old domain is gone completely, also change `SMTP_HOSTNAME` and `IMAP_HOSTNAME` in `.env` and run
   `docker compose up -d`. The DNS page warns when the mail server name is not on one of your active domains.
4. Set the domain's *Web address for share links*, and `PUBLIC_URL` in `.env`.

### Using aliases

Mail to `shop-x7k2@yourdomain.com` is stored in your main mailbox and tagged with the alias it was sent to. In the web app, open the alias to see only that alias's mail. To reply *from* the alias, click **Compose** (the big button above your addresses; the round button on a phone) and choose it under **Send as**.

**Catch-all:** on a domain you can choose a mailbox to receive mail for *any* address that does not exist. Leave it off to reject unknown addresses.

## 4. TLS certificate (needed for IMAP)

Thunderbird and Android connect straight to port 993 on your server and need a valid TLS certificate for your mail hostname. A web reverse proxy (Nginx Proxy Manager, Cloudflare Tunnel) cannot provide it because it never sees that traffic. The IMAP server **refuses to run without a certificate** and retries by itself, so it starts as soon as one appears.

`./setup.sh` can get one for you. Choose:

1. **Let's Encrypt with Cloudflare DNS.** Works behind proxies and tunnels and needs no open port 80. Create a Cloudflare API token with the **Edit zone DNS** template for your zone. Certificates renew with `./setup.sh renew` (the installer prints the cron line).
2. **Let's Encrypt on port 80.** Port 80 must reach this server and be free.
3. **Your own certificate files.**

Keep port 993 closed on your router until the certificate is in place. `IMAP_ALLOW_INSECURE=1` exists for local testing only; it sends passwords unencrypted.

## 5. Read your mail in Thunderbird or Android

BearerMail supports **IMAP** (not JMAP).

| Setting | Value |
|---|---|
| Server | your mail hostname, e.g. `mail.yourdomain.com` |
| Port | `993` |
| Security | SSL/TLS |
| Authentication | Normal password |
| Username | your full mailbox address |
| Password | an **app password** (recommended, see below) or the mailbox password |

Apps: Thunderbird, Thunderbird for Android, FairEmail, K-9 Mail.

### App passwords (My account > App passwords)

Like Gmail: instead of typing your real password into Thunderbird, your phone or some other program, create an **app
password** for it (16 letters, shown once). Your username stays your email address, and one app password works for both
reading (993) and sending (587/465). Make one per app or device; if a phone is lost or an app looks shady, **revoke** just
that one, nothing else changes.

- **Mail apps must use an app password** (switch under My account): the real password then only works in the web app
  (together with two-factor). Turning it off again asks for the password.
- Admins can switch it on for one person (Setup > Users > Manage) or for **everyone** (Setup > Users, top).
- The Security page shows which app password a mail app used ("Thunderbird 128, app password "Laptop"") and refuses
  mail apps that still send the real password when app passwords are required.
- Only a hash is stored. App passwords are listed (and can be revoked by an admin) under Setup > APIs too.

## 6. Sending mail

**From the web app:** Compose, choose your mailbox or alias under **Send as**, send. It goes out through your SMTP provider and appears in the Sent list.

**From Thunderbird / Android:** BearerMail accepts mail from your apps on ports **587** (STARTTLS) and **465** (SSL/TLS)
and sends it on through your SMTP provider. The app signs in like it does for incoming mail, never with the provider's
own API key and secret.

| Setting | Value |
|---|---|
| Server | your mail hostname, e.g. `mail.yourdomain.com` |
| Port / security | `587` with STARTTLS, or `465` with SSL/TLS |
| Authentication | Normal password |
| Username / password | your email address + an app password (or the mailbox password, unless app passwords are required). Scripts can use an SMTP key (`bm-...`) instead. |

- Thunderbird: Account Settings, **Outgoing Server (SMTP)**, **Add**. Then in **Manage Identities**, add each alias as an extra identity to send from it.
- Android: Account settings, **Outgoing server**.

Messages sent this way also appear in the web app's Sent list.

### SMTP keys (Setup > APIs)

Your provider (Mailjet, Brevo...) has one secret. If you handed it to every user, one abuser would force you to change it
and send the new one to everyone. Instead, each person gets **their own key**:

- **Setup > APIs** (admin): choose the mailbox, a label ("Jane's phone"), optionally the provider and an hourly limit,
  **Create key**. The password is shown **once**; give it to the person. The list shows every key, when it was last used,
  from where and how many messages it sent.
- **Revoke** stops that key at once, even in a mail app that is signed in right now. Nobody else is affected.
  **Revoke all** does it for every key of one mailbox. Turning off **Send mail** for a user stops all their keys too.
- Users can make their own keys under **Setup > Connect a mail app** (one per device is best), unless you turn off
  *Create their own SMTP keys* for them under Setup > Users > Manage. At most 5 active keys per person.
- A key can only send **from its own mailbox and that mailbox's aliases** (checked on the envelope and on the visible From
  line), only through the providers that mailbox is allowed, up to `RELAY_HOURLY_LIMIT` messages an hour and
  `RELAY_MAX_RCPTS` recipients per message. Ten wrong passwords from one address lock it out for 15 minutes.
- Only a hash of the key's password is stored. The provider's secret never leaves the server.
- Ports 587/465 use the **same TLS certificate as IMAP** (`IMAP_CERTS_PATH`). Without it they stay off and Setup > APIs
  says why; the HTTP API below still works. Passwords never cross the network unencrypted: port 587 refuses to sign in
  before STARTTLS.

**Scripts and apps (HTTP API):** send with the same key, through the web app's address:

```bash
curl https://mail.yourdomain.com/api/v1/send \
  -H "Authorization: Bearer bm-xxxxxxxxxxxx:bmk_the-password" \
  -H "Content-Type: application/json" \
  -d '{"from": "you@yourdomain.com", "to": ["friend@example.com"], "subject": "Hello", "text": "Hi!"}'
```

Fields: `from`, `to`, `cc`, `bcc`, `subject`, `text` and/or `html`, `reply_to`, `from_name`, `attachments`
(`[{"filename", "content_type", "content": base64}]`). HTTP Basic authentication with the key also works.

### Example: Mailjet

1. In Mailjet, add your domain under *Sender domains & addresses*. Copy the DKIM and SPF records it shows.
2. In BearerMail, Setup, Domains & DNS, your domain, *Records from your SMTP provider*: paste them in.
3. Setup, 3rd-party SMTP: choose **Mailjet**, enter your **API Key** (username) and **Secret Key** (password), press **Test**.
4. Mail apps do not need these: give each person an SMTP key (Setup > APIs) instead of the Mailjet API key and secret.

Providers only send from domains and addresses you have verified with them.

## 7. Drive, Calendar and storage

### Drive

The **Drive** tab is a personal file store for each mailbox (files are kept in MongoDB, so the backup below includes them).

- **Upload** (button or drag and drop, with progress), folders, rename, move, delete, download. Images, PDFs and text files
  open in the browser; anything else downloads (uploaded web pages never run inside BearerMail).
- **Save an email to Drive** (... menu of a message): as **PDF**, **Word (.docx)** or **.eml**, into "Saved emails".
  Attachments can be saved one by one into "Attachments". Sent mail has **Save PDF** too. The PDF holds the text of the
  message; remote pictures are never downloaded for it.
- **Compose > From Drive**: *Attach* adds a copy of the file (up to `ATTACH_FROM_DRIVE_MAX_MB`, default 20 MB in total),
  *Link* puts a share link into the message instead (better for big files).
- **Share links**: ... > Share link gives a short link like `https://mail.yourdomain.com/s/Ab3dE9xY`, optionally with a
  **password** and an **expiry** (1 day to a year, or until you turn it off). The recipient sees a small download page; no
  account needed. **Shared links** lists every link with its views and downloads, and **Turn off** stops one at once.
  Deleting the file turns its links off. Admins can take the right away per person (Users > Manage > *Make public share links*).
  **Which address a link uses:** each domain can have its own web address (Setup > Domains & DNS > *Web address for share
  links*, e.g. `https://mail.yourdomain.com`). A link uses the address of the sender's mailbox domain, or another domain they
  were given (a choice appears when there are several). Domains without one, or removed/disabled domains, fall back to
  `PUBLIC_URL` (or `CORS_ORIGINS`) from `.env`. Each such address must reach this web app, e.g. as a Cloudflare Tunnel
  public hostname pointing at the web app.

### Calendar

- Month and list views; click a day or **New event**. Times are shown in your browser's time zone.
- **From an email**: ... > **Add to calendar**. An attached invitation (.ics, as sent by Google, Outlook, Zoom...) is
  imported with its time and place (importing it again updates it). Without one, a new event is prefilled from the email.
- **Invite people**: open an event > **Email invitation**, or **Compose > Invite**. The email carries a standard invitation
  that Gmail, Outlook and phone calendars show with Accept / Decline; recipients become the event's guests.
- **Share** an event with a link (optional password and expiry): the page shows the event and an *Add to my calendar* button.
- **Download .ics** for any event.

### Storage

Each mailbox has a quota (default `DEFAULT_QUOTA_MB`, 5 GB) for its mail plus its Drive files. A bar **under Recent** shows
how much is used (yellow above 80 %, red above 95 %). When it is full, uploads and saving to Drive stop; **incoming mail is
still accepted**. Admins change the quota per person under Setup > Users > Manage > *Storage (MB)* (empty = the default,
`0` = unlimited).

### Dynamic IP (home internet) with Cloudflare

If your public IP can change, open **Setup > Domains & DNS > Dynamic IP & Cloudflare**:

1. At Cloudflare: **My Profile > API Tokens > Create Token > "Edit zone DNS"** template, pick your zone(s)
   (it needs *Zone · DNS · Edit* and *Zone · Zone · Read*), create it and copy the token.
2. Paste it, press **Save**, and turn on **Watch this server's public IP** (and *Update Cloudflare automatically*).
3. Press **Check IP & preview** to see what it would change, or **Update Cloudflare now**.

From then on, an IP change updates the A records that pointed at the old IP and the `ip4:` part of SPF at
Cloudflare, and the DNS page shows the new IP at once. Nothing needs restarting. Each domain's DNS records
also get an **Apply to Cloudflare** button that creates or fixes A, MX, SPF, DKIM and DMARC for you.

Keep the mail hostname (e.g. `mail.yourdomain`) as **DNS only** (grey cloud): mail can't pass through
Cloudflare's proxy. Your web address can stay on a Cloudflare Tunnel.

## 8. Inbox tabs and flood protection

The inbox is sorted into tabs: **Primary, Favorites, Security, Promotions, Social, Updates, Forums, Work,
School** and any you add. New mail is sorted when it arrives; older mail the first time you open the mailbox.

- **Move** (on an open email, or on selected emails) puts mail in another tab. Pick "always put email from
  this sender" (or the whole @domain) and future mail goes there too. Favorites works the same way.
- **Security** collects password changes, new sign-ins, codes and SIM / phone-number changes, so a flood
  of junk can't bury them. Forged senders never land there.
- When a mailbox gets `MAIL_FLOOD_THRESHOLD` (default 30) emails in an hour, the inbox shows a **Mail flood**
  warning. Check the Security tab and your phone carrier / bank accounts right away.
- The gear at the end of the tab row turns tabs off, hides tabs, and edits tabs and sorting rules.

## 9. Everyday commands

```bash
docker compose ps                     # what is running
docker compose logs -f mail-service   # live logs (also: mail-viewer, imap-server)
docker compose restart                # restart everything
docker compose down                   # stop (mail is kept)
docker compose up -d --build          # rebuild after changing code
```

### Update to a new version

```bash
# unzip the new version over the old folder, keeping your .env
unzip -o bearermail.zip -d /tmp/bm && cp -r /tmp/bm/bearermail/. ~/mailserver/
cd ~/mailserver && python3 tools/check_production_config.py && docker compose up -d --build
```

Your mail (Docker volumes) and `.env` are untouched. The app refuses to start if `.env` still has an example secret or no `ACCESS_PASSWORD`.

### Backup

Your mail, Drive files and calendars live in the Docker volume `mongo_data`, not in the project folder. Back up:

```bash
docker compose exec -T mongodb mongodump --archive --gzip > bearermail-backup.gz
```

Also keep a copy of `.env` (especially `SECRETS_KEY`).

Restore into a running stack:

```bash
docker compose exec -T mongodb mongorestore --archive --gzip --drop < bearermail-backup.gz
```

### Remove BearerMail

```bash
docker compose down          # stops it, KEEPS your mail
docker compose down -v       # stops it AND DELETES all mail (the volume). Cannot be undone.
```

## 10. Troubleshooting

| Problem | What to check |
|---|---|
| `.env` is empty / containers fail at start | Run `./setup.sh` again. |
| Setup screen shows `yourdomain.com` or `1.2.3.4` | `SMTP_HOSTNAME`, `DOMAINS` or `SERVER_IP` in `.env` still has the example value. Fix it and run `docker compose up -d`. |
| Web app loads but the Setup tab is empty | Rebuild the web app image: `docker compose up -d --build mail-viewer`. |
| Web app not reachable from the proxy machine | Set `WEB_BIND=0.0.0.0` in `.env`, then `docker compose up -d`. |
| App exits at start with "refusing to start" | `.env` still has an example secret or no `ACCESS_PASSWORD`. Run `python3 tools/check_production_config.py`. |
| Login page rejects the password | It is `ACCESS_PASSWORD` from `.env` (no username). A `$` in the value is read by Docker Compose as a variable and silently cuts the password: wrap it in single quotes (`ACCESS_PASSWORD='...'`) or avoid `$`. `python3 tools/check_production_config.py` warns about this. After editing `.env`, run `docker compose up -d --force-recreate mail-viewer`. |
| Lost the phone with the two-factor app | Sign in with one of your recovery codes. No codes left: `docker compose exec mail-viewer rm /data/security.json` turns two-factor off (and signs everyone out), then set it up again. |
| Personal accounts: locked out of the admin mailbox | Set `ALLOW_EMERGENCY_ADMIN=1` in `.env`, `docker compose up -d`, sign in with email `admin` + `ACCESS_PASSWORD`. Or switch back to single-password mode from the terminal: `docker compose exec mongodb mongosh mailserver --quiet --eval 'db.settings.updateOne({_id:"auth"},{$set:{mode:"single"}})'` |
| A user lost the phone with their two-factor app | They can use a recovery code. Otherwise an admin: Setup > Users > Manage > Turn off their 2FA. |
| Locked yourself out with the block list | `docker compose exec mongodb mongosh mailserver --quiet --eval 'db.ip_blocklist.deleteMany({})'` |
| Thunderbird keeps the old mailbox password | Settings > Privacy & Security > Saved Passwords, remove the `imap://` entry, restart Thunderbird. |
| No mail arrives | `MX` record must point at your mail hostname, the hostname's `A` record at your server IP, and port 25 must be open (`ss -tlnp \| grep :25`). Use **Check DNS now**. |
| "Domain not accepted" from senders | The domain is missing under Setup, Domains & DNS. |
| IMAP will not connect | Certificate missing or wrong hostname. Check `docker compose logs imap-server`. The hostname in your app must match the certificate. |
| Test send says "Authentication failed" | Wrong provider username or password. For Mailjet the username is the API key and the password is the secret key. |
| Provider refuses the sender address | Verify that domain or address in the provider's dashboard. |
| Sent mail lands in spam | Publish SPF, DKIM and DMARC (Check DNS now) and the provider's own records. New domains also take time to build reputation. |
| Saved SMTP password suddenly fails | `SECRETS_KEY` changed. Re-enter the password in Setup, 3rd-party SMTP, Edit. |
| Setup > APIs says the sending ports are off | No certificate at `IMAP_CERTS_PATH` (the same one port 993 uses), or `SUBMISSION_ENABLED=0`. `docker compose logs mail-service \| grep -i submission` shows why. |
| `docker compose up` fails: port 587 or 465 "address already in use" | Something else on the server uses it (e.g. a local Postfix). Stop it, or set `SUBMISSION_BIND=127.0.0.1` in `.env`. |
| Mail app refused after turning on "app passwords only" | Create an app password under My account and put it in the app's password field (incoming and outgoing). The Security log shows "mailbox password refused". |
| Share links point to `127.0.0.1` or `http://` | Set `PUBLIC_URL=https://mail.yourdomain.com` in `.env` (or a correct `CORS_ORIGINS`) and run `docker compose up -d`. |
| Drive upload fails at about 100 MB | Cloudflare Tunnel and many proxies cap uploads at 100 MB. Nginx: `client_max_body_size 100m;`. |
| "Your storage is full" | Delete Drive files or old mail (empty the Trash), or raise the quota under Setup > Users > Manage. |
| Mail app: "authentication failed" on port 587 | Use your email address with an app password (or an SMTP key's `bm-...` username and password). Revoked ones stop working at once. |
| Mail app: sending refused with "can only send from..." | A key only sends from its own mailbox and that mailbox's aliases. Check the identity/From address in the app. |

## 11. Security page and email privacy

Open **Setup > Security** (the **Settings** gear in the top bar, or the ⋮ menu on a phone, then Security).

- **Overview.** What reached each port in the last day (or 7 / 30 days): port 25 connections, relay attempts, bots trying to log in on port 25, forged senders; port 993 sign-ins, wrong passwords, throttled addresses, broken TLS from scanners; ports 587/465 messages sent with SMTP keys, wrong or revoked keys, attempts to send as someone else; web app sign-ins and failures; external accounts. Below that, who is connected **right now**: mail apps on port 993 (with the app name, e.g. "Thunderbird 128", its address and folder, and an **End** button), signed-in web browsers (with **Sign out**), and the Gmail/Outlook/... accounts the external-accounts bridge keeps open. Suspicious addresses get a **Block** button.
- **Activity.** The full log, filterable by port, severity and IP address. Repeats from the same address are grouped per hour. Kept for `SECURITY_LOG_DAYS` (default 30). The **block list** (single addresses or ranges, for an hour, a day, a week or permanently) applies to port 25, port 993 and the web app. Your own current address and private networks cannot be blocked.
- **Sign-in.** Two-factor sign-in for the web app with any authenticator app (Google/Microsoft Authenticator, Aegis, 1Password, Bitwarden...), with 10 one-time recovery codes. Sessions are kept on the server: signing out, or **Sign out all others**, ends them for real, so a copied cookie stops working.
- **Privacy.** Hide remote images until you click, ask before suspicious links, strip tracking tags from links, and the list of senders whose images are always shown.
- **DMARC reports.** Your DMARC record (`rua=mailto:...`) asks Gmail, Microsoft, Yahoo and others to send a daily report about
  mail they received *claiming to be from your domains*. These reports (a .zip or .gz of XML) mean nothing to someone
  reading mail, so BearerMail recognises them when they arrive and files them here instead of in the inbox. You see, per
  sending server, how many messages it sent as your domain and whether they passed SPF/DKIM: green rows are your own servers
  (this server, your SMTP provider), **red rows** are someone faking your address or a service you forgot to set up.
  When everything is green for a few weeks, the page suggests tightening your DMARC policy to `p=quarantine`.
  *Collect reports from mailboxes* files reports that arrived earlier (and moves those emails to Trash). A switch keeps a
  copy in the inbox as well. Only reports about your own domains are taken; others stay normal mail.
- **Alerts.** Email alerts (sent through your SMTP provider) for a web sign-in from a new address, a mail app signing in from a new address, password guessing, and forged senders.

**Other ports.** Containers cannot see the rest of the server. For every listening port, live connections, firewall-blocked attempts and SSH sign-in attempts, run `sudo ./tools/port_report.sh` (read-only; `sudo ./tools/port_report.sh 6` for the last 6 hours). Blocked attempts appear if the firewall logs them (`sudo ufw logging low`).

### Reading a message

- **Remote images are hidden** until you press **Show images** (or choose **Always from this sender**). Loading a picture from the internet tells the sender that, and when, you opened the message. Pictures are always fetched by the server's image proxy, so senders see the server's address, never your device's.
- **Tracking pixels** (1x1 images, hidden images, known tracking services) stay blocked even after Show images. Styles that try to load images (`background:url(...)`) are removed; before this version they loaded straight from your browser.
- **Sender check.** Every incoming message is checked with SPF, DKIM and DMARC. A red banner means the message claims a domain that did not send it (a typical phishing mail); a verified sender gets a small check mark. A name that contains a different address ("PayPal service@paypal.com" sent from elsewhere) and a Reply-To on another domain are pointed out. Mail apps get the result too, as an `Authentication-Results` header. `SMTP_ENFORCE_DMARC_REJECT=1` refuses mail that fails DMARC when the sender's domain asks for that.
- **Links** whose text shows one website but lead to another, links to raw IP addresses, look-alike (punycode) domains and link shorteners are outlined; clicking one shows the real address and asks first.
- **Read receipts.** When a sender asks for one, you are told. BearerMail never sends read receipts.
- **Attachments are scanned** when mail arrives (older mail the first time it is opened): programs and scripts, disguised names (`invoice.pdf.exe`), disk images, macro documents, password-protected archives, PDFs with JavaScript, and documents or web pages that **contact the internet when opened** (which would tell the sender you opened them). Risky ones are marked red and ask before downloading.
- Thunderbird and phone apps have their own image setting: in Thunderbird, Settings > Privacy & Security > untick "Allow remote content in messages".

### On a phone or tablet

The web app adapts to the screen: on a phone the tabs move to the bottom, there is a round Compose button (also on tablets; on a computer Compose is the large button at the top left), a message opens full screen (the phone's Back gesture returns to the list), Compose fills the screen, and the Setup tables turn into cards. A tablet shows the list and the message side by side. The app reopens the mailbox you used last.

## 12. Personal accounts (multi-user)

By default BearerMail has **one shared password** (`ACCESS_PASSWORD`) that opens everything. Turn on **personal accounts**
under **Setup > Users** to run it like Gmail for a family or small team:

- Everyone signs in with **their own mailbox address and password** (the same password their mail apps use) and can turn on
  **their own two-factor sign-in** under **My account**.
- A regular user only sees **their own mailbox and its aliases**. They cannot open anyone else's mail, see the Setup screens,
  the Security page or the logs. This is checked by the server on every request, not just hidden in the page.
- **Admins** (you pick the first one when switching; promote others later) manage everything: domains, mailboxes, users,
  SMTP, keys, security. Like everyone else, their **Your addresses**, **Recent** and **Send as** lists only hold their own
  mailbox and its aliases, so other people's addresses never appear there (and a shared browser keeps a separate Recent
  list per account).
- **Stealth sign-in** (admins): Setup > Users (or Mailboxes) > **Stealth sign-in** opens a user's mailbox **read-only**.
  A banner shows whose mail you are looking at, with **Return to my account**. Nothing changes that the person could
  notice: messages stay unread, nothing can be sent, deleted or changed, their "last sign-in" and their list of signed-in
  browsers stay the same, and they get no alert. It is recorded in the admins' Security log (who looked at which
  mailbox, when). Admins cannot open other admins' mailboxes this way. The emergency admin has no mailbox of its own and
  uses stealth sign-in to look into one.
- **Domains per user:** people only ever see their own mailbox's domain and the domains you tick for them under Setup >
  Users > Manage > *Domains they may use*. Those are the only domains they can make aliases on and use for share links;
  your other domains stay invisible to them. Admins can use every domain.
- For each user the admin decides whether they may **send mail**, **through which shared SMTP providers**, **add their own
  SMTP provider** (private to them), **create aliases** (and how many), **add external accounts** (Gmail, Outlook..., private
  to them), **create their own SMTP keys** and **change their own password**. Admins can reset a password, turn off someone's two-factor if they lost
  their phone, disable an account (signs it out at once) or delete it.

**Turning it on:** Setup > Users > choose the admin mailbox, optionally give it a new password, enter the current
`ACCESS_PASSWORD` to confirm, **Turn on personal accounts**. Everyone is signed out; sign in again with the admin mailbox's
address and password. **Add a user** creates their mailbox; give them the address and password.

**The old shared password** stops working. If you ever lock yourself out, set `ALLOW_EMERGENCY_ADMIN=1` in `.env`, run
`docker compose up -d`, and sign in with the email **`admin`** and `ACCESS_PASSWORD` (plus its two-factor code if you set
one under Security > Sign-in). Set it back to `0` afterwards. You can also switch back to one shared password under
Setup > Users at any time.

## 13. Good to know

- **Appearance** (Setup, Appearance): pick a theme (Mint, Blossom Pink, Blossom Pink Dark, Red, Red Dark; saved in your browser; the login page has its own colour dots). Upload up to four logos, one each for the signed-in header and the login page, for light and dark themes. Empty slots fall back to the closest logo you did upload, and with none the text name is shown. Logos are shared by everyone and kept in the `viewer_data` volume.
- **New mail alerts** (Setup, Appearance): a browser notification plus a short sound when new mail arrives in the mailbox you have open. It works while BearerMail is open in a browser tab, needs HTTPS and the browser's permission, and is set per browser. Sound only plays after you have clicked something on the page once (a browser rule). Alerts are not sent while the browser is closed.
- **Top bar:** **Settings** (gear) opens the Setup area; the arrow next to it signs out. On a phone or tablet both are in the ⋮ menu.
- The inbox refreshes itself every 15 seconds. Turn it off with the **Auto** switch; your choice is remembered.
- One `SECRETS_KEY` protects every saved SMTP password and DKIM key.
- The web app holds an admin API key internally. Keep it behind HTTPS and a strong `ACCESS_PASSWORD`.
- Run `python tools/check_production_config.py` after editing `.env`. See also `docs/production-hardening.md`.
- Aliases are not separate inboxes. They are addresses that deliver into a mailbox.

### External IMAP bridge (Gmail, Outlook...)

In the web app you can add an existing Gmail/Outlook/Yahoo etc. account to read it alongside your own mail. Use an **app password**, not your main password. The bridge runs only on the internal Docker network, requires the internal key, refuses private/local server addresses, and stores credentials encrypted (`IMAP_ACCOUNT_PERSISTENCE`).

### Security model

- **Mailbox passwords.** Each mailbox has its own password (bcrypt). There is no shared or default mailbox password. A mailbox the web app auto-creates for an unknown address gets a random password; set one under Setup, Mailboxes before using it in an IMAP app.
- **Startup guards.** The app will not start with example secrets or a missing login password. Only set `ALLOW_INSECURE_DEFAULTS=1` for local testing.
- **Input handling.** Fields must be plain strings (NoSQL operators are refused), user data is escaped in the UI, outgoing IMAP responses have line breaks stripped, and the image proxy and admin proxy reject redirects, `..` paths and private addresses.
- **Disabled or deleted mailboxes** stop working immediately, including tokens already issued.
- **Limits.** IMAP command size, idle timeout and connections per IP are capped (`IMAP_MAX_CONN_PER_IP`, default 20).
- **No outside requests.** Bootstrap, the icons, Quill and the fonts are served by the web app itself, and a Content-Security-Policy stops the page and message frames from loading anything from other servers.
- **Not done yet.** Non-root / read-only containers (switching needs care with existing volumes and ports 25/993).
- **Code audit.** The code was reviewed for backdoors and calls to the original author's servers; none were found and the leftover defaults were removed.

### Login security

- The login has no username. It is one shared password, compared in constant time, with no database lookup (so nothing to inject into).
- Failed logins are rate limited per visitor address (`LOGIN_RATE_LIMIT_MAX` attempts per `LOGIN_RATE_LIMIT_WINDOW` seconds, default 10 per 5 minutes). Set `TRUSTED_PROXY_COUNT` to the number of reverse proxies in front of the app (1 for Nginx Proxy Manager or Caddy, 2 for a Cloudflare Tunnel in front of that) so the real visitor address is used and a forged `X-Forwarded-For` header cannot bypass the limit.
- The limit lives in memory per worker and resets on restart, and it cannot stop a very large distributed attack. So use a long random password (`setup.sh` generates one), turn on two-factor sign-in (Setup > Security > Sign-in), keep the app behind HTTPS, and consider a rate limit or access rule at Cloudflare or your proxy.
- IMAP logins (port 993) are throttled too: an address is blocked for 15 minutes after 10 failed logins in 10 minutes (`IMAP_MAX_AUTH_FAILURES`, `IMAP_AUTH_WINDOW_SECONDS`, `IMAP_AUTH_BLOCK_SECONDS`; `0` turns it off). Passwords are stored as bcrypt hashes.
- Request fields must be plain strings. Objects such as `{"$gt": ""}` are refused before they can reach a database query, and nothing in the project runs shell commands.
- The session cookie is HttpOnly, SameSite=Strict, and Secure in production. The web app and bridge containers drop all Linux capabilities and cannot gain privileges. Non-root users and read-only filesystems are not enabled.
- Sessions last `SESSION_HOURS` (default 168). They are recorded on the server (`viewer_data` volume), so logout, "Sign out all others" and ending a session on the Security page take effect immediately. Logout is POST only.
- Changing two-factor settings asks for the password again. The two-factor secret is stored encrypted with a key derived from `SECRET_KEY`; changing `SECRET_KEY` turns two-factor off in practice (see Troubleshooting).

## 14. Development and tests

```bash
cd mail-service && pip install -r requirements.txt pytest mongomock httpx pytest-asyncio && python -m pytest tests
cd mail-viewer  && ENVIRONMENT=development python -m pytest tests
cd imap-server && npm ci && npm test
cd mail-viewer/imap-mail-app && npm ci && npm test
```

## 15. Change a mailbox password from the terminal

The same as Setup > Mailboxes > Reset password in the web app. List your mailboxes:

```bash
docker compose exec mongodb mongosh mailserver --quiet --eval 'db.accounts.find({}, {address:1, is_active:1, _id:0})'
```

Set a new password for a mailbox:

```bash
docker compose exec mail-service python -c '
import bcrypt, getpass, os
from pymongo import MongoClient
db = MongoClient(os.getenv("MONGO_URL", "mongodb://mongodb:27017"))[os.getenv("DB_NAME", "mailserver")]
a = input("Mailbox address: ").strip().lower()
p = getpass.getpass("New password: ")
if len(p) < 8: raise SystemExit("Password must be at least 8 characters")
h = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
r = db.accounts.update_one({"address": a}, {"$set": {"password_hash": h}})
print("Password updated" if r.matched_count else "No mailbox with that address")
'
```

It asks for the address and then the new password. The password won't show while you type. Special characters like `$` are fine here, since the password never passes through the shell or `.env`.

## License

MIT. Original work (c) margbug01 https://github.com/margbug01/ManyMail; modifications (c) the BearerMail authors.
