#!/usr/bin/env bash
# BearerMail installer. Asks a few questions, writes .env with fresh random secrets,
# optionally gets a TLS certificate for IMAP, and starts everything.
#
#   ./setup.sh          first-time setup (or reconfigure)
#   ./setup.sh renew    renew the Let's Encrypt certificate (run from cron)
set -euo pipefail
cd "$(dirname "$0")"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
say()  { printf '%s\n' "$*"; }
die()  { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { # ask "Question" "default" -> sets REPLY_VAL
  local prompt="$1" def="${2:-}" v
  if [ -n "$def" ]; then read -r -p "$prompt [$def]: " v; REPLY_VAL="${v:-$def}"
  else read -r -p "$prompt: " v; REPLY_VAL="$v"; fi
}
yesno() { local v; read -r -p "$1 [${2:-y}]: " v; v="${v:-${2:-y}}"; [[ "$v" =~ ^[Yy] ]]; }
rand()  { openssl rand -hex "$1"; }

need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed."; }
need docker; need openssl
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required ('docker compose version' must work)."

# ---------------------------------------------------------------- renew mode
if [ "${1:-}" = "renew" ]; then
  [ -f secrets/cloudflare.ini ] || die "No saved Cloudflare credentials (secrets/cloudflare.ini). Renew manually with certbot."
  docker run --rm -v "$PWD/letsencrypt:/etc/letsencrypt" -v "$PWD/secrets/cloudflare.ini:/cf.ini:ro" \
    certbot/dns-cloudflare renew --dns-cloudflare-credentials /cf.ini
  docker compose restart imap-server
  exit 0
fi

bold "BearerMail setup"
say  "Answer a few questions. Press Enter to accept the value in [brackets]."
say

if [ -f .env ]; then
  yesno ".env already exists. Replace it (a backup is kept as .env.bak)?" n || die "Cancelled. Nothing was changed."
  cp .env .env.bak
fi

# ---------------------------------------------------------------- questions
while :; do
  ask "Your domain (e.g. example.org)"; DOMAIN="$(echo "$REPLY_VAL" | tr 'A-Z' 'a-z')"
  [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$ ]] && break
  say "That does not look like a domain name."
done
case "$DOMAIN" in yourdomain.com|example.com|example.org) die "Use your real domain, not the example one.";; esac

ask "Mail hostname (the MX and IMAP name)" "mail.$DOMAIN"; MAILHOST="$(echo "$REPLY_VAL" | tr 'A-Z' 'a-z')"

DETECTED=""
DETECTED="$(curl -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
while :; do
  ask "This server's public IPv4 address" "$DETECTED"; SERVER_IP="$REPLY_VAL"
  [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [ "$SERVER_IP" != "1.2.3.4" ] && break
  say "Enter a valid public IPv4 address."
done

say
say "Where will you open the web app? If a reverse proxy (Nginx Proxy Manager, Caddy, Cloudflare Tunnel) will"
say "forward to it, enter the public address it will have, e.g. https://mail-admin.$DOMAIN"
while :; do
  ask "Web app URL" "http://127.0.0.1:5000"; WEB_URL="${REPLY_VAL%/}"
  [[ "$WEB_URL" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] && break
  say "Enter one full address like https://mail-admin.$DOMAIN (start with http:// or https://, no path)."
done
WEB_BIND="127.0.0.1"
say "Is your reverse proxy on THIS server, or on a different machine?"
say "  1) this server (or I will use an SSH tunnel)"
say "  2) a different machine on my network (open port 5000 to the LAN)"
ask "Choose 1 or 2" "1"
[ "$REPLY_VAL" = "2" ] && WEB_BIND="0.0.0.0"
say "How many reverse proxies are between the internet and the web app? (Nginx Proxy Manager or Caddy = 1;"
say "a Cloudflare Tunnel that feeds into one of those = 2; none = 0.) This keeps the login rate limit accurate."
ask "Number of proxies" "1"; PROXIES="$REPLY_VAL"
[[ "$PROXIES" =~ ^[0-9]$ ]] || PROXIES=1

while :; do
  read -r -s -p "Admin password for the web login (Enter to generate one): " ADMIN_PW; echo
  if [ -z "$ADMIN_PW" ]; then ADMIN_PW="$(rand 10)"; GENERATED_PW=1; break; fi
  if [ "${#ADMIN_PW}" -lt 10 ]; then say "Use at least 10 characters."; continue; fi
  if [[ "$ADMIN_PW" == *'$'* || "$ADMIN_PW" == *' '* || "$ADMIN_PW" == *'"'* || "$ADMIN_PW" == *"'"* || "$ADMIN_PW" == *'#'* ]]; then
    say "Please avoid spaces and the characters \$ # \" ' (they break .env files)."; continue; fi
  GENERATED_PW=0; break
done

# ---------------------------------------------------------------- write .env
KEY="$(rand 24)"
umask 077
cat > .env <<ENV
ENVIRONMENT=production
SMTP_HOSTNAME=$MAILHOST
DOMAINS=$DOMAIN
SERVER_IP=$SERVER_IP
IMAP_HOSTNAME=$MAILHOST
CORS_ORIGINS=$WEB_URL
WEB_BIND=$WEB_BIND
TRUSTED_PROXY_COUNT=$PROXIES
JWT_SECRET=$(rand 32)
API_KEY=$KEY
DUCKMAIL_API_KEY=$KEY
SECRET_KEY=$(rand 32)
SECRETS_KEY=$(rand 32)
ACCESS_PASSWORD=$ADMIN_PW
AUTO_CREATE_ACCOUNTS=0
MESSAGE_TTL_DAYS=0
IMAP_ACCOUNT_ENCRYPTION_KEY=$(rand 32)
ENV
chmod 600 .env
bold "Wrote .env"

# ---------------------------------------------------------------- TLS for IMAP
say
say "Thunderbird and Android connect to your server directly on port 993 and need a TLS certificate"
say "for $MAILHOST. (A reverse proxy cannot provide this.) How do you want to get one?"
say "  1) Let's Encrypt using Cloudflare DNS (works behind proxies and tunnels; needs a Cloudflare API token)"
say "  2) Let's Encrypt on port 80 (this server must be reachable on port 80 and nothing else may use it)"
say "  3) I already have certificate files"
say "  4) Skip for now (web mail and receiving work; IMAP starts once a certificate exists)"
ask "Choose 1-4" "1"; TLS_CHOICE="$REPLY_VAL"

set_env() { grep -v "^$1=" .env > .env.tmp || true; printf '%s=%s\n' "$1" "$2" >> .env.tmp; mv .env.tmp .env; chmod 600 .env; }

case "$TLS_CHOICE" in
  1)
    say "Create a token at https://dash.cloudflare.com/profile/api-tokens : template 'Edit zone DNS', zone = $DOMAIN."
    read -r -s -p "Cloudflare API token: " CF_TOKEN; echo
    [ -n "$CF_TOKEN" ] || die "No token entered."
    ask "Email for Let's Encrypt notices" "admin@$DOMAIN"; LE_EMAIL="$REPLY_VAL"
    mkdir -p secrets letsencrypt; chmod 700 secrets
    printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > secrets/cloudflare.ini; chmod 600 secrets/cloudflare.ini
    docker run --rm -v "$PWD/letsencrypt:/etc/letsencrypt" -v "$PWD/secrets/cloudflare.ini:/cf.ini:ro" \
      certbot/dns-cloudflare certonly --dns-cloudflare --dns-cloudflare-credentials /cf.ini \
      -d "$MAILHOST" -m "$LE_EMAIL" --agree-tos --non-interactive || die "Certificate request failed (see the message above)."
    set_env IMAP_CERTS_PATH ./letsencrypt
    set_env IMAP_TLS_CERT "/certs/live/$MAILHOST/fullchain.pem"
    set_env IMAP_TLS_KEY "/certs/live/$MAILHOST/privkey.pem"
    say "Renew every 60 days by adding this to cron (crontab -e):"
    say "  0 4 1 */2 * cd $PWD && ./setup.sh renew >> renew.log 2>&1"
    ;;
  2)
    ask "Email for Let's Encrypt notices" "admin@$DOMAIN"; LE_EMAIL="$REPLY_VAL"
    mkdir -p letsencrypt
    docker run --rm -p 80:80 -v "$PWD/letsencrypt:/etc/letsencrypt" certbot/certbot certonly --standalone \
      -d "$MAILHOST" -m "$LE_EMAIL" --agree-tos --non-interactive || die "Certificate request failed (is port 80 free and forwarded here?)."
    set_env IMAP_CERTS_PATH ./letsencrypt
    set_env IMAP_TLS_CERT "/certs/live/$MAILHOST/fullchain.pem"
    set_env IMAP_TLS_KEY "/certs/live/$MAILHOST/privkey.pem"
    say "To renew later, stop whatever uses port 80 and run:"
    say "  docker run --rm -p 80:80 -v $PWD/letsencrypt:/etc/letsencrypt certbot/certbot renew && docker compose restart imap-server"
    ;;
  3)
    ask "Path to fullchain.pem"; FC="$REPLY_VAL"; ask "Path to privkey.pem"; PK="$REPLY_VAL"
    [ -r "$FC" ] && [ -r "$PK" ] || die "Cannot read those files."
    mkdir -p certs; cp "$FC" certs/fullchain.pem; cp "$PK" certs/privkey.pem; chmod 600 certs/privkey.pem
    set_env IMAP_CERTS_PATH ./certs
    ;;
  *) say "Skipping. Run ./setup.sh again later to add a certificate." ;;
esac

# ---------------------------------------------------------------- check + start
if command -v python3 >/dev/null 2>&1; then
  python3 tools/check_production_config.py || die "Configuration check failed. Fix .env and run 'docker compose up -d --build'."
fi

if yesno "Start BearerMail now?" y; then
  docker compose up -d --build
  say; docker compose ps
fi

say
bold "Done. Next steps"
[ "${GENERATED_PW:-0}" = "1" ] && say "  Admin password (shown once, also in .env as ACCESS_PASSWORD): $ADMIN_PW"
say "  1. On your router forward port 25 (and 993 for IMAP) to this server."
say "  2. In your DNS add: A  $MAILHOST -> $SERVER_IP (DNS only, not proxied), and MX $DOMAIN -> $MAILHOST (priority 10)."
say "  3. Open $WEB_URL, sign in, then follow Setup > Get started (it shows the SPF, DKIM and DMARC records)."
say "  Back up .env: losing SECRETS_KEY means saved SMTP passwords must be re-entered."
