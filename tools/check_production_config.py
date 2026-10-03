"""BearerMail production configuration self-check.

Run from the repository root after creating .env:
    python tools/check_production_config.py
"""

from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
COMPOSE_FILE = ROOT / "docker-compose.yml"

WEAK_VALUES = {
    "",
    "change-this-in-production",
    "your-strong-jwt-secret-here",
    "your-api-key-here",
    "same-as-API_KEY-above",
    "your-viewer-login-password",
    "random-flask-session-secret",
    "shared-mailbox-password",
    "openai123456",
    "CHOOSE-A-STRONG-LOGIN-PASSWORD",
    "change-me-to-a-long-random-string",
}


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _raw_env_lines(path: Path) -> dict[str, str]:
    raw: dict[str, str] = {}
    if not path.exists():
        return raw
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            raw[key.strip()] = value.strip()
    return raw


def is_weak(value: str) -> bool:
    return value.strip() in WEAK_VALUES or value.lower().startswith("your-")


def env_true(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    env = {**parse_env_file(ENV_FILE), **os.environ}
    errors: list[str] = []
    warnings: list[str] = []

    required_secret_keys = ["JWT_SECRET", "API_KEY", "DUCKMAIL_API_KEY", "ACCESS_PASSWORD", "SECRET_KEY", "SECRETS_KEY"]
    for key in required_secret_keys:
        value = env.get(key, "")
        if is_weak(value) or len(value) < 16:
            errors.append(f"{key} must be set to a strong non-default value (16+ chars recommended)")

    # Docker Compose reads "$" in .env as the start of a variable, so an unquoted password containing
    # "$" silently loses part of itself and the login page rejects the real password.
    for key, raw in _raw_env_lines(ENV_FILE).items():
        if "$" in raw and not (raw.startswith("'") and raw.endswith("'")) and "$$" not in raw:
            errors.append(f"{key} contains '$', which Docker Compose treats as a variable. Wrap the value in single quotes "
                          f"({key}='...') or use a value without '$'")
        elif raw.startswith('"') and "$" in raw:
            errors.append(f"{key} is in double quotes and contains '$'; Compose still expands it inside double quotes. Use single quotes")
        if " #" in raw and not raw.startswith(("'", '"')):
            warnings.append(f"{key} contains ' #'; everything after it is treated as a comment. Quote the value")

    # A setting written twice: Docker Compose silently uses the last one.
    seen: dict[str, int] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k = line.split("=", 1)[0].strip()
                seen[k] = seen.get(k, 0) + 1
    for k, n in seen.items():
        if n > 1:
            errors.append(f"{k} appears {n} times in .env; only the last one is used. Keep one line")

    # Share links (/s/...) must use the address people outside your network open BearerMail with.
    public = (env.get("PUBLIC_URL") or env.get("CORS_ORIGINS", "").split(",")[0]).strip()
    if not public:
        warnings.append("PUBLIC_URL is not set; share links use whatever address you browse with. Set PUBLIC_URL=https://your-web-address")
    elif re.search(r"your-|example\.|yourdomain", public):
        errors.append(f"PUBLIC_URL is still an example ('{public}'); set it to your real web address, e.g. https://mail.yourrealdomain.com")
    elif re.search(r"://(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", public):
        warnings.append(f"{'PUBLIC_URL' if env.get('PUBLIC_URL') else 'CORS_ORIGINS'} is a local address ({public}); share links will not "
                        "work outside your network. Set PUBLIC_URL to your public web address")
    elif public.endswith("/"):
        warnings.append("PUBLIC_URL ends with '/'; leave the trailing slash off")

    if env.get("DUCKMAIL_API_KEY") and env.get("API_KEY") and env["DUCKMAIL_API_KEY"] != env["API_KEY"]:
        warnings.append("DUCKMAIL_API_KEY differs from API_KEY; ensure mail-viewer can access admin endpoints")

    domains = [d.strip() for d in env.get("DOMAINS", "").split(",") if d.strip()]
    if not domains:
        errors.append("DOMAINS must include at least one receiving domain")

    for key in ("SMTP_HOSTNAME", "DOMAINS", "IMAP_HOSTNAME"):
        for part in [x.strip().lower() for x in env.get(key, "").split(",") if x.strip()]:
            if part in {"yourdomain.com", "example.com", "mail.yourdomain.com", "mail.example.com"} or part.endswith((".yourdomain.com", ".example.com")):
                errors.append(f"{key} still has the placeholder value '{part}'; set your real domain")
    server_ip = env.get("SERVER_IP", "").strip()
    if not server_ip:
        warnings.append("SERVER_IP is empty; the Setup screen cannot show your A and SPF records")
    elif server_ip in {"1.2.3.4", "0.0.0.0"}:
        errors.append("SERVER_IP still has the placeholder value; set your server's public IPv4")

    cors_origins = [o.strip() for o in env.get("CORS_ORIGINS", "").split(",") if o.strip()]
    if not cors_origins:
        errors.append("CORS_ORIGINS must be set for production")
    elif "*" in cors_origins:
        errors.append("CORS_ORIGINS must not use '*' in production")

    if env_true(env.get("ENABLE_API_DOCS", "0")):
        warnings.append("ENABLE_API_DOCS is enabled; keep interactive API docs disabled in production unless needed")
    if env_true(env.get("EXPOSE_HEALTH_DETAILS", "0")):
        warnings.append("EXPOSE_HEALTH_DETAILS is enabled; health responses may reveal internal status")

    ttl = env.get("MESSAGE_TTL_DAYS", "3").strip().lower()
    if ttl in {"0", "forever", "none", "never", "off", "disabled"}:
        warnings.append("MESSAGE_TTL_DAYS disables automatic cleanup; ensure backups and storage monitoring are configured")
    elif not ttl.isdigit() or int(ttl) < 1:
        errors.append("MESSAGE_TTL_DAYS must be a positive integer, or 0/forever to disable cleanup")

    try:
        max_message_bytes = int(env.get("SMTP_MAX_MESSAGE_BYTES", "20971520"))
        if max_message_bytes < 1:
            errors.append("SMTP_MAX_MESSAGE_BYTES must be positive")
        elif max_message_bytes < 10 * 1024 * 1024:
            warnings.append(f"SMTP_MAX_MESSAGE_BYTES is only {max_message_bytes // 1024} KB: emails with photos or PDFs above that "
                            "are refused and the sender gets a bounce. 20971520 (20 MB) is recommended")
        elif max_message_bytes > 20 * 1024 * 1024:
            warnings.append("SMTP_MAX_MESSAGE_BYTES is above 20 MB; BearerMail caps it at 20 MB (MongoDB's 16 MB document limit)")
    except ValueError:
        errors.append("SMTP_MAX_MESSAGE_BYTES must be an integer byte count")

    if env_true(env.get("AUTO_CREATE_ACCOUNTS", "0")):
        warnings.append("AUTO_CREATE_ACCOUNTS is enabled; only use this behind strong access controls")

    if env.get("IMAP_ACCOUNT_PERSISTENCE", "encrypted").strip().lower() not in {"disabled", "off", "0"}:
        key = env.get("IMAP_ACCOUNT_ENCRYPTION_KEY", "")
        if is_weak(key) or len(key) < 32:
            errors.append("IMAP_ACCOUNT_ENCRYPTION_KEY must be configured with a strong 32+ char key, or disable IMAP_ACCOUNT_PERSISTENCE")

    cert = env.get("SMTP_TLS_CERT", "")
    tls_key = env.get("SMTP_TLS_KEY", "")
    if bool(cert) != bool(tls_key):
        errors.append("SMTP_TLS_CERT and SMTP_TLS_KEY must be configured together")
    if not cert or not tls_key:
        warnings.append("SMTP STARTTLS is not configured; inbound SMTP will advertise no STARTTLS")

    imap_certs_path = env.get("IMAP_CERTS_PATH", "")
    if not imap_certs_path:
        warnings.append("IMAP_CERTS_PATH is not set; docker-compose will use ./certs for IMAPS certificates")

    if COMPOSE_FILE.exists():
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        if re.search(r'"0\.0\.0\.0:5000:5000"|"5000:5000"', compose):
            warnings.append("mail-viewer appears publicly exposed; prefer binding it to 127.0.0.1 behind a reverse proxy")
        if re.search(r'"0\.0\.0\.0:8080:8080"|"8080:8080"', compose):
            warnings.append("mail-service API appears publicly exposed; prefer binding it to 127.0.0.1")

    print("BearerMail production configuration check")
    print("=" * 43)
    for item in errors:
        print(f"ERROR: {item}")
    for item in warnings:
        print(f"WARN:  {item}")
    if not errors and not warnings:
        print("OK: no obvious production configuration issues detected")
    elif not errors:
        print("OK with warnings")
    else:
        print("FAILED")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
