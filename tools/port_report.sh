#!/usr/bin/env bash
# BearerMail port report: every port on this server, not just BearerMail's.
#
# BearerMail's Security page shows what reaches ports 25, 993 and the web app. Containers cannot
# see the rest of the machine (SSH, other services, scans against closed ports), so this script
# looks at the host itself:
#
#   1. Which ports are listening, and which program owns them
#   2. Live connections right now, grouped by port and remote address
#   3. Connection attempts the firewall blocked (needs UFW logging or iptables LOG rules)
#   4. SSH sign-in attempts
#
# Usage:  sudo ./tools/port_report.sh            (last 24 hours)
#         sudo ./tools/port_report.sh 6          (last 6 hours)
# Read-only: it changes nothing.

set -uo pipefail
HOURS="${1:-24}"
case "$HOURS" in (*[!0-9]*|'') echo "Usage: $0 [hours]"; exit 1;; esac
TOP="${TOP:-15}"

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
note() { printf '  %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Tip: run with sudo to see program names and firewall/SSH logs." >&2
fi

bold "1. Listening ports (open to connections)"
if have ss; then
  ss -H -tulpn 2>/dev/null | awk '{
      proto=$1; local=$5; proc=$7;
      n=split(local, a, ":"); port=a[n]; addr=substr(local, 1, length(local)-length(port)-1);
      scope=(addr ~ /^(127\.|\[::1\]|::1)/) ? "this machine only" : (addr ~ /^(0\.0\.0\.0|\*|\[::\]|::)$/ ? "ALL networks" : addr);
      gsub(/users:\(\("|".*/, "", proc);
      printf "  %-4s %-6s %-20s %s\n", proto, port, scope, proc
    }' | sort -k2,2n -u
else
  note "'ss' is not installed (package iproute2)."
fi
note "Ports shown as 'ALL networks' are reachable from outside unless your router or firewall blocks them."
note "BearerMail needs 25 and 993 open to the internet; 5000 should be 'this machine only' (or your LAN for a proxy)."

bold "2. Connections right now (established)"
if have ss; then
  ss -H -tn state established 2>/dev/null | awk '{
      n=split($3, l, ":"); lport=l[n];
      r=$4; m=split(r, p, ":"); raddr=substr(r, 1, length(r)-length(p[m])-1); gsub(/^\[|\]$/, "", raddr);
      print lport, raddr
    }' | sort | uniq -c | sort -rn | head -n "$TOP" | awk '{printf "  port %-6s from %-40s %s connection(s)\n", $2, $3, $1}'
  total=$(ss -H -tn state established 2>/dev/null | wc -l)
  note "$total established TCP connection(s) in total."
fi

bold "3. Blocked connection attempts (last ${HOURS}h)"
SINCE="$(date -d "-${HOURS} hours" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
fw_lines() {
  if have journalctl && [ -n "$SINCE" ]; then
    journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -E 'UFW BLOCK|IPTABLES|DROP|REJECT' || true
  fi
  for f in /var/log/ufw.log /var/log/kern.log; do
    [ -r "$f" ] && grep -hE 'UFW BLOCK' "$f" 2>/dev/null | tail -n 20000
  done
}
FW="$(fw_lines | sort -u)"
if [ -n "$FW" ]; then
  echo "  Most targeted ports:"
  printf '%s\n' "$FW" | grep -oE 'DPT=[0-9]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -n "$TOP" \
    | while read -r c p; do
        name=$(getent services "$p/tcp" 2>/dev/null | awk '{print $1}')
        printf '    port %-6s %-12s %s attempt(s)\n' "$p" "${name:-}" "$c"
      done
  echo "  Most active sources:"
  printf '%s\n' "$FW" | grep -oE 'SRC=[0-9a-fA-F:.]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -n "$TOP" \
    | awk '{printf "    %-40s %s attempt(s)\n", $2, $1}'
else
  note "No firewall log entries found."
  note "With UFW:  sudo ufw logging low   (then run this again later)."
  note "Blocked attempts only appear if the firewall logs them; open ports are covered by the Security page and section 2."
fi

bold "4. SSH sign-in attempts (last ${HOURS}h)"
SSH=""
if have journalctl && [ -n "$SINCE" ]; then
  SSH="$(journalctl --since "$SINCE" --no-pager -u ssh -u sshd 2>/dev/null | grep -E 'Failed password|Invalid user|Accepted|authentication failure' || true)"
fi
if [ -z "$SSH" ] && [ -r /var/log/auth.log ]; then
  SSH="$(grep -hE 'sshd.*(Failed password|Invalid user|Accepted)' /var/log/auth.log 2>/dev/null | tail -n 5000)"
fi
if [ -n "$SSH" ]; then
  ok=$(printf '%s\n' "$SSH" | grep -c 'Accepted' || true)
  bad=$(printf '%s\n' "$SSH" | grep -cE 'Failed password|Invalid user' || true)
  note "$ok successful sign-in(s), $bad failed attempt(s)."
  if [ "$ok" -gt 0 ]; then
    echo "  Successful sign-ins (check these are you):"
    printf '%s\n' "$SSH" | grep 'Accepted' | grep -oE 'for [^ ]+ from [0-9a-fA-F:.]+' | sort | uniq -c | sort -rn | head -n "$TOP" | sed 's/^/    /'
  fi
  if [ "$bad" -gt 0 ]; then
    echo "  Addresses guessing passwords:"
    printf '%s\n' "$SSH" | grep -E 'Failed password|Invalid user' | grep -oE 'from [0-9a-fA-F:.]+' | awk '{print $2}' \
      | sort | uniq -c | sort -rn | head -n "$TOP" | awk '{printf "    %-40s %s attempt(s)\n", $2, $1}'
  fi
else
  note "No SSH log entries found (or SSH is not installed)."
fi

bold "5. Docker published ports"
if have docker; then
  docker ps --format '  {{.Names}}: {{.Ports}}' 2>/dev/null | sed 's/, /\n     /g'
else
  note "docker not found."
fi
echo
