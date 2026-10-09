#!/usr/bin/env bash
# Holdfast Brick full-stack provisioner for a fresh DietPi or Raspberry Pi OS
# device (Debian bookworm or newer, arm64/armhf).
#
# Installs and wires: Unbound (DNS-over-TLS upstream), AdGuard Home, Tailscale,
# Headscale (self-hosted Tailscale control plane), ntopng, NextDNS CLI, Debian
# unattended security updates — then installs the Holdfast API (deploy/install.sh).
#
# Resulting DNS chain (default, "forward" mode):
#   LAN clients :53 -> AdGuard Home -> 127.0.0.1:5335 Unbound -> DoT (Cloudflare/Quad9 :853)
#
# Usage:
#   sudo bash deploy/provision.sh              # forward mode (Unbound -> DoT upstreams)
#   sudo bash deploy/provision.sh --recursive  # Unbound does full recursion itself
#                                              # (DNSSEC via trust anchor; not encrypted)
#
# Ports are user-designatable, as flags or environment variables (flags win):
#   --adguard-dns-port N   (default 53,   env ADGUARD_DNS_PORT)  DNS for the LAN
#   --adguard-ui-port N    (default 3000, env ADGUARD_UI_PORT)   AdGuard web UI
#   --unbound-port N       (default 5335, env UNBOUND_PORT)      localhost only
#   --nextdns-port N       (default 5054, env NEXTDNS_PORT)      localhost only
#   --ntopng-port N        (default 3001, env NTOPNG_PORT)       ntopng web/REST UI
#   --headscale-port N     (default 443,  env HEADSCALE_PORT)    household VPN TLS (must be free)
#   --api-port N           (default 8787, env API_PORT)          Holdfast API
#   e.g.  sudo bash deploy/provision.sh --adguard-ui-port 6969 --adguard-dns-port 54
#
# Safe to re-run: every step is idempotent. Config files that already exist
# with different content are backed up as <file>.bak.<epoch> before overwrite.
# Re-running with different ports rewrites the configs to the new ports.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Pinned upstream installer (audit M1) ─────────────────────────────────────
# The AdGuard Home installer script is fetched from a fixed, reviewed release
# tag instead of the mutable master branch — never execute a moving target as
# root. Re-check the tag whenever AdGuard ships a release (the patch SLA
# cadence: review the release notes, bump, re-run). Env var overrides.
# Checked 2026-10-09 against api.github.com AdguardTeam/AdGuardHome latest.
ADGUARD_INSTALLER_TAG="${ADGUARD_INSTALLER_TAG:-v0.107.79}"

# ── Ports used by the stack (env vars supply defaults, flags override) ───────
# For the AdGuard ports we track whether the user chose them explicitly:
# if not, a re-run ADOPTS whatever ports the wizard/user already configured
# in AdGuardHome.yaml rather than resetting them to the defaults.
ADGUARD_DNS_PORT_SET=0; ADGUARD_UI_PORT_SET=0
if [ -n "${ADGUARD_DNS_PORT:-}" ]; then ADGUARD_DNS_PORT_SET=1; fi
if [ -n "${ADGUARD_UI_PORT:-}" ]; then ADGUARD_UI_PORT_SET=1; fi
ADGUARD_DNS_PORT="${ADGUARD_DNS_PORT:-53}"      # AdGuard Home DNS, for the LAN
ADGUARD_UI_PORT="${ADGUARD_UI_PORT:-3000}"      # AdGuard Home web UI
UNBOUND_PORT="${UNBOUND_PORT:-5335}"            # Unbound, localhost only
NEXTDNS_PORT="${NEXTDNS_PORT:-5054}"            # NextDNS CLI (installed, NOT in chain)
NTOPNG_PORT="${NTOPNG_PORT:-3001}"              # ntopng web/REST UI
HEADSCALE_PORT="${HEADSCALE_PORT:-443}"         # Headscale TLS (household VPN)
API_PORT="${API_PORT:-8787}"                    # Holdfast API

RECURSIVE=0
while [ $# -gt 0 ]; do
  arg="$1"
  shift
  # Accept both "--flag value" and "--flag=value".
  case "$arg" in
    *=*) key="${arg%%=*}"; value="${arg#*=}"; inline=1 ;;
    *)   key="$arg";       value="${1:-}";    inline=0 ;;
  esac
  case "$key" in
    --recursive) RECURSIVE=1 ;;
    --adguard-dns-port) ADGUARD_DNS_PORT="$value"; ADGUARD_DNS_PORT_SET=1; if [ "$inline" -eq 0 ]; then shift; fi ;;
    --adguard-ui-port)  ADGUARD_UI_PORT="$value";  ADGUARD_UI_PORT_SET=1;  if [ "$inline" -eq 0 ]; then shift; fi ;;
    --unbound-port)     UNBOUND_PORT="$value";     if [ "$inline" -eq 0 ]; then shift; fi ;;
    --cloudflared-port)
      echo "NOTE: --cloudflared-port is obsolete (cloudflared's proxy-dns was discontinued" >&2
      echo "      upstream; Unbound now speaks DNS-over-TLS directly). Flag ignored." >&2
      if [ "$inline" -eq 0 ]; then shift; fi ;;
    --nextdns-port)     NEXTDNS_PORT="$value";     if [ "$inline" -eq 0 ]; then shift; fi ;;
    --ntopng-port)      NTOPNG_PORT="$value";      if [ "$inline" -eq 0 ]; then shift; fi ;;
    --headscale-port)   HEADSCALE_PORT="$value";   if [ "$inline" -eq 0 ]; then shift; fi ;;
    --api-port)         API_PORT="$value";         if [ "$inline" -eq 0 ]; then shift; fi ;;
    -h|--help)
      sed -n '2,29p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "Unknown argument: $key (see --help for supported flags)" >&2
      exit 1
      ;;
  esac
done

# Validate ports: numeric, 1-65535, no duplicates.
ALL_PORTS=""
for pair in "adguard-dns:${ADGUARD_DNS_PORT}" "adguard-ui:${ADGUARD_UI_PORT}" \
            "unbound:${UNBOUND_PORT}" \
            "nextdns:${NEXTDNS_PORT}" "ntopng:${NTOPNG_PORT}" \
            "headscale:${HEADSCALE_PORT}" "api:${API_PORT}"; do
  name="${pair%%:*}"; port="${pair##*:}"
  case "$port" in
    ''|*[!0-9]*) echo "Invalid ${name} port: '${port}' (must be a number)" >&2; exit 1 ;;
  esac
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "Invalid ${name} port: ${port} (must be 1-65535)" >&2; exit 1
  fi
  case " $ALL_PORTS " in
    *" $port "*) echo "Port ${port} is assigned twice — every service needs its own port." >&2; exit 1 ;;
  esac
  ALL_PORTS="$ALL_PORTS $port"
done

if [ "$ADGUARD_DNS_PORT" != "53" ]; then
  echo
  echo "NOTE: DNS port is ${ADGUARD_DNS_PORT}, not 53. Routers can only hand out a DNS *address*"
  echo "      via DHCP — there is no port field — so LAN devices will NOT use this port"
  echo "      automatically. Fine for testing; for whole-network filtering, move back"
  echo "      to 53 (or redirect 53 -> ${ADGUARD_DNS_PORT} on the Pi with nftables)."
  echo
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must run as root:  sudo bash deploy/provision.sh" >&2
  exit 1
fi

ARCH="$(dpkg --print-architecture)"       # arm64 / armhf / amd64
CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME:-bookworm}")"

stage() { echo; echo "════════════════════════════════════════════════════════"; echo "==> $*"; echo "════════════════════════════════════════════════════════"; }
note()  { echo "    -> $*"; }

BACKED_UP=()
CONFIG_CHANGED=0
# write_config <path> <<'EOF' ... — writes stdin to <path>; if the file already
# exists with different content it is backed up first (and we say so).
# Sets CONFIG_CHANGED=1 when the file was created or its content changed,
# CONFIG_CHANGED=0 when it was already identical — stages use this to skip
# restarting services that are already configured correctly.
write_config() {
  local dest="$1" tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
    CONFIG_CHANGED=0
    rm -f "$tmp"
    return 0
  fi
  if [ -f "$dest" ]; then
    local bak="${dest}.bak.$(date +%s)"
    cp -a "$dest" "$bak"
    BACKED_UP+=("$bak")
    note "Existing $dest differed — backed up to $bak"
  fi
  install -D -m 644 "$tmp" "$dest"
  rm -f "$tmp"
  CONFIG_CHANGED=1
}

# ensure_service <unit> <config_changed> — restart only when the config
# changed or the unit isn't running; otherwise leave a healthy service alone.
ensure_service() {
  local unit="$1" changed="$2"
  systemctl enable "$unit" >/dev/null 2>&1 || true
  if [ "$changed" -eq 1 ] || ! systemctl is-active --quiet "$unit"; then
    systemctl restart "$unit"
    note "${unit}: (re)started."
  else
    note "${unit}: already configured and running — skipping restart."
  fi
}

# set_env_kv <file> <key> <value> — idempotently set KEY=VALUE in an env file.
# Sets ENV_CHANGED=1 only when the value actually changed.
set_env_kv() {
  local file="$1" key="$2" value="$3"
  if grep -q "^${key}=${value}$" "$file" 2>/dev/null; then
    return 0
  fi
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
  ENV_CHANGED=1
}

# tailscale_control_url — best-effort read of the control server the brick's
# tailscaled is (or would be) talking to. Empty when it can't be determined.
tailscale_control_url() {
  tailscale debug prefs 2>/dev/null \
    | grep -oE '"ControlURL"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | head -1 | sed -e 's/.*:[[:space:]]*"//' -e 's/"$//' || true
}

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 0/10: Preflight — base packages, SSH hardening, detect environment"
# ─────────────────────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates gnupg apt-transport-https \
  dnsutils python3 python3-yaml python3-bcrypt
note "Architecture: ${ARCH}, Debian codename: ${CODENAME}"

# Base SSH hardening (audit H4) via a drop-in. Both Debian and Raspberry Pi OS
# (bookworm) ship `Include /etc/ssh/sshd_config.d/*.conf` as the FIRST line of
# /etc/ssh/sshd_config, so drop-ins are read before the main file's own
# directives win the first-match race. That Include is verified below rather
# than assumed — if it is missing the drop-in would be inert and silently give
# false confidence, so we skip with a warning instead.
# Deliberately NOT set here: PasswordAuthentication. The app's Remote Console
# flow installs a root SSH key on first pairing and then turns passwords off
# itself; hardening it here would lock the very first key install out.
# DietPi devices that run Dropbear instead of OpenSSH skip this block (Dropbear
# has its own config; X11Forwarding/MaxAuthTries are OpenSSH directives).
SSH_DROPIN=/etc/ssh/sshd_config.d/holdfast-base.conf
if [ -x /usr/sbin/sshd ]; then
  if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config 2>/dev/null; then
    SSH_PREV="$(mktemp)"
    [ -f "$SSH_DROPIN" ] && cp -a "$SSH_DROPIN" "$SSH_PREV"
    write_config "$SSH_DROPIN" <<'EOF'
# Installed by Holdfast provision.sh — base SSH hardening (audit H4).
# PasswordAuthentication is handled by the Holdfast API after the first SSH
# key is installed (see PROVISIONING.md), so it is deliberately not set here.
X11Forwarding no
MaxAuthTries 4
EOF
    if [ "$CONFIG_CHANGED" -eq 1 ]; then
      if SSHD_ERR="$(sshd -t 2>&1)"; then
        note "SSH drop-in installed and validated (sshd -t): X11Forwarding no, MaxAuthTries 4."
        if systemctl is-active --quiet ssh 2>/dev/null; then
          systemctl reload ssh || true
        fi
      else
        note "WARNING: sshd -t rejected the drop-in — rolling back. Output below."
        printf '%s\n' "$SSHD_ERR" | sed 's/^/    | /'
        if [ -f "$SSH_PREV" ]; then
          cp -a "$SSH_PREV" "$SSH_DROPIN"
        else
          rm -f "$SSH_DROPIN"
        fi
        sshd -t 2>/dev/null || note "WARNING: sshd config still invalid after rollback — inspect /etc/ssh/ manually."
      fi
    else
      note "SSH drop-in already installed and current."
    fi
    rm -f "$SSH_PREV"
  else
    note "WARNING: /etc/ssh/sshd_config has no 'Include /etc/ssh/sshd_config.d' line —"
    note "         SSH drop-ins would be ignored. Base SSH hardening skipped; check this OS's sshd packaging."
  fi
else
  note "No OpenSSH server installed (DietPi may run Dropbear) — nothing to harden yet."
fi

DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}')"
DEFAULT_IFACE="${DEFAULT_IFACE:-eth0}"
PI_IP="$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')"
PI_IP="${PI_IP:-<pi-ip>}"
note "Default interface: ${DEFAULT_IFACE}, address: ${PI_IP}"

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 1/10: Free port 53 (systemd-resolved stub listener, if present)"
# ─────────────────────────────────────────────────────────────────────────────
if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1 \
   && systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
  mkdir -p /etc/systemd/resolved.conf.d
  write_config /etc/systemd/resolved.conf.d/99-holdfastbrick.conf <<'EOF'
# Installed by Holdfast provision.sh — frees port 53 for AdGuard Home.
[Resolve]
DNSStubListener=no
EOF
  systemctl restart systemd-resolved || true
  note "systemd-resolved DNSStubListener disabled (port 53 freed)."
else
  note "systemd-resolved not active — nothing to do (typical on DietPi and Raspberry Pi OS)."
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 2/10: Unbound + encrypted DNS on 127.0.0.1:${UNBOUND_PORT}"
# ─────────────────────────────────────────────────────────────────────────────
if command -v unbound >/dev/null 2>&1; then
  note "Unbound already installed — skipping install."
else
  apt-get install -y -qq unbound
fi

# unbound-control is used by the Holdfast API — make sure its keys exist.
if [ ! -f /etc/unbound/unbound_control.key ]; then
  unbound-control-setup -d /etc/unbound
  note "unbound-control keys generated (unbound-control-setup)."
else
  note "unbound-control keys already present."
fi

if [ "$RECURSIVE" -eq 1 ]; then
  note "--recursive: Unbound will do full recursion itself (no DoT forward zone)."
  write_config /etc/unbound/unbound.conf.d/holdfastbrick.conf <<EOF
# Installed by Holdfast provision.sh (--recursive mode).
# Unbound performs full recursion from the root servers, validating DNSSEC
# via the auto-managed trust anchor (Debian ships
# unbound.conf.d/root-auto-trust-anchor-file.conf pointing at
# /var/lib/unbound/root.key). No forward zone: upstream queries go straight
# to the authoritative servers (plain DNS — not encrypted).
server:
    interface: 127.0.0.1
    port: ${UNBOUND_PORT}
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow

    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    qname-minimisation: yes
    prefetch: yes
    cache-min-ttl: 60
    cache-max-ttl: 86400
    edns-buffer-size: 1232

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
EOF
else
  write_config /etc/unbound/unbound.conf.d/holdfastbrick.conf <<EOF
# Installed by Holdfast provision.sh (forward mode).
# Unbound forwards everything over DNS-over-TLS directly to Cloudflare and
# Quad9 (native forward-tls-upstream — no separate DoH daemon; cloudflared's
# proxy-dns mode was discontinued upstream in Nov 2025), adding a local
# cache in between. Re-run provision.sh with --recursive for full recursion.
server:
    interface: 127.0.0.1
    port: ${UNBOUND_PORT}
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow

    # CA bundle to authenticate the DoT upstreams' certificates:
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    qname-minimisation: yes
    prefetch: yes
    cache-min-ttl: 60
    cache-max-ttl: 86400
    edns-buffer-size: 1232

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
EOF
fi

ensure_service unbound "$CONFIG_CHANGED"
note "Unbound on 127.0.0.1:${UNBOUND_PORT}."

# Retire any leftover Holdfast cloudflared unit: encrypted DNS is provided by
# Unbound's native DNS-over-TLS forwarding (configured above), and cloudflared's
# proxy-dns mode was discontinued upstream in Nov 2025. Earlier versions of
# this script installed cloudflared here, so re-runs clean it up.
if [ -f /etc/systemd/system/cloudflared.service ] \
   && grep -qE "(Privacy|Holdfast)Brick provision.sh" /etc/systemd/system/cloudflared.service; then
  systemctl disable --now cloudflared >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/cloudflared.service /etc/default/cloudflared \
        /etc/apt/sources.list.d/cloudflared.list
  systemctl daemon-reload
  note "Legacy Holdfast cloudflared unit removed (proxy-dns discontinued upstream)."
else
  note "No legacy Holdfast cloudflared unit — nothing to clean up."
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 3/10: AdGuard Home (official installer) — DNS :${ADGUARD_DNS_PORT}, UI :${ADGUARD_UI_PORT}"
# ─────────────────────────────────────────────────────────────────────────────
# AdGuard may already be installed several ways (this script's official
# installer, DietPi's dietpi-software package, a manual install), each with
# its own service name and config location. Detect what's actually there
# instead of assuming one layout.
AGH_UNIT=""
for unit in AdGuardHome adguardhome; do
  if systemctl cat "$unit" >/dev/null 2>&1; then AGH_UNIT="$unit"; break; fi
done

# Find the live config: prefer the path the systemd unit points at
# (ExecStart's -c/--config flag, else its -w/--work-dir flag, else systemd's
# WorkingDirectory=), then fall back to well-known install locations.
AGH_YAML=""
if [ -n "$AGH_UNIT" ]; then
  UNIT_TEXT="$(systemctl cat "$AGH_UNIT" 2>/dev/null || true)"
  # AdGuardHome's own installer (kardianos/service) writes ExecStart with
  # each argument individually quoted ("-c" "/path/x.yaml") — strip the
  # quotes first or the flag patterns never match.
  EXECSTART="$(printf '%s\n' "$UNIT_TEXT" \
    | sed -n 's/^ExecStart=//p' | head -1 | tr -d '"')"
  AGH_YAML="$(printf '%s\n' "$EXECSTART" \
    | sed -nE 's/.*(-c|--config)[= ]([^ ]*\.yaml).*/\2/p')"
  if [ -z "$AGH_YAML" ]; then
    # DietPi's unit passes the data dir via -w instead of -c, and sets no
    # WorkingDirectory= at all.
    WORKDIR="$(printf '%s\n' "$EXECSTART" \
      | sed -nE 's/.*(-w|--work-dir)[= ]([^ ]*).*/\2/p')"
    if [ -z "$WORKDIR" ]; then
      WORKDIR="$(printf '%s\n' "$UNIT_TEXT" \
        | sed -n 's/^WorkingDirectory=\(.*\)$/\1/p' | head -1)"
    fi
    if [ -n "$WORKDIR" ] && [ -f "${WORKDIR}/AdGuardHome.yaml" ]; then
      AGH_YAML="${WORKDIR}/AdGuardHome.yaml"
    fi
  fi
fi
if [ -z "$AGH_YAML" ] || [ ! -f "$AGH_YAML" ]; then
  AGH_YAML=""
  for candidate in /opt/AdGuardHome/AdGuardHome.yaml \
                   /opt/adguardhome/AdGuardHome.yaml \
                   /mnt/dietpi_userdata/adguardhome/AdGuardHome.yaml \
                   /etc/AdGuardHome/AdGuardHome.yaml \
                   /etc/adguardhome/AdGuardHome.yaml; do
    if [ -f "$candidate" ]; then AGH_YAML="$candidate"; break; fi
  done
fi

if [ -n "$AGH_UNIT" ]; then
  note "AdGuard Home service detected: ${AGH_UNIT} — skipping installer."
  note "AdGuard config: ${AGH_YAML:-not found yet (wizard not completed)}"
else
  # Official script per https://github.com/AdguardTeam/AdGuardHome, fetched
  # from the pinned release tag ADGUARD_INSTALLER_TAG (audit M1) — the master
  # branch is a moving target and this runs as root. The tag is re-reviewed at
  # each AdGuard release per the patch SLA; override via env if needed.
  curl -s -S -L --max-time 60 \
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/${ADGUARD_INSTALLER_TAG}/scripts/install.sh" \
    | sh -s -- -v
  AGH_UNIT="AdGuardHome"
  if [ -z "$AGH_YAML" ] && [ -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
    AGH_YAML=/opt/AdGuardHome/AdGuardHome.yaml
  fi
fi
systemctl enable "$AGH_UNIT" >/dev/null 2>&1 || true
systemctl start "$AGH_UNIT" || true

# AdGuard writes AdGuardHome.yaml only after its first-run wizard has been
# completed. Once that file exists — e.g. on a re-run of this script after
# the wizard — reconcile it with the chain:
#   1. DETECT the ports AdGuard is actually configured with. Unless the user
#      explicitly chose ports (flag/env), ADOPT the detected ones — a wizard
#      choice like UI :6969 / DNS :54 is respected, not reset to defaults.
#   2. PATCH the config (upstream = local Unbound, LAN bind, chosen ports)
#      only if something actually differs; a correctly-wired AdGuard is
#      left running untouched.
if [ -f "$AGH_YAML" ]; then
  read -r CUR_UI_PORT CUR_DNS_PORT <<AGHEOF
$(python3 - "$AGH_YAML" <<'PYEOF'
import sys, yaml
with open(sys.argv[1]) as f:
    cfg = yaml.safe_load(f) or {}
http = cfg.get("http") or {}
addr = str(http.get("address") or "")
if ":" in addr:                       # current schema: http.address "0.0.0.0:3000"
    ui = addr.rsplit(":", 1)[1]
else:                                 # older schema: top-level bind_port
    ui = str(cfg.get("bind_port") or http.get("port") or "0")
dns = str((cfg.get("dns") or {}).get("port") or "0")
print(ui or "0", dns or "0")
PYEOF
)
AGHEOF
  if [ "$ADGUARD_UI_PORT_SET" -eq 0 ] && [ "${CUR_UI_PORT:-0}" != "0" ] \
     && [ "$CUR_UI_PORT" != "$ADGUARD_UI_PORT" ]; then
    note "Detected existing AdGuard web UI port :${CUR_UI_PORT} — adopting it."
    ADGUARD_UI_PORT="$CUR_UI_PORT"
  fi
  if [ "$ADGUARD_DNS_PORT_SET" -eq 0 ] && [ "${CUR_DNS_PORT:-0}" != "0" ] \
     && [ "$CUR_DNS_PORT" != "$ADGUARD_DNS_PORT" ]; then
    note "Detected existing AdGuard DNS port :${CUR_DNS_PORT} — adopting it."
    ADGUARD_DNS_PORT="$CUR_DNS_PORT"
  fi

  AGH_STATE="$(python3 - "$AGH_YAML" "$ADGUARD_DNS_PORT" "$ADGUARD_UI_PORT" "$UNBOUND_PORT" check <<'PYEOF'
import sys, yaml
path, dns_port, ui_port, unbound_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
http_addr = str((cfg.get("http") or {}).get("address") or "")
dns = cfg.get("dns") or {}
ok = (
    http_addr.endswith(":%d" % ui_port)
    and dns.get("port") == dns_port
    and dns.get("bind_hosts") == ["0.0.0.0"]
    and dns.get("upstream_dns") == ["127.0.0.1:%d" % unbound_port]
)
print("OK" if ok else "DIFF")
PYEOF
)"
  if [ "$AGH_STATE" = "OK" ]; then
    note "AdGuard already wired (UI :${ADGUARD_UI_PORT}, DNS :${ADGUARD_DNS_PORT}, upstream Unbound) — skipping."
    systemctl start "$AGH_UNIT" 2>/dev/null || true
  else
    systemctl stop "$AGH_UNIT" || true
    BAK="${AGH_YAML}.bak.$(date +%s)"
    cp -a "$AGH_YAML" "$BAK"
    BACKED_UP+=("$BAK")
    note "Backed up existing AdGuard config to $BAK"
    python3 - "$AGH_YAML" "$ADGUARD_DNS_PORT" "$ADGUARD_UI_PORT" "$UNBOUND_PORT" <<'PYEOF'
import sys, yaml
path, dns_port, ui_port, unbound_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
cfg.setdefault("http", {})["address"] = "0.0.0.0:%d" % ui_port
dns = cfg.setdefault("dns", {})
dns["bind_hosts"] = ["0.0.0.0"]
dns["port"] = dns_port
dns["upstream_dns"] = ["127.0.0.1:%d" % unbound_port]
dns["bootstrap_dns"] = ["9.9.9.9", "1.1.1.1"]
with open(path, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
print("    -> Patched %s: DNS 0.0.0.0:%d, UI :%d, upstream 127.0.0.1:%d"
      % (path, dns_port, ui_port, unbound_port))
PYEOF
    systemctl start "$AGH_UNIT"
  fi
  ADGUARD_WIRED=1
else
  ADGUARD_WIRED=0
  note "No AdGuardHome.yaml yet — complete the first-run wizard at http://${PI_IP}:${ADGUARD_UI_PORT}"
  note "(choose web port ${ADGUARD_UI_PORT} and DNS port ${ADGUARD_DNS_PORT}), then RE-RUN this script"
  note "to wire AdGuard's upstream to Unbound automatically — or set the upstream to"
  note "127.0.0.1:${UNBOUND_PORT} yourself under Settings -> DNS settings."
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 4/10: ntopng on 127.0.0.1:${NTOPNG_PORT} (packages.ntop.org if reachable, else Debian)"
# ─────────────────────────────────────────────────────────────────────────────
NTOP_SOURCE="Debian apt"
if ! command -v ntopng >/dev/null 2>&1; then
  # Prefer the official ntop repo (fresher builds). Repo setup deb per
  # https://packages.ntop.org/ (RaspberryPI flavour for arm, apt flavour else).
  case "$ARCH" in
    arm64|armhf) APT_NTOP_URL="https://packages.ntop.org/RaspberryPI/apt-ntop.deb" ;;
    *)           APT_NTOP_URL="https://packages.ntop.org/apt/${CODENAME}/all/apt-ntop.deb" ;;
  esac
  if curl -fsIL --max-time 15 "$APT_NTOP_URL" >/dev/null 2>&1; then
    TMPDEB="$(mktemp --suffix=.deb)"
    curl -fsSL --max-time 60 -o "$TMPDEB" "$APT_NTOP_URL"
    dpkg -i "$TMPDEB" || apt-get install -y -qq -f
    rm -f "$TMPDEB"
    apt-get update -qq
    if apt-get install -y -qq ntopng; then
      NTOP_SOURCE="packages.ntop.org"
    else
      note "packages.ntop.org install failed (dependency mismatch is common on Pi) — falling back to Debian apt."
      rm -f /etc/apt/sources.list.d/ntop*.list
      apt-get update -qq
      apt-get install -y -qq ntopng
    fi
  else
    note "packages.ntop.org not reachable — installing ntopng from Debian apt."
    apt-get install -y -qq ntopng
  fi
else
  note "ntopng already installed — skipping install."
fi

mkdir -p /etc/ntopng
# Loopback-only bind (audit M5): ntopng's web/REST UI ships with no configured
# auth, so it is never exposed on the LAN. The household UI goes through the
# authenticated Holdfast API, which proxies ntopng's REST interface on 127.0.0.1.
write_config /etc/ntopng/ntopng.conf <<EOF
# Installed by Holdfast provision.sh.
# Web/REST UI bound to 127.0.0.1 only (audit M5); the Holdfast API proxies it.
# Direct LAN access is blocked by the nftables stage (and by the bind itself).
-w=127.0.0.1:${NTOPNG_PORT}
-i=${DEFAULT_IFACE}
EOF
# Debian's packaging wants this marker before it will start the service.
touch /etc/ntopng/ntopng.start 2>/dev/null || true

systemctl enable ntopng >/dev/null 2>&1 || true
if [ "$CONFIG_CHANGED" -eq 1 ] || ! systemctl is-active --quiet ntopng; then
  systemctl restart ntopng || note "WARNING: ntopng failed to start — check 'journalctl -u ntopng'."
else
  note "ntopng already configured and running — skipping restart."
fi
note "ntopng (${NTOP_SOURCE}) on 127.0.0.1:${NTOPNG_PORT} (loopback only — UI via the API), monitoring ${DEFAULT_IFACE}."

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 5/10: NextDNS CLI on 127.0.0.1:${NEXTDNS_PORT} (installed, NOT activated)"
# ─────────────────────────────────────────────────────────────────────────────
# Install straight from NextDNS's own apt repo (repo.nextdns.io). The
# nextdns.io installer script is interactive even under RUN_COMMAND=install —
# its configure() step loops forever prompting for a profile ID, which wedges
# headless devices — so it is never used here.
if command -v nextdns >/dev/null 2>&1 && [ -f /etc/apt/sources.list.d/nextdns.list ]; then
  note "NextDNS already installed from repo.nextdns.io — skipping repo setup and install."
else
  if [ ! -f /etc/apt/keyrings/nextdns.gpg ]; then
    mkdir -p /etc/apt/keyrings
    if ! curl -fsSL --max-time 30 https://repo.nextdns.io/nextdns.gpg \
         -o /etc/apt/keyrings/nextdns.gpg; then
      wget -q --timeout=30 -O /etc/apt/keyrings/nextdns.gpg \
        https://repo.nextdns.io/nextdns.gpg
    fi
    chmod 0644 /etc/apt/keyrings/nextdns.gpg
  fi
  write_config /etc/apt/sources.list.d/nextdns.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/nextdns.gpg] https://repo.nextdns.io/deb stable main
EOF
  apt-get update -qq
  apt-get install -y -qq nextdns \
    || note "WARNING: NextDNS install failed — check repo.nextdns.io reachability and re-run."
fi

if command -v nextdns >/dev/null 2>&1; then
  # NextDNS is an ALTERNATIVE cloud-filtering upstream. It listens on
  # 127.0.0.1:${NEXTDNS_PORT} but is deliberately NOT part of the DNS chain and is
  # NOT "activated" (it never touches /etc/resolv.conf or system DNS).
  # To route through NextDNS instead of the Unbound chain:
  #   1. nextdns config set -profile <your-profile-id>  && nextdns restart
  #   2. In AdGuard Home -> Settings -> DNS settings, replace upstream
  #      127.0.0.1:${UNBOUND_PORT} with 127.0.0.1:${NEXTDNS_PORT}.
  if nextdns config 2>/dev/null | grep -q "listen 127.0.0.1:${NEXTDNS_PORT}"; then
    note "NextDNS already listening on 127.0.0.1:${NEXTDNS_PORT} — skipping reconfigure."
  else
    nextdns config set -listen "127.0.0.1:${NEXTDNS_PORT}" >/dev/null
    nextdns restart >/dev/null 2>&1 || nextdns start >/dev/null 2>&1 || true
  fi
  note "NextDNS CLI listening on 127.0.0.1:${NEXTDNS_PORT} — standing by, not in the chain."
  note "(Switch AdGuard's upstream to 127.0.0.1:${NEXTDNS_PORT} to use it; see comments in this script.)"
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 6/10: Tailscale (official apt repo)"
# ─────────────────────────────────────────────────────────────────────────────
# Official repo per https://pkgs.tailscale.com/stable/ (bookworm).
if command -v tailscale >/dev/null 2>&1; then
  note "Tailscale already installed — skipping repo setup and install."
else
  if [ ! -f /usr/share/keyrings/tailscale-archive-keyring.gpg ]; then
    curl -fsSL "https://pkgs.tailscale.com/stable/debian/${CODENAME}.noarmor.gpg" \
      | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
  fi
  if [ ! -f /etc/apt/sources.list.d/tailscale.list ]; then
    curl -fsSL "https://pkgs.tailscale.com/stable/debian/${CODENAME}.tailscale-keyring.list" \
      | tee /etc/apt/sources.list.d/tailscale.list >/dev/null
  fi
  apt-get update -qq
  apt-get install -y -qq tailscale
fi
systemctl enable --now tailscaled

TAILSCALE_PENDING=0
if tailscale status >/dev/null 2>&1; then
  note "Tailscale already up: $(tailscale ip -4 2>/dev/null | head -1)"
else
  note "Running 'tailscale up' (30s window) — watch for the auth URL below:"
  set +e
  timeout 30 tailscale up 2>&1 | sed 's/^/    | /'
  set -e
  if tailscale status >/dev/null 2>&1; then
    note "Tailscale is up: $(tailscale ip -4 2>/dev/null | head -1)"
  else
    TAILSCALE_PENDING=1
    note "Not authenticated yet — that's fine. Visit the URL above, or just run"
    note "'sudo tailscale up' again later; nothing else here depends on it."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 7/10: Headscale — household VPN control plane (official DEB, checksum-verified) on :${HEADSCALE_PORT}"
# ─────────────────────────────────────────────────────────────────────────────
# Self-hosted Tailscale control plane: family phones run the official
# Tailscale apps pointed at the brick. TLS terminates on headscale itself with
# a certificate from a household root CA generated below (a LAN IP cannot get
# a certificate from a public CA). Enrolling the brick also MIGRATES its
# remote access off any prior Tailscale Inc login — intended product behavior.
HEADSCALE_PENDING=0
HS_ENROLLED=0
HS_CONFIGURED=0
HS_REISSUED=0
if [ "$HEADSCALE_PORT" = "443" ]; then
  HS_SERVER_URL="https://${PI_IP}"
else
  HS_SERVER_URL="https://${PI_IP}:${HEADSCALE_PORT}"
fi
BRICK_HOSTNAME="$(hostname)"
HS_ETC=/etc/headscale
HS_CA_DIR="${HS_ETC}/ca"
HS_STATE_DIR=/var/lib/headscale
HS_RUN_DIR=/var/run/headscale
HS_EXAMPLE=/usr/share/doc/headscale/examples/config-example.yaml

case "$ARCH" in
  arm64|amd64) HS_ARCH_OK=1 ;;
  *)
    HS_ARCH_OK=0; HEADSCALE_PENDING=1
    note "WARNING: headscale publishes arm64/amd64 DEBs only (this device: ${ARCH})."
    note "         Household VPN skipped — re-provision on a 64-bit OS to enable it."
    ;;
esac

if [ "$HS_ARCH_OK" -eq 1 ]; then

  # Install: official DEB from GitHub releases; skipped when the installed
  # version already matches (latest tag, or HEADSCALE_VERSION override).
  HS_INSTALLED=""
  if command -v headscale >/dev/null 2>&1; then
    HS_INSTALLED="$(headscale version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  fi
  if [ -n "${HEADSCALE_VERSION:-}" ]; then
    HS_TARGET="${HEADSCALE_VERSION#v}"
  else
    HS_TARGET="$(curl -fsSL --max-time 20 \
      https://api.github.com/repos/juanfont/headscale/releases/latest 2>/dev/null \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1 || true)"
  fi
  if [ -n "$HS_TARGET" ] && [ "$HS_INSTALLED" != "$HS_TARGET" ]; then
    # Integrity gate (audit M1): the DEB is installed only after its sha256
    # matches the release's checksums.txt (same release URL base, fetched over
    # GitHub TLS). Mismatch or missing checksum = fail closed with the same
    # graceful-skip philosophy as an unreachable GitHub: warn, set
    # HEADSCALE_PENDING, install nothing.
    TMPDEB="$(mktemp --suffix=.deb)"
    TMPCHK="$(mktemp)"
    HS_DEB_NAME="headscale_${HS_TARGET}_linux_${ARCH}.deb"
    HS_SHA_OK=0
    set +e
    curl -fsSL --max-time 120 -o "$TMPDEB" \
      "https://github.com/juanfont/headscale/releases/download/v${HS_TARGET}/${HS_DEB_NAME}"
    HS_DEB_RC=$?
    curl -fsSL --max-time 60 -o "$TMPCHK" \
      "https://github.com/juanfont/headscale/releases/download/v${HS_TARGET}/checksums.txt"
    HS_CHK_RC=$?
    set -e
    if [ "$HS_DEB_RC" -eq 0 ] && [ "$HS_CHK_RC" -eq 0 ]; then
      HS_EXPECTED="$(awk -v f="$HS_DEB_NAME" '$2==f {print $1; exit}' "$TMPCHK")"
      HS_ACTUAL="$(sha256sum "$TMPDEB" 2>/dev/null | awk '{print $1}')"
      if [ -n "$HS_EXPECTED" ] && [ -n "$HS_ACTUAL" ] && [ "$HS_EXPECTED" = "$HS_ACTUAL" ]; then
        HS_SHA_OK=1
      fi
    fi
    if [ "$HS_SHA_OK" -eq 1 ]; then
      dpkg -i "$TMPDEB" || apt-get install -y -qq -f
      note "Installed headscale ${HS_TARGET} (${ARCH}) — sha256 verified against checksums.txt."
    else
      HEADSCALE_PENDING=1
      note "WARNING: could not verify headscale ${HS_TARGET} against its checksums.txt — NOT installing."
      note "         (checksums.txt missing, entry missing, or sha256 mismatch). Re-run provision.sh to"
      note "         retry, or set HEADSCALE_VERSION=<version> to pin a specific release."
    fi
    rm -f "$TMPDEB" "$TMPCHK"
  elif [ -n "$HS_INSTALLED" ]; then
    note "Headscale ${HS_INSTALLED} already installed and current — skipping download."
  fi

  if ! command -v headscale >/dev/null 2>&1; then
    note "WARNING: headscale is not installed and the latest release could not be resolved"
    note "         (GitHub unreachable?). Set HEADSCALE_VERSION=<version> and re-run."
    HEADSCALE_PENDING=1
  else
    HS_CONFIGURED=1

    # Household root CA: generated once, never overwritten on re-runs.
    if [ ! -f "${HS_CA_DIR}/ca.crt" ]; then
      mkdir -p "$HS_CA_DIR"
      openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 \
        -keyout "${HS_CA_DIR}/ca.key" -out "${HS_CA_DIR}/ca.crt" \
        -subj "/CN=Holdfast Household CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
      chmod 600 "${HS_CA_DIR}/ca.key"
      note "Generated household root CA (CN 'Holdfast Household CA', 10 years): ${HS_CA_DIR}/ca.crt"
    else
      note "Household root CA already present — never regenerated."
    fi

    # Server certificate: reissued only when its SANs no longer match the
    # current IP/hostname, or it is expired / within 30 days of expiry
    # (825 days is the iOS maximum for non-CA certificates).
    HS_CERT_OK=0
    if [ -f "${HS_CA_DIR}/server.crt" ] && [ -f "${HS_CA_DIR}/server.key" ]; then
      HS_NOT_AFTER="$(openssl x509 -in "${HS_CA_DIR}/server.crt" -noout -enddate 2>/dev/null | cut -d= -f2 || true)"
      HS_END_EPOCH="$(date -d "$HS_NOT_AFTER" +%s 2>/dev/null || echo 0)"
      HS_SAN="$(openssl x509 -in "${HS_CA_DIR}/server.crt" -noout -ext subjectAltName 2>/dev/null | tr -d ' ' || true)"
      if [ -z "$HS_SAN" ]; then
        # Older openssl builds lack -ext; read the SAN out of -text instead.
        HS_SAN="$(openssl x509 -in "${HS_CA_DIR}/server.crt" -noout -text 2>/dev/null \
          | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ' || true)"
      fi
      HS_SAN="${HS_SAN},"
      if [ "$HS_END_EPOCH" -gt "$(date -d '+30 days' +%s)" ] \
         && [ "${HS_SAN#*IPAddress:${PI_IP},}" != "$HS_SAN" ] \
         && [ "${HS_SAN#*DNS:${BRICK_HOSTNAME},}" != "$HS_SAN" ]; then
        HS_CERT_OK=1
      fi
    fi
    if [ "$HS_CERT_OK" -eq 1 ]; then
      note "Server certificate valid, SANs match (${PI_IP} / ${BRICK_HOSTNAME}) — skipping."
    else
      for f in server.crt server.key; do
        if [ -f "${HS_CA_DIR}/$f" ]; then
          BAK="${HS_CA_DIR}/$f.bak.$(date +%s)"
          cp -a "${HS_CA_DIR}/$f" "$BAK"
          BACKED_UP+=("$BAK")
          note "Backed up existing ${HS_CA_DIR}/$f to $BAK"
        fi
      done
      HS_WORK="$(mktemp -d)"
      openssl req -newkey rsa:2048 -sha256 -nodes \
        -keyout "${HS_CA_DIR}/server.key" -out "${HS_WORK}/server.csr" \
        -subj "/CN=${BRICK_HOSTNAME}"
      cat > "${HS_WORK}/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${PI_IP},DNS:${BRICK_HOSTNAME}
EOF
      openssl x509 -req -sha256 -days 825 \
        -in "${HS_WORK}/server.csr" \
        -CA "${HS_CA_DIR}/ca.crt" -CAkey "${HS_CA_DIR}/ca.key" -CAcreateserial \
        -out "${HS_CA_DIR}/server.crt" -extfile "${HS_WORK}/server.ext"
      rm -rf "$HS_WORK"
      HS_REISSUED=1
      note "Issued server certificate: SANs IP ${PI_IP} + DNS ${BRICK_HOSTNAME}, 825 days."
    fi

    # Unsigned iOS configuration profile carrying the CA for one-tap trust
    # install (PayloadUUIDs are fixed so re-runs converge to identical files).
    CA_DER_B64="$(openssl x509 -in "${HS_CA_DIR}/ca.crt" -outform DER | base64 -w 0)"
    write_config "${HS_CA_DIR}/holdfast-household-ca.mobileconfig" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadContent</key>
            <data>${CA_DER_B64}</data>
            <key>PayloadDisplayName</key>
            <string>Holdfast Household CA</string>
            <key>PayloadIdentifier</key>
            <string>com.holdfastbrick.ca</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>6F1D2C3B-4A5E-4F60-8A70-1B2C3D4E5F60</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>Holdfast Household CA</string>
    <key>PayloadIdentifier</key>
    <string>com.holdfastbrick.ca.profile</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>6F1D2C3B-4A5E-4F60-8A70-1B2C3D4E5F61</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

    # Convergent config: start from the DEB's own example (its YAML schema
    # always matches the installed headscale version) and patch the four keys
    # that matter; fall back to a minimal known-good config only if the
    # example is missing.
    if [ -f "$HS_EXAMPLE" ]; then
      HS_BASE="$(mktemp)"
      cp "$HS_EXAMPLE" "$HS_BASE"
      sed -i \
        -e "s|^server_url:.*|server_url: ${HS_SERVER_URL}|" \
        -e "s|^listen_addr:.*|listen_addr: 0.0.0.0:${HEADSCALE_PORT}|" \
        -e "s|^tls_cert_path:.*|tls_cert_path: ${HS_CA_DIR}/server.crt|" \
        -e "s|^tls_key_path:.*|tls_key_path: ${HS_CA_DIR}/server.key|" \
        "$HS_BASE"
      write_config "$HS_ETC/config.yaml" < "$HS_BASE"
      rm -f "$HS_BASE"
    else
      note "WARNING: DEB example config missing at ${HS_EXAMPLE} — writing a minimal config (verify on-device)."
      write_config "$HS_ETC/config.yaml" <<EOF
server_url: ${HS_SERVER_URL}
listen_addr: 0.0.0.0:${HEADSCALE_PORT}
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: ${HS_STATE_DIR}/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: true
  update_frequency: 24h
disable_check_updates: false
ephemeral_node_inactivity_timeout: 30m
database:
  type: sqlite
  sqlite:
    path: ${HS_STATE_DIR}/db.sqlite
private_key_path: ${HS_STATE_DIR}/private.key
tls_cert_path: ${HS_CA_DIR}/server.crt
tls_key_path: ${HS_CA_DIR}/server.key
unix_socket: ${HS_RUN_DIR}/headscale.sock
unix_socket_permission: "0770"
log:
  level: info
EOF
    fi
    HS_CFG_CHANGED=$CONFIG_CHANGED

    # The service runs as the DEB's headscale user: it must read the TLS key.
    # Ownership is per-file on purpose (audit H3): ONLY the files headscale
    # actually reads — server.crt/server.key and their .bak siblings — are
    # headscale-owned. The CA private key (ca.key) and ca.srl stay root:root,
    # so one headscale-service compromise can no longer sign household-wide
    # MITM certificates against the CA phones trust at full trust. The sweep
    # below converges any state left by older versions (which chown'd -R).
    for f in "${HS_CA_DIR}"/*; do
      [ -e "$f" ] || continue
      case "$(basename "$f")" in
        server.crt|server.key|server.crt.bak.*|server.key.bak.*)
          chown headscale:headscale "$f" ;;
        *)
          chown root:root "$f" ;;
      esac
    done
    chown root:root "$HS_CA_DIR"
    chmod 755 "$HS_CA_DIR"
    chmod 600 "${HS_CA_DIR}/ca.key" "${HS_CA_DIR}/server.key"
    chmod 644 "${HS_CA_DIR}/ca.crt" "${HS_CA_DIR}/server.crt" \
              "${HS_CA_DIR}/holdfast-household-ca.mobileconfig"
    mkdir -p "$HS_STATE_DIR" "$HS_RUN_DIR"
    chown headscale:headscale "$HS_STATE_DIR" "$HS_RUN_DIR" 2>/dev/null || true

    ensure_service headscale "$(( HS_CFG_CHANGED + HS_REISSUED ))"

    # The headscale CLI runs as root and reaches headscale through its unix
    # socket; wait briefly for the socket after a (re)start.
    HS_CLI_OK=0
    for _ in 1 2 3 4 5; do
      if headscale users list >/dev/null 2>&1; then HS_CLI_OK=1; break; fi
      sleep 2
    done

    if [ "$HS_CLI_OK" -eq 0 ]; then
      note "WARNING: headscale CLI not answering (unit state? socket permissions?) — check 'journalctl -u headscale'."
      note "Skipping user/key/enrollment — fix, then re-run this script."
      HEADSCALE_PENDING=1
    else

      # Household 'family' user, idempotent ("already exists" is fine).
      # Resolved via the JSON listing: `preauthkeys create --user` demands the
      # numeric id, not the name (observed v0.29.4), and the table output is
      # ANSI-colored, so the table is no good for parsing either.
      HS_USER_JSON="$(headscale users list -o json 2>/dev/null || echo null)"
      case "$HS_USER_JSON" in
        *'"name": "family"'*|*'"name":"family"'*)
          note "Headscale user 'family' already exists."
          ;;
        *)
          set +e
          HS_USER_OUT="$(headscale users create family 2>&1)"
          HS_USER_RC=$?
          set -e
          if [ "$HS_USER_RC" -eq 0 ]; then
            note "Created Headscale user 'family'."
          else
            case "$HS_USER_OUT" in
              *"already exists"*)
                note "Headscale user 'family' already exists."
                ;;
              *)
                note "WARNING: could not create headscale user 'family' — output below."
                printf '%s\n' "$HS_USER_OUT" | sed 's/^/    | /'
                note "Skipping key minting and brick enrollment — fix, then re-run this script."
                HEADSCALE_PENDING=1
                ;;
            esac
          fi
          # Refresh the listing either way: on a first-ever create the earlier
          # capture predates the user, and the id lookup below needs it.
          HS_USER_JSON="$(headscale users list -o json 2>/dev/null || echo null)"
          ;;
      esac

      # Enroll the brick: single-use preauth key + tailscale up against the
      # household server. Skipped when already enrolled to it.
      if [ "$HEADSCALE_PENDING" -eq 0 ]; then
        if [ "$(tailscale_control_url)" = "$HS_SERVER_URL" ] && tailscale status >/dev/null 2>&1; then
          HS_ENROLLED=1
          note "Brick already enrolled to this household Headscale (${HS_SERVER_URL}) — skipping."
        else
          # Resolve the numeric id ("--user" rejects names) and mint a
          # single-use key aligned with the API's 24h enrollment window.
          HS_USER_ID="$(printf '%s' "$HS_USER_JSON" \
            | tr -d '\n\t ' \
            | grep -oE '\{"id":[0-9]+,"name":"family"' \
            | grep -oE '[0-9]+' | head -1 || true)"
          HS_KEY=""
          if [ -n "$HS_USER_ID" ]; then
            HS_KEY="$(headscale preauthkeys create --user "$HS_USER_ID" \
                      --expiration 24h 2>/dev/null \
                      | grep -oE 'hskey-auth-[A-Za-z0-9-]+' | tail -1 || true)"
          fi
          if [ -z "$HS_KEY" ]; then
            note "WARNING: could not mint a preauth key for 'family' — brick not enrolled; re-run to retry."
            HEADSCALE_PENDING=1
          else
            note "MIGRATION NOTICE: enrolling this brick into the household VPN."
            note "  Remote access moves off any previous Tailscale Inc login — the old"
            note "  tailnet association ends. This is the intended product behavior."
            set +e
            timeout 60 tailscale up --login-server="$HS_SERVER_URL" --authkey="$HS_KEY" \
              --accept-dns=false 2>&1 | sed 's/^/    | /'
            set -e
            if [ "$(tailscale_control_url)" = "$HS_SERVER_URL" ] && tailscale status >/dev/null 2>&1; then
              HS_ENROLLED=1
              note "Brick enrolled to the household Headscale: $(tailscale ip -4 2>/dev/null | head -1)"
            else
              note "WARNING: enrollment did not complete. Finish it with:"
              note "  sudo tailscale up --login-server=${HS_SERVER_URL} --accept-dns=false"
              note "or simply re-run this script."
              HEADSCALE_PENDING=1
            fi
          fi
        fi
      fi
    fi
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 8/10: Host firewall — nftables (LAN service ports only, tailnet open)"
# ─────────────────────────────────────────────────────────────────────────────
# Minimal host firewall (audit M5): input is default-drop. Everything the
# brick legitimately serves is allowed, and management/service ports only from
# RFC1918 LAN sources; anything arriving over the tailnet interfaces is trusted
# (the household VPN is authenticated). Output and forwarding stay
# unrestricted — this brick is the household DNS/router, egress must not break.
# Port notes:
#   443   headscale — family phones reach https://<pi-ip> from the LAN to
#         enroll and to reach the control plane (not in the audit's original
#         port list, but without it the household VPN breaks).
#   5353  mDNS — the iOS app discovers the brick via _holdfastbrick._tcp
#         (zeroconf); without inbound mDNS the app never finds a fresh brick.
#   Tailscale's WireGuard transport needs no inbound allow: the brick's own
#         outbound probes open the conntrack entry, and DERP relays cover the
#         rest (tailscale's documented no-port-forwarding operation).
# SAFETY: the ruleset is validated with `nft -c -f` BEFORE it is installed;
# validation failure (or a ruleset that cannot even be parsed here) means the
# stage warns and skips — a bad ruleset must never lock a household out.
NFT_CONF=/etc/nftables.conf
NFT_CONF_DIR=/etc/nftables.d
NFT_CHANGED=0
if ! command -v nft >/dev/null 2>&1; then
  apt-get install -y -qq nftables
fi

# Debian and Raspberry Pi OS ship /etc/nftables.conf WITHOUT any include line,
# so wire one in if it is missing (idempotent, backed up like every config).
if [ ! -f "$NFT_CONF" ]; then
  write_config "$NFT_CONF" <<EOF
#!/usr/sbin/nft -f
flush ruleset

include "${NFT_CONF_DIR}/*.nft"
EOF
  NFT_CHANGED=1
elif ! grep -qE '^[[:space:]]*include[[:space:]].*nftables\.d' "$NFT_CONF"; then
  BAK="${NFT_CONF}.bak.$(date +%s)"
  cp -a "$NFT_CONF" "$BAK"
  BACKED_UP+=("$BAK")
  note "Backed up existing $NFT_CONF to $BAK"
  printf '\n# Holdfast firewall rulesets (audit M5)\ninclude "%s/*.nft"\n' "$NFT_CONF_DIR" >> "$NFT_CONF"
  NFT_CHANGED=1
  note "Added include line for ${NFT_CONF_DIR} to ${NFT_CONF}."
fi

mkdir -p "$NFT_CONF_DIR"
write_config "${NFT_CONF_DIR}/holdfast.nft" <<'EOF'
#!/usr/sbin/nft -f
# Installed by Holdfast provision.sh — household brick firewall (audit M5).
# Input is default-drop: loopback, established/related, ping + PMTU, DHCP,
# IGMP, mDNS, the tailnet interfaces, and the brick's LAN services (from
# RFC1918 sources only) are allowed. Output and forwarding are unrestricted.

table inet holdfast {
    chain input {
        type filter hook input priority filter; policy drop;

        iifname "lo" accept
        ct state established,related accept

        # Tailnet traffic is authenticated by the household VPN itself.
        iifname { "tailscale0", "wg0" } accept

        # DHCP: client role (replies from the router) and, for the future
        # DHCP-takeover feature, server role (requests from LAN clients).
        udp sport 67 udp dport 68 accept
        udp sport 68 udp dport 67 accept

        # LAN multicast group management
        ip protocol igmp accept

        # ping + path-MTU discovery (v4), plus the v6 set: echo, PMTU, and
        # IPv6 neighbor/router discovery, without which IPv6 breaks entirely.
        icmp type { echo-request, destination-unreachable, time-exceeded } accept
        icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept

        # mDNS: the iOS app's _holdfastbrick._tcp discovery
        udp dport 5353 accept

        # Everything the brick serves to the household LAN, RFC1918 only:
        # ssh 22, DNS 53 (udp+tcp), headscale 443, AdGuard UI 3000, API 8787.
        # (ntopng 3001 is deliberately absent: it binds to loopback only.)
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport { 22, 53, 443, 3000, 8787 } accept
        ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } udp dport 53 accept
    }

    chain forward {
        type filter hook forward priority filter; policy accept;
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
NFT_CHANGED=$(( NFT_CHANGED + CONFIG_CHANGED ))

NFT_OK=0
if NFT_ERR="$(nft -c -f "${NFT_CONF_DIR}/holdfast.nft" 2>&1)"; then
  NFT_OK=1
else
  case "$NFT_ERR" in
    *"Permission denied"*|*"Operation not permitted"*|*"cache initialization failed"*)
      note "WARNING: cannot validate the ruleset in this environment (no kernel netlink access)."
      note "         Firewall NOT enabled — re-run provision.sh on the device itself to apply it."
      ;;
    *)
      note "WARNING: nft rejected the ruleset — firewall NOT enabled. Output below."
      printf '%s\n' "$NFT_ERR" | sed 's/^/    | /'
      ;;
  esac
fi

if [ "$NFT_OK" -eq 1 ]; then
  systemctl enable nftables >/dev/null 2>&1 || true
  if [ "$NFT_CHANGED" -ge 1 ] || ! systemctl is-active --quiet nftables; then
    systemctl restart nftables || note "WARNING: nftables.service failed to start — rules unchanged; check 'journalctl -u nftables'."
  else
    note "nftables already configured and running — skipping restart."
  fi
  if nft list ruleset 2>/dev/null | grep -q 'table inet holdfast'; then
    note "Firewall active: input default-drop, LAN service ports + tailnet allowed."
    note "Inspect anytime with:  sudo nft list ruleset"
  else
    note "WARNING: 'table inet holdfast' not found in the live ruleset — check 'systemctl status nftables'."
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 9/10: Unattended security updates (Debian) — security origin only"
# ─────────────────────────────────────────────────────────────────────────────
# Patch SLA (docs/requirements-home-server-v1.md): critical CVEs patched within
# 7 days, high within 30. The -security origin installs on its own daily;
# every other origin waits for the user — no surprise breakage.
# Debian-like = debian in os-release ID/ID_LIKE (Raspberry Pi OS) or apt+dpkg
# present (DietPi sets ID=dietpi but is Debian underneath).
OS_IDS="$(. /etc/os-release 2>/dev/null && echo "${ID:-} ${ID_LIKE:-}" || echo "")"
DEBIAN_LIKE=0
case " ${OS_IDS} " in *" debian "*) DEBIAN_LIKE=1 ;; esac
if [ "$DEBIAN_LIKE" -eq 0 ] && command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
  DEBIAN_LIKE=1
fi
if [ "$DEBIAN_LIKE" -eq 1 ]; then
  apt-get install -y -qq unattended-upgrades
  write_config /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  write_config /etc/apt/apt.conf.d/50holdfast-unattended <<'EOF'
// Installed by Holdfast provision.sh — security patches apply automatically;
// every other origin waits for the user.
Unattended-Upgrade::Allowed-Origins {
    "${distro_id} ${distro_codename}-security";
};
EOF
  systemctl enable unattended-upgrades >/dev/null 2>&1 || true
  note "Debian security updates now install daily (other upgrades stay manual)."
  note "Verify: systemctl status unattended-upgrades"
  note "        unattended-upgrade --dry-run   (what the next sweep would do)"
else
  note "WARNING: base is not Debian-like (${OS_IDS:-/etc/os-release unreadable}) —"
  note "         skipping unattended security updates; OS patches stay manual."
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 10/10: Holdfast API (deploy/install.sh)"
# ─────────────────────────────────────────────────────────────────────────────
bash "${REPO_DIR}/deploy/install.sh"

# Sync the API's config to the ports in effect this run (including AdGuard
# ports adopted from an existing AdGuardHome.yaml). Restart only on change.
ENV_FILE=/etc/holdfastbrick/.env
ENV_CHANGED=0
set_env_kv "$ENV_FILE" HOLDFASTBRICK_ADGUARD_URL "http://127.0.0.1:${ADGUARD_UI_PORT}"
set_env_kv "$ENV_FILE" HOLDFASTBRICK_NTOPNG_URL "http://127.0.0.1:${NTOPNG_PORT}"
set_env_kv "$ENV_FILE" HOLDFASTBRICK_HEADSCALE_URL "${HS_SERVER_URL}"
set_env_kv "$ENV_FILE" HOLDFASTBRICK_PORT "${API_PORT}"
# TLS on the API (audit S1, provisioning half): the API terminates HTTPS with
# the household CA's server cert — the same pair the headscale unit serves.
# The systemd unit carries the same paths as Environment= lines; the API reads
# them itself (no flag plumbing here).
set_env_kv "$ENV_FILE" HOLDFASTBRICK_TLS_CERT "/etc/headscale/ca/server.crt"
set_env_kv "$ENV_FILE" HOLDFASTBRICK_TLS_KEY "/etc/headscale/ca/server.key"
# Encrypted DNS is carried by Unbound (DoT) in forward mode; in --recursive
# mode upstream traffic is plain DNS to the authoritative servers, so no
# unit legitimately represents "Encrypted DNS".
if [ "$RECURSIVE" -eq 1 ]; then
  set_env_kv "$ENV_FILE" HOLDFASTBRICK_DOH_SERVICE_UNIT ""
else
  set_env_kv "$ENV_FILE" HOLDFASTBRICK_DOH_SERVICE_UNIT "unbound"
fi

# Give the API its own AdGuard Home login: a dedicated service account with a
# random password, created once the wizard has produced a config. No manual
# credential wiring, and the user's own admin login stays untouched. Skipped
# whenever .env already carries a username (user-provided or from a prior run).
if [ -n "${AGH_UNIT:-}" ] && [ -n "${AGH_YAML:-}" ] && [ -f "$AGH_YAML" ] \
   && ! grep -qE '^HOLDFASTBRICK_ADGUARD_USERNAME=.+' "$ENV_FILE"; then
  # If AdGuard has no users at all, its API is open — adding one would
  # suddenly lock the web UI, so leave it alone.
  AGH_HAS_AUTH="$(python3 - "$AGH_YAML" <<'PYEOF'
import sys, yaml
with open(sys.argv[1]) as f:
    cfg = yaml.safe_load(f) or {}
print(1 if (cfg.get("users") or []) else 0)
PYEOF
)"
  if [ "$AGH_HAS_AUTH" = "1" ]; then
    PB_AGH_USER=holdfastbrick
    PB_AGH_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    systemctl stop "$AGH_UNIT" || true
    BAK="${AGH_YAML}.bak.$(date +%s)"
    cp -a "$AGH_YAML" "$BAK"
    BACKED_UP+=("$BAK")
    python3 - "$AGH_YAML" "$PB_AGH_USER" "$PB_AGH_PASS" <<'PYEOF'
import sys, yaml, bcrypt
path, user, password = sys.argv[1:4]
with open(path) as f:
    cfg = yaml.safe_load(f) or {}
users = [u for u in (cfg.get("users") or []) if u.get("name") != user]
users.append({
    "name": user,
    "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
})
cfg["users"] = users
with open(path, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)
print("    -> Created AdGuard service account '%s' for the API" % user)
PYEOF
    systemctl start "$AGH_UNIT"
    set_env_kv "$ENV_FILE" HOLDFASTBRICK_ADGUARD_USERNAME "$PB_AGH_USER"
    set_env_kv "$ENV_FILE" HOLDFASTBRICK_ADGUARD_PASSWORD "$PB_AGH_PASS"
    note "API's AdGuard credentials written to ${ENV_FILE}."
  else
    note "AdGuard Home has no users configured — API needs no credentials."
  fi
fi

if [ "$ENV_CHANGED" -eq 1 ]; then
  note "Updated ${ENV_FILE} to current ports — restarting holdfastbrick-api."
  systemctl restart holdfastbrick-api
else
  note "${ENV_FILE} already matches current ports."
fi

# ─────────────────────────────────────────────────────────────────────────────
stage "Summary"
# ─────────────────────────────────────────────────────────────────────────────
if [ "$RECURSIVE" -eq 1 ]; then
  CHAIN="LAN -> AdGuard Home :${ADGUARD_DNS_PORT} -> Unbound 127.0.0.1:${UNBOUND_PORT} (full recursion, DNSSEC)"
else
  CHAIN="LAN -> AdGuard Home :${ADGUARD_DNS_PORT} -> Unbound 127.0.0.1:${UNBOUND_PORT} -> DoT :853 (Cloudflare/Quad9)"
fi
HS_SUMMARY="(household VPN: brick NOT enrolled — re-run provision.sh)"
if [ "$HS_ENROLLED" -eq 1 ]; then
  HS_SUMMARY="(household VPN: brick enrolled)"
fi
cat <<EOF

  DNS chain:   ${CHAIN}

  Running services and ports:
    AdGuard Home     DNS :${ADGUARD_DNS_PORT} (LAN)      web UI http://${PI_IP}:${ADGUARD_UI_PORT}
    Unbound          127.0.0.1:${UNBOUND_PORT}$( [ "$RECURSIVE" -eq 1 ] && echo "  (full recursion)" || echo "  (DNS-over-TLS upstream)" )
    NextDNS CLI      127.0.0.1:${NEXTDNS_PORT}  (standby — NOT in the chain)
    ntopng           127.0.0.1:${NTOPNG_PORT}  (loopback only — household UI via the API)
    Headscale        ${HS_SERVER_URL}  ${HS_SUMMARY}
    Tailscale        $( [ "$TAILSCALE_PENDING" -eq 1 ] && echo "LOGIN PENDING — run: sudo tailscale up" || echo "up ($(tailscale ip -4 2>/dev/null | head -1))" )
    Firewall         nftables 'inet holdfast' — input default-drop, LAN service ports + tailnet only
    OS security      unattended-upgrades, ${CODENAME}-security origin only (daily)
    Holdfast API https://${PI_IP}:${API_PORT}  (household CA cert; pairing code printed above)

  Still to do (manual):
EOF
if [ "$ADGUARD_WIRED" -eq 1 ]; then
  if grep -qE '^HOLDFASTBRICK_ADGUARD_USERNAME=.+' "$ENV_FILE" 2>/dev/null; then
    echo "    1. AdGuard Home: wired to Unbound; the API has its own AdGuard login. Nothing to do."
  else
    echo "    1. AdGuard Home is wired to Unbound. Log in at http://${PI_IP}:${ADGUARD_UI_PORT} and put"
    echo "       your admin credentials into /etc/holdfastbrick/.env"
    echo "       (HOLDFASTBRICK_ADGUARD_USERNAME / _PASSWORD), then:"
    echo "       sudo systemctl restart holdfastbrick-api"
  fi
else
  echo "    1. Finish AdGuard Home's first-run wizard: http://${PI_IP}:${ADGUARD_UI_PORT}"
  echo "       (web port ${ADGUARD_UI_PORT}, DNS port ${ADGUARD_DNS_PORT}). Then RE-RUN this script: it wires the"
  echo "       upstream to Unbound (127.0.0.1:${UNBOUND_PORT}) and creates the API's AdGuard login automatically."
fi
if [ "$HEADSCALE_PENDING" -eq 1 ]; then
  echo "    2. Household VPN (Headscale) enrollment incomplete — re-run provision.sh to retry."
elif [ "$HS_ENROLLED" -eq 0 ] && [ "$TAILSCALE_PENDING" -eq 1 ]; then
  echo "    2. Authenticate Tailscale:  sudo tailscale up"
fi
if [ "$ADGUARD_DNS_PORT" = "53" ]; then
  echo "    3. Point your router's DHCP DNS server at this Pi: ${PI_IP}"
  echo "       (so every LAN device resolves through AdGuard Home)."
else
  echo "    3. NOTE: AdGuard DNS is on port ${ADGUARD_DNS_PORT}, not 53. Routers can only hand"
  echo "       out a DNS *address* (no port), so LAN devices won't use it automatically."
  echo "       For whole-network filtering, move AdGuard to port 53 (re-run with"
  echo "       --adguard-dns-port 53) or redirect 53 -> ${ADGUARD_DNS_PORT} on the Pi with nftables."
fi
echo "    4. Optional: to use NextDNS as the upstream instead of the Unbound chain,"
echo "       set a profile (nextdns config set -profile <id>; nextdns restart) and"
echo "       change AdGuard's upstream to 127.0.0.1:${NEXTDNS_PORT} in its DNS settings."
if [ "$HS_CONFIGURED" -eq 1 ]; then
  echo "    5. Family phones (household VPN):"
  echo "       a. Copy /etc/headscale/ca/holdfast-household-ca.mobileconfig to each phone"
  echo "          (AirDrop, scp, ...), install the profile, then enable full trust:"
  echo "          Settings -> General -> About -> Certificate Trust Settings."
  echo "       b. In the Tailscale app: account -> 'Use custom coordination server' ->"
  echo "          ${HS_SERVER_URL}, then finish the login page it opens: run the"
  echo "          'headscale nodes register --user family <key>' command it shows, on the brick."
fi
echo "    6. Firewall check:  sudo nft list ruleset   (table 'inet holdfast' must be"
echo "       listed; input is default-drop except the brick's LAN service ports, mDNS,"
echo "       DHCP, ping/PMTU and the tailnet interfaces)."
if [ "${#BACKED_UP[@]}" -gt 0 ]; then
  echo
  echo "  Config backups made this run:"
  for b in "${BACKED_UP[@]}"; do echo "    ${b}"; done
fi
echo
echo "==> Provisioning complete. See deploy/PROVISIONING.md for verification steps."
