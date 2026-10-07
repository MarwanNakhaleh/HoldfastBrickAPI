#!/usr/bin/env bash
# Holdfast Brick full-stack provisioner for a fresh DietPi or Raspberry Pi OS
# device (Debian bookworm or newer, arm64/armhf).
#
# Installs and wires: Unbound (DNS-over-TLS upstream), AdGuard Home, Tailscale,
# ntopng, NextDNS CLI — then installs the Holdfast API via deploy/install.sh.
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
#   --api-port N           (default 8787, env API_PORT)          Holdfast API
#   e.g.  sudo bash deploy/provision.sh --adguard-ui-port 6969 --adguard-dns-port 54
#
# Safe to re-run: every step is idempotent. Config files that already exist
# with different content are backed up as <file>.bak.<epoch> before overwrite.
# Re-running with different ports rewrites the configs to the new ports.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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
    --api-port)         API_PORT="$value";         if [ "$inline" -eq 0 ]; then shift; fi ;;
    -h|--help)
      sed -n '2,27p' "${BASH_SOURCE[0]}"
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
            "nextdns:${NEXTDNS_PORT}" "ntopng:${NTOPNG_PORT}" "api:${API_PORT}"; do
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

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 0/8: Preflight — base packages, detect environment"
# ─────────────────────────────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates gnupg apt-transport-https \
  dnsutils python3 python3-yaml python3-bcrypt
note "Architecture: ${ARCH}, Debian codename: ${CODENAME}"

DEFAULT_IFACE="$(ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}')"
DEFAULT_IFACE="${DEFAULT_IFACE:-eth0}"
PI_IP="$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2); print $2; exit}')"
PI_IP="${PI_IP:-<pi-ip>}"
note "Default interface: ${DEFAULT_IFACE}, address: ${PI_IP}"

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 1/8: Free port 53 (systemd-resolved stub listener, if present)"
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
stage "Stage 2/8: Unbound (apt) on 127.0.0.1:${UNBOUND_PORT}"
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

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 3/8: Encrypted DNS — Unbound DoT (remove legacy cloudflared, if any)"
# ─────────────────────────────────────────────────────────────────────────────
# Encrypted DNS is provided by Unbound's native DNS-over-TLS forwarding
# (configured in Stage 2). cloudflared's proxy-dns mode — which earlier
# versions of this script installed here — was discontinued upstream in
# Nov 2025, so any leftover install from a previous run is retired.
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
stage "Stage 4/8: AdGuard Home (official installer) — DNS :${ADGUARD_DNS_PORT}, UI :${ADGUARD_UI_PORT}"
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
  # Official script per https://github.com/AdguardTeam/AdGuardHome
  curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
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
stage "Stage 5/8: ntopng on :${NTOPNG_PORT} (packages.ntop.org if reachable, else Debian)"
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
write_config /etc/ntopng/ntopng.conf <<EOF
# Installed by Holdfast provision.sh.
# Web/REST UI on ${NTOPNG_PORT} (AdGuard Home owns 3000), monitoring ${DEFAULT_IFACE}.
-w=${NTOPNG_PORT}
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
note "ntopng (${NTOP_SOURCE}) on http://${PI_IP}:${NTOPNG_PORT}, monitoring ${DEFAULT_IFACE}."

# ─────────────────────────────────────────────────────────────────────────────
stage "Stage 6/8: NextDNS CLI on 127.0.0.1:${NEXTDNS_PORT} (installed, NOT activated)"
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v nextdns >/dev/null 2>&1; then
  # Official installer per https://nextdns.io/install (github.com/nextdns/nextdns).
  # RUN_COMMAND makes it non-interactive; on Debian it adds repo.nextdns.io.
  RUN_COMMAND=install sh -c "$(curl -sL https://nextdns.io/install)" </dev/null \
    || note "WARNING: NextDNS installer failed — install manually later with: sh -c \"\$(curl -sL https://nextdns.io/install)\""
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
stage "Stage 7/8: Tailscale (official apt repo)"
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
stage "Stage 8/8: Holdfast API (deploy/install.sh)"
# ─────────────────────────────────────────────────────────────────────────────
bash "${REPO_DIR}/deploy/install.sh"

# Sync the API's config to the ports in effect this run (including AdGuard
# ports adopted from an existing AdGuardHome.yaml). Restart only on change.
ENV_FILE=/etc/holdfastbrick/.env
ENV_CHANGED=0
set_env_kv "$ENV_FILE" HOLDFASTBRICK_ADGUARD_URL "http://127.0.0.1:${ADGUARD_UI_PORT}"
set_env_kv "$ENV_FILE" HOLDFASTBRICK_NTOPNG_URL "http://127.0.0.1:${NTOPNG_PORT}"
set_env_kv "$ENV_FILE" HOLDFASTBRICK_PORT "${API_PORT}"
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
cat <<EOF

  DNS chain:   ${CHAIN}

  Running services and ports:
    AdGuard Home     DNS :${ADGUARD_DNS_PORT} (LAN)      web UI http://${PI_IP}:${ADGUARD_UI_PORT}
    Unbound          127.0.0.1:${UNBOUND_PORT}$( [ "$RECURSIVE" -eq 1 ] && echo "  (full recursion)" || echo "  (DNS-over-TLS upstream)" )
    NextDNS CLI      127.0.0.1:${NEXTDNS_PORT}  (standby — NOT in the chain)
    ntopng           http://${PI_IP}:${NTOPNG_PORT}
    Tailscale        $( [ "$TAILSCALE_PENDING" -eq 1 ] && echo "LOGIN PENDING — run: sudo tailscale up" || echo "up ($(tailscale ip -4 2>/dev/null | head -1))" )
    Holdfast API http://${PI_IP}:${API_PORT}  (pairing code printed above)

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
if [ "$TAILSCALE_PENDING" -eq 1 ]; then
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
if [ "${#BACKED_UP[@]}" -gt 0 ]; then
  echo
  echo "  Config backups made this run:"
  for b in "${BACKED_UP[@]}"; do echo "    ${b}"; done
fi
echo
echo "==> Provisioning complete. See deploy/PROVISIONING.md for verification steps."
