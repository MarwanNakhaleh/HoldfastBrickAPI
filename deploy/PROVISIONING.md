# Provisioning a Holdfast Brick from scratch

`deploy/provision.sh` turns a **fresh DietPi or Raspberry Pi OS** device
(Debian bookworm or newer, arm64/armhf) into a complete Holdfast Brick. Run it
as root from a clone of this repo:

```bash
sudo bash deploy/provision.sh              # default: Unbound forwards over DNS-over-TLS
sudo bash deploy/provision.sh --recursive  # Unbound does full recursion itself
```

It is **idempotent** — re-running is safe and is actually part of the normal
flow (see [Post-install steps](#post-install-manual-steps)). Any existing
config file it would change is backed up first as `<file>.bak.<epoch>`.

## What it installs (latest, from official sources)

| Component | Source |
|---|---|
| Unbound | Debian apt (also carries encrypted DNS via native DoT forwarding) |
| AdGuard Home | official installer (`raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh`) |
| Tailscale | Tailscale apt repo (`pkgs.tailscale.com/stable/debian`, bookworm) |
| ntopng | ntop apt repo (`packages.ntop.org`) if reachable, else Debian apt |
| NextDNS CLI | official installer (`nextdns.io/install`) |
| Holdfast API | this repo, via `deploy/install.sh` (invoked at the end) |

It also disables `systemd-resolved`'s stub listener if present (to free
port 53) and runs `unbound-control-setup` (the API drives Unbound through
`unbound-control`).

## The DNS chain

Default (**forward** mode):

```
LAN clients / router
        │  port 53
        ▼
┌─────────────────┐    ┌──────────────────────────────┐
│  AdGuard Home   │───▶│     Unbound                  │──▶ DNS-over-TLS :853
│  0.0.0.0:53     │    │  127.0.0.1:5335              │     → 1.1.1.1 / 1.0.0.1
│  (ad blocking)  │    │  (cache + DoT forwarding)    │     → 9.9.9.9 / 149.112.112.112
└─────────────────┘    └──────────────────────────────┘

standby (not in chain):  NextDNS CLI on 127.0.0.1:5054
```

Encrypted DNS is Unbound's own `forward-tls-upstream` — there is no separate
DoH daemon. (Earlier versions used `cloudflared proxy-dns`, a feature
Cloudflare discontinued in Nov 2025; the script removes that leftover unit
on re-runs.)

With **`--recursive`**: Unbound resolves directly from the root servers
(no forward zone) with DNSSEC validation via the auto-managed trust anchor
(`/var/lib/unbound/root.key`). Upstream traffic is plain DNS — not encrypted.

## Ports

Every port is a **default, not a requirement** — override any of them with a
flag or environment variable (flag wins):

| Default | Service | Bound to | Flag / env var | Purpose |
|---|---|---|---|---|
| 53 | AdGuard Home | 0.0.0.0 | `--adguard-dns-port` / `ADGUARD_DNS_PORT` | DNS for the LAN |
| 5335 | Unbound | 127.0.0.1 | `--unbound-port` / `UNBOUND_PORT` | caching resolver behind AdGuard, DoT upstream |
| 5054 | NextDNS CLI | 127.0.0.1 | `--nextdns-port` / `NEXTDNS_PORT` | alternative upstream, standby only |
| 3000 | AdGuard Home | 0.0.0.0 | `--adguard-ui-port` / `ADGUARD_UI_PORT` | web UI / REST API |
| 3001 | ntopng | 0.0.0.0 | `--ntopng-port` / `NTOPNG_PORT` | web UI / REST API |
| 8787 | Holdfast API | 0.0.0.0 | `--api-port` / `API_PORT` | control-plane API for the iOS app |

```bash
# Example: AdGuard UI on 6969, DNS on 54
sudo bash deploy/provision.sh --adguard-ui-port 6969 --adguard-dns-port 54
```

Two behaviors worth knowing:

- **Existing AdGuard settings are detected and adopted.** On a re-run, the
  script reads `AdGuardHome.yaml` and, unless you explicitly passed AdGuard
  port flags, keeps whatever ports the wizard/you already configured — and
  syncs the API's `/etc/holdfastbrick/.env` to match. Explicit flags win and
  re-patch the config.
- **DNS on a port other than 53 has a catch**: DHCP can only hand out a DNS
  *address* — there is no port field — so LAN devices won't use a nonstandard
  DNS port automatically. Fine for testing; for whole-network filtering use
  port 53 (or redirect 53 → your port with nftables on the Pi).

## Flags

- `--recursive` — configure Unbound for full recursion (no forwarding,
  DNSSEC trust anchor) instead of forwarding over DNS-over-TLS. Switch modes
  any time by re-running the script with/without the flag.
- `--<service>-port N` — see the Ports table above. Both `--flag N` and
  `--flag=N` forms work.

## Re-runs only touch what's wrong

The script is convergent: each stage first checks its own end state
(package installed? config identical? service active?) and **skips anything
already configured properly** — a re-run after a partial failure redoes only
the broken stages. Changing a port flag counts as "not configured properly"
for the affected services, so they (and only they) get rewritten and
restarted.

## Post-install manual steps

1. **AdGuard Home first-run wizard** — open `http://<pi-ip>:3000`, choose web
   port **3000** and DNS port **53**, and create admin credentials. Then
   **re-run `provision.sh`**: it detects the now-existing
   `AdGuardHome.yaml`, patches the upstream to Unbound (`127.0.0.1:5335`),
   and creates a dedicated `holdfastbrick` AdGuard service account with a
   random password for the API (written to `/etc/holdfastbrick/.env`) — no
   manual credential wiring needed. Your own admin login is untouched.
2. **ntopng token** *(optional)* — if you create one, put it in
   `/etc/holdfastbrick/.env` (`HOLDFASTBRICK_NTOPNG_TOKEN`), then
   `sudo systemctl restart holdfastbrick-api`.
3. **Tailscale login** — if the script printed an auth URL you didn't visit,
   run `sudo tailscale up` and follow the link.
4. **Router** — point your router's DHCP DNS at the Pi's LAN IP so every
   device on the network resolves through AdGuard Home.
5. *(Optional)* **NextDNS instead of the Unbound chain** —
   `sudo nextdns config set -profile <your-profile-id> && sudo nextdns restart`,
   then change AdGuard's upstream from `127.0.0.1:5335` to `127.0.0.1:5054`.
   The CLI is installed and listening but intentionally not "activated" (it
   never touches system DNS).

## Verifying each link of the chain

Run these **on the Pi** (`dnsutils` is installed by the script). Work from the
far end of the chain back toward the LAN:

```bash
# 1. Unbound (DoT forwarding in forward mode, or full recursion)
dig @127.0.0.1 -p 5335 example.com +short

#    DNSSEC check: should return SERVFAIL (validation working)
dig @127.0.0.1 -p 5335 dnssec-failed.org +short

# 2. AdGuard Home on port 53 (only after its wizard + re-run of provision.sh)
dig @127.0.0.1 example.com +short
dig @<pi-ip>  example.com +short          # from another LAN machine

#    Ad blocking check: should return 0.0.0.0/NXDOMAIN once blocklists are on
dig @127.0.0.1 doubleclick.net +short

# 3. NextDNS standby listener
dig @127.0.0.1 -p 5054 example.com +short

# 4. Web UIs and API
curl -s http://127.0.0.1:3000/ -o /dev/null -w 'adguard ui: %{http_code}\n'
curl -s http://127.0.0.1:3001/ -o /dev/null -w 'ntopng ui:  %{http_code}\n'
curl -s http://127.0.0.1:8787/api/v1/ping

# 5. Services at a glance
systemctl --no-pager status unbound AdGuardHome ntopng nextdns tailscaled holdfastbrick-api
sudo unbound-control status                 # the API uses this same channel
tailscale status
```

If a link fails, check its logs: `journalctl -u <unit> -e` (units: `unbound`,
`AdGuardHome`, `ntopng`, `nextdns`, `tailscaled`, `holdfastbrick-api`) — or
`holdfastbrick-logs <service>`.
