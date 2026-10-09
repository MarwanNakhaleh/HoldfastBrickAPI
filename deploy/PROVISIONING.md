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
| Headscale | official DEB from GitHub releases (`github.com/juanfont/headscale`, arm64/amd64) |
| ntopng | ntop apt repo (`packages.ntop.org`) if reachable, else Debian apt |
| NextDNS CLI | NextDNS apt repo (`repo.nextdns.io`) — the interactive `nextdns.io/install` script is never used (it wedges headless devices) |
| Unattended security updates | Debian `unattended-upgrades` (security origin only) |
| Holdfast API | this repo, via `deploy/install.sh` (invoked at the end) |

It also disables `systemd-resolved`'s stub listener if present (to free
port 53) and runs `unbound-control-setup` (the API drives Unbound through
`unbound-control`).

**Security patches apply on their own.** The script installs
`unattended-upgrades` and configures `APT::Periodic` to refresh the package
list and run the upgrade daily, while `/etc/apt/apt.conf.d/50holdfast-unattended`
restricts `Unattended-Upgrade::Allowed-Origins` to the
`${distro_id} ${distro_codename}-security` origin only: Debian security
patches install automatically (critical CVEs within 7 days, high within 30 —
the signed-off patch SLA), and everything else waits for the user. Both files
are written with the same backup-first `write_config` discipline as every
other config.

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
| 443 | Headscale | 0.0.0.0 | `--headscale-port` / `HEADSCALE_PORT` | household VPN control plane (TLS) — **must be free** |
| 5335 | Unbound | 127.0.0.1 | `--unbound-port` / `UNBOUND_PORT` | caching resolver behind AdGuard, DoT upstream |
| 5054 | NextDNS CLI | 127.0.0.1 | `--nextdns-port` / `NEXTDNS_PORT` | alternative upstream, standby only |
| 3000 | AdGuard Home | 0.0.0.0 | `--adguard-ui-port` / `ADGUARD_UI_PORT` | web UI / REST API |
| 3001 | ntopng | 0.0.0.0 | `--ntopng-port` / `NTOPNG_PORT` | web UI / REST API |
| 8787 | Holdfast API | 0.0.0.0 | `--api-port` / `API_PORT` | control-plane API for the iOS app |

Headscale's 443 is the one port with a hard edge: phones reach it as
`https://<pi-ip>` (no port suffix), and if something else already owns 443
you must move that service or override the port (`--headscale-port N` — the
URL the phones use then becomes `https://<pi-ip>:N`).

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
- `HEADSCALE_VERSION=v0.26.0` (env only) — pin a specific headscale release
  instead of the latest GitHub tag.

## Headscale: the household VPN

The brick runs **Headscale**, the open-source Tailscale control plane, so
family phones use the official Tailscale apps pointed at the brick instead of
Tailscale Inc. It is installed from the official DEB on the
[juanfont/headscale GitHub releases](https://github.com/juanfont/headscale/releases).
Only arm64 and amd64 builds exist: on a 32-bit (armhf) OS the stage prints a
warning and skips itself. The DEB ships the `headscale` systemd unit and a
`headscale` service user, which the config and key ownership below assume.

### The household CA

A LAN IP cannot get a certificate from a public CA, so the stage generates its
own root CA on the brick. It is generated once and never regenerated; the
phone-facing server cert is reissued automatically on a re-run when the LAN IP
or hostname changed, or when it is within 30 days of expiry (the old one is
backed up first, like every config file):

| File | What |
|---|---|
| `/etc/headscale/ca/ca.crt` | household root CA, CN `Holdfast Household CA`, RSA 4096, 10 years |
| `/etc/headscale/ca/ca.key` | CA private key, 0600 — stays on the brick |
| `/etc/headscale/ca/server.crt` | TLS cert for headscale: SANs = brick LAN IP (IP SAN) + hostname (DNS SAN), 825 days (the iOS maximum for non-CA certs) |
| `/etc/headscale/ca/server.key` | TLS private key, 0600 |
| `/etc/headscale/ca/holdfast-household-ca.mobileconfig` | unsigned iOS configuration profile containing the CA, for one-tap trust install |

All of `/etc/headscale/ca/` is owned by `headscale:headscale` (the service
user must read the TLS key); the cert, CA cert and profile are world-readable,
the two private keys are 0600.

### Headscale config

`/etc/headscale/config.yaml` is built convergently: the DEB's own example
(`/usr/share/doc/headscale/examples/config-example.yaml`) is used as the base
— its YAML schema always matches the exact headscale version installed — and
four keys are patched:

| Key | Value |
|---|---|
| `server_url` | `https://<pi-ip>` (plus `:N` only if you overrode `--headscale-port`) |
| `listen_addr` | `0.0.0.0:443` |
| `tls_cert_path` | `/etc/headscale/ca/server.crt` |
| `tls_key_path` | `/etc/headscale/ca/server.key` |

With `tls_cert_path`/`tls_key_path` set, `listen_addr` serves TLS. Everything
else (sqlite DB under `/var/lib/headscale`, unix socket under
`/var/run/headscale`, noise keys, DERP map) keeps the DEB example's defaults.

### Brick enrollment (remote-access migration)

After headscale is up, the stage creates the `family` headscale user
(idempotent: an "already exists" result is fine), mints a single-use preauth
key, and runs:

```bash
tailscale up --login-server=https://<pi-ip> --authkey <key> --accept-dns=false
```

**This moves the brick's remote access to the household headscale.** Any
previous Tailscale Inc login on the brick ends — that is the intended product
behavior, and the script prints a notice when it happens. Re-runs detect an
existing enrollment (via `tailscale debug prefs` → `ControlURL`) and skip.
`--accept-dns=false` keeps the brick's DNS stack on the AdGuard chain;
headscale never touches `/etc/resolv.conf`.

The API picks the URL up from `/etc/holdfastbrick/.env`:
`HOLDFASTBRICK_HEADSCALE_URL=https://<pi-ip>`.

### Phones (per family member)

1. Copy `holdfast-household-ca.mobileconfig` off the brick (AirDrop, `scp`,
   ...) and install it, then enable full trust: Settings → General → About →
   Certificate Trust Settings. Without this the Tailscale app rejects the
   brick's certificate.
2. Tailscale app → account → **Use custom coordination server** →
   `https://<pi-ip>` → finish the login page it opens: approve the
   registration with the `headscale nodes register --user family <key>`
   command the page shows, run on the brick.

### Verifying the headscale chain

```bash
systemctl status headscale
curl -k https://127.0.0.1/health        # headscale serves /health itself
                                        # or: curl --cacert /etc/headscale/ca/ca.crt https://127.0.0.1/health
headscale nodes list                    # the brick is listed under user 'family'
openssl verify -CAfile /etc/headscale/ca/ca.crt /etc/headscale/ca/server.crt
tailscale status                        # brick has a 100.x address from the household tailnet
```

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
3. **Tailscale / household VPN** — the script enrolls the brick into the
   household headscale automatically (see
   [Headscale: the household VPN](#headscale-the-household-vpn)); this
   migrates remote access off any prior Tailscale Inc login, which is
   intended. If it printed that enrollment didn't complete, just re-run
   `provision.sh`.
4. **Family phones** — trust the household CA, then point the Tailscale app
   at the brick (both steps in
   [Phones](#phones-per-family-member) above).
5. **Router** — point your router's DHCP DNS at the Pi's LAN IP so every
   device on the network resolves through AdGuard Home.
6. *(Optional)* **NextDNS instead of the Unbound chain** —
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

# 4. Headscale (household VPN) — see its section above for the full chain
systemctl status headscale
curl -k https://127.0.0.1/health
headscale nodes list
openssl verify -CAfile /etc/headscale/ca/ca.crt /etc/headscale/ca/server.crt

# 5. Web UIs and API
curl -s http://127.0.0.1:3000/ -o /dev/null -w 'adguard ui: %{http_code}\n'
curl -s http://127.0.0.1:3001/ -o /dev/null -w 'ntopng ui:  %{http_code}\n'
curl -s http://127.0.0.1:8787/api/v1/ping

# 6. Services at a glance
systemctl --no-pager status unbound AdGuardHome ntopng nextdns tailscaled headscale holdfastbrick-api
sudo unbound-control status                 # the API uses this same channel
tailscale status                            # 100.x address = enrolled to the household headscale

# 7. Unattended security updates (security origin only)
systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --debug 2>&1 | grep -E 'Allowed origins|Checking' | head -5
```

If a link fails, check its logs: `journalctl -u <unit> -e` (units: `unbound`,
`AdGuardHome`, `ntopng`, `nextdns`, `tailscaled`, `headscale`,
`holdfastbrick-api`) — or `holdfastbrick-logs <service>`.
