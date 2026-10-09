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
| AdGuard Home | official installer, fetched from the pinned release tag `ADGUARD_INSTALLER_TAG` (currently `v0.107.79`) instead of the mutable master branch |
| Tailscale | Tailscale apt repo (`pkgs.tailscale.com/stable/debian`, bookworm) |
| Headscale | official DEB from GitHub releases (`github.com/juanfont/headscale`, arm64/amd64), sha256-verified against the release's `checksums.txt` before install |
| ntopng | ntop apt repo (`packages.ntop.org`) if reachable, else Debian apt — web UI bound to loopback only |
| NextDNS CLI | NextDNS apt repo (`repo.nextdns.io`) — the interactive `nextdns.io/install` script is never used (it wedges headless devices) |
| Host firewall | nftables (`inet holdfast` table, `/etc/nftables.d/holdfast.nft`) — input default-drop, see [Host firewall](#host-firewall-nftables-audit-m5) |
| Unattended security updates | Debian `unattended-upgrades` (security origin only) |
| Holdfast API | this repo, via `deploy/install.sh` — dependencies from the hash-pinned `requirements-lock.txt`; serves HTTPS with the household CA cert |

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
| 3001 | ntopng | 127.0.0.1 | `--ntopng-port` / `NTOPNG_PORT` | web UI / REST API — **loopback only**; the household UI goes through the authenticated Holdfast API, which proxies ntopng's REST interface (the firewall also blocks it from the LAN) |
| 8787 | Holdfast API | 0.0.0.0 | `--api-port` / `API_PORT` | control-plane API for the iOS app — **HTTPS**, terminated with the household CA's server cert |

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
- `ADGUARD_INSTALLER_TAG=v0.107.79` (env only) — the AdGuard Home installer
  script is fetched from this pinned release tag, never from the mutable
  master branch (it runs as root). Re-review the tag at each AdGuard release
  per the patch SLA and bump the constant in `provision.sh`.

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

Ownership is per-file (audit H3): ONLY the files headscale actually reads —
`server.crt`, `server.key`, and their `.bak` siblings — are owned by
`headscale:headscale`. The CA private key `ca.key` (and `ca.srl`, the
mobileconfig, and everything else in the directory) stay `root:root`, with
`ca.key` at 0600. `ca.crt`, `server.crt`, and the mobileconfig are
world-readable. The split is deliberate: phones install this CA at full trust
and the brick answers household DNS, so if the headscale service user could
read `ca.key`, one headscale compromise would be enough to sign
household-wide MITM certificates. Re-running `provision.sh` converges any
directory state left by older versions (which `chown`ed the whole tree to
headscale) back to this model.

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

## Base SSH hardening (audit H4)

The stage writes `/etc/ssh/sshd_config.d/holdfast-base.conf` with two
directives:

| Directive | Value | Why |
|---|---|---|
| `X11Forwarding` | `no` | a headless appliance has no use for forwarded X sessions |
| `MaxAuthTries` | `4` | bounds brute-force noise per connection |

Two things it deliberately does NOT set:

- **`PasswordAuthentication` is left alone here.** The app's Remote Console
  flow installs a root SSH key on first pairing, and the API turns password
  auth off at that point. Hardening it during provisioning would lock out
  that first key install and strand the household. The handoff: provisioning
  hardens X11/auth-tries, the API completes keys-only after the first key
  lands.
- **`PermitRootLogin`** is likewise left to the API's key-install flow.

Both Debian and Raspberry Pi OS (bookworm) ship
`Include /etc/ssh/sshd_config.d/*.conf` as the first effective line of
`/etc/ssh/sshd_config`, so the drop-in is read and wins the first-match race
against the main file's defaults. The stage verifies that Include line
rather than assuming it: if it is missing, the stage warns and skips instead
of writing a drop-in that would silently do nothing. After writing, the
drop-in is validated with `sshd -t`; a rejected drop-in is rolled back
(restored or removed) before anything else happens.

## Host firewall: nftables (audit M5)

The stage installs `nftables` (Debian apt) if absent, writes
`/etc/nftables.d/holdfast.nft` (creating the directory and the include line
in `/etc/nftables.conf` if either is missing), enables `nftables.service`,
and applies the ruleset only when something changed — same convergent
discipline as every other config.

The `inet holdfast` table's input chain is **default-drop**. Allowed:

- loopback, and established/related connections
- everything arriving on `tailscale0` (and `wg0`, kept for the future) —
  tailnet traffic is already authenticated by the household VPN
- ICMPv4 echo + unreachable/time-exceeded and the IPv6 equivalents (echo,
  PMTU packet-too-big, neighbor/router discovery — without NDP, IPv6 breaks)
- DHCP client replies (udp 67→68), and the server-side reverse for the
  planned DHCP-takeover feature
- IGMP (LAN multicast group management)
- mDNS on udp 5353 — this is how the iOS app discovers the brick
- from RFC1918 source addresses only: tcp `22` (ssh), `53` (DNS), `443`
  (headscale), `3000` (AdGuard UI), `8787` (Holdfast API), and udp `53`

ntopng's port (3001) is deliberately absent: it binds to loopback only, and
the household UI goes through the authenticated API instead. Output and
forwarding are unrestricted (the brick is the household DNS/router).

Safety: the ruleset is validated with `nft -c -f` **before** it is enabled;
a ruleset that fails validation — or that cannot be validated at all in the
current environment — is skipped with a warning and nothing is applied. A
bad ruleset must never lock a household out.

```bash
sudo nft list ruleset        # inspect the live rules ('table inet holdfast')
systemctl status nftables
```

## Supply-chain integrity (audits M1/M2/M9)

- **Headscale (M1)** — the DEB is downloaded together with the release's
  `checksums.txt` (same release URL base) and installed only if the DEB's
  sha256 matches the entry for its exact filename. A mismatch, a missing
  checksum file, or a missing entry fails closed: nothing is installed, the
  stage warns, and `HEADSCALE_PENDING=1` puts headscale on the
  re-run-to-retry list (same graceful-skip philosophy as GitHub being
  unreachable).
- **AdGuard Home installer (M1)** — fetched from the pinned release tag
  `ADGUARD_INSTALLER_TAG` (see [Flags](#flags)), never from the mutable
  master branch; the script executes as root, so it does not get to be a
  moving target. The tag is re-reviewed at each AdGuard release per the
  patch SLA.
- **Self-update (M2)** — `deploy/self-update.sh` refuses to run unless the
  checkout's `origin` is exactly
  `https://github.com/MarwanNakhaleh/HoldfastBrickAPI` (`.git` suffix
  optional). It then does `git fetch origin` + `git reset --hard
  origin/master` + `git clean -fd` instead of `git pull --ff-only`, so only
  committed, pushed code ever installs — no uncommitted working-tree edits,
  no stray files. The installed commit hash is printed at the end. The
  detached `systemd-run` invocation is unchanged.
- **Python dependencies (M9)** — `requirements-lock.txt` pins every
  dependency (plus the `setuptools`/`wheel` build pair) with
  `--hash=sha256` entries covering the arm64 and amd64 manylinux wheels the
  Pi/NUC devices install from. `install.sh` installs with
  `pip install --require-hashes -r requirements-lock.txt` and then installs
  the `holdfastbrick-api` package itself with `--no-deps` from the local
  checkout. If the lockfile is missing, install.sh falls back to unpinned
  resolution with a loud warning — that is the escape hatch, not the path.

  Regenerate the lock after any `pyproject.toml` dependency change:

  ```bash
  uv pip compile pyproject.toml <(printf 'setuptools>=68\nwheel\n') \
    -o requirements-lock.txt --generate-hashes --universal --python-version 3.11
  ```

  (`--universal` + `--python-version 3.11` targets the Debian bookworm base
  the devices run; the generated hashes cover every published artifact per
  package. Verify platform coverage when regenerating — each native package
  must have arm64 and amd64 wheels whose digests appear in the lock.)

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
curl -s http://127.0.0.1:3001/ -o /dev/null -w 'ntopng ui (loopback only):  %{http_code}\n'
#    The API serves HTTPS with the household CA's server cert; -k here because
#    the shell doesn't trust that CA. Phones trust it via the household CA
#    profile installed in the 'Phones' steps above, which is what makes the
#    TLS trust work for the app.
curl -sk https://127.0.0.1:8787/api/v1/ping
curl -sk https://<pi-ip>:8787/api/v1/ping       # from another LAN machine

# 6. Host firewall (input default-drop, LAN service ports + tailnet allowed)
sudo nft list ruleset | grep -A4 'table inet holdfast'

# 7. Services at a glance
systemctl --no-pager status unbound AdGuardHome ntopng nextdns tailscaled headscale nftables holdfastbrick-api
sudo unbound-control status                 # the API uses this same channel
sudo sshd -t                                # SSH drop-in validates cleanly
tailscale status                            # 100.x address = enrolled to the household headscale

# 8. Unattended security updates (security origin only)
systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --debug 2>&1 | grep -E 'Allowed origins|Checking' | head -5
```

If a link fails, check its logs: `journalctl -u <unit> -e` (units: `unbound`,
`AdGuardHome`, `ntopng`, `nextdns`, `tailscaled`, `headscale`, `nftables`,
`holdfastbrick-api`) — or `holdfastbrick-logs <service>`.
