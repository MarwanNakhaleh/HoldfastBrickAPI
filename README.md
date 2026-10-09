# HoldfastBrickAPI

The local control-plane API for a **Holdfast Brick** — a Raspberry Pi (DietPi or Raspberry Pi OS)
plugged into your router that runs Unbound (with DNS-over-TLS), AdGuard Home,
Tailscale, ntopng, and the NextDNS CLI.

**It runs on the Pi itself. There is no cloud, no centralized server, and no
account.** The [Holdfast iOS app](https://github.com/MarwanNakhaleh/HoldfastBrickUI-iOS)
finds the Pi on your WiFi automatically (Bonjour/mDNS), pairs once with a
6-digit code, and talks to this API directly. If Tailscale is up, the same API
is reachable securely from anywhere — still with no central server.

```
┌──────────┐   Bonjour discovery + HTTP (LAN)         ┌─────────────────────┐
│  iPhone  │ ───────────────────────────────────────▶ │  Raspberry Pi       │
│  (app)   │   or via Tailscale from anywhere         │  holdfastbrick-api   │
└──────────┘                                          │   ├─ unbound-control│
                                                      │   ├─ tailscale CLI  │
                                                      │   ├─ nextdns CLI    │
                                                      │   ├─ AdGuard REST   │
                                                      │   ├─ ntopng REST    │
                                                      │   └─ systemd/DietPi │
                                                      └─────────────────────┘
```

## Install (on the Pi)

```bash
git clone https://github.com/MarwanNakhaleh/HoldfastBrickAPI.git
cd HoldfastBrickAPI
sudo bash deploy/install.sh
```

The installer creates a venv in `/opt/holdfastbrick`, installs a systemd
service (`holdfastbrick-api`, port **8787**), writes a config template to
`/etc/holdfastbrick/.env`, and prints a pairing code.

AdGuard credentials are wired automatically: `deploy/provision.sh` creates a
dedicated `holdfastbrick` service account in AdGuard Home and writes it to
`/etc/holdfastbrick/.env`. (Installing the API alone with `install.sh`? Add
your AdGuard admin login to `.env` yourself — or run `provision.sh`, which
converges safely on an existing setup. Add `HOLDFASTBRICK_NTOPNG_TOKEN` too if
you use one, then `sudo systemctl restart holdfastbrick-api`.)

To pair another phone later: `holdfastbrick-pair`

## How each tool is controlled

| App-facing name  | Underlying tool | Mechanism |
|------------------|-----------------|-----------|
| Ad Blocking      | AdGuard Home    | local REST API (`/control/...`) |
| Private DNS      | Unbound         | `unbound-control` |
| Encrypted DNS    | Unbound DoT forwarding | systemd unit status |
| Remote Access    | Tailscale       | `tailscale` CLI (`--json`) |
| Cloud Filtering  | NextDNS         | `nextdns` CLI |
| Network Monitor  | ntopng          | local REST API (`/lua/rest/v2/...`) |
| Network          | Device network role | /proc + files + nmcli |
| Household        | Headscale       | `headscale` CLI |
| Device           | DietPi / OS     | `systemctl`, `vcgencmd`, `free`, `df`, … |
| Updates          | OS + component freshness | apt + vendor APIs |

All subprocess calls go through an **allowlist** (`holdfastbrick_api/runner.py`) —
the API can only run the specific binaries above, argv-style with no shell.

## API surface (all under `/api/v1`)

- `GET /ping` — unauthenticated identity check (used during discovery)
- `POST /pair` `{code, client_name}` → `{token}` — exchange pairing code for a bearer token
- `GET /overview` — one call for the app's home screen: per-service health + overall "protected"
- `GET /identity` — device name/version + LAN and Tailscale addresses (how the app learns its remote address)
- `GET|POST /adguard/{status,stats,querylog,protection}`
- `GET|POST /adguard/blocklists`, `POST /adguard/blocklists/remove` — manage blocklist subscriptions
- `POST /adguard/rules` `{domain, action: allow|deny}` — allow/block a single domain
- `GET|POST /unbound/{status,stats,flush-cache,restart}`
- `GET|POST /doh/{status,restart}`
- `GET|POST /tailscale/{status,up,down}`
- `GET|POST /nextdns/{status,config,activate,deactivate,restart}`
- `GET /ntopng/{status,hosts,interface-stats}`
- `GET /network/status` — connection report: interface, ethernet or WiFi, cable state, IP, gateway, whether the IP is static, and what manages it
- `POST /network/pin-ip` — pin the brick's current IP as static (standalone, no DHCP takeover); idempotent, tells you when a reboot is needed
- `GET /network/health` — connection-health verdict (protected / at risk / down): wired link, static IP, DNS serving, upstream DNS, tunnel, plus the fail-open note (router as secondary resolver)
- `GET|POST /system/{info,reboot}`
- `GET /updates/check` — pending OS packages (security ones flagged) plus current-vs-latest for every stack component; installs nothing
- `GET /household/status` — Headscale availability + devices enrolled on the household
- `POST /household/enroll` `{device_name?}` → `{server_url, auth_key, expires_at}` — single-use join key (24h) for a new phone
- `GET /household/devices` — enrolled household devices
- `POST /household/devices/{id}/remove` — remove an enrolled device
- `GET /household/ca`, `GET /household/ca/profile` — household CA certificate (PEM) and Apple `.mobileconfig` profile so phones trust the brick's Headscale certificate

Everything except `/ping` and `/pair` requires `Authorization: Bearer <token>`.
Interactive docs at `http://<pi>:8787/docs` while developing.

## Security model

- **Pairing**: single-use, 5-minute, 6-digit codes generated on the device
  (`holdfastbrick-pair`). Successful pairing issues a long-lived token stored
  in the phone's Keychain. Tokens live in `/etc/holdfastbrick/state.json` (0600).
- **No inbound cloud dependency**: the API binds to the LAN; remote access is
  only via your own tailnet.
- **Command allowlist**: no shell execution, fixed binary set, hard timeouts.
- Secrets for AdGuard/ntopng stay on the Pi; the phone only ever holds its
  bearer token.

## Development (any machine)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
HOLDFASTBRICK_STATE_DIR=./tmp-state holdfastbrick-api   # http://localhost:8787/docs
pytest                                                 # smoke tests, no Pi needed
```

Service wrappers degrade gracefully when a tool isn't installed (reported as
`installed: false` in `/overview`), so the API runs fine on a laptop for UI
development.
