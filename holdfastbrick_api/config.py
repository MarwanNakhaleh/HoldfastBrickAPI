"""Configuration for the Holdfast API.

Everything is overridable via environment variables prefixed with
``HOLDFASTBRICK_`` (e.g. ``HOLDFASTBRICK_PORT=8787``) or a ``.env`` file next to
the working directory. Secrets (API tokens, pairing state) live in a small
JSON state file under ``/etc/holdfastbrick`` by default.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HOLDFASTBRICK_", env_file=".env")

    # Server
    host: str = "0.0.0.0"
    port: int = 8787
    device_name: str = "Holdfast Brick"

    # Where persistent state (issued tokens, pairing secret) is stored.
    state_dir: Path = Path("/etc/holdfastbrick")

    # How long a pairing window stays open after `holdfastbrick-pair` (seconds).
    pairing_window_seconds: int = 300

    # mDNS / Bonjour advertisement
    mdns_enabled: bool = True
    mdns_service_type: str = "_holdfastbrick._tcp.local."

    # --- Downstream services -------------------------------------------------
    # AdGuard Home local web/API address and credentials.
    adguard_url: str = "http://127.0.0.1:3000"
    adguard_username: str = ""
    adguard_password: str = ""

    # ntopng local web/API address and (optional) token auth.
    ntopng_url: str = "http://127.0.0.1:3001"
    ntopng_token: str = ""

    # Unbound control. `unbound-control` must be set up (`unbound-control-setup`).
    unbound_control_bin: str = "unbound-control"

    # Tailscale CLI.
    tailscale_bin: str = "tailscale"

    # Headscale CLI (household coordination server).
    headscale_bin: str = "headscale"

    # Coordination URL phones use to join the household (written by
    # provisioning into /etc/holdfastbrick/.env).
    headscale_url: str = ""

    # Household CA certificate; the .mobileconfig profile next to it is
    # served to phones so they trust the brick's Headscale certificate.
    headscale_ca_cert: Path = Path("/etc/headscale/ca/ca.crt")

    # NextDNS CLI.
    nextdns_bin: str = "nextdns"

    # Where the git checkout of this repo lives on the device (recorded by
    # deploy/install.sh). Empty disables the self-update endpoint.
    repo_dir: str = ""

    # Encrypted DNS: name of the systemd unit carrying the encrypted upstream.
    # The provisioned stack uses unbound itself (native DNS-over-TLS
    # forwarding); an https-dns-proxy-style unit also works. Leave blank when
    # upstream DNS isn't encrypted (e.g. --recursive mode).
    doh_service_unit: str = "unbound"


settings = Settings()


class StateStore:
    """Tiny JSON-file-backed store for tokens and pairing state.

    The API service and the ``holdfastbrick-pair`` CLI are separate
    processes, each with its own instance over the same file — so every
    read re-loads from disk, and writes re-load before mutating. Plain
    file I/O is plenty at this scale (one Pi, a handful of phones).
    """

    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / "state.json"
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except (OSError, json.JSONDecodeError):
                self._data = {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._data, indent=2))
        tmp.replace(self._path)
        self._path.chmod(0o600)

    # --- tokens --------------------------------------------------------------
    @property
    def tokens(self) -> dict[str, dict]:
        return self._data.setdefault("tokens", {})

    def issue_token(self, client_name: str) -> str:
        self._load()
        token = secrets.token_urlsafe(32)
        self.tokens[token] = {"client": client_name}
        self._save()
        return token

    def revoke_token(self, token: str) -> bool:
        self._load()
        removed = self.tokens.pop(token, None) is not None
        if removed:
            self._save()
        return removed

    def is_valid_token(self, token: str) -> bool:
        self._load()
        return token in self.tokens

    # --- pairing -------------------------------------------------------------
    def set_pairing(self, code: str, expires_at: float) -> None:
        self._load()
        self._data["pairing"] = {"code": code, "expires_at": expires_at}
        self._save()

    def get_pairing(self) -> dict | None:
        self._load()
        return self._data.get("pairing")

    def clear_pairing(self) -> None:
        self._load()
        if self._data.pop("pairing", None) is not None:
            self._save()


state = StateStore(settings.state_dir)
