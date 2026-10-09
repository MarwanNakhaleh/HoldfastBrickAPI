"""Configuration for the Holdfast API.

Everything is overridable via environment variables prefixed with
``HOLDFASTBRICK_`` (e.g. ``HOLDFASTBRICK_PORT=8787``) or a ``.env`` file next to
the working directory. Secrets (API tokens, pairing state) live in a small
JSON state file under ``/etc/holdfastbrick`` by default.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import time
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

    # TLS for the API itself (the household CA signs the server cert that
    # provisioning puts next to it). HTTPS comes up only when both paths are
    # set AND the files exist; setting either to an empty string disables TLS
    # entirely (plain HTTP — useful in development).
    tls_cert: str = "/etc/headscale/ca/server.crt"
    tls_key: str = "/etc/headscale/ca/server.key"

    # Extra Host header values the DNS-rebinding guard accepts, comma-separated
    # (e.g. "holdfast.example.com,brick.home.arpa").
    allowed_hosts: str = ""

    def tls_enabled(self) -> bool:
        """True when TLS material is configured and present on disk. When
        False the API serves plain HTTP on the same port."""
        if not (self.tls_cert and self.tls_key):
            return False
        return Path(self.tls_cert).exists() and Path(self.tls_key).exists()


# sha256 over the DER form of the first PEM certificate in the file — the
# standard "certificate fingerprint". Stdlib-only (no X.509 parsing needed).
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S
)


def cert_fingerprint() -> str | None:
    """sha256 hex of the API's TLS certificate, or None when TLS is disabled
    or the certificate can't be read. Phones show this at first pair so the
    user can pin the brick's identity."""
    if not settings.tls_cert:
        return None
    try:
        pem = Path(settings.tls_cert).read_text()
    except OSError:
        return None
    match = _PEM_CERT_RE.search(pem)
    if match is None:
        return None
    der = base64.b64decode("".join(match.group(1).split()))
    return hashlib.sha256(der).hexdigest()


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
        # created_at powers the token list in the app; missing on tokens
        # issued by older versions — readers must tolerate that.
        self.tokens[token] = {"client": client_name, "created_at": time.time()}
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

    # --- pairing hardening ----------------------------------------------------
    def record_pairing_failure(self) -> int:
        """Count one wrong pairing code; returns the consecutive total."""
        self._load()
        count = int(self._data.get("pairing_failures", 0)) + 1
        self._data["pairing_failures"] = count
        self._save()
        return count

    def clear_pairing_failures(self) -> None:
        self._load()
        if self._data.pop("pairing_failures", None) is not None:
            self._save()

    # --- physical-presence confirmation (SSH key install) ----------------------
    def set_confirm_code(self, code: str, expires_at: float) -> None:
        self._load()
        self._data["confirm_code"] = {"code": code, "expires_at": expires_at}
        self._save()

    def get_confirm_code(self) -> dict | None:
        self._load()
        return self._data.get("confirm_code")

    def clear_confirm_code(self) -> None:
        self._load()
        if self._data.pop("confirm_code", None) is not None:
            self._save()

    # --- reboot cooldown -------------------------------------------------------
    def get_last_reboot_at(self) -> float | None:
        self._load()
        value = self._data.get("last_reboot_at")
        return float(value) if value is not None else None

    def set_last_reboot_at(self, timestamp: float) -> None:
        self._load()
        self._data["last_reboot_at"] = timestamp
        self._save()

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
