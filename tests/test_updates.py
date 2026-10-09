"""Software update check: apt parsing, version comparison, the component
sweep with faked CLIs and GitHub responses, and the runner's shape gates."""

from __future__ import annotations

import asyncio
from datetime import datetime

import httpx
import pytest

from holdfastbrick_api import runner
from holdfastbrick_api.runner import CommandError, CommandResult
from holdfastbrick_api.services import adguard, updates

# --- apt fixtures ----------------------------------------------------------------

APT_GET_SIM = (
    "Reading package lists... Done\n"
    "Building dependency tree... Done\n"
    "Calculating upgrade... Done\n"
    "The following packages will be upgraded:\n"
    "  bash curl\n"
    "3 upgraded, 5 newly installed, 0 to remove and 0 not upgraded.\n"
)

APT_GET_SIM_ZERO = (
    "Reading package lists... Done\n"
    "Calculating upgrade... Done\n"
    "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
)

APT_LIST = (
    "Listing...\n"
    "bash/bookworm-security 5.2.15-2+b8 [upgradable from: 5.2.15-2+b7]\n"
    "curl/bookworm 7.88.1-10+deb12u1 [upgradable from: 7.88.1-9]\n"
    "garbage line without columns\n"
)

APT_POLICY_UNBOUND = """unbound:
  Installed: 1.17.1-2+deb12u1
  Candidate: 1.17.1-2+deb12u2
  Version table:
 *** 1.17.1-2+deb12u1 500
        500 http://deb.debian.org/debian bookworm/main arm64 Packages
     1.17.1-2+deb12u2 500
        500 http://security.debian.org/debian-security bookworm-security/main arm64 Packages
"""

APT_POLICY_NTOPNG = """ntopng:
  Installed: 5.6.0
  Candidate: 5.8.0
"""

HEADSCALE_VERSION_OUT = "headscale version 0.23.0 (2024-06-10T17:39:29Z)\n"

GH_TAGS = {
    "AdguardTeam/AdGuardHome": "v0.108.0",
    "juanfont/headscale": "v0.24.0",
    "tailscale/tailscale": "v1.72.0",
    "nextdns/nextdns": "v1.43.0",
}


# --- version comparison (pure) ----------------------------------------------------


def test_normalize_version_shapes():
    assert updates.normalize_version("v1.2.3-1~deb12u1") == (1, 2, 3)
    assert updates.normalize_version("1.2") == (1, 2)
    assert updates.normalize_version("0.23.0-alpha5 (2024-06-10)") == (0, 23, 0)
    assert updates.normalize_version("release-2024") is None
    assert updates.normalize_version("") is None


@pytest.mark.parametrize(
    "current,latest,expected",
    [
        ("1.2.3", "1.2.3", False),  # equal
        ("v0.26.0", "0.26.1", True),  # v-prefix stripped
        ("5.2.15-2+b7", "5.2.15-2+b8", False),  # Debian revision stripped -> equal
        ("5.2.15-2+b7", "5.2.16-1", True),
        ("1.9", "1.10", True),  # numeric order, not lexical: 1.10 is newer
        ("1.10", "1.9", False),
        ("1.2", "1.2.0", False),  # zero padding
        ("0.9.0", "0.23.0", True),  # minor 23 > minor 9, numerically
        ("1.2.3", "2024.01+build5", None),  # unparseable latest
        ("unknown-shape", "1.2.3", None),  # unparseable current
        ("1.2.3", "", None),
        ("0.23.0-alpha5", "0.23.0", False),  # pre-release suffix dropped
    ],
)
def test_compare_versions_table(current, latest, expected):
    assert updates.compare_versions(current, latest) is expected


# --- apt parsing (pure) -----------------------------------------------------------


def test_parse_upgrade_summary_normal():
    assert updates.parse_upgrade_summary(APT_GET_SIM) == 3


def test_parse_upgrade_summary_zero():
    assert updates.parse_upgrade_summary(APT_GET_SIM_ZERO) == 0


def test_parse_upgrade_summary_garbage():
    assert updates.parse_upgrade_summary("E: Sub-process returned an error code\n") is None
    assert updates.parse_upgrade_summary("") is None


def test_parse_upgradable_list_full_detail():
    packages = updates.parse_upgradable_list(APT_LIST)
    assert packages == [
        {
            "name": "bash",
            "current": "5.2.15-2+b7",
            "candidate": "5.2.15-2+b8",
            "security": True,
        },
        {
            "name": "curl",
            "current": "7.88.1-9",
            "candidate": "7.88.1-10+deb12u1",
            "security": False,
        },
    ]


def test_parse_upgradable_list_skips_junk():
    assert updates.parse_upgradable_list("Listing...\n\ngarbage\n") == []
    # Unrecognized bracket shape: current honestly null, columns kept.
    (pkg,) = updates.parse_upgradable_list("pkg/bookworm 1.0 [installed,upgradable to: 1.1]")
    assert pkg["name"] == "pkg" and pkg["current"] is None and pkg["candidate"] == "1.0"


def test_parse_apt_candidate_found():
    assert updates.parse_apt_candidate(APT_POLICY_UNBOUND) == "1.17.1-2+deb12u2"


def test_parse_apt_candidate_none_or_absent():
    assert updates.parse_apt_candidate("unbound:\n  Candidate: (none)\n") is None
    assert updates.parse_apt_candidate("unbound:\n  Installed: 1.0\n") is None
    assert updates.parse_apt_candidate("") is None


# --- fakes -------------------------------------------------------------------------


class FakeGitHubResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://api.github.com/")
            raise httpx.HTTPStatusError(
                "error", request=request, response=httpx.Response(self.status_code, request=request)
            )

    def json(self):
        return self._data


class FakeGitHub:
    """Stands in for the httpx.AsyncClient returned by updates._github_client()."""

    def __init__(self, tags=None, fail_repos=()):
        self.tags = tags or {}
        self.fail_repos = set(fail_repos)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, **kwargs):
        repo = url.removeprefix("https://api.github.com/repos/").removesuffix("/releases/latest")
        if repo in self.fail_repos:
            raise httpx.ConnectTimeout("timed out", request=httpx.Request("GET", url))
        tag = self.tags.get(repo)
        if tag is None:
            return FakeGitHubResponse({}, status_code=404)
        return FakeGitHubResponse({"tag_name": tag})


class FakeAdGuardClient:
    """Stands in for the httpx.AsyncClient returned by adguard._client()."""

    def __init__(self, get_routes=None):
        self.get_routes = get_routes or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, path, **kwargs):
        data = self.get_routes[path]
        if isinstance(data, Exception):
            raise data
        return FakeGitHubResponse(data)


def _wire_sweep(monkeypatch, *, gh_tags=None, gh_fail=(), os_apt_fails=False, headscale_missing=False):
    gh = FakeGitHub(tags=gh_tags if gh_tags is not None else GH_TAGS, fail_repos=gh_fail)
    monkeypatch.setattr(updates, "_github_client", lambda: gh)
    calls: list[list[str]] = []

    async def fake_run(argv, timeout=20.0):
        calls.append(argv)
        if argv == ["apt-get", "-s", "upgrade"]:
            if os_apt_fails:
                return CommandResult(ok=False, exit_code=100, stdout="", stderr="E: broken")
            return CommandResult(ok=True, exit_code=0, stdout=APT_GET_SIM, stderr="")
        if argv == ["apt", "list", "--upgradable"]:
            if os_apt_fails:
                return CommandResult(ok=False, exit_code=100, stdout="", stderr="E: broken")
            return CommandResult(ok=True, exit_code=0, stdout=APT_LIST, stderr="")
        if argv[:2] == ["headscale", "version"]:
            if headscale_missing:
                raise CommandError("binary not installed: headscale")
            return CommandResult(ok=True, exit_code=0, stdout=HEADSCALE_VERSION_OUT, stderr="")
        if argv[:2] == ["tailscale", "version"]:
            return CommandResult(
                ok=True, exit_code=0, stdout="1.72.0\ntailscale commit: abcdef\n", stderr=""
            )
        if argv[:2] == ["nextdns", "version"]:
            return CommandResult(ok=True, exit_code=0, stdout="1.42.0\n", stderr="")
        if argv == ["dpkg-query", "-W", "-f=${Version}", "unbound"]:
            return CommandResult(ok=True, exit_code=0, stdout="1.17.1-2+deb12u1", stderr="")
        if argv == ["dpkg-query", "-W", "-f=${Version}", "ntopng"]:
            return CommandResult(ok=True, exit_code=0, stdout="5.6.0", stderr="")
        if argv == ["apt-cache", "policy", "unbound"]:
            return CommandResult(ok=True, exit_code=0, stdout=APT_POLICY_UNBOUND, stderr="")
        if argv == ["apt-cache", "policy", "ntopng"]:
            return CommandResult(ok=True, exit_code=0, stdout=APT_POLICY_NTOPNG, stderr="")
        raise AssertionError(f"unexpected command: {argv}")

    monkeypatch.setattr(updates, "run", fake_run)
    monkeypatch.setattr(
        adguard, "_client", lambda: FakeAdGuardClient({"/control/status": {"version": "v0.107.52"}})
    )
    return gh, calls


# --- endpoint auth gating ----------------------------------------------------------


def test_updates_endpoints_require_token(client):
    test_client, _ = client
    assert test_client.get("/api/v1/updates/check").status_code == 401


# --- /updates/check ----------------------------------------------------------------


def test_check_sweep_happy_path(authed, monkeypatch):
    test_client, headers = authed
    _, calls = _wire_sweep(monkeypatch)
    resp = test_client.get("/api/v1/updates/check", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"os", "components", "checked_at"}
    assert body["os"] == {
        "upgradable_count": 3,
        "security_count": 1,
        "packages": updates.parse_upgradable_list(APT_LIST),
    }
    by_name = {c["name"]: c for c in body["components"]}
    assert set(by_name) == {"adguard", "headscale", "tailscale", "nextdns", "unbound", "ntopng"}
    assert by_name["adguard"] == {
        "name": "adguard",
        "current": "v0.107.52",
        "latest": "v0.108.0",
        "update_available": True,
    }
    assert by_name["headscale"]["current"] == "0.23.0"
    assert by_name["headscale"]["update_available"] is True
    assert by_name["tailscale"]["update_available"] is False  # v1.72.0 == 1.72.0
    assert by_name["nextdns"]["update_available"] is True
    # Debian revision suffixes are stripped before comparing: a revision-only
    # bump (unbound) is honestly "no update detected".
    assert by_name["unbound"]["update_available"] is False
    assert by_name["ntopng"] == {
        "name": "ntopng",
        "current": "5.6.0",
        "latest": "5.8.0",
        "update_available": True,
    }
    assert ["apt-get", "-s", "upgrade"] in calls
    assert ["apt", "list", "--upgradable"] in calls
    checked = datetime.fromisoformat(body["checked_at"])
    assert checked.utcoffset() is not None


def test_check_github_timeout_gives_null_latest(authed, monkeypatch):
    test_client, headers = authed
    _wire_sweep(monkeypatch, gh_fail=("tailscale/tailscale",))
    resp = test_client.get("/api/v1/updates/check", headers=headers)
    assert resp.status_code == 200
    tailscale = {c["name"]: c for c in resp.json()["components"]}["tailscale"]
    assert tailscale == {
        "name": "tailscale",
        "current": "1.72.0",
        "latest": None,
        "update_available": None,
    }


def test_check_github_404_gives_null_latest(authed, monkeypatch):
    test_client, headers = authed
    _wire_sweep(monkeypatch, gh_tags={})  # no repo answers
    resp = test_client.get("/api/v1/updates/check", headers=headers)
    assert resp.status_code == 200
    for component in resp.json()["components"]:
        if component["name"] in ("adguard", "headscale", "tailscale", "nextdns"):
            assert component["latest"] is None
            assert component["update_available"] is None


def test_check_apt_failures_are_nulls_not_500(authed, monkeypatch):
    test_client, headers = authed
    _wire_sweep(monkeypatch, os_apt_fails=True)
    resp = test_client.get("/api/v1/updates/check", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["os"] == {"upgradable_count": None, "security_count": None, "packages": []}


def test_check_missing_cli_reports_null_current(authed, monkeypatch):
    test_client, headers = authed
    _wire_sweep(monkeypatch, headscale_missing=True)
    resp = test_client.get("/api/v1/updates/check", headers=headers)
    assert resp.status_code == 200
    headscale = {c["name"]: c for c in resp.json()["components"]}["headscale"]
    assert headscale == {
        "name": "headscale",
        "current": None,
        "latest": "v0.24.0",
        "update_available": None,
    }


def test_check_adguard_unreachable_reports_null_current(authed, monkeypatch):
    test_client, headers = authed
    _wire_sweep(monkeypatch)

    class UnreachableAdGuard:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, path, **kwargs):
            raise httpx.ConnectError(
                "refused", request=httpx.Request("GET", "http://127.0.0.1:3000/")
            )

    monkeypatch.setattr(adguard, "_client", lambda: UnreachableAdGuard())
    resp = test_client.get("/api/v1/updates/check", headers=headers)
    assert resp.status_code == 200
    adguard_row = {c["name"]: c for c in resp.json()["components"]}["adguard"]
    assert adguard_row["current"] is None
    assert adguard_row["update_available"] is None


# --- runner shape gates ------------------------------------------------------------


def test_probe_shapes_pass_the_gate(monkeypatch):
    # Gate checks run before the installed-binary lookup; forcing which() to
    # miss means "binary not installed" proves the argv itself was allowed.
    monkeypatch.setattr(runner.shutil, "which", lambda _: None)
    for argv in (
        ["apt-get", "-s", "upgrade"],
        ["apt", "list", "--upgradable"],
        ["apt-cache", "policy", "unbound"],
        ["apt-cache", "policy", "libssl3"],
        ["dpkg-query", "-W", "-f=${Version}", "unbound"],
        ["nextdns", "version"],
        ["headscale", "version"],
    ):
        with pytest.raises(CommandError, match="binary not installed"):
            asyncio.run(runner.run(argv))


@pytest.mark.parametrize(
    "argv",
    [
        ["apt-get", "install", "evil"],  # mutating verb
        ["apt-get", "remove", "unbound"],
        ["apt-get", "update"],
        ["apt-get", "-s", "install", "evil"],  # -s passes argv[1]; shape must not
        ["apt-get", "-s", "upgrade", "extra"],
        ["apt-get"],
        ["apt", "install", "evil"],
        ["apt", "list", "--installed"],
        ["apt", "list"],
        ["apt-cache", "show", "evil"],
        ["apt-cache", "policy"],
        ["apt-cache", "policy", "unbound", "extra"],
        ["dpkg-query", "-L", "unbound"],
        ["dpkg-query", "-W", "-f=${db:Status-Abbrev}", "unbound"],
        ["dpkg-query", "-W", "-f=${Version}", "unbound", "extra"],
        ["nextdns", "install"],
        ["nextdns", "run"],
        ["nextdns"],
        ["sudo", "apt-get", "-s", "upgrade"],  # unknown binary
        ["curl", "https://evil.example"],
    ],
)
def test_probe_gates_refuse_everything_else(argv):
    with pytest.raises(CommandError, match="not allowlisted"):
        asyncio.run(runner.run(argv))

def test_nextdns_gate_restores_service_subcommands_but_blocks_install():
    """`nextdns install` is the interactive configuration wizard that wedges
    a headless brick (found in the deployed run); status/config/etc. must
    keep working for the Cloud Filtering endpoints."""
    import asyncio

    from holdfastbrick_api.runner import CommandError, run as real_run

    for argv in (
        ["nextdns", "version"],
        ["nextdns", "status"],
        ["nextdns", "config"],
        ["nextdns", "activate"],
        ["nextdns", "deactivate"],
        ["nextdns", "restart"],
    ):
        try:
            asyncio.run(real_run(argv))
        except CommandError as exc:
            assert "arguments not allowlisted" not in str(exc), argv
        except Exception:
            pass
    try:
        asyncio.run(real_run(["nextdns", "install"]))
        raise AssertionError("nextdns install unexpectedly allowed")
    except CommandError as exc:
        assert "not allowlisted" in str(exc) or "allowlist" in str(exc)
