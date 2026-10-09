#!/usr/bin/env bash
# Holdfast API installer for DietPi / Raspberry Pi OS.
# Run as root on the Pi:  sudo bash deploy/install.sh
set -euo pipefail

INSTALL_DIR=/opt/holdfastbrick
STATE_DIR=/etc/holdfastbrick
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Installing Holdfast API from ${REPO_DIR}"

apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip

mkdir -p "${INSTALL_DIR}" "${STATE_DIR}"

if [ ! -d "${INSTALL_DIR}/venv" ]; then
  python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip -q
# Hash-pinned dependencies (audit M9): requirements-lock.txt pins every
# dependency (and the setuptools/wheel build pair) with --hash=sha256 entries;
# pip refuses any artifact whose digest does not match. The lock must cover
# the arm64/amd64 manylinux wheels the Pi/NUC devices install from.
# The holdfastbrick-api package itself is then installed with --no-deps from
# the local checkout (it is not a PyPI artifact, so the lock cannot pin it).
LOCK="${REPO_DIR}/requirements-lock.txt"
if [ -f "${LOCK}" ]; then
  "${INSTALL_DIR}/venv/bin/pip" install -q --require-hashes -r "${LOCK}"
  "${INSTALL_DIR}/venv/bin/pip" install -q --no-deps --no-build-isolation "${REPO_DIR}"
else
  echo "!!! WARNING: ${LOCK} is missing — falling back to UNPINNED dependency"
  echo "!!! resolution. This is not the supported install path: dependencies will"
  echo "!!! be resolved live from PyPI with no integrity pinning. Restore or"
  echo "!!! regenerate requirements-lock.txt (see deploy/PROVISIONING.md)."
  "${INSTALL_DIR}/venv/bin/pip" install -q "${REPO_DIR}"
fi

if [ ! -f "${STATE_DIR}/.env" ]; then
  cat > "${STATE_DIR}/.env" <<'EOF'
# Holdfast API configuration — edit to match your setup.
HOLDFASTBRICK_DEVICE_NAME=Holdfast Brick

# AdGuard Home admin API (set the credentials you chose in AdGuard's setup)
HOLDFASTBRICK_ADGUARD_URL=http://127.0.0.1:3000
HOLDFASTBRICK_ADGUARD_USERNAME=
HOLDFASTBRICK_ADGUARD_PASSWORD=

# ntopng REST API
HOLDFASTBRICK_NTOPNG_URL=http://127.0.0.1:3001
HOLDFASTBRICK_NTOPNG_TOKEN=

# systemd unit carrying encrypted DNS upstream. With the provisioned stack
# this is unbound itself (DNS-over-TLS forwarding); blank disables the card.
HOLDFASTBRICK_DOH_SERVICE_UNIT=unbound
EOF
  chmod 600 "${STATE_DIR}/.env"
  echo "==> Wrote default config to ${STATE_DIR}/.env — edit it to add AdGuard credentials."
fi

# Record where the repo lives so the API's self-update endpoint can git-pull it.
# Appended outside the template block above (which only runs on first install),
# guarded so re-runs don't duplicate the line.
if ! grep -q '^HOLDFASTBRICK_REPO_DIR=' "${STATE_DIR}/.env"; then
  {
    echo ""
    echo "# Where this git checkout lives (used by the in-app self-update)"
    echo "HOLDFASTBRICK_REPO_DIR=${REPO_DIR}"
  } >> "${STATE_DIR}/.env"
fi

# The app's Remote Console needs an SSH server; Raspberry Pi OS ships with
# it disabled. Enable OpenSSH when present (DietPi may run Dropbear instead,
# which is left alone — it's already on when installed).
if systemctl cat ssh >/dev/null 2>&1; then
  systemctl enable --now ssh >/dev/null 2>&1 || true
  echo "==> OpenSSH server enabled (used by the app's Remote Console)."
fi

install -m 644 "${REPO_DIR}/deploy/holdfastbrick-api.service" /etc/systemd/system/holdfastbrick-api.service
ln -sf "${INSTALL_DIR}/venv/bin/holdfastbrick-pair" /usr/local/bin/holdfastbrick-pair
install -m 755 "${REPO_DIR}/deploy/holdfastbrick-logs" /usr/local/bin/holdfastbrick-logs

systemctl daemon-reload
systemctl enable holdfastbrick-api
# restart (not `enable --now`): an already-running service must be bounced
# to load the code this script just installed.
systemctl restart holdfastbrick-api

echo
echo "==> Holdfast API is running on port 8787 (HTTPS, household CA server cert)."
echo "==> To pair a phone, run:  holdfastbrick-pair"
echo "==> To watch live logs, run:  holdfastbrick-logs   (or holdfastbrick-logs all)"
echo
# Only open a pairing window when someone is actually at a terminal. The
# detached self-update (deploy/self-update.sh) also runs this script, and it
# must NOT silently open a 5-minute window anyone on the LAN could pair with.
if [ -t 0 ]; then
  "${INSTALL_DIR}/venv/bin/holdfastbrick-pair"
fi
