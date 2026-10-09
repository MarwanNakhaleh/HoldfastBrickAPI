#!/usr/bin/env bash
# Holdfast Brick self-updater. Launched DETACHED by the API (POST
# /api/v1/system/update) as a transient systemd unit:
#   systemd-run --unit=holdfastbrick-update --collect /bin/bash self-update.sh <repo_dir>
# Detached because install.sh restarts holdfastbrick-api, which would kill an
# updater running inside the API process.
#
# Audit M2 hardening:
#   - The repo's origin must be the official Holdfast API GitHub repository
#     (HTTPS); anything else aborts. A brick must never pull and install as
#     root from a repo someone re-pointed at their own code.
#   - The working tree is FORCED to origin/master (fetch + reset --hard +
#     clean) instead of `git pull`: only committed, pushed code can ever be
#     installed — local uncommitted edits and stray files never ship.
set -euo pipefail

REPO_DIR="${1:?usage: self-update.sh <repo_dir>}"
ALLOWED_ORIGIN="https://github.com/MarwanNakhaleh/HoldfastBrickAPI"

ORIGIN_URL="$(git -C "${REPO_DIR}" remote get-url origin 2>/dev/null || true)"
case "${ORIGIN_URL}" in
  "${ALLOWED_ORIGIN}"|"${ALLOWED_ORIGIN}.git") ;;
  *)
    echo "Refusing to self-update: this checkout's origin is not the Holdfast API repository." >&2
    echo "  origin:   ${ORIGIN_URL:-<none>}" >&2
    echo "  expected: ${ALLOWED_ORIGIN} (.git suffix optional)" >&2
    exit 1
    ;;
esac

git -C "${REPO_DIR}" fetch origin
git -C "${REPO_DIR}" reset --hard origin/master
git -C "${REPO_DIR}" clean -fd

bash "${REPO_DIR}/deploy/install.sh"

echo "==> Self-update complete: installed commit $(git -C "${REPO_DIR}" rev-parse HEAD)"
