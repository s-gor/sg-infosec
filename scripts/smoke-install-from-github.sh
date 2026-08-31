#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
SOURCE_REPOSITORY="$TEMP_DIR/source.git"
SOURCE_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"
INSTALLED=0

fail() {
    printf 'clean install bootstrap smoke: %s\n' "$*" >&2
    systemctl --no-pager --full status sg-infosec-enforcer.service sg-infosec.service >&2 || true
    journalctl -u sg-infosec-enforcer.service -u sg-infosec.service --no-pager -n 120 >&2 || true
    exit 1
}

cleanup() {
    set +e
    if (( INSTALLED )); then
        "$ROOT_DIR/packaging/uninstall.sh" --purge
    fi
    rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || fail "run as root"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "source SHA is not complete"

git clone --quiet --bare "$ROOT_DIR" "$SOURCE_REPOSITORY"

"$ROOT_DIR/packaging/uninstall.sh" --purge >/dev/null 2>&1 || true
rm -rf /usr/local/go

SG_INFOSEC_REPOSITORY_URL="file://$SOURCE_REPOSITORY" \
    bash "$ROOT_DIR/install-from-github.sh" "$SOURCE_SHA"
INSTALLED=1

systemctl is-active --quiet sg-infosec-enforcer.service || fail "enforcer is not active"
systemctl is-active --quiet sg-infosec.service || fail "core is not active"
[[ -S /run/sg-infosec/enforcer.sock ]] || fail "enforcer socket is missing"
[[ -S /run/sg-infosec/control.sock ]] || fail "control socket is missing"
[[ -S /run/sg-infosec/events.sock ]] || fail "events socket is missing"
/usr/local/sbin/sg-infosecctl health >/dev/null
/usr/local/sbin/sg-infosecctl nft status >/dev/null

printf '\n# preserve-clean-install-marker\n' >>/etc/sg-infosec/sg-infosec.yaml

SG_INFOSEC_REPOSITORY_URL="file://$SOURCE_REPOSITORY" \
    bash "$ROOT_DIR/install-from-github.sh" "$SOURCE_SHA"

grep -Fq 'preserve-clean-install-marker' /etc/sg-infosec/sg-infosec.yaml || \
    fail "repeat install overwrote configuration"
systemctl is-active --quiet sg-infosec-enforcer.service || fail "enforcer stopped after repeat install"
systemctl is-active --quiet sg-infosec.service || fail "core stopped after repeat install"
/usr/local/sbin/sg-infosecctl health >/dev/null
/usr/local/sbin/sg-infosecctl nft status >/dev/null

printf 'clean install bootstrap smoke passed\n'
