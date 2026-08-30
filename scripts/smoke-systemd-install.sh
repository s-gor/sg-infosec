#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLED=0

fail() {
    printf 'systemd install smoke: %s\n' "$*" >&2
    systemctl --no-pager --full status sg-infosec-enforcer.service sg-infosec.service >&2 || true
    journalctl -u sg-infosec-enforcer.service -u sg-infosec.service --no-pager -n 120 >&2 || true
    exit 1
}

cleanup() {
    set +e
    if (( INSTALLED )); then
        "$ROOT_DIR/packaging/uninstall.sh" --purge
    else
        systemctl stop sg-infosec.service sg-infosec-enforcer.service >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ $EUID -ne 0 ]]; then
    fail "run as root"
fi

SG_INFOSEC_NO_START=1 "$ROOT_DIR/packaging/install.sh"
INSTALLED=1

systemctl daemon-reload
systemd-tmpfiles --create /usr/lib/tmpfiles.d/sg-infosec.conf
systemctl reset-failed sg-infosec-enforcer.service sg-infosec.service 2>/dev/null || true

[[ "$(stat -c '%U:%G' /run/sg-infosec)" == "root:sg-infosec" ]] || \
    fail "unexpected runtime directory ownership"
runuser -u sg-infosec -- touch /run/sg-infosec/.daemon-write-probe || \
    fail "service user cannot write runtime directory"
rm -f /run/sg-infosec/.daemon-write-probe

systemctl start sg-infosec-enforcer.service
for _ in $(seq 1 50); do
    if systemctl is-active --quiet sg-infosec-enforcer.service && [[ -S /run/sg-infosec/enforcer.sock ]]; then
        break
    fi
    sleep 0.1
done
systemctl is-active --quiet sg-infosec-enforcer.service || fail "enforcer did not become active"
[[ -S /run/sg-infosec/enforcer.sock ]] || fail "enforcer socket was not created"

systemctl start sg-infosec.service
for _ in $(seq 1 50); do
    if systemctl is-active --quiet sg-infosec.service && \
       [[ -S /run/sg-infosec/control.sock ]] && \
       [[ -S /run/sg-infosec/events.sock ]]; then
        break
    fi
    sleep 0.1
done
systemctl is-active --quiet sg-infosec.service || fail "core daemon did not become active"
[[ -S /run/sg-infosec/control.sock ]] || fail "control socket was not created"
[[ -S /run/sg-infosec/events.sock ]] || fail "events socket was not created"

/usr/local/sbin/sg-infosecctl health
/usr/local/sbin/sg-infosecctl status
/usr/local/sbin/sg-infosecctl nft status

systemctl restart sg-infosec.service
[[ -S /run/sg-infosec/enforcer.sock ]] || fail "core restart removed enforcer socket"
systemctl is-active --quiet sg-infosec-enforcer.service || fail "core restart stopped enforcer"

printf 'systemd install smoke passed\n'
