#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="$(mktemp -d)"
SOURCE_REPOSITORY="$TEMP_DIR/source.git"
SOURCE_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"
FIRST_OUTPUT="$TEMP_DIR/first-install.out"
SECOND_OUTPUT="$TEMP_DIR/second-install.out"
INSTALLED=0

fail() {
    printf 'clean install bootstrap smoke: %s\n' "$*" >&2
    systemctl --no-pager --full status sg-infosec-ssh-agent.service sg-infosec-enforcer.service sg-infosec.service >&2 || true
    journalctl -u sg-infosec-ssh-agent.service -u sg-infosec-enforcer.service -u sg-infosec.service --no-pager -n 120 >&2 || true
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

if ! SG_INFOSEC_REPOSITORY_URL="file://$SOURCE_REPOSITORY" \
    SG_INFOSEC_FORCE_GO_INSTALL=1 \
    TERM=dumb \
    bash "$ROOT_DIR/install-from-github.sh" "$SOURCE_SHA" >"$FIRST_OUTPUT" 2>&1; then
    cat "$FIRST_OUTPUT" >&2
    fail "first bootstrap failed"
fi
cat "$FIRST_OUTPUT"
INSTALLED=1

grep -Fq '[OK] Checking system' "$FIRST_OUTPUT" || fail "plain system progress is missing"
grep -Fq '[OK] Installing dependencies' "$FIRST_OUTPUT" || fail "plain dependency progress is missing"
grep -Fq '[OK] Building components' "$FIRST_OUTPUT" || fail "plain build progress is missing"
grep -Fq '[OK] Verifying installation' "$FIRST_OUTPUT" || fail "plain verification progress is missing"
grep -Fq 'SG InfoSec successfully installed' "$FIRST_OUTPUT" || fail "success summary is missing"
grep -Fq 'SSH journal collector: active' "$FIRST_OUTPUT" || fail "SSH collector summary is missing"
if LC_ALL=C grep -q $'\033\[' "$FIRST_OUTPUT"; then
    fail "non-interactive output contains terminal escape sequences"
fi

[[ "$(/usr/local/go/bin/go env GOVERSION)" == "go1.24.12" ]] || \
    fail "bootstrap did not install the pinned Go toolchain"
systemctl is-active --quiet sg-infosec-enforcer.service || fail "enforcer is not active"
systemctl is-active --quiet sg-infosec.service || fail "core is not active"
systemctl is-active --quiet sg-infosec-ssh-agent.service || fail "SSH collector is not active"
[[ -S /run/sg-infosec/enforcer.sock ]] || fail "enforcer socket is missing"
[[ -S /run/sg-infosec/control.sock ]] || fail "control socket is missing"
[[ -S /run/sg-infosec/events.sock ]] || fail "events socket is missing"
/usr/local/sbin/sg-infosecctl health >/dev/null
/usr/local/sbin/sg-infosecctl nft status >/dev/null
/usr/local/sbin/sg-infosecctl overview >/dev/null

printf '\n# preserve-clean-install-marker\n' >>/etc/sg-infosec/sg-infosec.yaml
printf '\n# preserve-ssh-policy-marker\n' >>/etc/sg-infosec/policies.d/ssh.yaml

if ! SG_INFOSEC_REPOSITORY_URL="file://$SOURCE_REPOSITORY" \
    SG_INFOSEC_VERBOSE=1 \
    TERM=dumb \
    bash "$ROOT_DIR/install-from-github.sh" "$SOURCE_SHA" >"$SECOND_OUTPUT" 2>&1; then
    cat "$SECOND_OUTPUT" >&2
    fail "repeat bootstrap failed"
fi
cat "$SECOND_OUTPUT"

grep -Fq 'go build -o bin/sg-infosecd' "$SECOND_OUTPUT" || fail "verbose core build output is missing"
grep -Fq 'go build -o bin/sg-infosec-ssh-agent' "$SECOND_OUTPUT" || fail "verbose SSH agent build output is missing"
grep -Fq 'preserve-clean-install-marker' /etc/sg-infosec/sg-infosec.yaml || \
    fail "repeat install overwrote configuration"
grep -Fq 'preserve-ssh-policy-marker' /etc/sg-infosec/policies.d/ssh.yaml || \
    fail "repeat install overwrote SSH policy"
systemctl is-active --quiet sg-infosec-enforcer.service || fail "enforcer stopped after repeat install"
systemctl is-active --quiet sg-infosec.service || fail "core stopped after repeat install"
systemctl is-active --quiet sg-infosec-ssh-agent.service || fail "SSH collector stopped after repeat install"
/usr/local/sbin/sg-infosecctl health >/dev/null
/usr/local/sbin/sg-infosecctl nft status >/dev/null
/usr/local/sbin/sg-infosecctl overview >/dev/null

printf 'clean install bootstrap smoke passed\n'
