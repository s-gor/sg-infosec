#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_URL="${SG_INFOSEC_REPOSITORY_URL:-https://github.com/s-gor/sg-infosec.git}"
SOURCE_SHA="${SG_INFOSEC_SOURCE_SHA:-}"
GO_VERSION="1.24.12"
GO_MIN_MAJOR=1
GO_MIN_MINOR=23
TEMP_DIR=""
INSTALLATION_STARTED=0

usage() {
    printf 'usage: %s <full-40-character-commit-sha>\n' "$0" >&2
}

diagnostics() {
    systemctl --no-pager --full status \
        sg-infosec-enforcer.service \
        sg-infosec.service >&2 2>/dev/null || true
    journalctl \
        -u sg-infosec-enforcer.service \
        -u sg-infosec.service \
        --no-pager -n 120 >&2 2>/dev/null || true
}

finish() {
    local status=$?
    set +e
    if (( status != 0 && INSTALLATION_STARTED )); then
        printf 'SG InfoSec installation failed; service diagnostics follow.\n' >&2
        diagnostics
    fi
    if [[ -n "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
    exit "$status"
}
trap finish EXIT

fail() {
    printf 'SG InfoSec install: %s\n' "$*" >&2
    exit 1
}

if (( $# > 1 )); then
    usage
    exit 2
fi
if (( $# == 1 )); then
    SOURCE_SHA="$1"
fi
if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    fail "SG InfoSec source commit must be a full 40-character SHA"
fi
if (( EUID != 0 )); then
    fail "run as root"
fi
[[ -d /run/systemd/system ]] || fail "systemd is not running"
command -v apt-get >/dev/null 2>&1 || fail "only Debian/Ubuntu apt-based hosts are supported"

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    fail "/etc/os-release is missing"
fi
case "${ID:-}:${ID_LIKE:-}" in
    ubuntu:*|debian:*|*:debian*) ;;
    *) fail "only Debian and Ubuntu are supported" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    build-essential \
    pkg-config \
    libsqlite3-dev

version_is_supported() {
    local binary="$1" version major minor
    version="$($binary env GOVERSION 2>/dev/null || true)"
    if [[ ! "$version" =~ ^go([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]]; then
        return 1
    fi
    major="${BASH_REMATCH[1]}"
    minor="${BASH_REMATCH[2]}"
    (( major > GO_MIN_MAJOR || (major == GO_MIN_MAJOR && minor >= GO_MIN_MINOR) ))
}

find_supported_go() {
    local candidate
    if command -v go >/dev/null 2>&1; then
        candidate="$(command -v go)"
        if version_is_supported "$candidate"; then
            printf '%s' "$candidate"
            return 0
        fi
    fi
    candidate="/usr/local/go/bin/go"
    if [[ -x "$candidate" ]] && version_is_supported "$candidate"; then
        printf '%s' "$candidate"
        return 0
    fi
    return 1
}

install_go() {
    local machine archive checksum url download
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)
            archive="go1.24.12.linux-amd64.tar.gz"
            checksum="bddf8e653c82429aea7aec2520774e79925d4bb929fe20e67ecc00dd5af44c50"
            ;;
        aarch64|arm64)
            archive="go1.24.12.linux-arm64.tar.gz"
            checksum="4e02e2979e53b40f3666bba9f7e5ea0b99ea5156e0824b343fd054742c25498d"
            ;;
        *) fail "unsupported CPU architecture: $machine" ;;
    esac

    url="https://go.dev/dl/$archive"
    download="$TEMP_DIR/$archive"
    printf 'Installing Go %s for %s...\n' "$GO_VERSION" "$machine"
    curl --fail --location --silent --show-error \
        --retry 3 --retry-delay 2 \
        --output "$download" "$url"
    printf '%s  %s\n' "$checksum" "$download" | sha256sum --check --status || \
        fail "Go archive checksum verification failed"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$download"
    version_is_supported /usr/local/go/bin/go || fail "installed Go version is not supported"
}

TEMP_DIR="$(mktemp -d)"
if ! GO_BINARY="$(find_supported_go)"; then
    install_go
    GO_BINARY="/usr/local/go/bin/go"
fi
export PATH="$(dirname "$GO_BINARY"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export GOTOOLCHAIN=local

SOURCE_DIR="$TEMP_DIR/source"
git init --quiet "$SOURCE_DIR"
cd "$SOURCE_DIR"
git remote add origin "$REPOSITORY_URL"
git fetch --depth=1 origin "$SOURCE_SHA"
git checkout --quiet --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "$SOURCE_SHA"

make build
[[ -x bin/sg-infosecd ]] || fail "sg-infosecd was not built"
[[ -x bin/sg-infosecctl ]] || fail "sg-infosecctl was not built"
[[ -x bin/sg-infosec-enforcerd ]] || fail "sg-infosec-enforcerd was not built"

if [[ -f /etc/sg-infosec/sg-infosec.yaml ]]; then
    bin/sg-infosecd \
        --config /etc/sg-infosec/sg-infosec.yaml \
        --check-config
fi

INSTALLATION_STARTED=1
systemctl stop sg-infosec.service sg-infosec-enforcer.service 2>/dev/null || true
SG_INFOSEC_NO_START=1 ./packaging/install.sh

systemctl daemon-reload
systemd-tmpfiles --create /usr/lib/tmpfiles.d/sg-infosec.conf
rm -f \
    /run/sg-infosec/control.sock \
    /run/sg-infosec/events.sock \
    /run/sg-infosec/enforcer.sock \
    /run/sg-infosec/enforcer-debug.sock
systemctl reset-failed sg-infosec-enforcer.service sg-infosec.service 2>/dev/null || true
systemctl enable sg-infosec-enforcer.service sg-infosec.service

wait_for_service_socket() {
    local service="$1" socket="$2"
    local attempt
    for attempt in $(seq 1 100); do
        if systemctl is-active --quiet "$service" && [[ -S "$socket" ]]; then
            return 0
        fi
        sleep 0.1
    done
    fail "$service did not create $socket"
}

systemctl start sg-infosec-enforcer.service
wait_for_service_socket sg-infosec-enforcer.service /run/sg-infosec/enforcer.sock

systemctl start sg-infosec.service
wait_for_service_socket sg-infosec.service /run/sg-infosec/control.sock
[[ -S /run/sg-infosec/events.sock ]] || fail "events socket was not created"

/usr/local/sbin/sg-infosecctl health
/usr/local/sbin/sg-infosecctl nft status

printf 'SG InfoSec installed from commit %s.\n' "$SOURCE_SHA"
printf 'Existing configuration and state were preserved. SG-Gateway was not restarted.\n'
