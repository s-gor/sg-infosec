#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_REPOSITORY_URL="https://github.com/s-gor/sg-infosec.git"
REPOSITORY_URL="${SG_INFOSEC_REPOSITORY_URL:-$DEFAULT_REPOSITORY_URL}"
SOURCE_SHA="${SG_INFOSEC_SOURCE_SHA:-}"
FORCE_GO_INSTALL="${SG_INFOSEC_FORCE_GO_INSTALL:-0}"
VERBOSE="${SG_INFOSEC_VERBOSE:-0}"
GO_VERSION="1.24.12"
GO_MIN_MAJOR=1
GO_MIN_MINOR=23
TEMP_DIR=""
INSTALL_LOG=""
STATUS_OUTPUT=""
INSTALLATION_STARTED=0
UI_ENABLED=0
GREEN=$'\033[32m'
RED=$'\033[31m'
BOLD=$'\033[1m'
RESET=$'\033[0m'
SPINNER_FRAMES=('/' '-' '\\' '|')
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/false

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

show_failure_log() {
    if [[ -s "$INSTALL_LOG" ]]; then
        printf '\nLast installer log lines:\n' >&2
        tail -n 40 "$INSTALL_LOG" >&2 || true
    fi
}

finish() {
    local status=$?
    set +e
    if (( status != 0 )); then
        show_failure_log
        if (( INSTALLATION_STARTED )); then
            printf 'SG InfoSec installation failed; service diagnostics follow.\n' >&2
            diagnostics
        fi
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

plain_marker() {
    local state="$1"
    case "$state" in
        start) printf '[..]' ;;
        ok) printf '[OK]' ;;
        fail) printf '[FAIL]' ;;
    esac
}

run_step() {
    local label="$1"
    shift
    local status pid frame_index=0

    if (( VERBOSE )); then
        printf '\n%s\n' "$label"
        if "$@" 2>&1 | tee -a "$INSTALL_LOG"; then
            status=0
        else
            status=${PIPESTATUS[0]}
        fi
    elif (( UI_ENABLED )); then
        "$@" >>"$INSTALL_LOG" 2>&1 &
        pid=$!
        while kill -0 "$pid" 2>/dev/null; do
            printf '\r\033[2K%s[%s]%s %s' \
                "$GREEN" "${SPINNER_FRAMES[$frame_index]}" "$RESET" "$label"
            frame_index=$(( (frame_index + 1) % ${#SPINNER_FRAMES[@]} ))
            sleep 0.1
        done
        if wait "$pid"; then
            status=0
        else
            status=$?
        fi
    else
        printf '%s %s\n' "$(plain_marker start)" "$label"
        if "$@" >>"$INSTALL_LOG" 2>&1; then
            status=0
        else
            status=$?
        fi
    fi

    if (( status == 0 )); then
        if (( UI_ENABLED && ! VERBOSE )); then
            printf '\r\033[2K%s[✓]%s %s\n' "$GREEN" "$RESET" "$label"
        elif (( ! VERBOSE )); then
            printf '%s %s\n' "$(plain_marker ok)" "$label"
        fi
        return 0
    fi

    if (( UI_ENABLED && ! VERBOSE )); then
        printf '\r\033[2K%s[✗]%s %s\n' "$RED" "$RESET" "$label" >&2
    elif (( ! VERBOSE )); then
        printf '%s %s\n' "$(plain_marker fail)" "$label" >&2
    fi
    return "$status"
}

check_system() {
    [[ -d /run/systemd/system ]] || fail "systemd is not running"
    command -v apt-get >/dev/null 2>&1 || fail "only Debian/Ubuntu apt-based hosts are supported"
    [[ -r /etc/os-release ]] || fail "/etc/os-release is missing"

    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        ubuntu:*|debian:*|*:debian*) ;;
        *) fail "only Debian and Ubuntu are supported" ;;
    esac
    printf 'System: %s %s (%s)\n' "${PRETTY_NAME:-${ID:-Linux}}" "${VERSION_ID:-}" "$(uname -m)"
}

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        build-essential \
        pkg-config \
        libsqlite3-dev
}

version_is_supported() {
    local binary="$1" version major minor
    version="$("$binary" env GOVERSION 2>/dev/null || true)"
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
    curl --fail --location --silent --show-error \
        --retry 3 --retry-delay 2 \
        --output "$download" "$url"
    printf '%s  %s\n' "$checksum" "$download" | sha256sum --check --status || \
        fail "Go archive checksum verification failed"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$download"
    version_is_supported /usr/local/go/bin/go || fail "installed Go version is not supported"
}

prepare_go() {
    local binary
    if [[ "$FORCE_GO_INSTALL" == "1" ]]; then
        install_go
        binary="/usr/local/go/bin/go"
    elif binary="$(find_supported_go)"; then
        :
    else
        install_go
        binary="/usr/local/go/bin/go"
    fi
    printf '%s\n' "$binary" >"$TEMP_DIR/go-binary"
    "$binary" env GOVERSION
}

download_public_source_archive() {
    local archive="$TEMP_DIR/source.tar.gz"
    curl --fail --location --silent --show-error \
        --retry 6 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
        --output "$archive" \
        "https://codeload.github.com/s-gor/sg-infosec/tar.gz/$SOURCE_SHA"
    mkdir -p "$SOURCE_DIR"
    tar -xzf "$archive" --strip-components=1 -C "$SOURCE_DIR"
    [[ -f "$SOURCE_DIR/go.mod" ]] || fail "pinned source archive is incomplete"
}

download_git_source() {
    git init --quiet "$SOURCE_DIR"
    git -C "$SOURCE_DIR" remote add origin "$REPOSITORY_URL"
    git -c credential.helper= -C "$SOURCE_DIR" fetch --depth=1 origin "$SOURCE_SHA"
    git -C "$SOURCE_DIR" checkout --quiet --detach FETCH_HEAD
    test "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$SOURCE_SHA"
}

download_source() {
    if [[ "$REPOSITORY_URL" == "$DEFAULT_REPOSITORY_URL" ]]; then
        download_public_source_archive
    else
        download_git_source
    fi
}

build_components() {
    cd "$SOURCE_DIR"
    make build
    [[ -x bin/sg-infosecd ]] || fail "sg-infosecd was not built"
    [[ -x bin/sg-infosecctl ]] || fail "sg-infosecctl was not built"
    [[ -x bin/sg-infosec-enforcerd ]] || fail "sg-infosec-enforcerd was not built"
}

validate_existing_config() {
    cd "$SOURCE_DIR"
    if [[ -f /etc/sg-infosec/sg-infosec.yaml ]]; then
        bin/sg-infosecd \
            --config /etc/sg-infosec/sg-infosec.yaml \
            --check-config
    fi
}

install_services() {
    cd "$SOURCE_DIR"
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
}

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

start_services() {
    systemctl start sg-infosec-enforcer.service
    wait_for_service_socket sg-infosec-enforcer.service /run/sg-infosec/enforcer.sock

    systemctl start sg-infosec.service
    wait_for_service_socket sg-infosec.service /run/sg-infosec/control.sock
    [[ -S /run/sg-infosec/events.sock ]] || fail "events socket was not created"
}

verify_installation() {
    {
        /usr/local/sbin/sg-infosecctl health
        /usr/local/sbin/sg-infosecctl nft status
    } | tee "$STATUS_OUTPUT"
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
case "$FORCE_GO_INSTALL" in
    0|1) ;;
    *) fail "SG_INFOSEC_FORCE_GO_INSTALL must be 0 or 1" ;;
esac
case "$VERBOSE" in
    0|1) ;;
    *) fail "SG_INFOSEC_VERBOSE must be 0 or 1" ;;
esac
if (( EUID != 0 )); then
    fail "run as root"
fi

TEMP_DIR="$(mktemp -d)"
INSTALL_LOG="$TEMP_DIR/install.log"
STATUS_OUTPUT="$TEMP_DIR/status.out"
SOURCE_DIR="$TEMP_DIR/source"
if [[ -t 1 && "${TERM:-dumb}" != "dumb" ]]; then
    UI_ENABLED=1
fi

if (( UI_ENABLED )); then
    printf '%sSG InfoSec Installer%s\n\n' "$BOLD" "$RESET"
else
    printf 'SG InfoSec Installer\n'
fi

run_step "Checking system" check_system
run_step "Installing dependencies" install_dependencies
run_step "Preparing Go toolchain" prepare_go
GO_BINARY="$(cat "$TEMP_DIR/go-binary")"
export PATH="$(dirname "$GO_BINARY"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export GOTOOLCHAIN=local
run_step "Downloading pinned source" download_source
run_step "Building components" build_components
run_step "Validating existing configuration" validate_existing_config
INSTALLATION_STARTED=1
run_step "Installing system services" install_services
run_step "Starting SG InfoSec" start_services
run_step "Verifying installation" verify_installation

printf '\n'
if (( UI_ENABLED )); then
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$GREEN" "$RESET"
    printf '%s SG InfoSec successfully installed%s\n' "$GREEN" "$RESET"
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$GREEN" "$RESET"
else
    printf 'SG InfoSec successfully installed\n'
fi
cat "$STATUS_OUTPUT"
printf 'Commit: %s\n' "$SOURCE_SHA"
printf 'Existing configuration and state were preserved. SG-Gateway was not restarted.\n'
