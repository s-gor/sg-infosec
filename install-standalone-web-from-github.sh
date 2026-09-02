#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_REPOSITORY_URL="https://github.com/s-gor/sg-infosec.git"
REPOSITORY_URL="${SG_INFOSEC_REPOSITORY_URL:-$DEFAULT_REPOSITORY_URL}"
SOURCE_SHA="${SG_INFOSEC_SOURCE_SHA:-}"
WEB_GROUP="sg-infosec-web"
WEB_USER="sg-infosec-web"
WEB_BINARY="/usr/local/sbin/sg-infosec-web"
WEB_UNIT="/etc/systemd/system/sg-infosec-web.service"
WEB_STATE_DIR="/var/lib/sg-infosec/web"
WEB_STATE="$WEB_STATE_DIR/auth.json"
WEB_SOURCE_CONFIG="/etc/sg-infosec/sources.d/standalone-web.yaml"
TLS_DIR="/etc/sg-infosec/web"
TLS_CERT="$TLS_DIR/tls.crt"
TLS_KEY="$TLS_DIR/tls.key"
TLS_CERT_SOURCE="${SG_INFOSEC_WEB_TLS_CERT_SOURCE:-}"
TLS_KEY_SOURCE="${SG_INFOSEC_WEB_TLS_KEY_SOURCE:-}"
NGINX_AVAILABLE="/etc/nginx/sites-available/sg-infosec-web.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/sg-infosec-web.conf"
TEMP_DIR=""
SOURCE_DIR=""
SETUP_RESULT=""
NGINX_MEMBERSHIP_CHANGED=0
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/false

usage() {
    printf 'usage: %s <full-40-character-commit-sha>\n' "$0" >&2
}

fail() {
    printf 'SG InfoSec standalone web install: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    local status=$?
    set +e
    if (( status != 0 )); then
        systemctl --no-pager --full status sg-infosec-web.service sg-infosec.service nginx.service >&2 2>/dev/null || true
        journalctl -u sg-infosec-web.service -u sg-infosec.service -u nginx.service --no-pager -n 80 >&2 2>/dev/null || true
    fi
    [[ -z "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"
    exit "$status"
}
trap cleanup EXIT

check_system() {
    (( EUID == 0 )) || fail "run as root"
    [[ -d /run/systemd/system ]] || fail "systemd is not running"
    command -v apt-get >/dev/null 2>&1 || fail "only Debian/Ubuntu apt-based hosts are supported"
    [[ -r /etc/os-release ]] || fail "/etc/os-release is missing"
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        ubuntu:*|debian:*|*:debian*) ;;
        *) fail "only Debian and Ubuntu are supported" ;;
    esac
}

install_dependencies() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        nginx \
        openssl \
        iproute2
}

download_public_source_archive() {
    local archive="$TEMP_DIR/source.tar.gz"
    curl --fail --location --silent --show-error \
        --retry 6 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
        --output "$archive" \
        "https://codeload.github.com/s-gor/sg-infosec/tar.gz/$SOURCE_SHA"
    mkdir -p "$SOURCE_DIR"
    tar -xzf "$archive" --strip-components=1 -C "$SOURCE_DIR"
    [[ -f "$SOURCE_DIR/install-from-github.sh" ]] || fail "pinned core installer is missing"
}

download_git_source() {
    git init --quiet "$SOURCE_DIR"
    git -C "$SOURCE_DIR" remote add origin "$REPOSITORY_URL"
    git -c credential.helper= -C "$SOURCE_DIR" fetch --depth=1 origin "$SOURCE_SHA"
    git -C "$SOURCE_DIR" checkout --quiet --detach FETCH_HEAD
    [[ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" == "$SOURCE_SHA" ]] || fail "exact source checkout failed"
}

download_source() {
    if [[ "$REPOSITORY_URL" == "$DEFAULT_REPOSITORY_URL" ]]; then
        download_public_source_archive
    else
        download_git_source
    fi
    [[ -f "$SOURCE_DIR/install-from-github.sh" ]] || fail "pinned core installer is missing"
    [[ -f "$SOURCE_DIR/packaging/systemd/sg-infosec-web.service" ]] || fail "web systemd unit is missing"
    [[ -f "$SOURCE_DIR/packaging/nginx/sg-infosec-web.conf" ]] || fail "web nginx config is missing"
    [[ -f "$SOURCE_DIR/packaging/sources.d/standalone-web.yaml" ]] || fail "standalone-web.yaml authorization source is missing"
}

install_core() {
    SG_INFOSEC_REPOSITORY_URL="$REPOSITORY_URL" \
        bash "$SOURCE_DIR/install-from-github.sh" "$SOURCE_SHA"
    systemctl is-active --quiet sg-infosec-enforcer.service || fail "sg-infosec-enforcer.service is not active"
    systemctl is-active --quiet sg-infosec.service || fail "sg-infosec.service is not active"
    [[ -S /run/sg-infosec/control.sock ]] || fail "core control socket is missing"
}

find_go() {
    local candidate
    if command -v go >/dev/null 2>&1; then
        candidate="$(command -v go)"
    elif [[ -x /usr/local/go/bin/go ]]; then
        candidate=/usr/local/go/bin/go
    else
        fail "Go toolchain was not available after core installation"
    fi
    printf '%s' "$candidate"
}

build_web() {
    local go_binary
    go_binary="$(find_go)"
    (
        cd "$SOURCE_DIR"
        GOTOOLCHAIN=local "$go_binary" build -trimpath -o "$TEMP_DIR/sg-infosec-web" ./cmd/sg-infosec-web
    )
    [[ -x "$TEMP_DIR/sg-infosec-web" ]] || fail "sg-infosec-web was not built"
}

install_identity_and_state() {
    getent group "$WEB_GROUP" >/dev/null 2>&1 || groupadd --system "$WEB_GROUP"
    if ! id -u "$WEB_USER" >/dev/null 2>&1; then
        useradd --system \
            --gid "$WEB_GROUP" \
            --home-dir "$WEB_STATE_DIR" \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$WEB_USER"
    fi
    id -u www-data >/dev/null 2>&1 || fail "nginx user www-data is missing"
    getent group sg-infosec >/dev/null 2>&1 || fail "core group sg-infosec is missing"
    if ! id -nG "$WEB_USER" | tr ' ' '\n' | grep -Fxq sg-infosec; then
        usermod -a -G sg-infosec "$WEB_USER"
    fi
    if ! id -nG www-data | tr ' ' '\n' | grep -Fxq "$WEB_GROUP"; then
        usermod -a -G "$WEB_GROUP" www-data
        NGINX_MEMBERSHIP_CHANGED=1
    fi
    install -d -o "$WEB_USER" -g "$WEB_GROUP" -m 0750 "$WEB_STATE_DIR"
    install -d -o root -g root -m 0750 "$TLS_DIR"
}

install_core_authorization() {
    install -m 0640 "$SOURCE_DIR/packaging/sources.d/standalone-web.yaml" "$WEB_SOURCE_CONFIG"
    chown root:sg-infosec "$WEB_SOURCE_CONFIG"
    /usr/local/sbin/sg-infosecd --config /etc/sg-infosec/sg-infosec.yaml --check-config
    systemctl restart sg-infosec.service
    local attempt
    for attempt in $(seq 1 100); do
        if systemctl is-active --quiet sg-infosec.service && [[ -S /run/sg-infosec/control.sock ]]; then
            return 0
        fi
        sleep 0.1
    done
    fail "core did not recover after standalone web authorization install"
}

install_tls() {
    if [[ -n "$TLS_CERT_SOURCE" || -n "$TLS_KEY_SOURCE" ]]; then
        [[ -n "$TLS_CERT_SOURCE" && -n "$TLS_KEY_SOURCE" ]] || fail "both SG_INFOSEC_WEB_TLS_CERT_SOURCE and SG_INFOSEC_WEB_TLS_KEY_SOURCE are required"
        [[ -r "$TLS_CERT_SOURCE" && -r "$TLS_KEY_SOURCE" ]] || fail "configured TLS source files are not readable"
        openssl x509 -in "$TLS_CERT_SOURCE" -noout >/dev/null || fail "TLS certificate is invalid"
        openssl pkey -in "$TLS_KEY_SOURCE" -noout >/dev/null || fail "TLS private key is invalid or encrypted"
        install -m 0644 "$TLS_CERT_SOURCE" "$TLS_CERT"
        install -m 0600 "$TLS_KEY_SOURCE" "$TLS_KEY"
        return
    fi

    if [[ -s "$TLS_CERT" && -s "$TLS_KEY" ]]; then
        openssl x509 -in "$TLS_CERT" -noout >/dev/null || fail "existing TLS certificate is invalid"
        openssl pkey -in "$TLS_KEY" -noout >/dev/null || fail "existing TLS key is invalid or encrypted"
        return
    fi

    local server_ip san
    server_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    san="DNS:localhost,IP:127.0.0.1"
    if [[ -n "$server_ip" && "$server_ip" =~ ^[0-9A-Fa-f:.]+$ ]]; then
        san+=",IP:$server_ip"
    fi
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
        -subj "/CN=SG InfoSec" \
        -addext "subjectAltName=$san" \
        -keyout "$TEMP_DIR/tls.key" \
        -out "$TEMP_DIR/tls.crt" >/dev/null 2>&1
    install -m 0644 "$TEMP_DIR/tls.crt" "$TLS_CERT"
    install -m 0600 "$TEMP_DIR/tls.key" "$TLS_KEY"
}

install_web_files() {
    install -m 0755 "$TEMP_DIR/sg-infosec-web" "$WEB_BINARY"
    install -m 0644 "$SOURCE_DIR/packaging/systemd/sg-infosec-web.service" "$WEB_UNIT"
    install -D -m 0644 "$SOURCE_DIR/packaging/nginx/sg-infosec-web.conf" "$NGINX_AVAILABLE"
    ln -sfn "$NGINX_AVAILABLE" "$NGINX_ENABLED"
    systemctl daemon-reload
}

bootstrap_auth() {
    SETUP_RESULT="$(runuser -u "$WEB_USER" -- env \
        SG_INFOSEC_WEB_STATE="$WEB_STATE" \
        "$WEB_BINARY" --ensure-setup-code)" || fail "could not prepare standalone web authentication"
    [[ "$SETUP_RESULT" == "configured" || "$SETUP_RESULT" =~ ^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$ ]] || \
        fail "unexpected authentication bootstrap result"
}

start_and_verify() {
    rm -f /run/sg-infosec-web/web.sock
    systemctl enable --now sg-infosec-web.service
    local attempt
    for attempt in $(seq 1 100); do
        if systemctl is-active --quiet sg-infosec-web.service && [[ -S /run/sg-infosec-web/web.sock ]]; then
            break
        fi
        sleep 0.1
    done
    systemctl is-active --quiet sg-infosec-web.service || fail "sg-infosec-web.service is not active"
    [[ -S /run/sg-infosec-web/web.sock ]] || fail "standalone web socket was not created"
    [[ "$(stat -c '%U:%G' /run/sg-infosec-web/web.sock)" == "$WEB_USER:$WEB_GROUP" ]] || fail "standalone web socket has unsafe ownership"

    nginx -t
    if (( NGINX_MEMBERSHIP_CHANGED )); then
        systemctl restart nginx.service
    else
        systemctl enable nginx.service >/dev/null 2>&1 || true
        if systemctl is-active --quiet nginx.service; then
            systemctl reload nginx.service
        else
            systemctl start nginx.service
        fi
    fi
    systemctl enable nginx.service >/dev/null 2>&1 || true
    systemctl is-active --quiet nginx.service || fail "nginx.service is not active"

    local page=""
    for attempt in $(seq 1 50); do
        if page="$(curl --fail --silent --show-error --insecure --location --max-time 5 https://127.0.0.1:64443/infosec/ 2>/dev/null)" && \
            grep -Fq "SG InfoSec" <<<"$page"; then
            return 0
        fi
        sleep 0.1
    done
    fail "HTTPS verification failed on port 64443"
}

print_result() {
    local server_ip
    server_ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    [[ -n "$server_ip" ]] || server_ip="SERVER_IP"
    printf '\nSG InfoSec standalone web successfully installed.\n'
    printf 'URL: https://%s:64443/infosec/\n' "$server_ip"
    printf 'Commit: %s\n' "$SOURCE_SHA"
    if [[ "$SETUP_RESULT" != "configured" ]]; then
        printf 'One-time setup code: %s\n' "$SETUP_RESULT"
        printf 'The setup code expires in 30 minutes and is invalidated after administrator creation.\n'
    else
        printf 'Existing standalone administrator and authentication state were preserved.\n'
    fi
    if [[ -z "$TLS_CERT_SOURCE" ]]; then
        printf 'TLS: existing certificate was preserved, or a local self-signed certificate was created when none existed.\n'
    else
        printf 'TLS: configured certificate sources were installed.\n'
    fi
    printf 'SG-Gateway was not restarted.\n'
}

if (( $# > 1 )); then
    usage
    exit 2
fi
if (( $# == 1 )); then
    SOURCE_SHA="$1"
fi
if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
    fail "source commit must match ^[0-9a-f]{40}$"
fi

check_system
TEMP_DIR="$(mktemp -d)"
SOURCE_DIR="$TEMP_DIR/source"
install_dependencies
download_source
install_core
build_web
install_identity_and_state
install_core_authorization
install_tls
install_web_files
bootstrap_auth
start_and_verify
print_result
