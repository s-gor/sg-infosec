#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="sg-infosec"
SERVICE_GROUP="sg-infosec"
DESTDIR="${DESTDIR:-}"
NO_START="${SG_INFOSEC_NO_START:-0}"
DAEMON_SOURCE="${SG_INFOSEC_DAEMON_SOURCE:-$ROOT_DIR/bin/sg-infosecd}"
CTL_SOURCE="${SG_INFOSEC_CTL_SOURCE:-$ROOT_DIR/bin/sg-infosecctl}"
ENFORCER_SOURCE="${SG_INFOSEC_ENFORCER_SOURCE:-$ROOT_DIR/bin/sg-infosec-enforcerd}"

root_path() { printf '%s%s' "$DESTDIR" "$1"; }
DAEMON_PATH="$(root_path /usr/local/sbin/sg-infosecd)"
CTL_PATH="$(root_path /usr/local/sbin/sg-infosecctl)"
ENFORCER_PATH="$(root_path /usr/local/sbin/sg-infosec-enforcerd)"
UNIT_PATH="$(root_path /etc/systemd/system/sg-infosec.service)"
ENFORCER_UNIT_PATH="$(root_path /etc/systemd/system/sg-infosec-enforcer.service)"
TMPFILES_PATH="$(root_path /usr/lib/tmpfiles.d/sg-infosec.conf)"
CONFIG_ROOT="$(root_path /etc/sg-infosec)"

fail() { printf 'sg-infosec install: %s\n' "$*" >&2; exit 1; }

if [[ -z "$DESTDIR" && $EUID -ne 0 ]]; then
    fail "run as root"
fi
[[ -x "$DAEMON_SOURCE" ]] || fail "missing executable: $DAEMON_SOURCE"
[[ -x "$CTL_SOURCE" ]] || fail "missing executable: $CTL_SOURCE"
[[ -x "$ENFORCER_SOURCE" ]] || fail "missing executable: $ENFORCER_SOURCE"

if [[ -z "$DESTDIR" ]]; then
    getent group "$SERVICE_GROUP" >/dev/null 2>&1 || groupadd --system "$SERVICE_GROUP"
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system \
            --gid "$SERVICE_GROUP" \
            --home-dir /var/lib/sg-infosec \
            --no-create-home \
            --shell /usr/sbin/nologin \
            "$SERVICE_USER"
    fi
fi

install -D -m 0755 "$DAEMON_SOURCE" "$DAEMON_PATH"
install -D -m 0755 "$CTL_SOURCE" "$CTL_PATH"
install -D -m 0755 "$ENFORCER_SOURCE" "$ENFORCER_PATH"
install -D -m 0644 "$ROOT_DIR/packaging/systemd/sg-infosec.service" "$UNIT_PATH"
install -D -m 0644 "$ROOT_DIR/packaging/systemd/sg-infosec-enforcer.service" "$ENFORCER_UNIT_PATH"
install -D -m 0644 "$ROOT_DIR/packaging/tmpfiles.d/sg-infosec.conf" "$TMPFILES_PATH"

install_if_missing() {
    local source="$1" destination="$2" mode="$3"
    if [[ -e "$destination" ]]; then
        return 0
    fi
    install -D -m "$mode" "$source" "$destination"
    if [[ -z "$DESTDIR" ]]; then
        chown root:"$SERVICE_GROUP" "$destination"
    fi
}

install_if_missing "$ROOT_DIR/config/example/sg-infosec.yaml" \
    "$CONFIG_ROOT/sg-infosec.yaml" 0640
install_if_missing "$ROOT_DIR/config/example/sources.d/local-admin.yaml" \
    "$CONFIG_ROOT/sources.d/local-admin.yaml" 0640

GATEWAY_MEMBERSHIP_CHANGED=0
if [[ -z "$DESTDIR" ]] && id -u sg-gateway >/dev/null 2>&1; then
    if ! id -nG sg-gateway | tr ' ' '\n' | grep -Fxq "$SERVICE_GROUP"; then
        usermod -a -G "$SERVICE_GROUP" sg-gateway
        GATEWAY_MEMBERSHIP_CHANGED=1
    fi
    install_if_missing "$ROOT_DIR/config/example/sources.d/sg-gateway.yaml" \
        "$CONFIG_ROOT/sources.d/sg-gateway.yaml" 0640
    install_if_missing "$ROOT_DIR/config/example/policies.d/admin.yaml" \
        "$CONFIG_ROOT/policies.d/admin.yaml" 0640
    install_if_missing "$ROOT_DIR/config/example/policies.d/admin-api.yaml" \
        "$CONFIG_ROOT/policies.d/admin-api.yaml" 0640
fi

if [[ -z "$DESTDIR" ]]; then
    systemd-tmpfiles --create "$TMPFILES_PATH"
    systemctl daemon-reload
    if [[ "$NO_START" != "1" ]]; then
        systemctl enable --now sg-infosec-enforcer.service sg-infosec.service
    fi
fi

if (( GATEWAY_MEMBERSHIP_CHANGED )); then
    printf 'note: SG Gateway group membership takes effect after the next planned sg-gateway.service restart; the installer did not restart it.\n' >&2
fi

printf 'SG InfoSec installed. Existing configuration and state were preserved.\n'
