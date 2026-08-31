#!/usr/bin/env bash
set -Eeuo pipefail

PURGE=0
case "${1:-}" in
    "") ;;
    --purge) PURGE=1 ;;
    *) printf 'usage: %s [--purge]\n' "$0" >&2; exit 2 ;;
esac

DESTDIR="${DESTDIR:-}"
if [[ -z "$DESTDIR" && $EUID -ne 0 ]]; then
    printf 'sg-infosec uninstall: run as root\n' >&2
    exit 1
fi

root_path() { printf '%s%s' "$DESTDIR" "$1"; }
DAEMON_PATH="$(root_path /usr/local/sbin/sg-infosecd)"
CTL_PATH="$(root_path /usr/local/sbin/sg-infosecctl)"
ENFORCER_PATH="$(root_path /usr/local/sbin/sg-infosec-enforcerd)"
SSH_AGENT_PATH="$(root_path /usr/local/sbin/sg-infosec-ssh-agent)"
UNIT_PATH="$(root_path /etc/systemd/system/sg-infosec.service)"
ENFORCER_UNIT_PATH="$(root_path /etc/systemd/system/sg-infosec-enforcer.service)"
SSH_AGENT_UNIT_PATH="$(root_path /etc/systemd/system/sg-infosec-ssh-agent.service)"
TMPFILES_PATH="$(root_path /usr/lib/tmpfiles.d/sg-infosec.conf)"
CONFIG_ROOT="$(root_path /etc/sg-infosec)"
STATE_ROOT="$(root_path /var/lib/sg-infosec)"
RUNTIME_ROOT="$(root_path /run/sg-infosec)"

if [[ -z "$DESTDIR" ]]; then
    systemctl disable --now sg-infosec-ssh-agent.service 2>/dev/null || true
    systemctl disable --now sg-infosec.service sg-infosec-enforcer.service 2>/dev/null || true
fi
if (( PURGE )) && [[ -z "$DESTDIR" && -x "$ENFORCER_PATH" ]]; then
    "$ENFORCER_PATH" --purge-owned-table
fi
rm -f -- \
    "$DAEMON_PATH" "$CTL_PATH" "$ENFORCER_PATH" "$SSH_AGENT_PATH" \
    "$UNIT_PATH" "$ENFORCER_UNIT_PATH" "$SSH_AGENT_UNIT_PATH" "$TMPFILES_PATH"
if [[ -z "$DESTDIR" ]]; then
    systemctl daemon-reload
    systemctl reset-failed sg-infosec-ssh-agent.service sg-infosec.service sg-infosec-enforcer.service 2>/dev/null || true
fi

if (( PURGE )); then
    rm -rf -- "$CONFIG_ROOT" "$STATE_ROOT" "$RUNTIME_ROOT"
    if [[ -z "$DESTDIR" ]]; then
        if id -u sg-infosec >/dev/null 2>&1; then
            userdel sg-infosec
        fi
        if getent group sg-infosec >/dev/null 2>&1; then
            groupdel sg-infosec
        fi
    fi
else
    rm -rf -- "$RUNTIME_ROOT"
fi

if (( PURGE )); then
    printf 'SG InfoSec removed with configuration and state.\n'
else
    printf 'SG InfoSec removed; configuration and state preserved.\n'
fi
