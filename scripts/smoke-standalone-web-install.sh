#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD)"
TEMP_DIR="$(mktemp -d)"
INSTALL_OUTPUT="$TEMP_DIR/install.out"
COOKIE_JAR="$TEMP_DIR/cookies.txt"
SETUP_PAGE="$TEMP_DIR/setup.html"
LOGIN_PAGE="$TEMP_DIR/login.html"
DECISIONS_PAGE="$TEMP_DIR/decisions.html"
INSTALLED=0

fail() {
    printf 'standalone web install smoke: %s\n' "$*" >&2
    [[ ! -f "$INSTALL_OUTPUT" ]] || tail -n 160 "$INSTALL_OUTPUT" >&2 || true
    systemctl --no-pager --full status sg-infosec-web.service sg-infosec.service sg-infosec-enforcer.service nginx.service >&2 2>/dev/null || true
    journalctl -u sg-infosec-web.service -u sg-infosec.service -u nginx.service --no-pager -n 120 >&2 2>/dev/null || true
    exit 1
}

cleanup() {
    set +e
    systemctl disable --now sg-infosec-web.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/sg-infosec-web.service \
        /usr/local/sbin/sg-infosec-web \
        /etc/nginx/sites-enabled/sg-infosec-web.conf \
        /etc/nginx/sites-available/sg-infosec-web.conf
    systemctl daemon-reload >/dev/null 2>&1 || true
    if (( INSTALLED )); then
        "$ROOT_DIR/packaging/uninstall.sh" --purge >/dev/null 2>&1 || true
    fi
    userdel sg-infosec-web >/dev/null 2>&1 || true
    groupdel sg-infosec-web >/dev/null 2>&1 || true
    rm -rf -- "$TEMP_DIR"
}
trap cleanup EXIT

[[ $EUID -eq 0 ]] || fail "run as root"
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "source SHA is not complete"

"$ROOT_DIR/packaging/uninstall.sh" --purge >/dev/null 2>&1 || true
systemctl disable --now sg-infosec-web.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sg-infosec-web.service \
    /usr/local/sbin/sg-infosec-web \
    /etc/nginx/sites-enabled/sg-infosec-web.conf \
    /etc/nginx/sites-available/sg-infosec-web.conf
userdel sg-infosec-web >/dev/null 2>&1 || true
groupdel sg-infosec-web >/dev/null 2>&1 || true
systemctl daemon-reload >/dev/null 2>&1 || true

if ! SG_INFOSEC_REPOSITORY_URL="file://$ROOT_DIR" \
    TERM=dumb \
    bash "$ROOT_DIR/install-standalone-web-from-github.sh" "$SOURCE_SHA" >"$INSTALL_OUTPUT" 2>&1; then
    cat "$INSTALL_OUTPUT" >&2
    fail "installer failed"
fi
cat "$INSTALL_OUTPUT"
INSTALLED=1

systemctl is-active --quiet sg-infosec-enforcer.service || fail "enforcer is not active"
systemctl is-active --quiet sg-infosec.service || fail "core is not active"
systemctl is-active --quiet sg-infosec-web.service || fail "web service is not active"
systemctl is-active --quiet nginx.service || fail "nginx is not active"
[[ -S /run/sg-infosec/control.sock ]] || fail "control socket is missing"
[[ -S /run/sg-infosec-web/web.sock ]] || fail "web socket is missing"

SETUP_CODE="$(grep -Eo 'One-time setup code: [0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}' "$INSTALL_OUTPUT" | tail -n1 | awk '{print $4}')"
[[ "$SETUP_CODE" =~ ^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$ ]] || fail "setup code was not emitted"

curl --fail --silent --show-error --insecure \
    https://127.0.0.1:64443/infosec/setup >"$SETUP_PAGE"
grep -Fq 'Первичная настройка' "$SETUP_PAGE" || fail "setup page is unavailable"

SETUP_STATUS="$(curl --silent --show-error --insecure \
    --output /dev/null \
    --write-out '%{http_code}' \
    --request POST \
    --data-urlencode "setup_code=$SETUP_CODE" \
    --data-urlencode 'username=admin' \
    --data-urlencode 'password=correct horse battery staple' \
    https://127.0.0.1:64443/infosec/setup)"
[[ "$SETUP_STATUS" == "303" ]] || fail "administrator setup returned HTTP $SETUP_STATUS"

curl --fail --silent --show-error --insecure \
    https://127.0.0.1:64443/infosec/login >"$LOGIN_PAGE"
grep -Fq 'Вход' "$LOGIN_PAGE" || fail "login page is unavailable"

LOGIN_STATUS="$(curl --silent --show-error --insecure \
    --output /dev/null \
    --write-out '%{http_code}' \
    --cookie-jar "$COOKIE_JAR" \
    --request POST \
    --data-urlencode 'username=admin' \
    --data-urlencode 'password=correct horse battery staple' \
    https://127.0.0.1:64443/infosec/login)"
[[ "$LOGIN_STATUS" == "303" ]] || fail "login returned HTTP $LOGIN_STATUS"

SESSION_VALUE="$(awk '$6 == "sg_infosec_session" {print $7}' "$COOKIE_JAR" | tail -n1)"
[[ "$SESSION_VALUE" == *.* ]] || fail "session cookie was not issued"
CSRF_TOKEN="${SESSION_VALUE#*.}"
[[ -n "$CSRF_TOKEN" ]] || fail "CSRF token is missing"

curl --fail --silent --show-error --insecure \
    --cookie "$COOKIE_JAR" \
    https://127.0.0.1:64443/infosec/decisions >"$DECISIONS_PAGE"
grep -Fq 'Блокировки' "$DECISIONS_PAGE" || fail "authenticated decisions page is unavailable"

DECISION_STATUS="$(curl --silent --show-error --insecure \
    --output /dev/null \
    --write-out '%{http_code}' \
    --cookie "$COOKIE_JAR" \
    --request POST \
    --data-urlencode "csrf=$CSRF_TOKEN" \
    --data-urlencode 'source=local-admin' \
    --data-urlencode 'scope=ssh' \
    --data-urlencode 'backend=nftables' \
    --data-urlencode 'ip=198.51.100.77' \
    --data-urlencode 'duration=5m' \
    --data-urlencode 'reason=standalone-web-smoke' \
    https://127.0.0.1:64443/infosec/decisions/add)"
[[ "$DECISION_STATUS" == "303" ]] || fail "manual decision returned HTTP $DECISION_STATUS"

curl --fail --silent --show-error --insecure \
    --cookie "$COOKIE_JAR" \
    https://127.0.0.1:64443/infosec/decisions >"$DECISIONS_PAGE"
grep -Fq '198.51.100.77' "$DECISIONS_PAGE" || fail "manual decision is missing from web UI"
/usr/local/sbin/sg-infosecctl decisions list | grep -Fq '198.51.100.77' || fail "manual decision is missing from core state"
/usr/local/sbin/sg-infosecctl nft list | grep -Fq '198.51.100.77' || fail "manual SSH decision is missing from nftables state"

printf 'standalone web install smoke passed\n'
