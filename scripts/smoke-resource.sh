#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
BIN="$TMP_DIR/sg-infosecd"
PID=""

cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

[[ "$(uname -s)" == "Linux" ]] || { echo "resource smoke requires Linux" >&2; exit 1; }
[[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "amd64" ]] || { echo "resource smoke requires amd64" >&2; exit 1; }
command -v go >/dev/null
command -v python3 >/dev/null
command -v pkg-config >/dev/null
pkg-config --exists sqlite3

mkdir -p "$TMP_DIR/sources.d" "$TMP_DIR/policies.d"
CURRENT_USER="$(id -un)"

cat > "$TMP_DIR/sg-infosec.yaml" <<CFG
database_path: $TMP_DIR/state.db
events_socket: $TMP_DIR/events.sock
control_socket: $TMP_DIR/control.sock
event_body_limit: 16384
sources_dir: sources.d
policies_dir: policies.d
retention:
  events: 168h
  audit: 2160h
CFG

cat > "$TMP_DIR/sources.d/smoke.yaml" <<CFG
source_id: smoke-local
user: $CURRENT_USER
allowed_events:
  - auth.failed
allowed_scopes:
  - admin-login
permissions:
  - check_decisions
  - read_admin
  - write_admin
CFG

cat > "$TMP_DIR/policies.d/smoke.yaml" <<'CFG'
policy_id: smoke-disabled
source_id: smoke-local
enabled: false
event_type: auth.failed
scope: admin-login
threshold: 5
window: 10m
base_duration: 30m
escalation_factor: 4
max_duration: 24h
reset_interval: 720h
backend: application
CFG

cd "$ROOT_DIR"
CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o "$BIN" ./cmd/sg-infosecd
"$BIN" --config "$TMP_DIR/sg-infosec.yaml" >"$TMP_DIR/daemon.out" 2>"$TMP_DIR/daemon.err" &
PID=$!

python3 - "$TMP_DIR/control.sock" <<'PY'
import http.client, json, os, socket, sys, time
path = sys.argv[1]
class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
deadline = time.time() + 5
last = None
while time.time() < deadline:
    try:
        conn = UnixConnection("unix", timeout=1)
        conn.request("GET", "/v1/health")
        response = conn.getresponse()
        body = json.loads(response.read())
        conn.close()
        if response.status == 200 and body.get("status") in ("healthy", "degraded"):
            sys.exit(0)
        last = (response.status, body)
    except Exception as exc:
        last = repr(exc)
    time.sleep(0.05)
raise SystemExit(f"daemon did not become healthy: {last}")
PY

RSS_KIB="$(awk '/^VmRSS:/ {print $2}' "/proc/$PID/status")"
[[ "$RSS_KIB" =~ ^[0-9]+$ ]] || { echo "could not read VmRSS" >&2; exit 1; }
if (( RSS_KIB > 30720 )); then
  echo "idle RSS ${RSS_KIB} KiB exceeds 30720 KiB" >&2
  exit 1
fi

echo "idle RSS: ${RSS_KIB} KiB"

python3 - "$TMP_DIR/events.sock" <<'PY'
import datetime, http.client, json, socket, sys
path = sys.argv[1]
class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
conn = UnixConnection("unix", timeout=5)
now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
for index in range(10000):
    address = f"198.51.100.{(index % 100) + 1}"
    body = json.dumps({
        "event_id": f"smoke-{index}",
        "event_type": "auth.failed",
        "scope": "admin-login",
        "ip": address,
        "occurred_at": now,
    }, separators=(",", ":"))
    conn.request("POST", "/v1/events", body=body, headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    payload = response.read()
    if response.status != 202:
        raise SystemExit(f"event {index} failed: HTTP {response.status} {payload[:200]!r}")
conn.close()
PY

python3 - "$TMP_DIR/control.sock" <<'PY'
import http.client, json, socket, sys
path = sys.argv[1]
class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
conn = UnixConnection("unix", timeout=2)
conn.request("GET", "/v1/health")
response = conn.getresponse()
body = json.loads(response.read())
conn.close()
if response.status != 200 or body.get("status") not in ("healthy", "degraded"):
    raise SystemExit(f"health after load failed: HTTP {response.status} {body!r}")
PY

kill -TERM "$PID"
wait "$PID"
PID=""

[[ ! -e "$TMP_DIR/events.sock" ]] || { echo "events socket remains after shutdown" >&2; exit 1; }
[[ ! -e "$TMP_DIR/control.sock" ]] || { echo "control socket remains after shutdown" >&2; exit 1; }

echo "resource smoke passed: 10000 events, health responsive, sockets cleaned"
