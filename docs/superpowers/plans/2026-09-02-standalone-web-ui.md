# SG InfoSec Standalone Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an SG InfoSec-owned HTTPS management interface at `https://<domain>:64443/infosec/` that works without SG-Gateway and survives independent SG-Gateway upgrades.

**Architecture:** Add an unprivileged `sg-infosec-web` Go service that serves server-rendered HTML on `/run/sg-infosec/web.sock` and talks to `sg-infosecd` only through the existing `/run/sg-infosec/control.sock` client contract. A dedicated nginx `server` on TCP `64443` terminates TLS and proxies `/infosec/` to the Unix socket. Authentication, sessions, setup state, UI templates/static assets, nginx fragment, service unit and installer lifecycle are owned by the `sg-infosec` repository.

**Tech Stack:** Go 1.23+, standard `net/http` + `html/template`, existing `pkg/client` and `pkg/protocol`, `golang.org/x/crypto/argon2` for password hashing, systemd, nginx, Unix sockets, Bash installer tests, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-02-standalone-web-ui-design.md`

## Global Constraints

- Production URL: `https://<domain>:64443/infosec/`.
- TCP `443` is reserved for VLESS and must never be bound, changed, restarted or reconfigured by SG InfoSec.
- SG-Gateway is optional and must not be modified, restarted, imported or used for authentication.
- `sg-infosec-web` must be unprivileged and must never call nftables or the enforcer socket directly.
- Browser mutations require an authenticated SG InfoSec session and CSRF validation.
- Web state is preserved under `/var/lib/sg-infosec/web/`; configuration remains under `/etc/sg-infosec/`; runtime sockets remain under `/run/sg-infosec/`.
- The application must work under `/infosec/`; no hard-coded root `/static` or old `/security/...` paths.
- nginx configuration is validated before reload and rollback must preserve the previously working SG InfoSec web edge.
- Installer remains exact-SHA and preserves existing SG InfoSec config/state/admin data.
- No automatic ACME operation on ports 80 or 443 in v1.
- Existing certificate/key for the configured domain may be reused on port `64443`.

---

## File Structure

New focused units:

- `cmd/sg-infosec-web/main.go` — process entrypoint, config parsing, Unix socket lifecycle and graceful shutdown.
- `internal/web/auth/store.go` — persisted administrator verifier, one-time setup code and server-side session records.
- `internal/web/auth/password.go` — Argon2id PHC-style password encoding/verification.
- `internal/web/auth/session.go` — random session/CSRF tokens, expiry and login throttling.
- `internal/web/coreclient/client.go` — narrow interface over existing `pkg/client.Client` for UI reads/writes.
- `internal/web/presentation/presentation.go` — human-readable labels and view models.
- `internal/web/server/server.go` — routes, middleware, security headers and base-path handling.
- `internal/web/server/templates/*.html` — setup, login, dashboard and help pages.
- `internal/web/server/static/app.css` — standalone UI styling.
- `internal/web/server/static/app.js` — minimal progressive-enhancement helpers only.
- `internal/web/config/config.go` — web runtime config from environment/flags.
- `config/example/sources.d/sg-infosec-web.yaml` — control-socket identity with read/write-admin permissions.
- `packaging/systemd/sg-infosec-web.service` — hardened unprivileged web unit.
- `packaging/nginx/sg-infosec.conf.template` — dedicated TLS listener template for `64443` only.
- `packaging/install-web.sh` — web user/source/nginx/state installation helper used by the exact-SHA installer.
- `scripts/smoke-web-install.sh` — real systemd/nginx HTTPS smoke.

Existing files modified:

- `go.mod` / `go.sum` — `golang.org/x/crypto` dependency.
- `Makefile` — build/check the fourth binary and web tests.
- `cmd/sg-infosecctl/main.go` and `internal/cli/cli.go` — root-only `admin setup-code` / `admin reset` recovery commands.
- `packaging/install.sh` / `packaging/uninstall.sh` — install/remove the web binary/unit/assets without destroying persistent auth state by default.
- `packaging/tmpfiles.d/sg-infosec.conf` — web state/runtime paths.
- `install-from-github.sh` — exact-SHA web/TLS/nginx transaction and verification.
- `.github/workflows/enforcer-gate.yml` — standalone web unit/integration/real smoke gates.
- `README.md` and `docs/standalone-web-ui.md` — operator install/first-login/update documentation.

---

### Task 1: Password, setup-code and session persistence

**Files:**
- Modify: `go.mod`
- Create: `internal/web/auth/password.go`
- Create: `internal/web/auth/password_test.go`
- Create: `internal/web/auth/store.go`
- Create: `internal/web/auth/store_test.go`
- Create: `internal/web/auth/session.go`
- Create: `internal/web/auth/session_test.go`

**Interfaces:**
- Produces: `auth.HashPassword(password string) (string, error)`, `auth.VerifyPassword(encoded, password string) bool`.
- Produces: `auth.Open(path string, now func() time.Time) (*Store, error)`.
- Produces: `(*Store).IssueSetupCode(ttl time.Duration) (string, error)`, `ConsumeSetup(code, username, password string) error`, `ResetAdmin(username, password string) error`, `Authenticate(username, password, remoteKey string) error`, `NewSession(username string, ttl time.Duration) (Session, error)`, `Session(token string) (Session, bool)`, `DeleteSession(token string) error`.
- `Session` contains `Username`, `Token`, `CSRFToken`, `ExpiresAt`.

- [ ] **Step 1: Add failing password KDF tests**

```go
func TestPasswordRoundTripAndSalt(t *testing.T) {
    first, err := HashPassword("correct horse battery staple")
    if err != nil { t.Fatal(err) }
    second, err := HashPassword("correct horse battery staple")
    if err != nil { t.Fatal(err) }
    if first == second { t.Fatal("password hashes must use independent salts") }
    if !VerifyPassword(first, "correct horse battery staple") { t.Fatal("valid password rejected") }
    if VerifyPassword(first, "wrong") { t.Fatal("invalid password accepted") }
    if !strings.HasPrefix(first, "$argon2id$v=19$") { t.Fatalf("unexpected encoding: %s", first) }
}
```

- [ ] **Step 2: Run the focused test and confirm RED**

Run: `go test ./internal/web/auth -run TestPasswordRoundTripAndSalt -v`
Expected: FAIL because the package/functions do not exist.

- [ ] **Step 3: Implement Argon2id encoding with fixed safe parameters**

Use `argon2.IDKey` with version 19, 64 MiB memory, 3 iterations, 2 lanes, 16-byte random salt and 32-byte derived key; encode as `$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-key>` and compare with `subtle.ConstantTimeCompare`.

- [ ] **Step 4: Add persistence/setup/session tests**

Tests must prove: setup code is random and expires after 15 minutes; consuming it is single-use; password is never written in plaintext; session token and CSRF token are random; expired sessions are rejected; logout deletes the session; admin state survives reopening the file; five failed logins for one remote key trigger a five-minute throttle while a successful login clears the failure bucket.

- [ ] **Step 5: Implement an atomic JSON state store**

Persist to `/var/lib/sg-infosec/web/auth.json` using write-to-temp + `fsync` + `rename`, file mode `0600`. Persist only username, Argon2id verifier, setup-code SHA-256 digest/expiry, session SHA-256 digests/CSRF digests/expiry and throttle timestamps; never persist raw passwords, raw setup codes or raw session tokens.

- [ ] **Step 6: Run auth tests**

Run: `go test ./internal/web/auth -v`
Expected: PASS.

- [ ] **Step 7: Run race tests for auth**

Run: `go test -race ./internal/web/auth`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/web/auth
git commit -m "feat: add standalone web authentication state"
```

---

### Task 2: Web runtime config and core client boundary

**Files:**
- Create: `internal/web/config/config.go`
- Create: `internal/web/config/config_test.go`
- Create: `internal/web/coreclient/client.go`
- Create: `internal/web/coreclient/client_test.go`

**Interfaces:**
- Produces `webconfig.Config{BasePath, ListenSocket, ControlSocket, StatePath, SessionTTL}` and `webconfig.LoadFromEnv() (Config, error)`.
- Produces `coreclient.Service` interface with `Health`, `ListDecisions`, `AddDecision`, `RevokeDecision`, `ListAllowlist`, `AddAllowlist`, `RemoveAllowlist`, `ListAudit`.
- Produces `coreclient.New(socketPath string) Service`, implemented by existing `pkg/client`.

- [ ] **Step 1: Write config validation tests**

```go
func TestLoadDefaults(t *testing.T) {
    t.Setenv("SG_INFOSEC_WEB_BASE_PATH", "")
    cfg, err := LoadFromEnv()
    if err != nil { t.Fatal(err) }
    if cfg.BasePath != "/infosec/" { t.Fatalf("base path=%q", cfg.BasePath) }
    if cfg.ListenSocket != "/run/sg-infosec/web.sock" { t.Fatalf("socket=%q", cfg.ListenSocket) }
    if cfg.ControlSocket != "/run/sg-infosec/control.sock" { t.Fatalf("control=%q", cfg.ControlSocket) }
}
```

Also reject base paths without leading/trailing slash, base path `/`, non-absolute socket/state paths and session TTL below 5 minutes or above 24 hours.

- [ ] **Step 2: Run config tests and confirm RED**

Run: `go test ./internal/web/config -v`
Expected: FAIL.

- [ ] **Step 3: Implement config loader**

Environment keys: `SG_INFOSEC_WEB_BASE_PATH`, `SG_INFOSEC_WEB_SOCKET`, `SG_INFOSEC_CONTROL_SOCKET`, `SG_INFOSEC_WEB_STATE`, `SG_INFOSEC_WEB_SESSION_TTL`. Defaults are `/infosec/`, `/run/sg-infosec/web.sock`, `/run/sg-infosec/control.sock`, `/var/lib/sg-infosec/web/auth.json`, `8h`.

- [ ] **Step 4: Add coreclient adapter tests with a temporary Unix HTTP server**

Verify exact API paths and JSON types for health, decision list/manual/revoke, allowlist list/create/delete and audit list. Ensure non-2xx protocol errors are propagated without exposing response bodies containing arbitrary server data to templates.

- [ ] **Step 5: Implement adapter by wrapping `pkg/client.New(socketPath)`**

Do not duplicate the Unix-socket transport. Keep the web package dependent only on the narrow `Service` interface so handlers can use a fake in tests.

- [ ] **Step 6: Run focused tests**

Run: `go test ./internal/web/config ./internal/web/coreclient -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/web/config internal/web/coreclient
git commit -m "feat: add web runtime and core client boundary"
```

---

### Task 3: Presentation model and standalone dashboard UI

**Files:**
- Create: `internal/web/presentation/presentation.go`
- Create: `internal/web/presentation/presentation_test.go`
- Create: `internal/web/server/templates/base.html`
- Create: `internal/web/server/templates/setup.html`
- Create: `internal/web/server/templates/login.html`
- Create: `internal/web/server/templates/dashboard.html`
- Create: `internal/web/server/templates/help.html`
- Create: `internal/web/server/static/app.css`
- Create: `internal/web/server/static/app.js`

**Interfaces:**
- Produces `presentation.Decision`, `Allowlist`, `Audit`, `Dashboard` view models.
- Produces `presentation.DecisionView(protocol.DecisionView) Decision`, `AllowlistView(protocol.AllowlistView) Allowlist`, `AuditView(protocol.AuditView) Audit`.
- Stable Russian labels map known scopes `admin-login`, `admin-api`, `ssh`, `panel-port`; unknown values display `Неизвестно` in the primary label while retaining raw values in technical details.

- [ ] **Step 1: Write presentation mapping tests**

Tests cover known and unknown scopes, reason codes, states, actions, UTC/local time formatting, expired/active decisions and safe rendering of arbitrary reason strings as text rather than HTML.

- [ ] **Step 2: Run tests and confirm RED**

Run: `go test ./internal/web/presentation -v`
Expected: FAIL.

- [ ] **Step 3: Implement presentation mappings**

Primary decision cards expose IP, state label, scope label/effect, human-readable reason and expiry. Raw `source_id`, `policy_id`, `backend`, raw scope/reason/state and timestamps stay in a `<details>` technical section.

- [ ] **Step 4: Create templates that work exclusively under `.BasePath`**

The dashboard contains: service state; active decisions; manual block form; allowlist; decision history; audit; autonomous detection/health summary; help link; technical disclosure sections. All links/forms/static paths are built as `{{.BasePath}}...`; no `/security/`, `/static/` or root-relative product links.

- [ ] **Step 5: Add responsive CSS and minimal JS**

CSS provides compact cards, two-column desktop layout and single-column mobile layout. JS is limited to progressive enhancement such as confirmation on destructive actions; the app remains usable without JavaScript.

- [ ] **Step 6: Add static safety tests**

Parse templates and assert no forbidden root paths, inline `<script>`, remote CDN assets, `javascript:` URLs or unescaped HTML injection helpers. Assert CSS/JS assets are local under `/infosec/assets/` at render time.

- [ ] **Step 7: Run presentation/template tests**

Run: `go test ./internal/web/presentation ./internal/web/server -run 'Presentation|Template|Asset' -v`
Expected: PASS after server package scaffold is introduced in Task 4; until then run presentation tests only.

- [ ] **Step 8: Commit**

```bash
git add internal/web/presentation internal/web/server/templates internal/web/server/static
git commit -m "feat: add standalone InfoSec presentation assets"
```

---

### Task 4: HTTP server, authentication flow and management routes

**Files:**
- Create: `internal/web/server/server.go`
- Create: `internal/web/server/server_test.go`
- Create: `internal/web/server/security_test.go`
- Create: `internal/web/server/assets.go`

**Interfaces:**
- Produces `server.New(cfg webconfig.Config, authStore *auth.Store, core coreclient.Service) (http.Handler, error)`.
- Public routes under base path: `GET /`, `GET|POST /setup`, `GET|POST /login`, `POST /logout`, `GET /help`, `GET /assets/app.css`, `GET /assets/app.js`.
- Authenticated mutations: `POST /decisions`, `POST /decisions/{id}/revoke`, `POST /allowlist`, `POST /allowlist/{id}/delete`.

- [ ] **Step 1: Write first-setup/login route tests**

Use `httptest`. Confirm unauthenticated `/infosec/` redirects to `/infosec/setup` while setup pending, then to `/infosec/login` after setup. Correct one-time code creates admin and redirects to login; wrong/expired code returns generic failure without revealing expected code. Successful login rotates to a fresh server-side session cookie.

- [ ] **Step 2: Write security-header/session tests**

Every HTML response must include `Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` disabling camera/microphone/geolocation and `Cache-Control: no-store`. Session cookie must be `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/infosec/`.

- [ ] **Step 3: Write CSRF and route-confusion tests**

Every POST except initial setup/login must reject missing/wrong CSRF with 403. Reject encoded traversal and double-slash path confusion. Requests outside `/infosec/` return 404 from the app handler. Forwarded client IP is accepted only from a normalized `X-SG-InfoSec-Client-IP` value supplied by nginx; malformed values become `unknown` for throttling rather than trusted input.

- [ ] **Step 4: Write dashboard degraded-state tests**

When core `Health` or list calls fail, dashboard renders `Защита недоступна/ограничена`, keeps help/logout available and disables mutation forms instead of returning 500. When IP intelligence is unavailable, decision display remains usable.

- [ ] **Step 5: Write management mutation tests**

Manual block validates IP with `net/netip`, scope whitelist, duration 1h..168h and reason 3..240 runes; sends `ManualDecisionRequest{SourceID:"sg-infosec-web", ...}`. Revoke/allowlist create/delete validate IDs/prefixes and redirect back using POST/Redirect/GET. Fake core errors render a generic action failure and never claim success.

- [ ] **Step 6: Implement handler and middleware**

Use `http.ServeMux`, `html/template` and `embed.FS`. No external web framework. Limit request bodies to 64 KiB; parse forms only after limit wrapper. Use `http.MaxBytesReader` and method checks. HTML templates receive typed view models only.

- [ ] **Step 7: Run server tests**

Run: `go test ./internal/web/server -v`
Expected: PASS.

- [ ] **Step 8: Run race tests for all web packages**

Run: `go test -race ./internal/web/...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/web/server
git commit -m "feat: add standalone InfoSec HTTP management server"
```

---

### Task 5: `sg-infosec-web` process and root recovery CLI

**Files:**
- Create: `cmd/sg-infosec-web/main.go`
- Create: `cmd/sg-infosec-web/main_test.go`
- Modify: `cmd/sg-infosecctl/main.go`
- Modify: `internal/cli/cli.go`
- Modify: `internal/cli/cli_test.go`
- Modify: `Makefile`

**Interfaces:**
- New binary: `/usr/local/sbin/sg-infosec-web`.
- `sg-infosecctl admin setup-code` issues/replaces a 15-minute setup code and prints it only to root's terminal/stdout.
- `sg-infosecctl admin reset --username NAME` reads a new password twice from a terminal when interactive; test seam accepts an injected password reader. It updates only web auth state and revokes all web sessions.

- [ ] **Step 1: Add Makefile/build tests**

Assert `make build` creates four executables including `bin/sg-infosec-web` and `fmt-check` scans `internal/web`/new command via existing directory roots.

- [ ] **Step 2: Add CLI recovery tests**

Confirm unknown users/options return usage, non-root invocation fails with permission exit, `admin setup-code` emits one code and persists only its digest, and reset revokes sessions without deleting core state.

- [ ] **Step 3: Implement CLI recovery subcommands**

Guard with `os.Geteuid()==0` in the command dependency layer. Default auth state path is `/var/lib/sg-infosec/web/auth.json`; allow `--web-state` only for tests/operator recovery.

- [ ] **Step 4: Write process lifecycle tests**

Test stale socket removal only when it is actually a Unix socket owned by the service user; refuse to unlink regular files. Ensure socket mode becomes `0660`, graceful SIGTERM closes listener, and runtime config errors exit before binding.

- [ ] **Step 5: Implement `cmd/sg-infosec-web/main.go`**

Open auth state, instantiate `coreclient.New`, construct server handler, create Unix listener with umask-safe mode, serve HTTP, and handle SIGTERM/SIGINT with a 10-second `http.Server.Shutdown` timeout.

- [ ] **Step 6: Update Makefile**

Add `go build -o bin/sg-infosec-web ./cmd/sg-infosec-web` to `build` and keep `check` as fmt/vet/test/race/build.

- [ ] **Step 7: Run command/CLI/build verification**

Run: `go test ./cmd/sg-infosec-web ./internal/cli -v && make check`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add cmd/sg-infosec-web cmd/sg-infosecctl internal/cli Makefile
git commit -m "feat: add standalone web daemon and admin recovery"
```

---

### Task 6: Unprivileged systemd/source identity and nginx edge

**Files:**
- Create: `config/example/sources.d/sg-infosec-web.yaml`
- Create: `packaging/systemd/sg-infosec-web.service`
- Create: `packaging/nginx/sg-infosec.conf.template`
- Create: `packaging/install-web.sh`
- Create: `tests/packaging_web_test.go` or shell-focused contract test under `tests/`
- Modify: `packaging/tmpfiles.d/sg-infosec.conf`
- Modify: `packaging/install.sh`
- Modify: `packaging/uninstall.sh`

**Interfaces:**
- Dedicated OS user/group: `sg-infosec-web` / `sg-infosec-web`.
- The web user is added to the existing `sg-infosec` group only to reach `/run/sg-infosec/control.sock`; its UID is registered as source `sg-infosec-web` with `read_admin`, `write_admin`, `check_decisions` and scopes `admin-login`, `admin-api`, `ssh`, `panel-port`.
- nginx generated file: `/etc/nginx/conf.d/sg-infosec.conf`.
- TLS listener: `${SG_INFOSEC_WEB_PORT:-64443}` with `ssl`, no port 443 directive anywhere in generated SG InfoSec config.

- [ ] **Step 1: Write packaging contract tests**

Assert service contains `User=sg-infosec-web`, `NoNewPrivileges=true`, empty capability sets, `RestrictAddressFamilies=AF_UNIX`, read-only `/etc/sg-infosec`, writable `/run/sg-infosec /var/lib/sg-infosec/web`; no `sg-gateway` dependency. Assert nginx template contains `listen 64443 ssl` placeholder substitution path, exact `/infosec/` proxy, Unix socket upstream, normalized client-IP header and security headers, and contains no `listen 443`.

- [ ] **Step 2: Add source identity tests**

Installer-generated source config must resolve `user: sg-infosec-web`, have source ID `sg-infosec-web`, and grant only the admin control permissions required by the UI. Core config validation must pass after web user/source installation.

- [ ] **Step 3: Implement systemd unit**

Use `After=sg-infosec.service`, `Requires=sg-infosec.service`, `RuntimeDirectory` only if it does not conflict with existing tmpfiles ownership, `UMask=0007`, `PrivateTmp=true`, `PrivateDevices=true`, `ProtectSystem=strict`, `ProtectHome=true`, `ProtectKernel*`, `ProtectControlGroups`, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictSUIDSGID`, `RestrictNamespaces`, `RestrictRealtime`, empty capabilities.

- [ ] **Step 4: Implement nginx template and generator**

Generated `server` binds `[::]:64443`/`0.0.0.0:64443` through a single nginx `listen 64443 ssl;` semantic listener, sets `server_name <domain>`, certificate/key paths, redirects `/` to `/infosec/`, proxies `/infosec/` to `http://unix:/run/sg-infosec/web.sock:`, preserves prefix consistently, disables request buffering beyond required form sizes and sets `X-SG-InfoSec-Client-IP $remote_addr` while clearing arbitrary `X-Forwarded-*` trust.

- [ ] **Step 5: Implement `install-web.sh` transaction staging**

Require root, validate domain syntax, cert/key readability and matching certificate key using `openssl x509 -pubkey` vs `openssl pkey -pubout`; verify cert hostname with `openssl x509 -checkhost`. Check `ss -H -ltn 'sport = :64443'` before activation and fail without killing owner. Stage nginx fragment to temp file, run `nginx -t`, then atomically replace only `/etc/nginx/conf.d/sg-infosec.conf` and reload nginx. Preserve old fragment for rollback if reload/HTTPS verification fails.

- [ ] **Step 6: Modify package install/uninstall**

Install four binaries and three systemd units; create web user/group and state directories; install web source only if missing; normal uninstall removes web binary/unit/nginx fragment/runtime socket but does not remove `/etc/sg-infosec` or `/var/lib/sg-infosec` unless the existing destructive mode explicitly requests state deletion.

- [ ] **Step 7: Run packaging tests**

Run: `go test ./tests/... -run 'Web|Nginx|Packaging' -v` plus `bash -n packaging/install.sh packaging/install-web.sh packaging/uninstall.sh`.
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add config/example/sources.d/sg-infosec-web.yaml packaging tests
git commit -m "feat: package isolated InfoSec web edge"
```

---

### Task 7: Exact-SHA installer integration, rollback and first-setup output

**Files:**
- Modify: `install-from-github.sh`
- Create: `tests/test_install_from_github_web_contract.sh`
- Create: `scripts/smoke-web-install.sh`

**Interfaces:**
- Installer inputs: existing positional full 40-char SHA; `SG_INFOSEC_WEB_DOMAIN` required to enable public web; `SG_INFOSEC_WEB_CERT` and `SG_INFOSEC_WEB_KEY` optional only when conventional `/etc/letsencrypt/live/$DOMAIN/{fullchain,privkey}.pem` exist; `SG_INFOSEC_WEB_PORT` defaults to `64443`; `SG_INFOSEC_WEB_BASE_PATH` defaults `/infosec/`.
- Installer success output includes exact final URL. It prints `First setup code:` only if setup is pending; updates never rotate an existing admin.

- [ ] **Step 1: Write installer contract tests**

Assert exact SHA is still mandatory, `make build` fourth binary is checked, 443 never appears in a bind/reconfiguration command, SG-Gateway service is never restarted, nginx is validated before reload, certificate/key are validated before active config replacement, and rollback path restores old SG InfoSec nginx fragment/web binary/unit on failure.

- [ ] **Step 2: Add web environment validation**

Reject port other than numeric 1..65535 and explicitly reject `443`; for current v1 default/production port is `64443`. Reject base path other than `/infosec/` in public installer v1 to keep one tested route contract. Require domain before cert-path autodetection.

- [ ] **Step 3: Integrate web build/install into existing step UI**

Add distinct steps: `Preparing SG InfoSec web edge`, `Installing SG InfoSec web service`, `Validating nginx`, `Starting SG InfoSec web`, `Verifying HTTPS`. Preserve current quiet-progress behavior and show detailed log only on failure.

- [ ] **Step 4: Implement rollback**

Before web activation snapshot current web binary/unit/nginx fragment (if any) into the installer temp directory. If any post-install web step fails, stop new web unit, restore previous files atomically, `systemctl daemon-reload`, restore/reload previous nginx only after `nginx -t`, and restart previous web service if it had been active. Core/enforcer preservation follows existing installer behavior.

- [ ] **Step 5: Implement HTTPS verification**

After nginx reload, wait for `/run/sg-infosec/web.sock`, verify `systemctl is-active sg-infosec-web.service`, and use `curl --resolve "$DOMAIN:$PORT:127.0.0.1" --cacert "$CERT" "https://$DOMAIN:$PORT/infosec/"` accepting setup/login redirect or 200. Never use `-k` in production verification.

- [ ] **Step 6: Implement first setup output**

If auth state has no admin, invoke `/usr/local/sbin/sg-infosecctl admin setup-code`, capture the code exactly once, and print it after successful HTTPS verification. If admin exists, print only final URL and `Existing administrator preserved.`

- [ ] **Step 7: Run installer contracts**

Run: `bash tests/test_install_from_github_web_contract.sh && bash -n install-from-github.sh`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add install-from-github.sh tests/test_install_from_github_web_contract.sh scripts/smoke-web-install.sh
git commit -m "feat: install standalone InfoSec web transactionally"
```

---

### Task 8: Real smoke, CI gate and operator documentation

**Files:**
- Modify: `.github/workflows/enforcer-gate.yml`
- Modify: `README.md`
- Create: `docs/standalone-web-ui.md`
- Modify: `scripts/smoke-web-install.sh`

**Interfaces:**
- CI must run unit, race, vet, build, existing kernel/resource smoke, packaging contracts and a privileged systemd/nginx standalone web smoke.

- [ ] **Step 1: Extend CI with web-focused gates**

Add explicit steps for `go test ./internal/web/...`, `go test -race ./internal/web/...`, `make check`, packaging shell syntax/contracts, and `sudo bash scripts/smoke-web-install.sh` on Ubuntu where systemd/nginx are available.

- [ ] **Step 2: Complete real smoke script**

The smoke creates a temporary self-signed cert for `infosec.test`, installs from the checked-out tree into the runner, binds only `64443`, verifies no SG InfoSec-owned listener on 443 before/after, obtains setup code through root CLI, POSTs setup/login with cookie+CSRF handling, loads dashboard, creates/revokes a controlled decision, creates/deletes an allowlist entry, checks audit, verifies `/help`, restarts web/core and confirms session/state persistence behavior expected by the design.

- [ ] **Step 3: Add update-preservation smoke**

Install once, complete admin setup, record auth state checksum/semantic username, rerun packaging/update path, confirm admin is preserved and setup does not reopen. Confirm unrelated nginx config file and a dummy 443 listener/config sentinel remain byte-for-byte unchanged.

- [ ] **Step 4: Write operator documentation**

Document required DNS/certificate assumptions, environment variables, canonical URL, first setup code, login recovery, service names, paths, update preservation, uninstall semantics and the invariant that port 443/VLESS and SG-Gateway are not touched.

- [ ] **Step 5: Run complete local verification**

Run: `make check && bash tests/test_install_from_github_web_contract.sh` and, on a systemd-capable environment, `sudo bash scripts/smoke-web-install.sh`.
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/enforcer-gate.yml README.md docs/standalone-web-ui.md scripts/smoke-web-install.sh
git commit -m "ci: gate standalone InfoSec web deployment"
```

---

### Task 9: Final same-SHA verification and release candidate

**Files:**
- No new production scope; only defect fixes discovered by verification are allowed.

- [ ] **Step 1: Run format/vet/unit/race/build on the final working tree**

Run: `make check`
Expected: PASS.

- [ ] **Step 2: Run all shell syntax and packaging contracts**

Run: `bash -n install-from-github.sh packaging/install.sh packaging/install-web.sh packaging/uninstall.sh scripts/smoke-web-install.sh && bash tests/test_install_from_github_web_contract.sh`
Expected: PASS.

- [ ] **Step 3: Run real systemd/nginx smoke where available**

Run: `sudo bash scripts/smoke-web-install.sh`
Expected: PASS with HTTPS on `64443`, no SG InfoSec listener/config mutation on `443`, setup/login/dashboard/mutations/help all verified.

- [ ] **Step 4: Push final feature HEAD and wait for exact-SHA CI**

The accepted candidate is only the SHA for which the workflow reports `completed/success`; do not report a branch name alone as verified.

- [ ] **Step 5: Verify branch boundary**

Compare feature branch to base `1a02dbea0860e7625c857ab82713ebf07397cff1`; confirm all production changes are inside `s-gor/sg-infosec` and no SG-Gateway repository ref was changed.

- [ ] **Step 6: Report final candidate**

Report exact SHA, CI run ID/conclusion, test/smoke results, canonical install inputs, and the future server install command. Do not merge/promote to any stable/main/dev branch without explicit user permission.

---

## Self-review

Spec coverage: architecture, independent auth, `/infosec/` base path, TCP `64443`, TLS, nginx isolation, Unix socket, privilege separation, persistence, installer/update/uninstall, degraded states, security headers/CSRF/rate limit, management functions, help, CI and same-SHA acceptance all have explicit tasks.

Placeholder scan: no `TBD`, `TODO`, `implement later` or unspecified test step remains.

Type consistency: auth store, core client, presentation and server interfaces are introduced before consumers; CLI and packaging paths use the same `/var/lib/sg-infosec/web/auth.json`, `/run/sg-infosec/web.sock`, `/run/sg-infosec/control.sock`, `/infosec/` and `64443` contracts throughout.
