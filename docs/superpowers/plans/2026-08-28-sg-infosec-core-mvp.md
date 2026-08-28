# SG InfoSec Core MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Построить непривилегированное ядро SG InfoSec, которое принимает структурированные события через Unix-сокет, доверенно определяет локальный источник, хранит состояние в SQLite, создаёт прикладные решения по политикам и предоставляет локальный control API и CLI.

**Architecture:** Один Go-процесс `sg-infosecd` слушает два Unix-сокета: events и control. Источник events-запроса определяется по `SO_PEERCRED`; обработка события, подсчёт окна и создание решения выполняются последовательно и транзакционно. В этом плане нет root-компонента и `nftables`: все решения имеют backend `application` и проверяются через control API.

**Tech Stack:** Go 1.26 language floor; CI on Go 1.26.x and 1.27.x; Linux Unix domain sockets; `net/http`; `golang.org/x/sys/unix`; SQLite through `modernc.org/sqlite`; YAML through `gopkg.in/yaml.v3`; UUID through `github.com/google/uuid`; GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-28-sg-infosec-design.md`

## Global Constraints

- Ядро не открывает TCP или UDP портов.
- `sg-infosecd` не требует root и не изменяет firewall.
- `admin-login` и `admin-api` создают только application-level решения.
- Пароли, токены, cookies, приватные ключи и полные subscription URL не принимаются и не журналируются.
- IPv4 и IPv6 поддерживаются через `net/netip`.
- События от неизвестного UID/GID отклоняются до разбора бизнес-данных.
- Источник определяется по Unix peer credentials, а не по полю запроса.
- Обработка события идемпотентна по `(source_id, event_id)`.
- Политики считают серверное `received_at`; клиентское `occurred_at` хранится только для аудита.
- Отказ ядра не должен блокировать защищаемую панель; fail-open реализуется интеграционным адаптером в отдельном плане.
- Целевой RSS `sg-infosecd` в простое — не более 30 МиБ на Linux amd64.
- Все времена хранятся в UTC в RFC3339Nano.
- В MVP работает один экземпляр демона на одном каталоге состояния.

---

## File Map

```text
.github/workflows/ci.yml                 lint, unit and race tests
.gitignore                               local build and database artifacts
Makefile                                 repeatable developer commands
README.md                                project purpose and safe local run
config/example/sg-infosec.yaml           main example configuration
config/example/sources.d/sg-gateway.yaml source authorization example
config/example/policies.d/admin.yaml     policy example
cmd/sg-infosecd/main.go                  daemon entrypoint
cmd/sg-infosecctl/main.go                CLI entrypoint
go.mod                                   module and Go floor
go.sum                                   pinned dependencies
internal/api/control/handler.go           control HTTP routes
internal/api/events/handler.go            events HTTP route
internal/app/app.go                       dependency assembly and lifecycle
internal/clock/clock.go                   real and fake clocks
internal/config/load.go                   YAML loading and validation
internal/config/types.go                  configuration DTOs
internal/decision/service.go              check, list, revoke and manual decision operations
internal/engine/engine.go                 serialized policy evaluation
internal/health/service.go                health snapshot
internal/model/event.go                   event domain model
internal/model/policy.go                  policy and scope domain model
internal/model/decision.go                decision domain model
internal/model/allowlist.go               allowlist domain model
internal/retention/worker.go              bounded cleanup
internal/sourceauth/peercred_linux.go      SO_PEERCRED extraction
internal/sourceauth/resolver.go            UID/GID to source permissions
internal/store/migrations/001_init.sql     initial SQLite schema
internal/store/store.go                    database lifecycle
internal/store/tx.go                       transaction operations
internal/store/query.go                    read operations
internal/transport/unixhttp/server.go      Unix HTTP listener and ConnContext identity
pkg/client/client.go                       minimal application decision client
pkg/protocol/types.go                      stable request/response DTOs
tests/e2e/core_test.go                     real-socket end-to-end contract
docs/protocol-v1.md                        public local protocol contract
```

---

### Task 1: Repository Bootstrap and CI Contract

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `Makefile`
- Create: `.github/workflows/ci.yml`
- Create: `cmd/sg-infosecd/main.go`
- Create: `cmd/sg-infosecctl/main.go`
- Create: `internal/buildinfo/buildinfo.go`
- Create: `internal/buildinfo/buildinfo_test.go`
- Create: `README.md`

**Interfaces:**
- Produces: `buildinfo.Info() buildinfo.Metadata`
- Produces: binaries `sg-infosecd` and `sg-infosecctl`

- [ ] **Step 1: Write the failing build metadata test**

```go
package buildinfo

import "testing"

func TestInfoHasStableDevelopmentDefaults(t *testing.T) {
    got := Info()
    if got.Version != "dev" {
        t.Fatalf("Version = %q, want dev", got.Version)
    }
    if got.ProtocolVersion != "v1" {
        t.Fatalf("ProtocolVersion = %q, want v1", got.ProtocolVersion)
    }
}
```

- [ ] **Step 2: Run the focused test and verify failure**

Run:

```bash
go test ./internal/buildinfo -run TestInfoHasStableDevelopmentDefaults -v
```

Expected: FAIL because `Info` is undefined.

- [ ] **Step 3: Create the module and minimal implementation**

`go.mod`:

```go
module github.com/s-gor/sg-infosec

go 1.26.0
```

`internal/buildinfo/buildinfo.go`:

```go
package buildinfo

var Version = "dev"
var Commit = "unknown"
var BuildTime = "unknown"

const ProtocolVersion = "v1"

type Metadata struct {
    Version         string `json:"version"`
    Commit          string `json:"commit"`
    BuildTime       string `json:"build_time"`
    ProtocolVersion string `json:"protocol_version"`
}

func Info() Metadata {
    return Metadata{
        Version:         Version,
        Commit:          Commit,
        BuildTime:       BuildTime,
        ProtocolVersion: ProtocolVersion,
    }
}
```

Both command entrypoints must support `--version`, print JSON from `buildinfo.Info()`, and exit zero. With no arguments they may return the explicit error `service startup is not implemented` until Task 8.

- [ ] **Step 4: Add repeatable checks**

`Makefile` must define:

```make
.PHONY: test race vet build check

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	go build ./cmd/sg-infosecd ./cmd/sg-infosecctl

check: vet test race build
```

CI must run `go mod tidy`, fail on a dirty tree, then run `make check` on Linux with Go `1.26.x` and `1.27.x`.

- [ ] **Step 5: Run all bootstrap checks**

Run:

```bash
go mod tidy
make check
git diff --exit-code
```

Expected: all commands succeed.

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum .gitignore Makefile .github/workflows/ci.yml README.md cmd internal/buildinfo
git commit -m "chore: bootstrap SG InfoSec Go project"
```

---

### Task 2: Domain Types and Strict Configuration Loader

**Files:**
- Create: `internal/model/event.go`
- Create: `internal/model/policy.go`
- Create: `internal/model/decision.go`
- Create: `internal/model/allowlist.go`
- Create: `internal/config/types.go`
- Create: `internal/config/load.go`
- Create: `internal/config/load_test.go`
- Create: `config/example/sg-infosec.yaml`
- Create: `config/example/sources.d/sg-gateway.yaml`
- Create: `config/example/policies.d/admin.yaml`

**Interfaces:**
- Produces: `config.Load(path string) (config.Config, error)`
- Produces: `model.ParseScope(string) (model.Scope, error)`
- Produces: `model.ParseEventType(string) (model.EventType, error)`
- Produces: validated `config.Config` consumed by Tasks 4–8

- [ ] **Step 1: Write configuration validation tests**

Cover these exact cases:

```go
func TestLoadRejectsUnknownYAMLFields(t *testing.T)
func TestLoadRejectsDuplicateSourceIDs(t *testing.T)
func TestLoadRejectsPolicyWithZeroThreshold(t *testing.T)
func TestLoadRejectsFirewallBackendInCoreMVP(t *testing.T)
func TestLoadAcceptsIPv4AndIPv6AllowlistPrefixes(t *testing.T)
func TestLoadResolvesRelativeFragmentDirectoriesFromMainConfig(t *testing.T)
```

The valid fixture must contain source `sg-gateway`, events `auth.failed` and `api.auth_failed`, scopes `admin-login` and `admin-api`, and one policy with threshold `5`, window `10m`, base duration `30m`, escalation factor `4`, maximum duration `24h`, and reset interval `720h`.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/config -v
```

Expected: FAIL because loader and domain types do not exist.

- [ ] **Step 3: Implement closed domain enums**

Use string-backed types with explicit parsers:

```go
package model

type Scope string

const (
    ScopeAdminLogin Scope = "admin-login"
    ScopeAdminAPI   Scope = "admin-api"
    ScopeSSH        Scope = "ssh"
    ScopePanelPort  Scope = "panel-port"
)

func ParseScope(value string) (Scope, error) {
    switch Scope(value) {
    case ScopeAdminLogin, ScopeAdminAPI, ScopeSSH, ScopePanelPort:
        return Scope(value), nil
    default:
        return "", fmt.Errorf("unsupported scope %q", value)
    }
}
```

Define event types `auth.failed`, `auth.succeeded`, and `api.auth_failed`. Define decision states `pending`, `active`, `expired`, `revoked`, and `failed`. Define backend `application`; reject backend `nftables` in this plan.

- [ ] **Step 4: Implement strict YAML loading**

`config.Load` must:

1. decode the main file with `yaml.Decoder.KnownFields(true)`;
2. resolve `sources_dir` and `policies_dir` relative to the main file;
3. sort fragment filenames before loading;
4. reject duplicate IDs;
5. parse all durations with `time.ParseDuration`;
6. resolve source `user` and optional `group` through an injected lookup interface;
7. normalize allowlist entries with `netip.ParsePrefix` or a single-address `/32`/`/128` prefix;
8. validate the complete configuration before returning it.

Use this public shape:

```go
type Config struct {
    DatabasePath string
    EventsSocket string
    ControlSocket string
    EventBodyLimit int64
    Retention EventRetention
    Sources []Source
    Policies []model.Policy
    Allowlist []model.AllowlistEntry
}
```

- [ ] **Step 5: Add safe example configuration**

`config/example/sg-infosec.yaml` must use:

```yaml
database_path: /var/lib/sg-infosec/sg-infosec.db
events_socket: /run/sg-infosec/events.sock
control_socket: /run/sg-infosec/control.sock
event_body_limit: 16384
sources_dir: sources.d
policies_dir: policies.d
retention:
  events: 168h
  audit: 2160h
```

The SG-Gateway source fragment must name Linux user `sg-gateway` and permit only the two administrative event types/scopes. It must not permit SSH events.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/model ./internal/config -v
go test ./...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/model internal/config config/example
git commit -m "feat: add strict configuration and domain model"
```

---

### Task 3: SQLite Schema, Transactions, and Query Store

**Files:**
- Create: `internal/store/migrations/001_init.sql`
- Create: `internal/store/store.go`
- Create: `internal/store/tx.go`
- Create: `internal/store/query.go`
- Create: `internal/store/store_test.go`
- Create: `internal/clock/clock.go`

**Interfaces:**
- Consumes: domain types from Task 2
- Produces: `store.Open(ctx context.Context, path string) (*store.Store, error)`
- Produces: `(*Store).WithTx(ctx context.Context, fn func(*store.Tx) error) error`
- Produces: event, decision, allowlist and audit query methods used by Tasks 5–8

- [ ] **Step 1: Write migration and persistence tests**

Cover:

```go
func TestOpenCreatesSchemaAndEnablesSQLiteSafetyPragmas(t *testing.T)
func TestInsertEventIsIdempotentPerSourceAndEventID(t *testing.T)
func TestWithTxRollsBackEventAndDecisionTogether(t *testing.T)
func TestActiveDecisionLookupMatchesIPv6CanonicalForm(t *testing.T)
func TestExpiredAllowlistEntryDoesNotMatch(t *testing.T)
func TestListDecisionsUsesStableCreatedAtIDPagination(t *testing.T)
```

The pragma test must assert `foreign_keys=1`, `journal_mode=wal`, and a nonzero `busy_timeout`.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/store -v
```

Expected: FAIL because store package does not exist.

- [ ] **Step 3: Create the initial schema**

The migration must define these tables and constraints:

```sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(source_id, event_id)
);

CREATE INDEX events_window_idx
ON events(source_id, event_type, scope, ip, received_at);

CREATE TABLE decisions (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    backend TEXT NOT NULL,
    state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    strike_count INTEGER NOT NULL CHECK(strike_count >= 1),
    starts_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT
);

CREATE INDEX decisions_active_idx
ON decisions(scope, ip, state, expires_at);

CREATE TABLE allowlist_entries (
    id TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    scope TEXT,
    description TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    result TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);
```

- [ ] **Step 4: Implement store lifecycle**

`store.Open` must create parent directories only when explicitly requested by the caller; tests pass an existing temporary directory. Configure SQLite with a single writer connection and multiple reader connections:

```go
db.SetMaxOpenConns(4)
db.SetMaxIdleConns(4)
```

Apply migrations transactionally and reject a database with a schema version newer than the binary supports.

- [ ] **Step 5: Implement exact transaction operations**

`store.Tx` must provide:

```go
InsertEvent(ctx context.Context, event model.Event) (inserted bool, err error)
CountEvents(ctx context.Context, sourceID string, eventType model.EventType, scope model.Scope, ip netip.Addr, since time.Time) (int, error)
FindActiveDecision(ctx context.Context, scope model.Scope, ip netip.Addr, now time.Time) (*model.Decision, error)
FindLastPolicyDecision(ctx context.Context, policyID string, ip netip.Addr, since time.Time) (*model.Decision, error)
InsertDecision(ctx context.Context, decision model.Decision) error
IsAllowlisted(ctx context.Context, scope model.Scope, ip netip.Addr, now time.Time) (bool, error)
AppendAudit(ctx context.Context, entry model.AuditEntry) error
```

Canonicalize all addresses with `addr.Unmap().String()` for IPv4 and `addr.String()` for IPv6 before storage.

- [ ] **Step 6: Implement read queries and pagination**

Expose:

```go
GetActiveDecision(ctx context.Context, scope model.Scope, ip netip.Addr, now time.Time) (*model.Decision, error)
ListDecisions(ctx context.Context, filter store.DecisionFilter) (store.DecisionPage, error)
RevokeDecision(ctx context.Context, id, actor, requestID string, now time.Time) error
PutAllowlistEntry(ctx context.Context, entry model.AllowlistEntry, actor, requestID string) error
DeleteAllowlistEntry(ctx context.Context, id, actor, requestID string, now time.Time) error
DeleteEventsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error)
DeleteAuditBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error)
```

Page size must default to 50 and reject values above 200.

- [ ] **Step 7: Run store tests including race detector**

```bash
go test ./internal/store -v
go test -race ./internal/store
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/store internal/clock go.mod go.sum
git commit -m "feat: add transactional SQLite store"
```

---

### Task 4: Unix Peer Credential Authentication

**Files:**
- Create: `internal/sourceauth/peercred_linux.go`
- Create: `internal/sourceauth/resolver.go`
- Create: `internal/sourceauth/resolver_test.go`
- Create: `internal/transport/unixhttp/server.go`
- Create: `internal/transport/unixhttp/server_linux_test.go`

**Interfaces:**
- Consumes: `config.Source`
- Produces: `sourceauth.IdentityFromContext(ctx) (sourceauth.Identity, bool)`
- Produces: `unixhttp.New(config unixhttp.Config, handler http.Handler, resolver *sourceauth.Resolver) (*unixhttp.Server, error)`

- [ ] **Step 1: Write authentication tests**

Required tests:

```go
func TestResolverMapsExactUIDToConfiguredSource(t *testing.T)
func TestResolverRejectsUnknownUID(t *testing.T)
func TestResolverRejectsEventOutsideSourcePermissions(t *testing.T)
func TestUnixServerPlacesPeerIdentityInRequestContext(t *testing.T)
func TestUnixServerRemovesStaleSocketOnlyWhenItIsASocket(t *testing.T)
func TestUnixServerRefusesToReplaceRegularFile(t *testing.T)
```

The real-socket test must dial a temporary Unix socket with `http.Transport.DialContext` and assert the server sees the test process UID.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
go test ./internal/sourceauth ./internal/transport/unixhttp -v
```

Expected: FAIL because packages do not exist.

- [ ] **Step 3: Implement Linux peer credential extraction**

Use `SyscallConn` and `unix.GetsockoptUcred`:

```go
func PeerCredentials(conn *net.UnixConn) (Credentials, error) {
    raw, err := conn.SyscallConn()
    if err != nil {
        return Credentials{}, err
    }
    var cred *unix.Ucred
    var controlErr error
    if err := raw.Control(func(fd uintptr) {
        cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
    }); err != nil {
        return Credentials{}, err
    }
    if controlErr != nil {
        return Credentials{}, controlErr
    }
    return Credentials{PID: int(cred.Pid), UID: cred.Uid, GID: cred.Gid}, nil
}
```

Do not trust PID for authorization; retain it only for diagnostics.

- [ ] **Step 4: Implement resolver and request authorization**

`Resolver.Resolve(credentials Credentials) (Identity, error)` must map UID to exactly one configured source. `Identity.Authorize(eventType, scope)` must require both values in the source allowlist.

No source ID from HTTP headers or JSON may override the resolved identity.

- [ ] **Step 5: Implement hardened Unix HTTP server**

The server must:

- reject non-Unix connections;
- set identity in `http.Server.ConnContext`;
- use `ReadHeaderTimeout=2s`, `ReadTimeout=5s`, `WriteTimeout=5s`, `IdleTimeout=15s`;
- set socket mode after bind;
- refuse symlink and regular-file replacement;
- remove only a stale socket owned by the expected UID;
- close and remove its socket during graceful shutdown.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/sourceauth ./internal/transport/unixhttp -v
go test -race ./internal/sourceauth ./internal/transport/unixhttp
```

Expected: PASS on Linux.

- [ ] **Step 7: Commit**

```bash
git add internal/sourceauth internal/transport go.mod go.sum
git commit -m "feat: authenticate Unix clients with peer credentials"
```

---

### Task 5: Events API and Idempotent Ingestion

**Files:**
- Create: `pkg/protocol/types.go`
- Create: `internal/api/events/handler.go`
- Create: `internal/api/events/handler_test.go`
- Modify: `internal/model/event.go`
- Modify: `internal/store/tx.go`

**Interfaces:**
- Consumes: source identity from Task 4 and store transaction from Task 3
- Produces: `POST /v1/events`
- Produces: `events.Processor.Process(ctx context.Context, source sourceauth.Identity, request protocol.EventRequest) (protocol.EventResponse, error)`

- [ ] **Step 1: Write HTTP contract tests**

Required tests:

```go
func TestPostEventAcceptsAuthorizedIPv4Event(t *testing.T)
func TestPostEventAcceptsAuthorizedIPv6Event(t *testing.T)
func TestPostEventReturnsSameResultForDuplicateEventID(t *testing.T)
func TestPostEventRejectsUnknownJSONField(t *testing.T)
func TestPostEventRejectsOversizedBody(t *testing.T)
func TestPostEventRejectsDisallowedEventTypeBeforeWritingDatabase(t *testing.T)
func TestPostEventRejectsMetadataContainingSensitiveKeys(t *testing.T)
func TestPostEventUsesServerReceivedAtForPolicyTime(t *testing.T)
```

Sensitive metadata keys must include case-insensitive `password`, `passwd`, `token`, `authorization`, `cookie`, `private_key`, `subscription_url`, and `config`.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/api/events -v
```

Expected: FAIL because handler does not exist.

- [ ] **Step 3: Define stable v1 DTOs**

```go
type EventRequest struct {
    EventID   string         `json:"event_id"`
    EventType string         `json:"event_type"`
    Scope     string         `json:"scope"`
    IP        string         `json:"ip"`
    Subject   string         `json:"subject,omitempty"`
    OccurredAt time.Time     `json:"occurred_at"`
    Metadata  map[string]any `json:"metadata,omitempty"`
}

type EventResponse struct {
    Accepted   bool   `json:"accepted"`
    Duplicate  bool   `json:"duplicate"`
    DecisionID string `json:"decision_id,omitempty"`
    RequestID  string `json:"request_id"`
}

type ErrorResponse struct {
    Code      string `json:"code"`
    Message   string `json:"message"`
    RequestID string `json:"request_id"`
}
```

The server generates a UUID request ID when `X-Request-ID` is absent or invalid. Valid incoming IDs match `[A-Za-z0-9._-]{1,64}`.

- [ ] **Step 4: Implement strict decode and validation**

The handler must:

1. permit only `POST` and `application/json`;
2. wrap body with `http.MaxBytesReader`;
3. use `json.Decoder.DisallowUnknownFields()`;
4. require exactly one JSON value;
5. parse IP with `netip.ParseAddr` and call `Unmap()`;
6. require nonempty event ID up to 128 bytes;
7. accept `occurred_at` no more than 5 minutes in the future;
8. authorize type/scope against peer identity;
9. reject sensitive metadata keys recursively to depth 8;
10. cap metadata after JSON encoding at 8 KiB;
11. set `ReceivedAt` from injected server clock.

- [ ] **Step 5: Persist an event transactionally**

Before policy evaluation exists, `Processor.Process` inserts the event and returns:

```json
{"accepted":true,"duplicate":false,"request_id":"..."}
```

A duplicate returns HTTP 200 with `duplicate=true` and does not insert another row.

Use status codes: 400 malformed request, 401 missing peer identity, 403 unauthorized event/scope, 405 wrong method, 413 too large, 415 wrong media type, 500 internal failure.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/api/events -v
go test ./...
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/protocol internal/api/events internal/model/event.go internal/store/tx.go
git commit -m "feat: add authenticated events ingestion API"
```

---

### Task 6: Policy Engine, Allowlist, and Application Decisions

**Files:**
- Create: `internal/engine/engine.go`
- Create: `internal/engine/engine_test.go`
- Create: `internal/decision/service.go`
- Create: `internal/decision/service_test.go`
- Modify: `internal/api/events/handler.go`
- Modify: `internal/store/tx.go`
- Modify: `internal/store/query.go`

**Interfaces:**
- Consumes: validated policies, clock, and store
- Produces: `engine.Process(ctx context.Context, source sourceauth.Identity, event model.Event) (engine.Result, error)`
- Produces: `decision.Service.Check(ctx context.Context, scope model.Scope, ip netip.Addr) (decision.CheckResult, error)`

- [ ] **Step 1: Write deterministic engine tests with a fake clock**

Required tests:

```go
func TestEngineCreatesDecisionAtExactThreshold(t *testing.T)
func TestEngineDoesNotCountEventsOutsideWindow(t *testing.T)
func TestEngineDoesNotCreateSecondDecisionWhileOneIsActive(t *testing.T)
func TestEngineEscalatesRepeatedDecisionFourTimes(t *testing.T)
func TestEngineCapsDurationAtTwentyFourHours(t *testing.T)
func TestEngineResetsStrikeAfterResetInterval(t *testing.T)
func TestEngineSkipsAutomaticDecisionForAllowlistedPrefix(t *testing.T)
func TestEngineProcessesConcurrentEventsIntoOneDecision(t *testing.T)
func TestEngineRollsBackEventWhenDecisionInsertFails(t *testing.T)
```

The concurrency test must launch 20 goroutines for the same source/IP and assert exactly 20 events and one active decision.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/engine ./internal/decision -v
```

Expected: FAIL because services do not exist.

- [ ] **Step 3: Implement serialized transactional evaluation**

`Engine` contains a process-local mutex because MVP supports one daemon instance:

```go
type Engine struct {
    mu       sync.Mutex
    store    *store.Store
    clock    clock.Clock
    policies []model.Policy
}
```

`Process` must acquire the mutex, open one database transaction, insert the event, return duplicate without evaluation when the unique key already exists, then evaluate matching enabled policies.

A policy matches exact source restriction when present, event type, and scope. The counter key is `(source_id, event_type, scope, canonical_ip)`.

- [ ] **Step 4: Implement duration calculation**

Use integer multiplication with saturation:

```go
func durationForStrike(base time.Duration, factor uint32, strike uint32, maximum time.Duration) time.Duration {
    value := base
    for n := uint32(1); n < strike; n++ {
        if factor == 0 || value > maximum/time.Duration(factor) {
            return maximum
        }
        value *= time.Duration(factor)
        if value >= maximum {
            return maximum
        }
    }
    return value
}
```

The first strike is `base_duration`; the next strike within reset interval multiplies by `escalation_factor`; the value never exceeds `max_duration`.

- [ ] **Step 5: Create one application decision atomically**

At threshold:

- check allowlist inside the same transaction;
- check for an active decision for scope/IP;
- derive strike from the latest decision for the same policy/IP after `now-reset_interval`;
- insert UUID decision with backend `application`, state `active`, reason `threshold_exceeded`;
- append audit action `decision.auto_created`;
- return its ID in the event response.

Events that do not create a decision still commit.

- [ ] **Step 6: Implement decision checking semantics**

`Check` returns blocked only when state is active and `expires_at > now`. When it sees an expired active row, it transactionally marks it `expired`, appends audit `decision.expired`, and returns not blocked.

Define:

```go
type CheckResult struct {
    Blocked    bool
    DecisionID string
    ExpiresAt  time.Time
    ReasonCode string
}
```

- [ ] **Step 7: Wire events API to the engine**

Replace direct event insertion in Task 5 with `Engine.Process`. Preserve duplicate semantics and include `decision_id` only when the current request created the decision.

- [ ] **Step 8: Run focused and race tests**

```bash
go test ./internal/engine ./internal/decision ./internal/api/events -v
go test -race ./internal/engine ./internal/decision ./internal/api/events
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/engine internal/decision internal/api/events internal/store
git commit -m "feat: evaluate policies and create application decisions"
```

---

### Task 7: Control API and Administrative Audit

**Files:**
- Create: `internal/api/control/handler.go`
- Create: `internal/api/control/handler_test.go`
- Modify: `pkg/protocol/types.go`
- Modify: `internal/decision/service.go`
- Modify: `internal/store/query.go`

**Interfaces:**
- Produces: `POST /v1/decisions/check`
- Produces: `GET /v1/decisions`
- Produces: `POST /v1/decisions/manual`
- Produces: `POST /v1/decisions/{id}/revoke`
- Produces: `GET /v1/allowlist`
- Produces: `POST /v1/allowlist`
- Produces: `DELETE /v1/allowlist/{id}`
- Produces: `GET /v1/audit`

- [ ] **Step 1: Write route authorization and behavior tests**

Required tests:

```go
func TestDecisionCheckAllowsConfiguredMiddlewareSource(t *testing.T)
func TestDecisionCheckRejectsSourceWithoutCheckPermission(t *testing.T)
func TestListDecisionsRequiresAdministrativePeer(t *testing.T)
func TestManualDecisionRequiresExplicitAllowlistOverride(t *testing.T)
func TestRevokeDecisionWritesActorAndRequestIDToAudit(t *testing.T)
func TestAllowlistCreateNormalizesSingleIPv4Address(t *testing.T)
func TestAllowlistCreateAcceptsIPv6CIDR(t *testing.T)
func TestAuditResponseNeverContainsMetadataFromSecurityEvents(t *testing.T)
```

Model control permissions separately from event permissions: `check_decisions`, `read_admin`, and `write_admin`.

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/api/control -v
```

Expected: FAIL because control handler does not exist.

- [ ] **Step 3: Define control DTOs**

```go
type DecisionCheckRequest struct {
    Scope     string `json:"scope"`
    IP        string `json:"ip"`
    RouteID   string `json:"route_id"`
    RequestID string `json:"request_id,omitempty"`
}

type DecisionCheckResponse struct {
    Blocked    bool      `json:"blocked"`
    DecisionID string    `json:"decision_id,omitempty"`
    ExpiresAt  time.Time `json:"expires_at,omitempty"`
    ReasonCode string    `json:"reason_code,omitempty"`
}
```

Manual decisions require scope, IP, duration, reason, and boolean `override_allowlist`. Maximum manual duration in MVP is 168h. Reject zero, negative, and larger durations.

- [ ] **Step 4: Implement least-privilege routing**

Use separate handlers/middleware for:

- decision check: sources with `check_decisions`;
- read routes: sources with `read_admin`;
- write routes: sources with `write_admin`.

The SG-Gateway service source may receive `check_decisions` but must not receive administrative write permission. A future panel-management adapter runs with a separately configured identity.

- [ ] **Step 5: Implement manual decisions and allowlist precedence**

Manual decision creation must:

- reject an allowlisted IP unless `override_allowlist=true`;
- use backend `application` in this plan;
- create state `active`, reason code `manual`;
- append audit actor from peer identity, not request JSON;
- use request ID generated/validated by the server.

Revoke must be idempotent: revoking an already revoked decision returns success and does not create a second audit entry.

- [ ] **Step 6: Implement bounded list responses**

All list endpoints use cursor pagination, default 50, maximum 200. Sort newest first with ID as a deterministic tiebreaker. Do not return event metadata through audit endpoints.

- [ ] **Step 7: Run tests**

```bash
go test ./internal/api/control ./internal/decision ./internal/store -v
go test ./...
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/api/control internal/decision internal/store pkg/protocol
git commit -m "feat: add local control API and administrative audit"
```

---

### Task 8: Daemon Assembly, Health, Graceful Shutdown, and Retention

**Files:**
- Create: `internal/app/app.go`
- Create: `internal/app/app_test.go`
- Create: `internal/health/service.go`
- Create: `internal/health/service_test.go`
- Create: `internal/retention/worker.go`
- Create: `internal/retention/worker_test.go`
- Modify: `cmd/sg-infosecd/main.go`
- Modify: `internal/api/control/handler.go`

**Interfaces:**
- Produces: `app.New(config.Config, app.Dependencies) (*app.App, error)`
- Produces: `(*app.App).Run(ctx context.Context) error`
- Produces: `GET /v1/health`

- [ ] **Step 1: Write lifecycle tests**

Required tests:

```go
func TestAppStartsBothSocketsAndServesHealth(t *testing.T)
func TestAppRefusesSecondInstanceUsingSameSockets(t *testing.T)
func TestAppShutdownClosesSocketsAndDatabase(t *testing.T)
func TestHealthReportsDatabaseFailureWithoutPanicking(t *testing.T)
func TestRetentionDeletesInBoundedBatches(t *testing.T)
func TestRetentionNeverDeletesActiveDecisionsOrAllowlist(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./internal/app ./internal/health ./internal/retention -v
```

Expected: FAIL because packages are missing.

- [ ] **Step 3: Assemble dependencies once**

`app.New` must:

1. open SQLite;
2. create source resolver;
3. create engine and decision service;
4. create events and control handlers;
5. create two Unix HTTP servers;
6. create health and retention services;
7. return an error after closing already-opened resources when any later step fails.

Do not use package-level mutable singletons.

- [ ] **Step 4: Implement health snapshot**

Return HTTP 200 for healthy and degraded, HTTP 503 only when the database cannot be queried. Response shape:

```go
type HealthResponse struct {
    Status          string            `json:"status"`
    Database        string            `json:"database"`
    ProtocolVersion string            `json:"protocol_version"`
    Build            buildinfo.Metadata `json:"build"`
    ActiveDecisions int64             `json:"active_decisions"`
    DatabaseBytes   int64             `json:"database_bytes"`
    LastRetentionAt *time.Time        `json:"last_retention_at,omitempty"`
}
```

Do not expose filesystem paths, UID lists, policy contents, or event metadata.

- [ ] **Step 5: Implement bounded retention worker**

Every 15 minutes, delete at most 1000 expired event rows per transaction until fewer than 1000 are deleted, then do the same for audit rows. Stop after 10 batches in one cycle to prevent long database monopolization. Record last success and last error for health diagnostics.

- [ ] **Step 6: Implement signal-aware daemon main**

`cmd/sg-infosecd` must accept:

```text
--config /etc/sg-infosec/sg-infosec.yaml
--version
--check-config
```

`--check-config` loads and validates configuration without opening sockets or the database. Normal run uses `signal.NotifyContext` for SIGINT and SIGTERM, starts both servers, and waits for clean shutdown with a 10-second deadline.

Exit codes: 0 success, 2 configuration/CLI error, 1 runtime failure.

- [ ] **Step 7: Run lifecycle and full tests**

```bash
go test ./internal/app ./internal/health ./internal/retention -v
go test -race ./...
go vet ./...
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/app internal/health internal/retention internal/api/control cmd/sg-infosecd
git commit -m "feat: assemble SG InfoSec core daemon"
```

---

### Task 9: CLI and Minimal Client SDK

**Files:**
- Create: `internal/cli/cli.go`
- Create: `internal/cli/cli_test.go`
- Create: `pkg/client/client.go`
- Create: `pkg/client/client_test.go`
- Modify: `cmd/sg-infosecctl/main.go`

**Interfaces:**
- Produces: `client.New(socketPath string, options ...client.Option) *client.Client`
- Produces: `(*client.Client).CheckDecision(ctx context.Context, request protocol.DecisionCheckRequest) (protocol.DecisionCheckResponse, error)`
- Produces CLI commands `status`, `health`, `decisions list`, `decisions add`, `decisions revoke`, `allowlist list`, `allowlist add`, `allowlist remove`, `audit list`, `config validate`

- [ ] **Step 1: Write client and CLI tests**

Required tests:

```go
func TestClientUsesUnixSocketAndNeverFallsBackToTCP(t *testing.T)
func TestClientEnforcesTwoSecondDefaultTimeout(t *testing.T)
func TestCLIHealthPrintsStableJSON(t *testing.T)
func TestCLIDecisionAddRequiresReasonAndDuration(t *testing.T)
func TestCLIAllowlistAddRequiresDescription(t *testing.T)
func TestCLIExitCodesDistinguishUsageAndServerFailure(t *testing.T)
```

- [ ] **Step 2: Run tests and verify failure**

```bash
go test ./pkg/client ./internal/cli -v
```

Expected: FAIL because packages do not exist.

- [ ] **Step 3: Implement Unix-only client transport**

```go
transport := &http.Transport{
    DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
    },
    DisableCompression: true,
}
```

Use a fixed synthetic base URL `http://unix`. Never inspect proxy environment variables and never retry over TCP.

- [ ] **Step 4: Implement CLI with explicit output modes**

Default output is human-readable. `--json` emits one JSON value to stdout. Errors go to stderr. Exit codes: 0 success, 2 usage/config error, 3 permission denied, 4 daemon unavailable, 1 other server/runtime error.

Sensitive request bodies must never be printed in error messages.

- [ ] **Step 5: Add config validation command**

```bash
sg-infosecctl config validate --config /etc/sg-infosec/sg-infosec.yaml
```

This command calls the local loader directly and does not require a running daemon.

- [ ] **Step 6: Run tests and manual binary smoke checks**

```bash
go test ./pkg/client ./internal/cli -v
go build -o /tmp/sg-infosecd ./cmd/sg-infosecd
go build -o /tmp/sg-infosecctl ./cmd/sg-infosecctl
/tmp/sg-infosecd --version
/tmp/sg-infosecctl --version
/tmp/sg-infosecctl config validate --config config/example/sg-infosec.yaml
```

Expected: tests pass, binaries build, version commands emit JSON, example configuration validates when the test user mapping is supplied by the fixture environment.

- [ ] **Step 7: Commit**

```bash
git add pkg/client internal/cli cmd/sg-infosecctl
git commit -m "feat: add local client and administration CLI"
```

---

### Task 10: End-to-End Contract, Protocol Documentation, and Resource Smoke Test

**Files:**
- Create: `tests/e2e/core_test.go`
- Create: `tests/e2e/helpers_test.go`
- Create: `docs/protocol-v1.md`
- Create: `scripts/smoke-resource.sh`
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: complete Core MVP
- Produces: executable protocol contract for later SG-Gateway integration

- [ ] **Step 1: Write real-socket end-to-end test**

The test must:

1. create temporary config, database, events socket, and control socket;
2. authorize the current test UID as source `e2e-panel`;
3. start `app.Run` in a goroutine;
4. send five distinct `auth.failed` events for `203.0.113.10`;
5. assert only the fifth response contains a decision ID;
6. check `admin-login` and assert blocked;
7. check `admin-api` and assert not blocked;
8. check IPv6 `2001:db8::10` independently;
9. revoke the decision through the administrative test identity;
10. assert the next check is not blocked;
11. stop the app and assert socket files are removed.

- [ ] **Step 2: Run end-to-end test and verify any missing wiring fails**

```bash
go test ./tests/e2e -run TestCoreDecisionLifecycleOverUnixSockets -v
```

Expected before final fixes: FAIL at the first incomplete contract boundary; do not weaken the assertions.

- [ ] **Step 3: Fix only contract gaps exposed by the test**

Keep protocol routes and DTO field names exactly as defined in Tasks 5 and 7. Do not add firewall behavior, SG-Gateway-specific imports, public listeners, or UI code.

- [ ] **Step 4: Document protocol v1**

`docs/protocol-v1.md` must specify:

- socket roles and permissions;
- peer credential identity model;
- all v1 routes, methods, request fields, response fields, status codes, and limits;
- idempotency rules;
- canonical IP rules;
- decision and allowlist precedence;
- sensitive fields that are forbidden;
- compatibility rule: additive optional response fields are allowed; removing or changing existing fields requires protocol v2.

Include complete curl-over-Unix-socket examples using only documentation-range IPs.

- [ ] **Step 5: Add resource smoke script**

`scripts/smoke-resource.sh` must:

- build a stripped Linux binary;
- start it with temporary state;
- wait for healthy control API;
- read RSS from `/proc/$pid/status`;
- fail when idle RSS exceeds 30 MiB;
- send 10,000 valid events across 100 IPs;
- verify health remains responsive;
- stop the process and clean temporary files.

The script is a smoke guard, not a benchmark. CI runs it only on Linux amd64.

- [ ] **Step 6: Run complete verification**

```bash
gofmt -w cmd internal pkg tests
go mod tidy
make check
go test ./tests/e2e -v
bash scripts/smoke-resource.sh
git diff --exit-code
```

Expected: all commands succeed and idle RSS stays within the 30 MiB budget.

- [ ] **Step 7: Commit**

```bash
git add tests/e2e docs/protocol-v1.md scripts/smoke-resource.sh README.md .github/workflows/ci.yml cmd internal pkg go.mod go.sum
git commit -m "test: lock SG InfoSec core MVP contract"
```

---

## Final Review Gate for Core MVP

Before merging the implementation branch, verify:

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/sg-infosecd ./cmd/sg-infosecctl
go test ./tests/e2e -v
bash scripts/smoke-resource.sh
```

Review the complete diff and confirm:

- no TCP/UDP listener exists;
- no root requirement or firewall code exists;
- source identity always comes from `SO_PEERCRED`;
- unknown sources and disallowed scopes are rejected;
- event idempotency is database-enforced;
- event insertion and automatic decision creation share one transaction;
- application decisions are isolated by scope and IP;
- IPv4 and IPv6 tests pass;
- allowlist and manual override behavior is audited;
- no sensitive metadata is stored or returned;
- graceful shutdown removes only owned Unix sockets;
- CI covers supported Go versions and race tests;
- resource smoke test enforces the 30 MiB idle target.

The Core MVP is complete only after this gate passes on the final commit SHA.
