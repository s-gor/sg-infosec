# SG InfoSec SOC Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the minimal standalone SG InfoSec web panel with the approved SOC-style dashboard using real backend data, add read-only event/overview APIs, and reuse an existing Let's Encrypt certificate when available.

**Architecture:** Extend the existing Unix-socket control API with bounded read-only event and overview endpoints. The web process consumes these endpoints through `internal/web/coreclient` and renders all dashboard widgets server-side in Go with HTML/CSS/inline SVG, preserving the current no-JavaScript security model. Existing decision, allowlist, audit, authentication, nginx listener and SG-Gateway isolation remain unchanged.

**Tech Stack:** Go 1.23, custom SQLite wrapper already in `internal/store`, net/http over Unix sockets, server-rendered HTML/CSS/SVG, nginx TLS proxy, GitHub Actions complete gate.

**Spec:** `docs/superpowers/specs/2026-09-12-soc-dashboard-design.md`

## Global Constraints

- Work only on `feature/standalone-web-ui`.
- Do not modify `s-gor/sg-gateway-v22`.
- Public SG InfoSec listener remains TCP 64443; do not touch TCP 443/VLESS.
- No fabricated countries, GeoIP, attack classes or metrics.
- No remote assets, JavaScript framework, CDN, WebSocket or telemetry.
- Existing `admin` login, secure cookie and CSRF rules stay intact.
- New control routes are read-only and require `read_admin`.
- All data-derived HTML must be escaped.
- Browser responses must not expose raw backend error strings.
- Every implementation task follows RED → GREEN TDD and ends with tests.

---

### Task 1: Read-only event history in store and protocol

**Files:**
- Modify: `pkg/protocol/types.go`
- Modify: `internal/store/query.go`
- Modify: `internal/store/store_test.go`

**Interfaces:**
- Produces `protocol.EventView`, `protocol.EventListResponse`, `protocol.OverviewResponse`, `protocol.OverviewBreakdown`, `protocol.OverviewBucket`, `protocol.SourceActivity`.
- Produces `store.EventFilter`, `store.EventPage`, `Store.ListEvents(ctx, filter)` and `Store.Overview(ctx, since, now)`.

- [ ] **Step 1: Write failing store tests**

Add tests that insert representative events through existing transaction/event ingestion paths and assert:

```go
page, err := database.ListEvents(ctx, store.EventFilter{
    Limit: 20,
    Scope: model.Scope("ssh"),
    Since: &since,
})
if err != nil { t.Fatal(err) }
if len(page.Items) != 2 { t.Fatalf("items=%d", len(page.Items)) }

summary, err := database.Overview(ctx, since, now)
if err != nil { t.Fatal(err) }
if summary.EventsTotal != 4 || summary.FailedEvents != 3 || summary.UniqueIPs != 2 {
    t.Fatalf("unexpected overview: %+v", summary)
}
```

Cover `source_id`, `scope`, `event_type`, `since`, newest-first ordering, exact unique-IP count, scope/event-type groupings, hourly buckets and source last-seen/count.

- [ ] **Step 2: Run store tests and verify RED**

Run:

```bash
go test ./internal/store -run 'TestListEvents|TestOverview' -count=1
```

Expected: compile failure because the new store types/methods do not exist.

- [ ] **Step 3: Add protocol response types**

In `pkg/protocol/types.go` add:

```go
type EventView struct {
    ID int64 `json:"id"`
    SourceID string `json:"source_id"`
    EventID string `json:"event_id"`
    EventType string `json:"event_type"`
    Scope string `json:"scope"`
    IP string `json:"ip"`
    Subject string `json:"subject,omitempty"`
    OccurredAt time.Time `json:"occurred_at"`
    ReceivedAt time.Time `json:"received_at"`
}

type EventListResponse struct {
    Items []EventView `json:"items"`
}

type OverviewBreakdown struct { Key string `json:"key"`; Count int64 `json:"count"` }
type OverviewBucket struct { Start time.Time `json:"start"`; Count int64 `json:"count"` }
type SourceActivity struct { SourceID string `json:"source_id"`; Count int64 `json:"count"`; LastSeen time.Time `json:"last_seen"` }
type OverviewResponse struct {
    Window string `json:"window"`
    EventsTotal int64 `json:"events_total"`
    FailedEvents int64 `json:"failed_events"`
    UniqueIPs int64 `json:"unique_ips"`
    ActiveDecisions int64 `json:"active_decisions"`
    AutomaticDecisions int64 `json:"automatic_decisions"`
    ByScope []OverviewBreakdown `json:"by_scope"`
    ByEventType []OverviewBreakdown `json:"by_event_type"`
    Hourly []OverviewBucket `json:"hourly"`
    Sources []SourceActivity `json:"sources"`
}
```

- [ ] **Step 4: Implement store queries**

Add `EventFilter` with `SourceID`, `Scope`, `EventType`, `Since`, `Limit`; validate limit 1..200 and supported event type before querying. Query `events` newest-first by `(received_at DESC, id DESC)`. Decode IP and times into `model.Event`.

Add `Store.Overview` using bounded SQL aggregate queries over `received_at >= since AND received_at <= now`:

```sql
SELECT COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ?;
SELECT COUNT(*) FROM events WHERE received_at >= ? AND received_at <= ? AND event_type IN ('auth.failed','api.auth_failed');
SELECT COUNT(DISTINCT ip) FROM events WHERE received_at >= ? AND received_at <= ? AND event_type IN ('auth.failed','api.auth_failed');
SELECT scope, COUNT(*) FROM events WHERE ... AND event_type IN (...) GROUP BY scope ORDER BY COUNT(*) DESC, scope;
SELECT event_type, COUNT(*) FROM events WHERE ... GROUP BY event_type ORDER BY COUNT(*) DESC, event_type;
SELECT source_id, COUNT(*), MAX(received_at) FROM events WHERE ... GROUP BY source_id ORDER BY source_id;
```

Hourly buckets are generated for every hour in the requested range, then populated from grouped SQLite counts so missing hours render as zero. Count active decisions with `state='active' AND expires_at > now`. Automatic decisions are active decisions whose `policy_id <> 'manual'`; if the existing manual convention differs, use the actual value found in `internal/decision/service.go` and cover it with tests.

- [ ] **Step 5: Run store tests GREEN**

```bash
go test ./internal/store -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/protocol/types.go internal/store/query.go internal/store/store_test.go
git commit -m "feat: add SOC event summary data"
```

---

### Task 2: Control API and clients for events/overview

**Files:**
- Create: `internal/api/control/event_routes.go`
- Modify: `internal/api/control/handler.go`
- Modify: `internal/api/control/handler_test.go`
- Modify: `pkg/client/client.go`
- Modify: `pkg/client/client_test.go`
- Modify: `internal/web/coreclient/client.go`
- Modify: `internal/web/coreclient/client_test.go`

**Interfaces:**
- `GET /v1/events`
- `GET /v1/overview?window=1h|24h`
- `Client.ListEvents(ctx, ListOptions)` extended with `EventType` and `Since`.
- `Client.Overview(ctx, window string)`.
- `coreclient.Service.ListEvents` and `.Overview`.

- [ ] **Step 1: Write failing control API tests**

Add authenticated tests using an identity with `read_admin` that call `/v1/events?limit=20&scope=ssh&since=<RFC3339>` and `/v1/overview?window=24h`. Assert HTTP 200 and exact JSON counts. Add negative tests: missing `read_admin` → 403, invalid `window` → 400, invalid `event_type` → 400.

- [ ] **Step 2: Run control tests RED**

```bash
go test ./internal/api/control -run 'TestEvent|TestOverview' -count=1
```

Expected: 404/compile failure.

- [ ] **Step 3: Implement event routes**

Create `event_routes.go` with strict method checks, permission check and parameter parsing. `window=1h` uses `now.Add(-time.Hour)`, `24h` uses `now.Add(-24*time.Hour)`. Convert model events to `protocol.EventView`. Never include metadata.

Wire routes in `Handler.ServeHTTP` before `not_found`.

- [ ] **Step 4: Run control tests GREEN**

```bash
go test ./internal/api/control -count=1
```

- [ ] **Step 5: Write failing client tests**

Extend test Unix HTTP server to assert exact paths/queries for `ListEvents` and `Overview`.

- [ ] **Step 6: Implement client/coreclient methods**

Extend `ListOptions`:

```go
EventType string
Since *time.Time
```

Add base client methods and delegate them through `internal/web/coreclient.Service`.

- [ ] **Step 7: Run client tests GREEN**

```bash
go test ./pkg/client ./internal/web/coreclient -count=1
```

- [ ] **Step 8: Commit**

```bash
git add internal/api/control/event_routes.go internal/api/control/handler.go internal/api/control/handler_test.go pkg/client/client.go pkg/client/client_test.go internal/web/coreclient/client.go internal/web/coreclient/client_test.go
git commit -m "feat: expose SOC event overview API"
```

---

### Task 3: SOC dashboard, attacks, sources and human presentation

**Files:**
- Create: `internal/web/app/soc.go`
- Create: `internal/web/app/soc_style.go`
- Modify: `internal/web/app/handler.go`
- Modify: `internal/web/app/handler_test.go`

**Interfaces:**
- Authenticated routes: `/infosec/`, `/infosec/attacks`, `/infosec/sources`, `/infosec/settings`.
- Helper functions in `soc.go`: `renderSOC`, `renderAttacks`, `renderSources`, `renderSettings`, `humanEventLabel`, `humanAuditAction`, `threatIndex`, `gaugeHTML`, `lineChartSVG`.

- [ ] **Step 1: Write failing web tests for SOC structure**

Extend `fakeCore` with real fake summary/events and assert the dashboard contains:

```go
for _, text := range []string{
    "Центр киберзащиты", "События угроз", "Активные блокировки",
    "Подозрительные IP", "Индекс угрозы", "SSH доля", "Web/API доля",
    "Динамика событий", "Радар источников", "Последние атаки",
    "Состояние источников",
} { ... }
```

Assert `/infosec/attacks`, `/infosec/sources`, `/infosec/settings` require a session and render after login. Assert the HTML does not contain fictional country labels or strings `RCE`, `SQL-инъекция` when fake backend data does not provide them.

- [ ] **Step 2: Run web tests RED**

```bash
go test ./internal/web/app -run 'TestSOC|TestAttacks|TestSources|TestSettings' -count=1
```

- [ ] **Step 3: Add SOC style layer**

Create `soc_style.go` with additional CSS constant `socStyles`. Use CSS grid/flex, gradients, `conic-gradient` gauges, status beads, compact tables and responsive breakpoints. No remote resources. Change `renderDocument` to concatenate `stylesheet + socStyles`.

- [ ] **Step 4: Implement server-rendered SOC helpers**

`renderSOC` fetches health, `Overview("24h")`, `Overview("1h")`, active decisions, recent failed events, audit and allowlist concurrently only if the current architecture safely supports concurrent Unix-socket requests; otherwise call sequentially to keep behavior deterministic. Any failed optional dataset renders `Нет данных`; health failure marks core unavailable.

Use real data only:

- KPI values from overview/health;
- threat index formula from the spec;
- SSH and Web/API percentages from summary scope counts;
- autoblock gauge from summary decision counts;
- `lineChartSVG` from hourly buckets;
- event-type donut with CSS `conic-gradient` from real breakdown;
- radar nodes from stable hashes of real IP strings and no country labels;
- top IP table from recent event page with explicit `последние N событий` caption.

- [ ] **Step 5: Add routes/navigation**

In `ServeHTTP`, add `attacks`, `sources`, `settings`. Replace top horizontal nav with a left SOC sidebar and compact top bar in `renderPrivate`. Keep logout form and CSRF.

Change dashboard method to delegate to `renderSOC`. Add human labels for known event/action codes. Change audit presentation to human labels with raw code/ID as secondary text.

- [ ] **Step 6: Remove raw backend errors from UI**

Replace response bodies such as:

```go
"Не удалось получить блокировки: "+err.Error()
```

with generic Russian messages. Keep detailed error values out of HTML.

- [ ] **Step 7: Run app tests GREEN**

```bash
go test ./internal/web/app -count=1
```

- [ ] **Step 8: Commit**

```bash
git add internal/web/app/soc.go internal/web/app/soc_style.go internal/web/app/handler.go internal/web/app/handler_test.go
git commit -m "feat: build standalone SOC dashboard"
```

---

### Task 4: Existing control pages in SOC visual language

**Files:**
- Modify: `internal/web/app/handler.go`
- Modify: `internal/web/app/handler_test.go`

- [ ] **Step 1: Write failing presentation tests**

Use decisions containing strike/source/backend/start/expiry and assert the page exposes readable fields without leading with UUIDs. Use allowlist entries with creator/expiry and audit entries with known codes. Assert destructive/mutating buttons still include CSRF.

- [ ] **Step 2: Run targeted tests RED**

```bash
go test ./internal/web/app -run 'TestDecisionPresentation|TestAllowlistPresentation|TestAuditPresentation' -count=1
```

- [ ] **Step 3: Restyle existing pages**

Blockings: add summary bar, reason labels, source, strike, remaining duration, compact manual-block panel.

Allowlist: add summary count, creator, expiry and SOC table styles.

Audit: convert action codes to Russian descriptions; show actor, time, human action/result; raw target/action only in muted secondary content.

- [ ] **Step 4: Run app package GREEN**

```bash
go test ./internal/web/app -count=1
```

- [ ] **Step 5: Commit**

```bash
git add internal/web/app/handler.go internal/web/app/handler_test.go
git commit -m "feat: align security controls with SOC UI"
```

---

### Task 5: Reuse existing Let's Encrypt certificate safely

**Files:**
- Modify: `install-standalone-web-from-github.sh`
- Modify: `tests/standalone_web_packaging_test.go`
- Modify: `scripts/smoke-standalone-web-install.sh`

- [ ] **Step 1: Write failing packaging test**

Require the installer to read `SG_INFOSEC_WEB_DOMAIN`, detect:

```text
/etc/letsencrypt/live/$DOMAIN/fullchain.pem
/etc/letsencrypt/live/$DOMAIN/privkey.pem
```

and install/reuse them before self-signed fallback. Assert it does not invoke `certbot` and does not contain `listen 443`.

- [ ] **Step 2: Run packaging test RED**

```bash
go test ./tests -run StandaloneWeb -count=1
```

- [ ] **Step 3: Implement TLS reuse**

Add `WEB_DOMAIN="${SG_INFOSEC_WEB_DOMAIN:-}"`. TLS precedence:

1. explicit certificate/key source env vars;
2. valid Let's Encrypt files for `WEB_DOMAIN` if both exist;
3. existing `/etc/sg-infosec/web/tls.crt|tls.key`;
4. self-signed fallback.

Use `openssl x509`/`openssl pkey` validation. Do not run Certbot. Print domain URL when `WEB_DOMAIN` is set. For a private RFC1918 detected address, label it `Local/private URL` rather than `Public URL`.

- [ ] **Step 4: Extend standalone smoke**

Keep the clean self-signed path working. Add a fixture directory only if needed for contract coverage; do not depend on Internet ACME.

- [ ] **Step 5: Run packaging/smoke contract tests GREEN**

```bash
go test ./tests -count=1
```

- [ ] **Step 6: Commit**

```bash
git add install-standalone-web-from-github.sh tests/standalone_web_packaging_test.go scripts/smoke-standalone-web-install.sh
git commit -m "fix: reuse existing panel TLS certificate"
```

---

### Task 6: Full verification and exact-SHA release candidate

**Files:**
- Modify if needed: `README.md`
- Modify only if verification proves needed: affected tests/code from earlier tasks.

- [ ] **Step 1: Update README**

Document SOC routes, the distinction between real event data and no-GeoIP radar, domain/TLS reuse, `admin` login and port 64443.

- [ ] **Step 2: Run local/repository gate where execution is available**

```bash
gofmt -w ./internal ./pkg ./cmd
make check
```

- [ ] **Step 3: Push exact feature HEAD and wait for GitHub Actions**

The existing workflow must pass all of:

- format/vet/unit/race/build;
- resource smoke;
- real kernel nftables smoke;
- real systemd installation smoke;
- clean install bootstrap smoke;
- standalone web installation smoke.

- [ ] **Step 4: Inspect exact run logs**

Any failure is fixed on the feature branch and the full gate is rerun. Do not report completion on a stale SHA.

- [ ] **Step 5: Final report**

Report only after exact current HEAD is green: feature branch, exact SHA, run id/number, functional summary, and the exact installer command pinned to that SHA. Do not merge to stable/main/dev without explicit owner permission.
