# Autonomous Detection V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add autonomous journald-based attack detection, multi-service correlation and narrowly scoped automatic decisions to SG InfoSec.

**Architecture:** A supervised unprivileged journal reader converts fixed systemd-unit JSON records into normalized findings. A pure parser/correlator package converts findings into existing protocol events, and the existing event processor remains the single path for validation, persistence, allowlists, escalation and nftables notification.

**Tech Stack:** Go 1.23+, standard library only, Linux systemd journal through `journalctl`, existing SQLite/event engine/nftables enforcer, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-01-autonomous-detection-v1-design.md`

## Global Constraints

- No public network API, telemetry, cloud dependency or external reputation feed.
- `sg-infosecd` stays unprivileged; only `sg-infosec-enforcerd` writes nftables.
- Never mutate foreign nftables tables or block VPN ports 585–587.
- Collector failure is fail-open and must not stop event/control APIs.
- No passwords, tokens, cookies, query strings or request bodies are persisted.
- Standard library only; no new Go module dependency.
- Correlation state is capped at 4096 IPs and expires after 60 minutes.
- All work remains on `feature/autonomous-detection-v1`.

---

### Task 1: Normalized findings and parsers

**Files:**
- Create: `internal/detection/types.go`
- Create: `internal/detection/parser.go`
- Create: `internal/detection/parser_test.go`

**Interfaces:**
- Produces: `type Finding`, `type JournalRecord`, `func Parse(JournalRecord) []Finding`.
- `Finding` contains `IP netip.Addr`, `Category Category`, `Service Service`, `OccurredAt time.Time`, `SubjectHash string`, and `Metadata map[string]any`.

- [ ] Write table-driven failing tests for OpenSSH failed password/publickey, invalid user, PAM `rhost`, suspicious HTTP paths, SG-Gateway structured auth failures, IPv6, malformed input and query-string removal.
- [ ] Run `go test ./internal/detection -run TestParse -v` and confirm compilation/test failure.
- [ ] Implement strict parsing with fixed regular expressions and JSON fields. Never extract an address from arbitrary message text outside the accepted forms.
- [ ] Run `go test ./internal/detection -run TestParse -v` and confirm PASS.
- [ ] Commit `feat: parse autonomous security findings`.

### Task 2: Bounded multi-service correlator

**Files:**
- Create: `internal/detection/correlator.go`
- Create: `internal/detection/correlator_test.go`

**Interfaces:**
- Consumes: `Finding` from Task 1.
- Produces: `type Signal` and `func (c *Correlator) Observe(Finding) []Signal`.
- `Signal` contains protocol event type/scope strings, IP, reason, evidence count and occurred time.

- [ ] Write failing tests for SSH 5/10m, slow SSH 12/60m, six distinct invalid users/15m, HTTP scan 6/5m, panel 5/10m, API 10/10m, cross-service score 100 with two services, duplicate suppression, 60-minute expiry and 4096-state eviction.
- [ ] Run `go test ./internal/detection -run TestCorrelator -v` and confirm FAIL.
- [ ] Implement bounded timestamp rings, hashed-subject sets, weighted scoring, represented-scope emission and per-scenario cooldown.
- [ ] Run `go test ./internal/detection -run TestCorrelator -v` and confirm PASS.
- [ ] Run `go test -race ./internal/detection` and confirm PASS.
- [ ] Commit `feat: correlate attacks across services`.

### Task 3: Supervised journal collector

**Files:**
- Create: `internal/journal/collector_linux.go`
- Create: `internal/journal/collector_linux_test.go`

**Interfaces:**
- Produces: `type Runner interface { Run(context.Context, func(detection.JournalRecord) error) error }` and `type Collector`.
- `Collector.Run` executes `journalctl --follow --output=json --no-pager --unit=<unit>...` directly with `exec.CommandContext`; no shell.

- [ ] Write failing tests using a fake command factory for exact arguments, JSON decoding, 64 KiB limit, malformed record skip, cancellation, restart backoff and no tight respawn loop.
- [ ] Run `go test ./internal/journal -v` and confirm FAIL.
- [ ] Implement scanner-based JSON streaming, fixed argument construction, bounded buffers, safe field extraction and exponential backoff from configured min to max.
- [ ] Run `go test ./internal/journal -v` and confirm PASS.
- [ ] Commit `feat: collect security events from journald`.

### Task 4: Detector worker and existing-engine integration

**Files:**
- Create: `internal/detection/worker.go`
- Create: `internal/detection/worker_test.go`
- Modify: `internal/app/app.go`
- Modify: `internal/app/app_test.go`

**Interfaces:**
- `Worker` consumes a journal `Runner`, parser, correlator and existing `events.Processor`.
- Internal identity: source ID `sg-infosec-detector`; allowed event types/scopes are exactly the detector outputs.

- [ ] Write failing tests proving findings become existing protocol events, decisions trigger the existing notifier, processor errors are non-fatal, collector retries do not terminate APIs, and shutdown cancels the worker.
- [ ] Run focused tests and confirm FAIL.
- [ ] Implement worker conversion to `protocol.EventRequest` with deterministic event IDs derived from safe record identifiers plus signal data.
- [ ] Add optional worker construction to `app.New`, an additional supervised component to `App.Run`, and fail-open lifecycle handling.
- [ ] Run `go test ./internal/detection ./internal/app -v` and confirm PASS.
- [ ] Commit `feat: feed autonomous detections into decision engine`.

### Task 5: Strict detector configuration

**Files:**
- Modify: `internal/config/types.go`
- Modify: `internal/config/load.go`
- Modify: `internal/config/load_test.go`
- Modify: `config/example/sg-infosec.yaml`

**Interfaces:**
- Adds `DetectorConfig` with `Enabled`, `Journal`, `Units`, `RestartMin`, `RestartMax`, and `MaxLineBytes`.
- Defaults: enabled, journal enabled, units `ssh.service`, `sshd.service`, `nginx.service`, `sg-gateway.service`, restart 1s..30s, max line 65536.

- [ ] Write failing configuration tests for defaults, explicit disable, unknown keys, empty unit, duplicate unit, invalid durations, restart max below min and line limit outside 4096..1048576.
- [ ] Run `go test ./internal/config -v` and confirm FAIL.
- [ ] Implement strict YAML decoding and validation following existing loader patterns.
- [ ] Wire config into `app.New` and journal collector construction.
- [ ] Run `go test ./internal/config ./internal/app -v` and confirm PASS.
- [ ] Commit `feat: configure autonomous detection safely`.

### Task 6: Packaging and service access

**Files:**
- Modify: `packaging/install.sh`
- Modify: `packaging/sg-infosec.service`
- Modify: installer/packaging tests under existing `tests` paths.

**Interfaces:**
- Installation grants `sg-infosec` read access to journald through the system journal group when that group exists.
- Existing configurations and databases remain untouched on reinstall.

- [ ] Write failing packaging contract tests for journald access, no SG-Gateway restart, config preservation and unchanged VPN/firewall contracts.
- [ ] Run focused packaging tests and confirm FAIL.
- [ ] Add safe supplementary group handling and service hardening compatible with journal reads.
- [ ] Run packaging tests and confirm PASS.
- [ ] Commit `build: enable unprivileged journal detection`.

### Task 7: Documentation, health visibility and full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/protocol-v1.md` only if health/status response fields change.
- Modify/Create focused health tests if collector status is exposed.
- Modify: `.github/workflows/enforcer-gate.yml` only when new focused commands are not already covered by `make check`.

**Interfaces:**
- Health remains backward compatible. Optional detector fields may report enabled/running/last error without making collector failure unhealthy.

- [ ] Add tests for backward-compatible health behavior and detector visibility.
- [ ] Document autonomous scenarios, limits, disable switch and exact non-goals.
- [ ] Run `gofmt` on all Go changes.
- [ ] Run `go test ./...`.
- [ ] Run `go test -race ./...`.
- [ ] Run `go vet ./...`.
- [ ] Run `make check`.
- [ ] Run existing resource, kernel and install/reinstall smoke tests.
- [ ] Commit `docs: document autonomous detection`.
- [ ] Push final branch HEAD and wait for GitHub Actions success before reporting completion.
