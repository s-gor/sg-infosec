# SG InfoSec Local Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a local SSH failure collector plus `overview` and interactive `console` commands, packaged and verified by the existing clean-install gate.

**Architecture:** A dedicated root-but-capability-free collector reads JSON records from `journalctl` without modifying sshd and submits structured events through the existing Unix events socket. A separate console package aggregates existing control/enforcer APIs and host probes, keeping rendering and interactive behavior testable and independent from protocol code.

**Tech Stack:** Go 1.23+, Linux systemd/journald, Unix-domain HTTP protocol v1, SQLite, nftables enforcer, Bash packaging tests.

**Spec:** `docs/superpowers/specs/2026-08-31-local-operations-design.md`

## Global Constraints

- No public network listener.
- Do not change PAM, sshd configuration, SG-Gateway services, VPN ports 585–587, or foreign nftables objects.
- Preserve existing configuration and database files on install/update.
- Collector failures are fail-open for SSH and SG-Gateway.
- Source identity continues to use Linux peer credentials.

---

### Task 1: SSH journal parser and event sender

**Files:**
- Create: `internal/sshjournal/parser.go`
- Create: `internal/sshjournal/parser_test.go`
- Create: `internal/sshjournal/runner.go`
- Create: `internal/sshjournal/runner_test.go`
- Modify: `pkg/client/client.go`
- Modify: `pkg/client/client_test.go`

**Interfaces:**
- Produces: `sshjournal.ParseRecord([]byte) (protocol.EventRequest, bool)` and `sshjournal.Run(context.Context, Config) error`.
- Produces: `client.Client.SubmitEvent(context.Context, protocol.EventRequest) (protocol.EventResponse, error)`.

- [ ] Write failing parser tests for failed password, invalid user, failed public key, IPv6, duplicate cursor identity, and ignored success/noise records.
- [ ] Run `go test ./internal/sshjournal ./pkg/client` and verify RED.
- [ ] Implement strict JSON journal decoding, explicit OpenSSH failure patterns, canonical IP parsing, metadata allowlist, and deterministic event IDs.
- [ ] Implement direct `journalctl` process execution and fail-open event submission with bounded retry.
- [ ] Run focused tests and verify GREEN.

### Task 2: CLI overview and interactive console

**Files:**
- Create: `internal/console/overview.go`
- Create: `internal/console/overview_test.go`
- Create: `internal/console/console.go`
- Create: `internal/console/console_test.go`
- Modify: `internal/cli/cli.go`
- Modify: `internal/cli/cli_test.go`
- Modify: `cmd/sg-infosecctl/main.go`

**Interfaces:**
- Consumes existing control and enforcer client interfaces.
- Produces `console.RenderOverview`, `console.Run`, and CLI commands `overview` and `console`.

- [ ] Write failing tests for Unicode/plain overview, socket and source diagnostics, JSON aggregation, scripted menu input, manual block, revoke, and quit.
- [ ] Run `go test ./internal/console ./internal/cli ./cmd/sg-infosecctl` and verify RED.
- [ ] Implement table rendering with ANSI only on TTY, bounded list calls, and deterministic labels.
- [ ] Implement interactive menu using injected reader/writer and existing service methods.
- [ ] Run focused tests and verify GREEN.

### Task 3: Packaging, policy, and systemd lifecycle

**Files:**
- Create: `cmd/sg-infosec-ssh-agent/main.go`
- Create: `cmd/sg-infosec-ssh-agent/main_test.go`
- Create: `config/example/policies.d/ssh.yaml`
- Create: `packaging/systemd/sg-infosec-ssh-agent.service`
- Modify: `Makefile`
- Modify: `packaging/install.sh`
- Modify: `packaging/uninstall.sh`
- Modify: `install-from-github.sh`
- Modify: `tests/packaging_contract_test.go`
- Modify: `scripts/smoke-systemd-install.sh`
- Modify: `scripts/smoke-install-from-github.sh`

**Interfaces:**
- Produces binary `/usr/local/sbin/sg-infosec-ssh-agent` and unit `sg-infosec-ssh-agent.service`.

- [ ] Write failing contract and smoke tests for binary installation, unit hardening, default SSH policy, startup order, uninstall, and preserved state.
- [ ] Run `go test ./tests ./cmd/sg-infosec-ssh-agent` and verify RED.
- [ ] Implement build/install/uninstall and start collector after core health is established.
- [ ] Run focused tests and clean-install smoke; verify GREEN.

### Task 4: Documentation and complete verification

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/enforcer-gate.yml` only if a permanent additional smoke step is required.

- [ ] Document `overview`, `console`, SSH collector behavior, fail-open semantics, and diagnostics.
- [ ] Run `make check`.
- [ ] Run resource, kernel nftables, systemd install, and clean bootstrap smokes.
- [ ] Publish a single clean commit whose parent is `818efda1dd24a2ccb8ad86f0a5c7c33b8529adfc` and run the full gate on that exact SHA.
