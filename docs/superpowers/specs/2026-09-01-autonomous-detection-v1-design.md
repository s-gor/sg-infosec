# SG InfoSec — Autonomous Detection V1

Date: 2026-09-01
Status: approved implementation design
Base: `818efda1dd24a2ccb8ad86f0a5c7c33b8529adfc`
Branch: `feature/autonomous-detection-v1`

## Goal

Turn SG InfoSec from a passive decision service into an autonomous, local-first detector that can protect a server even when an application adapter does not emit events.

This release is a useful vertical slice, not a claim to replace a SIEM, IDS or full WAF. It must autonomously detect the most common attacks against SSH and administrative HTTP endpoints, correlate activity across services, and create narrowly scoped decisions without touching VPN traffic.

## Security boundary

The existing boundaries remain mandatory:

- no public network API;
- no telemetry or cloud dependency;
- `sg-infosecd` remains unprivileged;
- `sg-infosec-enforcerd` remains the only nftables writer;
- no mutation of foreign nftables tables;
- no blocking of VPN ports 585–587;
- fail-open behavior for SG-Gateway if SG InfoSec is unavailable;
- no secret-bearing request bodies, cookies, tokens or passwords are stored.

## Scope

### Included

1. Autonomous journal collection through a supervised `journalctl --follow --output=json` child process.
2. Parsers for:
   - OpenSSH authentication failures and invalid-user probes;
   - Nginx/HTTP access messages containing common administrative-path scans;
   - SG-Gateway structured authentication failure messages when present in journald.
3. Normalized internal findings with source, category, IP, timestamp, confidence and safe metadata.
4. Sliding-window correlation by canonical IPv4/IPv6 address across all collectors.
5. Detection scenarios:
   - SSH brute force;
   - slow SSH brute force;
   - invalid-user enumeration;
   - administrative path scanning;
   - repeated panel/API authentication failures;
   - cross-service attack correlation.
6. Response ladder:
   - audit-only observation below threshold;
   - scoped application decision for `admin` or `admin-api`;
   - scoped nftables decision for `ssh`;
   - cross-service response creates only the affected scoped decisions, never a global all-port ban.
7. Bounded memory, bounded line size, restart backoff and fail-open collector failure handling.
8. Configuration with secure defaults and an explicit disable switch.
9. Unit, integration and lifecycle tests, plus CI coverage.

### Not included in this release

- GeoIP/ASN enrichment;
- external reputation lists;
- shared reputation between servers;
- packet inspection or Suricata-style IDS;
- full OWASP CRS or request-body WAF;
- automatic subnet bans;
- blocking VPN ports or subscriptions;
- machine learning.

These remain later stages after the autonomous collection and correlation foundation is proven.

## Architecture

```text
systemd journal
    |
    | journalctl JSON stream
    v
journal collector (unprivileged)
    |
    v
service parsers
    |
    v
normalized Finding
    |
    v
correlator / scenario engine
    |
    +--> audit observation
    |
    +--> existing event processor
              |
              +--> SQLite event + decision
              +--> existing nftables reconciliation
```

The detector feeds the existing event processor through an internal authenticated identity. It does not bypass validation, policy processing, persistence, allowlists, escalation or decision notification.

## Components

### `internal/detection`

Pure parsing and correlation package. It has no process, filesystem, database or network dependencies.

Key types:

- `Finding`: canonical IP, category, service, timestamp, subject, confidence and safe metadata;
- `Parser`: converts one journal record into zero or more findings;
- `Correlator`: maintains bounded per-IP windows and emits typed signals;
- `Signal`: event type, scope, IP, reason and evidence count.

The package is deterministic and tested with a fake clock.

### `internal/journal`

Supervises `journalctl` without invoking a shell. It uses fixed arguments, a bounded scanner buffer, context cancellation and exponential restart backoff. It accepts only JSON records and never interprets record fields as commands or paths.

A missing or inaccessible journal is non-fatal: the core service remains healthy, records the collector failure, and retries.

### Application integration

`internal/app` creates the detector only when enabled. The detector receives an internal identity named `sg-infosec-detector` with the minimum event/scope permissions needed for generated signals.

The detector is an additional supervised component in `App.Run`. Its failure does not terminate the control and event APIs; it retries internally until context cancellation.

## Default scenarios

### SSH burst

- category: `ssh.auth_failed` or `ssh.invalid_user`;
- threshold: 5 findings in 10 minutes;
- action: `auth.failed`, scope `ssh`, nftables backend through the existing SSH policy;
- base duration: existing policy duration and escalation rules.

### Slow SSH brute force

- threshold: 12 findings in 60 minutes;
- action: same SSH decision;
- purpose: catch low-rate attacks that evade burst-only rules.

### Username enumeration

- threshold: 6 distinct invalid usernames from one IP in 15 minutes;
- action: SSH decision;
- usernames are not persisted in raw form; only a bounded hash or distinct-count evidence is retained.

### Administrative path scan

- categories include probes for `.env`, `.git`, `wp-admin`, `phpmyadmin`, traversal sequences and known secret/config paths;
- threshold: 6 probes in 5 minutes;
- action: `api.auth_failed`, scope `admin-api`;
- this is an application decision unless the deployment explicitly uses a dedicated panel port.

### Panel/API authentication failures

- panel: 5 failures in 10 minutes -> `admin` decision;
- API: 10 failures in 10 minutes -> `admin-api` decision;
- structured SG-Gateway events remain preferred when available; journal parsing is a fallback.

### Cross-service correlation

A weighted score is maintained over 15 minutes:

- SSH authentication failure: 15;
- invalid-user probe: 20;
- administrative path probe: 20;
- panel authentication failure: 25;
- API authentication failure: 20.

At score 100 with evidence from at least two services, the detector emits decisions only for scopes represented by the evidence. It never creates a server-wide block.

## Parsing rules

OpenSSH parsing accepts common messages such as:

- `Failed password for ... from <ip>`;
- `Failed publickey for ... from <ip>`;
- `Invalid user ... from <ip>`;
- `PAM ... authentication failure ... rhost=<ip>`.

HTTP parsing extracts an address only from trusted journal fields or a validated access-log token. It recognizes a fixed, reviewed set of suspicious paths and traversal patterns. Query strings are discarded before metadata storage.

SG-Gateway parsing accepts structured JSON fields when available and a small set of stable text forms. It must not guess an address from arbitrary text.

## Configuration

A new `detector` section is added to the main config:

```yaml
detector:
  enabled: true
  journal: true
  units:
    - ssh.service
    - sshd.service
    - nginx.service
    - sg-gateway.service
  restart_min: 1s
  restart_max: 30s
  max_line_bytes: 65536
```

Unknown keys are rejected. Durations and limits are validated. Setting `enabled: false` restores the previous passive behavior.

## Resource limits

- no more than 4096 active IP correlation states;
- inactive states expire after 60 minutes;
- each IP stores bounded timestamp rings and bounded distinct-subject hashes;
- journal records larger than the configured maximum are dropped and audited;
- restart backoff prevents process-spawn loops;
- no periodic polling while `journalctl --follow` is healthy.

## Error handling

- malformed journal JSON: skip and count;
- unsupported message: ignore;
- parser panic: prohibited by design and covered with fuzz tests;
- journal child exit: retry with backoff;
- event-processing error: log safe reason and continue;
- database/enforcer errors continue to use existing engine behavior;
- shutdown cancels the child process and waits for it.

## Testing

1. Table-driven parser tests for IPv4/IPv6 and hostile input.
2. Correlator tests for every threshold, expiry, distinct-service requirement and bounded-state eviction.
3. Integration test proving a journal finding creates an existing SQLite decision.
4. Lifecycle test proving collector failure does not stop control/event APIs.
5. Test proving ports 585–587 and foreign nftables objects remain untouched.
6. Race test and existing `make check` gate.
7. Installer/reinstall tests ensure detector configuration is installed without overwriting an existing file.

## Delivery

All work remains on `feature/autonomous-detection-v1`. No merge to `main` or another branch is part of this task. The final report must include the branch, parent SHA, final SHA, changed files, test evidence, CI evidence and the pinned installation command.
