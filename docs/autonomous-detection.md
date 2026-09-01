# Autonomous detection

SG InfoSec can detect common attacks without waiting for an application adapter to submit a preclassified event. The detector is enabled by default and runs inside the unprivileged `sg-infosecd` process.

## Data source

The service follows new records from the systemd journal by launching `journalctl` directly, without a shell:

```text
journalctl --follow --lines=0 --output=json --no-pager \
  --unit=ssh.service \
  --unit=sshd.service \
  --unit=nginx.service \
  --unit=sg-gateway.service
```

`--lines=0` prevents historical records from being replayed after a restart. The child process is cancelled with the daemon, malformed JSON is ignored, records larger than 64 KiB are rejected, and failures are retried with bounded exponential backoff. A journal failure does not make the control or event APIs unavailable.

The systemd unit grants only supplementary membership in `systemd-journal`. The core service remains unprivileged, has no network address families except `AF_UNIX`, and receives no capabilities.

## Parsed events

The reviewed parsers recognize:

- OpenSSH failed password and failed public-key authentication;
- OpenSSH invalid-user probes;
- PAM authentication failures containing a validated `rhost` address;
- Nginx access records for a fixed set of high-confidence attack paths, including `.env`, `.git`, WordPress login probes, phpMyAdmin, exposed Spring actuator data, common CGI/PHPUnit probes and path traversal;
- structured SG-Gateway `auth.failed` and `api.auth_failed` records when those records are present in journald.

Normal SG-Gateway routes such as `/config`, `/api/config`, `/backup`, `/api/backups` and `/admin/settings` are deliberately not classified as attacks.

The parser stores only canonical IPv4/IPv6 addresses, event categories, fixed safe metadata and short hashes used to count distinct usernames. HTTP query strings, passwords, cookies, tokens, request bodies and raw usernames are not stored.

## Detection scenarios

The correlator uses bounded sliding windows per canonical IP address:

| Scenario | Default threshold | Result |
| --- | ---: | --- |
| SSH authentication burst | 5 events in 10 minutes | SSH nftables decision |
| Slow SSH brute force | 12 events in 60 minutes | SSH nftables decision |
| Invalid-user enumeration | 6 distinct username hashes in 15 minutes | SSH nftables decision |
| Administrative path scan | 6 probes in 5 minutes | `admin-api` application decision |
| Panel authentication failure | 5 events in 10 minutes | `admin-login` application decision |
| API authentication failure | 10 events in 10 minutes | `admin-api` application decision |
| Cross-service attack | score 100 in 15 minutes from at least two services | decisions only for represented scopes |

Cross-service weights are intentionally simple and deterministic:

- SSH authentication failure: 15;
- invalid-user probe: 20;
- HTTP administrative-path probe: 20;
- panel authentication failure: 25;
- API authentication failure: 20.

A cross-service signal never creates a global all-port block. It can create an SSH decision, an `admin-login` decision, an `admin-api` decision, or the applicable combination. VPN ports 585–587 are never targeted.

## Decision path

The detector does not write SQLite or nftables directly. It creates an internal authenticated event with source ID `sg-infosec-detector` and sends it through the existing event processor. That path retains normal validation, allowlists, audit, escalation, duplicate handling and decision notification.

Detector policies have threshold `1` because attack thresholds are already evaluated by the correlator:

- `sg-infosec-detector-ssh`: nftables backend, 30-minute base duration;
- `sg-infosec-detector-admin-login`: application backend, 30-minute base duration;
- `sg-infosec-detector-admin-api`: application backend, 15-minute base duration.

The event source and the protected decision source are deliberately separate. SSH decisions remain owned by `sg-infosec-detector`; panel and API decisions are stored for source `sg-gateway`, so the existing SG-Gateway `decision.check` middleware sees them without weakening source isolation for unrelated applications.

Repeated strikes use the existing factor-of-four escalation with a 24-hour maximum.

SSH decisions are reconciled to the owned `inet sg_infosec` timeout sets and affect only TCP port 22. Administrative decisions are consumed by SG-Gateway middleware; they remain fail-open when SG InfoSec is unavailable.

## Resource limits

The correlator retains at most 4096 active IP states. States expire after 60 minutes, each state retains at most 256 normalized findings, and scenario cooldowns prevent repeated decision creation from the same active burst. When the state cap is reached, the oldest state is evicted deterministically.

## Disabling autonomous mode

Autonomous detection is enabled by this systemd environment setting:

```ini
Environment=SG_INFOSEC_AUTONOMOUS_DETECTION=1
```

To disable it without changing the packaged unit:

```bash
sudo systemctl edit sg-infosec.service
```

Add:

```ini
[Service]
Environment=SG_INFOSEC_AUTONOMOUS_DETECTION=0
```

Then apply the drop-in:

```bash
sudo systemctl daemon-reload
sudo systemctl restart sg-infosec.service
```

Accepted enabled values are empty, `1`, `true`, `on` and `enabled`. Accepted disabled values are `0`, `false`, `off` and `disabled`. An ambiguous value is rejected rather than guessed.

## Operational checks

Check service health and decisions:

```bash
sudo sg-infosecctl health
sudo sg-infosecctl decisions list
sudo sg-infosecctl nft list
```

Inspect detector input and service diagnostics:

```bash
sudo journalctl -u ssh.service -u sshd.service -u nginx.service -u sg-gateway.service -n 100 --no-pager
sudo journalctl -u sg-infosec.service -n 100 --no-pager
```

An autonomous SSH decision should appear in both `decisions list` and `nft list`. Administrative decisions appear in `decisions list` with source `sg-gateway`; enforcement at the application layer requires the SG-Gateway adapter and its `decision.check` middleware.

## Deliberate non-goals of this release

This release does not claim packet inspection, a complete OWASP CRS-compatible WAF, GeoIP/ASN enrichment, third-party reputation feeds, shared reputation between servers, automatic subnet bans, machine learning, or Suricata/Wazuh replacement. Those capabilities require separate threat models and resource budgets. The implemented release is the autonomous local collection, parsing, correlation and narrow-response foundation.
