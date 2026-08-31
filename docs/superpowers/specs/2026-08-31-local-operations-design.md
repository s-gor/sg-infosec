# SG InfoSec Local Operations Design

## Goal

Add a safe local SSH event source and a usable SSH terminal interface without opening network ports or changing PAM, sshd configuration, SG-Gateway listeners, or foreign nftables objects.

## Scope

The release adds three user-visible capabilities:

1. `sg-infosecctl overview` prints a stable status table containing core health, database state, enforcer readiness, local socket paths, SSH collector state, SG-Gateway detection, active decisions, allowlist count, and recent audit count.
2. `sg-infosecctl console` provides an interactive local menu for overview, decisions, manual block/revoke, allowlist, audit, and connection diagnostics. It uses only the existing Unix-socket APIs and remains usable when the terminal has no color support.
3. `sg-infosec-ssh-agent` follows OpenSSH journal records, recognizes explicit authentication failures, canonicalizes IPv4/IPv6 addresses, and submits `auth.failed` events with scope `ssh` to `/run/sg-infosec/events.sock`.

## Architecture

`sg-infosec-ssh-agent` is a separate Go binary and systemd service. It runs as root only so it can read the system journal, has an empty capability set, no network address families except `AF_UNIX`, and cannot write outside its private runtime state. It launches `journalctl --follow --output=json` directly without a shell. The process is fail-open: if SG InfoSec is unavailable, SSH authentication continues normally and the agent retries event delivery without changing sshd.

The source identity remains Linux peer credentials. The agent connects as UID 0 and is resolved to the existing `local-admin` source, which already permits `auth.failed` in scope `ssh`. A default `ssh.yaml` policy creates nftables decisions after five failures in ten minutes, beginning at thirty minutes and escalating to twenty-four hours.

The CLI aggregation layer is isolated under `internal/console`. It receives API clients and host probes through interfaces so table rendering and the interactive loop are deterministic in tests. JSON output remains machine-readable and existing commands keep their current behavior.

## Safety contracts

- No public TCP or UDP listener is added.
- No changes are made to `/etc/ssh/sshd_config`, PAM, fail2ban, UFW, foreign nftables tables, SG-Gateway services, or VPN ports 585–587.
- The SSH collector only creates structured events. The existing policy engine and enforcer remain the sole decision and firewall authorities.
- Installation and update preserve existing configuration and database files.
- The collector starts only after `sg-infosec.service`; a collector failure cannot stop SSH or SG-Gateway.
- Non-interactive environments receive plain text without ANSI escape sequences.

## Validation

The permanent gate must cover parser fixtures for common OpenSSH failure messages, ignored success/noise messages, IPv4 and IPv6 canonicalization, deterministic event IDs, fail-open delivery, CLI overview rendering, scripted console input, systemd hardening, packaging preservation, and a clean install smoke that confirms all three services are active and an injected SSH failure creates an audit record and decision according to policy.
