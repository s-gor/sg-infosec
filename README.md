# SG InfoSec

SG InfoSec is a local-first security service for administrative panels and selected Linux services.

The Core MVP branch contains a functional Linux daemon core. It listens only on configured Unix domain sockets, stores state in SQLite, evaluates application-level policies, and exposes authenticated local events, control and health APIs. It does not open TCP or UDP ports, modify firewall rules or require root privileges.

## Current status

Implemented:

- trusted local source identity from Linux `SO_PEERCRED`;
- strict event ingestion with IPv4/IPv6 normalization and sensitive-field rejection;
- transactional SQLite persistence, policy windows, escalation and allowlist handling;
- application-level decisions isolated by source, scope and IP;
- local health, decision, allowlist and audit APIs;
- bounded retention, process locking and graceful socket cleanup;
- Unix-only Go client SDK and `sg-infosecctl` administration CLI;
- hardened systemd service, tmpfiles contract and preserving install/uninstall scripts;
- separate least-privilege SG-Gateway source and local root administration source;
- real-socket end-to-end contract and a 30 MiB idle-RSS smoke guard.

Not implemented yet:

- `nftables` enforcer;
- SG-Gateway panel UI and integrated release wiring;
- Debian package and automatic updater;
- Windows service or Android agent packages.

## Local requirements

- Linux;
- Go 1.23 or newer for the current development stage;
- SQLite development headers and `pkg-config` for the CGO-backed store.

## Local verification

```bash
make check
go test ./tests/e2e -v
bash scripts/smoke-resource.sh
bash scripts/smoke-sg-gateway-adapter.sh /path/to/sg-gateway-v22
```

Build and inspect the commands:

```bash
make build
./bin/sg-infosecd --version
./bin/sg-infosecd --check-config --config config/example/sg-infosec.yaml
./bin/sg-infosecctl --version
./bin/sg-infosecctl --json --socket /run/sg-infosec/control.sock health
```

For a systemd installation from a verified source checkout:

```bash
make build
sudo packaging/install.sh
```

The installer creates the unprivileged `sg-infosec` account, installs the two binaries, creates narrow runtime/state directories, and preserves every existing configuration file. When an existing `sg-gateway` account is detected, it receives socket access through the `sg-infosec` supplementary group and the two SG-Gateway policies are installed only when absent. No VPN service, firewall rule or public listener is changed.

Remove program files while preserving configuration and state:

```bash
sudo packaging/uninstall.sh
```

Explicitly purge SG InfoSec configuration and state:

```bash
sudo packaging/uninstall.sh --purge
```

No CI workflow is part of this stage.

## CLI

Global options must precede the command:

```text
sg-infosecctl [--json] [--socket PATH] <command>
```

Available commands:

```text
health
status
decisions list
decisions add
decisions revoke
allowlist list
allowlist add
allowlist remove
audit list
config validate
```

Exit codes are stable: `0` success, `2` usage/configuration error, `3` permission denied, `4` daemon unavailable and `1` another runtime/server failure.

## Protocol

The local protocol v1 contract, limits, routes and curl-over-Unix examples are documented in [`docs/protocol-v1.md`](docs/protocol-v1.md).

## Configuration

The Core MVP uses a strict dependency-free parser for the limited YAML subset required by SG InfoSec. It supports mappings, nested mappings, scalar sequences, quoted scalars and comments. Anchors, aliases, tags, flow collections, multiline scalars, duplicate fields and multiple documents are rejected.

Example configuration is stored under `config/example/`.

## Platform direction

The first deployable security service targets Linux servers. The protocol and decision model remain platform-neutral for later products:

- Windows will use a dedicated service, named-pipe transport and a Windows Firewall/WFP adapter;
- Android will use a client/agent library and, where appropriate, an Android `VpnService` adapter.

Windows and Android support will be separate platform packages, not the Linux server binary copied unchanged.

## SQLite development dependency

The current Linux store uses the system SQLite library through CGO. The dependency is isolated in `internal/store`; builds without CGO still compile and return an explicit runtime error when the SQLite store is opened.
