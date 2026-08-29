# SG InfoSec

SG InfoSec is a local-first security service for administrative panels and selected Linux services.

The current Core MVP branch contains a functional Linux daemon core. It listens only on configured Unix domain sockets, stores state in SQLite, evaluates application-level policies, and exposes authenticated local events, control, and health APIs. It does not open TCP or UDP ports, modify firewall rules, or require root privileges.

## Local requirements

- Linux
- Go 1.23 or newer for the current development stage
- SQLite development headers and `pkg-config` for the CGO-backed store

## Local verification

```bash
make check
./bin/sg-infosecd --version
./bin/sg-infosecd --check-config --config config/example/sg-infosec.yaml
./bin/sg-infosecctl --version
```

Normal daemon startup requires a valid configuration, an existing database parent directory, existing socket parent directories, and configured local source users. This branch is still a development artifact and is not an installation package.

No CI workflow is part of this stage.

## Configuration

The Core MVP defines strict domain types and a dependency-free parser for the limited YAML subset used by SG InfoSec configuration. Supported YAML features are mappings, nested mappings, scalar sequences, quoted scalars, and comments. Anchors, aliases, tags, flow collections, multiline scalars, duplicate fields, and multiple documents are rejected.

Example configuration is stored under `config/example/`.

## Current daemon capabilities

- authenticated event ingestion over a Unix socket;
- source identity from Linux peer credentials;
- transactional SQLite persistence;
- policy windows, escalation, allowlist checks, and application decisions;
- local decision, allowlist, audit, and health APIs;
- process lock preventing a second instance from taking over the same state;
- bounded event and audit retention;
- graceful SIGINT/SIGTERM shutdown with socket cleanup.

The Core MVP still has no `nftables` enforcer, panel adapter, Debian package, or production installer.

## Platform direction

The first deployable security service targets Linux servers. The protocol and decision model are kept platform-neutral so later products can reuse them:

- Windows can use a dedicated service with named-pipe transport and a Windows Firewall enforcement adapter.
- Android can use a client/agent library and, where appropriate, an Android `VpnService`-based adapter. It will not run the Linux systemd or nftables components.

Windows and Android support will be separate platform packages, not the Linux server binary copied unchanged.

## SQLite development dependency

The current Linux store uses the system SQLite library through CGO. The dependency is isolated in `internal/store`; builds without CGO still compile and return an explicit runtime error when the SQLite store is opened.
