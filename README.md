# SG InfoSec

SG InfoSec is a local-first security service for administrative panels and selected Linux services.

The current bootstrap contains two Go command binaries and stable build metadata. It does not open network ports, modify firewall rules, or require root privileges.

## Local requirements

- Linux
- Go 1.23 or newer for the current development stage

## Local verification

```bash
make check
./bin/sg-infosecd --version
./bin/sg-infosecctl --version
```

Running either command without arguments currently returns an explicit not-implemented error. Service startup and control commands are introduced in later Core MVP tasks.

No CI workflow is part of this stage.

## Configuration stage

The Core MVP now defines strict domain types and a dependency-free parser for the limited YAML subset used by SG InfoSec configuration. Supported YAML features are mappings, nested mappings, scalar sequences, quoted scalars, and comments. Anchors, aliases, tags, flow collections, multiline scalars, duplicate fields, and multiple documents are rejected.

Example configuration is stored under `config/example/`.

## Platform direction

The first deployable security service targets Linux servers. The protocol and decision model are kept platform-neutral so later products can reuse them:

- Windows can use a dedicated service with named-pipe transport and a Windows Firewall enforcement adapter.
- Android can use a client/agent library and, where appropriate, an Android `VpnService`-based adapter. It will not run the Linux systemd or nftables components.

Windows and Android support will be separate platform packages, not the Linux server binary copied unchanged.
