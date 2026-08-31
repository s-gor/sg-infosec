# SG InfoSec

SG InfoSec is a local-first security service for administrative panels and selected Linux services. It has no public network API and does not send telemetry.

## Current status

The Linux MVP is implemented as three binaries:

- `sg-infosecd` — unprivileged event processing, SQLite state, policy engine, application decisions and control API;
- `sg-infosec-enforcerd` — minimal root component that owns only `inet sg_infosec` and applies typed nftables decisions;
- `sg-infosecctl` — local administration and diagnostics CLI.

Implemented security contracts:

- source identity from Linux `SO_PEERCRED`, never from a claimed JSON identity;
- strict JSON/YAML schemas, bounded request bodies and rejection of sensitive metadata;
- transactional SQLite persistence, policy windows, escalation, allowlist and audit;
- application decisions isolated by source, scope and canonical IPv4/IPv6 address;
- raw `NETLINK_NETFILTER` nftables driver with no shell and no `nft` subprocess;
- a single owned table, `inet sg_infosec`, with fixed chain/set/rule names;
- timeout sets for IPv4 and IPv6 SSH decisions and explicitly configured dedicated panel ports;
- refusal to reconcile modified or unknown objects inside the owned table;
- no changes to foreign tables, SG-Gateway AWG tables, VPN ports 585–587, subscriptions or shared HTTPS routes;
- startup and periodic reconciliation from SQLite, plus immediate reconciliation after a new or revoked nftables decision;
- Unix-only enforcer API authorized for root and the configured `sg-infosec` UID;
- hardened systemd units, preserving install/uninstall scripts and explicit purge of only SG InfoSec state;
- real-kernel validation inside an isolated Linux user and network namespace.

Not included yet:

- SG-Gateway Security UI;
- Debian `.deb` packages and a signed automatic updater;
- Windows service and Android agent packages.

The SG-Gateway backend adapter is maintained separately so the panel remains fail-open if SG InfoSec is unavailable. Administrative login/API decisions are applied by panel middleware; nftables is reserved for SSH and an explicitly dedicated panel port.

## Requirements

- Linux with systemd and nftables-capable kernel;
- Go 1.23 or newer when building from source;
- SQLite development headers and `pkg-config` for the CGO-backed store;
- root only for installation and `sg-infosec-enforcerd`.

## Verification

Run the complete unit, race, vet and build gate:

```bash
make check
```

Run the application E2E, resource guard and actual kernel nftables tests:

```bash
go test ./tests/e2e -v
bash scripts/smoke-resource.sh
bash scripts/smoke-kernel-netns.sh
```

The kernel smoke uses `unshare -Urn`; it creates and deletes `inet sg_infosec` only inside an isolated user/network namespace. It tests schema creation, IPv4/IPv6 elements, reconciliation, Unix API access, shutdown cleanup and owned-table deletion against the real kernel.

The optional SG-Gateway adapter smoke requires the adapter checkout/path:

```bash
bash scripts/smoke-sg-gateway-adapter.sh /path/to/sg-gateway-v22
```

## Install on a clean Debian or Ubuntu host

Use a published full commit SHA and run the bootstrap from that same immutable commit:

```bash
SHA="<published-full-commit-sha>"
curl -fsSL \
  "https://raw.githubusercontent.com/s-gor/sg-infosec/${SHA}/install-from-github.sh" |
  sudo bash -s -- "$SHA"
```

The SHA appears twice intentionally: the first occurrence pins the installer itself, and the second requires that installer to fetch, verify and build exactly the same source commit.

The bootstrap supports Debian and Ubuntu on `amd64` and `arm64`. It installs the required system packages, installs a checksum-verified Go toolchain when no compatible Go 1.23+ toolchain is available, builds all three binaries, installs the systemd and tmpfiles contracts, starts the enforcer before the core service, and verifies health and nftables readiness. Re-running the command preserves the existing configuration and database. It does not restart SG-Gateway or any VPN service.

If installation fails after service deployment begins, the script prints the SG InfoSec service status and recent journal entries before exiting with a non-zero status.

## Build and install manually

For development from an existing checkout with all build dependencies already installed:

```bash
make build
sudo packaging/install.sh
```

The package installer:

- creates the unprivileged `sg-infosec` user/group when absent;
- installs all three binaries;
- installs the two systemd units and tmpfiles contract;
- preserves every existing configuration and database file;
- grants an existing `sg-gateway` account supplementary-group access to local sockets;
- starts the enforcer before the unprivileged core;
- does not restart or modify VPN services.

Remove binaries and units while preserving configuration/state:

```bash
sudo packaging/uninstall.sh
```

Explicitly remove the validated owned nftables table and purge SG InfoSec configuration/state:

```bash
sudo packaging/uninstall.sh --purge
```

The purge command refuses to reinterpret or delete foreign nftables objects. A schema conflict stops deletion.

## Commands

Global options must precede the command:

```text
sg-infosecctl [--json] [--socket PATH] [--enforcer-socket PATH] <command>
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
nft status
nft list
nft reconcile
config validate
```

Example manual SSH block:

```bash
sudo sg-infosecctl decisions add \
  --source local-admin \
  --scope ssh \
  --backend nftables \
  --ip 203.0.113.10 \
  --duration 30m \
  --reason "incident response"
```

Inspect the enforcer and force SQLite-to-kernel reconciliation:

```bash
sudo sg-infosecctl nft status
sudo sg-infosecctl nft list
sudo sg-infosecctl nft reconcile
```

Exit codes are stable: `0` success, `2` usage/configuration error, `3` permission denied, `4` daemon unavailable and `1` another runtime/server failure.

## Enforcer boundary

`sg-infosec-enforcerd` runs as root with only `CAP_NET_ADMIN` in its systemd capability bounding set. It accepts HTTP/JSON only through `/run/sg-infosec/enforcer.sock`. It supports the typed operations `ensure`, `add`, `remove`, `list` and `reconcile`.

The default policy permits only `ssh/tcp/22`. A dedicated panel port must be supplied explicitly with a repeated `--panel-port PORT` option. Ports `585`, `586` and `587` are always rejected.

The kernel table contains:

```text
inet sg_infosec
  chain input
  set ssh_v4
  set ssh_v6
  set panel_v4
  set panel_v6
```

All names, comments, hooks, priorities, key layouts and rule expressions are validated before mutation. SQLite remains the source of truth; timeout sets are an enforcement cache.

## Configuration and protocol

Example configuration is under `config/example/`. The dependency-free YAML subset supports mappings, nested mappings, scalar sequences, quoted scalars and comments. Anchors, aliases, tags, flow collections, multiline scalars, duplicate fields and multiple documents are rejected.

The local v1 routes, JSON schemas, limits and curl-over-Unix examples are documented in [`docs/protocol-v1.md`](docs/protocol-v1.md).

## Platform direction

The server product targets Linux. Shared protocol and decision types remain portable, but later platforms use separate implementations:

- Windows: dedicated service, named pipes and Windows Firewall/WFP adapter;
- Android: client/agent SDK and optional `VpnService` integration.

They are not copies of the Linux root daemon.
