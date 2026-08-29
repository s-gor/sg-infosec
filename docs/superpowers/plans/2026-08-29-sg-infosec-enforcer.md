# SG InfoSec nftables Enforcer Implementation Plan

**Goal:** Deliver a minimal root daemon that owns only `inet sg_infosec`, accepts typed local commands over a Unix socket, and reconciles nftables state from SG InfoSec decisions without touching any foreign table or VPN port.

## Security invariants

- no shell execution and no `nft` subprocess;
- no TCP/UDP listener;
- only `ssh` and explicitly configured `panel-port` targets are accepted;
- protocol/port pairs are exact allowlist entries;
- every IP is parsed with `net/netip`, canonicalized and bounded by an expiry;
- all firewall operations are serialized;
- unknown objects inside `inet sg_infosec` stop reconciliation;
- remove/uninstall operations may delete only the owned table;
- SQLite remains the source of truth; kernel timeout sets are an enforcement cache;
- AWG2, AWG3, AWG3.1, Xray, Mihomo, subscriptions and shared HTTPS routes are never targeted.

## Tasks

1. Add the public enforcer protocol, strict target policy, normalized entries, backend interface and serialized service.
2. Add a strict Unix HTTP API and peer-credential authorization for root and `sg-infosec` only.
3. Add a Linux nftables netlink encoder/decoder and a transport abstraction tested against captured kernel message contracts.
4. Implement owned schema creation, inspection and conflict detection for `inet sg_infosec`.
5. Implement timeout-set add/remove/list/reconcile for IPv4 and IPv6.
6. Add `sg-infosec-enforcerd`, hardened systemd unit, enforcer socket ownership and resource smoke tests.
7. Connect `sg-infosecd` to active `nftables` decisions with retry and startup reconciliation.
8. Extend CLI with `nft status`, `nft list` and `nft reconcile`; add VM validation instructions.

Each task is published as a separate commit or branch checkpoint. No target branch is updated until the full plan passes review and system validation.
