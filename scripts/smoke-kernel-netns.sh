#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf 'kernel smoke requires root (isolated network namespace)\n' >&2
    exit 77
fi
command -v unshare >/dev/null
command -v ip >/dev/null
exec unshare --net --mount-proc bash -Eeuo pipefail -c '
    ip link set lo up
    ip address add 203.0.113.1/32 dev lo
    ip address add 203.0.113.7/32 dev lo
    ip -6 address add 2001:db8::1/128 dev lo
    ip -6 address add 2001:db8::7/128 dev lo
    exec env SG_INFOSEC_KERNEL_SMOKE=1 go test -count=1 -run "^TestKernelSmoke$" ./internal/nftkernel
'
