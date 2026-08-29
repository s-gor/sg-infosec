#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT="${1:-${SG_GATEWAY_ADAPTER_PATH:-}}"

if [[ -z "$INPUT" ]]; then
    for candidate in \
        "$ROOT_DIR/../sg-gateway-v22/app/security/sg_infosec.py" \
        "$ROOT_DIR/../sg-gateway-adapter-work/app/security/sg_infosec.py"; do
        if [[ -f "$candidate" ]]; then
            INPUT="$candidate"
            break
        fi
    done
fi

if [[ -d "$INPUT" ]]; then
    INPUT="$INPUT/app/security/sg_infosec.py"
fi

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
    printf 'usage: %s /path/to/sg-gateway-v22-or-adapter.py\n' "$0" >&2
    exit 2
fi

command -v go >/dev/null 2>&1 || { echo 'go is required' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo 'python3 is required' >&2; exit 2; }

cd "$ROOT_DIR"
CGO_ENABLED=1 \
SG_GATEWAY_ADAPTER_PATH="$(realpath "$INPUT")" \
go test ./tests/sggateway \
    -run '^TestSGGatewayAdapterAgainstRealDaemon$' \
    -count=1 \
    -v
