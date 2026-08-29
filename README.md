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
