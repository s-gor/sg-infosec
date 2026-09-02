# SG InfoSec Standalone Web UI — Design

Date: 2026-09-02

## Status

Design for approval before implementation.

Base commit: `1a02dbea0860e7625c857ab82713ebf07397cff1` (`feature/infosec-complete-v1`).

Target implementation branch: `feature/standalone-web-ui`.

## Problem

The current SG InfoSec management/presentation UI was developed inside SG-Gateway. That makes the UI lifecycle depend on a particular SG-Gateway source tree. When SG-Gateway moves from one release line to another, the SG InfoSec templates, CSS, routes, presentation layer and management integration must be ported again. A standalone security product must not require this.

The new design makes SG InfoSec own its complete management interface. SG-Gateway becomes optional and no SG InfoSec application code is installed into the SG-Gateway repository or runtime tree.

## Goals

1. SG InfoSec must have its own web UI and authentication.
2. SG InfoSec must work when SG-Gateway is absent.
3. Updating or reinstalling SG-Gateway must not remove or replace the SG InfoSec UI.
4. Updating SG InfoSec must update backend and UI together while preserving configuration, state and administrator credentials.
5. The production URL for the selected deployment is `https://<domain>:64443/infosec/`.
6. TCP `443` is reserved for VLESS and must never be touched by the SG InfoSec installer.
7. The SG InfoSec application process must not expose a second raw application TCP listener to the Internet.
8. Existing SG InfoSec detection/enforcement security boundaries remain intact.

## Non-goals for v1

- No dependency on SG-Gateway login/session/authentication.
- No SSO with SG-Gateway in v1.
- No use of port 443.
- No automatic modification of VLESS/Xray configuration.
- No ACME listener on ports 80 or 443 in v1.
- No requirement to merge the UI back into SG-Gateway Security pages.
- No frontend SPA framework unless a concrete requirement appears; server-rendered HTML with small JS helpers is sufficient.

## Architecture

```text
Browser
  |
  | HTTPS :64443
  v
nginx
  |
  | proxy over Unix socket
  v
/run/sg-infosec/web.sock
  |
  v
sg-infosec-web (unprivileged)
  |
  | local SG InfoSec control protocol
  v
/run/sg-infosec/control.sock
  |
  v
sg-infosecd (unprivileged core)
  |
  v
sg-infosec-enforcerd (minimal privileged enforcer)
```

`sg-infosec-web` is a new component in the `sg-infosec` repository. It owns all HTML, CSS, static assets, form handlers, presentation mappings, session handling and administrative web operations.

`sg-infosec-web` must never call nftables directly and must not gain enforcer privileges. All security actions continue through the core control contract.

## Public endpoint

Canonical external URL:

```text
https://<domain>:64443/infosec/
```

The nginx listener is dedicated to TCP `64443`. It must not bind TCP `443`.

`/` on the `64443` listener may redirect to `/infosec/` for convenience. All application URLs, forms and static resources must work under the `/infosec/` prefix and must not assume `/` deployment.

The application socket is:

```text
/run/sg-infosec/web.sock
```

The socket is not world-writable and is accessible only to the nginx worker identity and the SG InfoSec web service according to the final packaging group contract.

## TLS and domain contract

The web edge uses a certificate for the configured hostname. A certificate is valid independently of the TCP port, therefore an existing certificate for the same domain may be reused on `64443`.

The installer accepts explicit web configuration rather than guessing unrelated product internals:

- hostname/domain;
- certificate path;
- private key path;
- external port, default and supported production value `64443`;
- base path, default `/infosec/`.

For Let's Encrypt installations, conventional certificate paths may be detected only after the domain is explicitly known. The installer must never request or renew a certificate through port 443 and must not alter VLESS.

If a valid certificate/key pair cannot be established, the installer must fail before changing the active web edge. It must not silently deploy plaintext HTTP to the public interface.

## nginx ownership and isolation

SG InfoSec owns only its dedicated nginx server configuration for `64443`. It must not overwrite the main nginx configuration or any SG-Gateway/VLESS configuration.

Installer behavior:

1. If nginx is already installed, preserve all existing configuration and add only the SG InfoSec server fragment.
2. Validate the complete nginx configuration before reload.
3. Verify that `64443/tcp` is available before activation.
4. Never modify listeners on 443.
5. On failed validation or activation, restore the previous SG InfoSec nginx fragment and leave existing nginx configuration unchanged.
6. If nginx must be installed on a host where it is absent, package installation must not be allowed to start an unreviewed default listener before SG InfoSec has installed its isolated configuration. The default Debian/Ubuntu site must not become part of the SG InfoSec public surface.

The exact file path is implementation-level, but it must live outside SG-Gateway ownership. Preferred location: `/etc/nginx/conf.d/sg-infosec.conf`, with SG InfoSec keeping a generated source/config under `/etc/sg-infosec/` for validation and recovery.

## Authentication and first setup

SG InfoSec has independent authentication.

On the first clean install, the installer creates a cryptographically random one-time setup code with a short lifetime (target: 15 minutes). The installer prints:

```text
SG InfoSec installed
Open: https://<domain>:64443/infosec/
First setup code: XXXX-XXXX-XXXX
```

The setup flow asks the administrator to:

1. enter the one-time setup code;
2. choose the SG InfoSec administrator username;
3. set the administrator password.

After successful setup, the one-time code is destroyed and cannot be reused.

Authentication requirements:

- password verifier stored using an appropriate modern password KDF;
- no plaintext password persistence;
- `Secure`, `HttpOnly`, `SameSite` session cookie;
- CSRF protection on all state-changing operations;
- login rate limiting;
- session rotation after login;
- logout invalidates the server-side session;
- administrator credentials survive SG InfoSec update/reinstall.

Root recovery is performed locally through a CLI operation such as `sg-infosecctl admin reset`. It must not depend on SG-Gateway credentials.

## Web component privilege model

New service: `sg-infosec-web.service`.

It runs as an unprivileged dedicated identity or the existing safe SG InfoSec service identity, whichever gives the smaller privilege set after implementation review.

The web process receives only the capabilities needed to:

- read its web configuration and static assets;
- maintain its own session/authentication state;
- connect to the SG InfoSec control socket;
- create and serve `/run/sg-infosec/web.sock`.

It receives no direct nftables capability and no access to private VPN key material.

Systemd hardening must follow the existing SG InfoSec pattern: filesystem restrictions, private temporary namespace where compatible, no-new-privileges and an explicit writable path set.

## Data flow

Read operation:

```text
browser -> nginx -> sg-infosec-web -> control.sock -> sg-infosecd
                                             <- structured response
browser <- rendered presentation <- sg-infosec-web
```

Write operation:

```text
browser POST
 -> authenticated session
 -> CSRF validation
 -> input validation
 -> sg-infosec-web request to sg-infosecd
 -> existing authorization/source policy
 -> enforcer only when the core decides enforcement is required
 -> structured result
 -> audit entry
 -> redirect/render result
```

The browser never talks directly to the core/enforcer sockets.

## UI scope for standalone v1

The first standalone UI carries forward the useful management experience already designed for SG InfoSec, but the implementation belongs to this repository.

Required screens/sections:

- overall protection/service status;
- active blocks/decisions;
- human-readable scope and reason labels;
- IP intelligence presentation when available (country, ASN/operator/source details according to available data);
- manual IP block;
- revoke/unblock;
- allowlist management;
- recent decision history;
- administrator audit trail;
- autonomous detection state and useful health information;
- settings that actually belong to SG InfoSec;
- full SG InfoSec help/instructions;
- technical details hidden behind disclosure controls rather than dominating the primary view.

Gateway-specific WAF controls are not automatically copied into standalone SG InfoSec unless they are backed by SG InfoSec itself. Product ownership must remain explicit.

## Presentation contract

Raw protocol values are not the primary UI language. The web layer maps internal scopes, actions and reasons to stable human-readable labels while preserving technical values in expandable details.

IP intelligence is presentation enrichment. Failure to resolve country/ASN/operator must not prevent security decisions from being displayed or managed.

The interface must render a useful unavailable/degraded state when the core is down, rather than returning a generic 500 page.

## Persistence

Persistent web state belongs below SG InfoSec ownership, for example:

```text
/var/lib/sg-infosec/web/
```

It includes only web-specific durable state such as administrator credential verifier, session metadata where needed, setup completion state and web audit metadata not already owned by the core.

Configuration belongs below:

```text
/etc/sg-infosec/
```

Runtime sockets/state belong below:

```text
/run/sg-infosec/
```

Updates must preserve `/etc/sg-infosec` and `/var/lib/sg-infosec` according to the existing installer preservation contract.

## Installer/update behavior

`install-from-github.sh` remains an exact-SHA installer and expands to build/install the web component.

The completed installation transaction must:

1. verify supported Debian/Ubuntu environment;
2. resolve explicit domain/TLS configuration;
3. verify `64443` availability without touching 443;
4. build the existing three binaries plus `sg-infosec-web`;
5. validate existing SG InfoSec configuration;
6. stage and validate nginx configuration;
7. install/update binaries and units while preserving config/state/auth data;
8. start enforcer, core and web in dependency order;
9. activate/reload only the dedicated nginx configuration after validation;
10. verify core health, nftables status, web Unix socket and HTTPS response on `64443`;
11. print the final URL and setup code only when initial setup is still pending.

An update failure must not leave the existing working UI replaced by a partial deployment. Web/nginx changes need rollback semantics comparable to the existing source/service install checks.

SG-Gateway is not restarted or modified by the SG InfoSec installer.

## Uninstall behavior

Uninstall must distinguish application removal from state destruction.

Normal uninstall removes services, binaries, runtime sockets and the SG InfoSec nginx server fragment. Destructive removal of `/etc/sg-infosec` and `/var/lib/sg-infosec` must remain an explicit operation rather than an accidental side effect.

It must not remove unrelated nginx configuration and must not touch VLESS or port 443.

## Compatibility with SG-Gateway

SG-Gateway is optional.

There is no runtime import of SG-Gateway Python code, no copied templates, no Gateway database dependency and no requirement for a matching Gateway release.

A future Gateway may expose a simple navigation link to `https://<host>:64443/infosec/`, but this is optional presentation integration, not a functional dependency.

## Migration from the old Gateway-hosted UI

The old `feature/sg-infosec-complete-ui` code is a reference for accepted UX and presentation behavior only. The standalone implementation must not depend on that branch at runtime.

Migration work will selectively port concepts and tests into `sg-infosec`:

- human-readable presentation mappings;
- compact decision/allowlist/history/audit UI concepts;
- help content;
- IP intelligence presentation semantics that belong to SG InfoSec.

Gateway-only guard/WAF logic remains Gateway-owned unless separately redesigned as an SG InfoSec capability.

Once standalone UI reaches acceptance, the old Gateway-hosted SG InfoSec management UI is considered legacy integration and should not be required for future SG InfoSec releases.

## Error handling

Expected failure states have explicit UI and installer behavior:

- core unavailable: UI renders degraded state; mutation controls disabled/fail safely;
- enforcer unavailable: core health exposes degraded enforcement; UI does not pretend a block succeeded;
- nginx validation failure: do not reload active nginx configuration;
- TLS certificate/key invalid: fail installation/web activation before public exposure;
- port 64443 occupied: fail with the owning listener information where safely obtainable; do not kill or reconfigure it;
- IP intelligence unavailable: display unknown/unavailable; core functionality continues;
- setup code expired: require a new root-generated setup/reset code;
- failed authentication: generic error response and rate-limit accounting, no account enumeration.

## Security invariants

- Port 443 is untouched.
- VPN ports and VLESS configuration are untouched.
- Web process never receives direct nftables privilege.
- Browser never receives access to local control/enforcer sockets.
- No secrets, passwords, cookies or raw sensitive request bodies are written to the SG InfoSec security event journal.
- State-changing browser actions require authenticated session and CSRF validation.
- Reverse-proxy trust is explicit; arbitrary client-supplied forwarded headers are not trusted without nginx normalization.
- Base path traversal and static asset path handling are tested.
- Security headers are set for the web UI, including CSP appropriate to the final asset model, frame restrictions and content-type protections.

## Testing strategy

Unit tests:

- authentication/password/session lifecycle;
- setup code creation, expiry and single-use behavior;
- CSRF enforcement;
- login rate limiting;
- presentation mappings;
- base-path URL generation under `/infosec/`;
- input validation for block/allowlist operations;
- degraded core/IP-intelligence states.

Integration tests:

- web component against a fake/real local SG InfoSec control socket;
- read and write management flows;
- audit generation;
- no direct enforcer access from web service;
- Unix socket ownership/mode contract.

Packaging tests:

- systemd hardening contract;
- nginx config binds 64443 and never 443;
- nginx config validation before reload;
- existing unrelated nginx configuration is preserved;
- exact-SHA installer builds four binaries;
- update preserves admin/config/state;
- failure rollback leaves previous web service usable.

Real CI smoke tests where runner capabilities permit:

- install on clean Ubuntu/Debian systemd environment;
- real nginx listener on 64443;
- HTTPS request to `/infosec/` using a test certificate;
- first-setup -> login -> view health -> controlled block/revoke flow;
- confirm no listener created by SG InfoSec on port 443;
- confirm enforcer/core/web services healthy after install.

## Acceptance criteria

The feature is accepted only when all of the following are demonstrated on the same final commit SHA:

1. `https://<domain>:64443/infosec/` serves the standalone UI.
2. No SG-Gateway code is required for the UI to operate.
3. SG-Gateway can be upgraded/reinstalled without replacing SG InfoSec web files/state.
4. SG InfoSec can be upgraded without losing admin credentials or security state.
5. Port 443/VLESS is unchanged.
6. Web actions control SG InfoSec through the core contract and not through privileged direct enforcement.
7. Clean install first-setup works.
8. Active blocks, revoke, allowlist, history, audit and help are usable from the standalone UI.
9. CI includes security/auth/base-path/packaging tests and real listener/install smoke where feasible.
10. Installer verifies the final HTTPS endpoint before reporting success.

## Implementation boundary

No SG-Gateway branch is part of this implementation. All production work for this design is confined to `s-gor/sg-infosec` on a feature branch until explicit acceptance/promotion.
