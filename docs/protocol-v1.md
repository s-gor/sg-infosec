# SG InfoSec Local Protocol v1

Status: Core MVP contract.

SG InfoSec v1 exposes HTTP/1.1 with JSON exclusively over Unix domain sockets. It does not expose a TCP or UDP listener.

## Socket roles

| Socket | Purpose | Typical caller |
|---|---|---|
| `events.sock` | Submit security events | Protected panel or local adapter |
| `control.sock` | Health, decision checks and administration | Panel middleware, CLI, management adapter |

The configured file mode is `0660`. Deployment tooling must set the socket directory and group membership so only intended local processes can connect.

## Identity and authorization

The daemon derives the caller identity from Linux `SO_PEERCRED`. A JSON field, HTTP header or query parameter cannot select or override `source_id`.

Each configured Unix UID maps to one logical source. Sources declare:

- allowed event types;
- allowed scopes;
- optional control permissions: `check_decisions`, `read_admin`, `write_admin`.

Unknown UIDs are rejected before business data is processed. A source cannot emit an event type or scope that is absent from its configuration.

## General request rules

- JSON request bodies must use `Content-Type: application/json`.
- Unknown JSON fields are rejected.
- A body must contain exactly one JSON value.
- The configured body limit defaults to 16 KiB and may range from 1 KiB to 1 MiB.
- `X-Request-ID` is accepted only when it matches `[A-Za-z0-9._-]{1,64}`; otherwise the daemon generates a new ID.
- Times are RFC3339/RFC3339Nano UTC values.
- IPv4-mapped IPv6 is normalized to canonical IPv4. Other IPv6 addresses are stored canonically.
- List endpoints default to 50 items and accept at most 200.

Error response:

```json
{
  "code": "permission_denied",
  "message": "read_admin permission is required",
  "request_id": "gateway.request-123"
}
```

Common statuses are `400` invalid request, `401` missing local identity, `403` unauthorized source, `404` unknown route/resource, `405` wrong method, `409` state conflict, `413` body too large, `415` wrong media type and `500` internal failure.

## Events socket

### `POST /v1/events`

Required permission: the peer source must allow the supplied `event_type` and `scope`.

Request:

```json
{
  "event_id": "login-01J6EXAMPLE",
  "event_type": "auth.failed",
  "scope": "admin-login",
  "ip": "203.0.113.10",
  "subject": "admin",
  "occurred_at": "2026-08-29T14:00:00Z",
  "metadata": {
    "reason": "invalid_password",
    "route": "/admin/login"
  }
}
```

Supported event types in Core MVP:

- `auth.failed`;
- `auth.succeeded`;
- `api.auth_failed`.

Supported scopes:

- `admin-login`;
- `admin-api`;
- `ssh`;
- `panel-port`.

Core MVP policies accept only the `application` backend. `ssh` and `panel-port` are domain values reserved for later enforcers and are not automatically applied by this daemon.

`event_id` is 1–128 UTF-8 bytes. `occurred_at` may not be more than five minutes in the future. Policy windows use the server's `received_at`, not the client timestamp.

Metadata is limited to 8 KiB and eight nesting levels. These keys are forbidden case-insensitively at every nesting level:

- `password`, `passwd`;
- `token`, `authorization`, `cookie`;
- `private_key`;
- `subscription_url`;
- `config`.

First accepted event: `202 Accepted`.

```json
{
  "accepted": true,
  "duplicate": false,
  "decision_id": "9f4c2a7e...",
  "request_id": "gateway.request-123"
}
```

`decision_id` is present only when this request created a decision. A duplicate `(source_id, event_id)` returns `200 OK`, `duplicate: true`, and does not re-evaluate policies.

Example:

```bash
curl --unix-socket /run/sg-infosec/events.sock \
  -H 'Content-Type: application/json' \
  -H 'X-Request-ID: docs.event-1' \
  -d '{"event_id":"docs-1","event_type":"auth.failed","scope":"admin-login","ip":"203.0.113.10","occurred_at":"2026-08-29T14:00:00Z"}' \
  http://unix/v1/events
```

## Control socket

### `GET /v1/health`

Any configured local source may read health.

```json
{
  "status": "healthy",
  "database": "ok",
  "protocol_version": "v1",
  "build": {
    "version": "dev",
    "commit": "unknown",
    "build_time": "unknown",
    "protocol_version": "v1"
  },
  "active_decisions": 2,
  "database_bytes": 65536
}
```

The response never exposes database or socket paths.

### `POST /v1/decisions/check`

Required permission: `check_decisions`.

```json
{
  "scope": "admin-login",
  "ip": "203.0.113.10",
  "route_id": "admin.login"
}
```

Allowed response:

```json
{"blocked":false}
```

Blocked response:

```json
{
  "blocked": true,
  "decision_id": "9f4c2a7e...",
  "expires_at": "2026-08-29T14:30:00Z",
  "reason_code": "threshold_exceeded"
}
```

A decision is keyed by source, scope and canonical IP. A decision for `admin-login` does not block `admin-api`, subscriptions, VPN traffic or another panel source.

### `GET /v1/decisions`

Required permission: `read_admin`.

Query parameters: `limit`, `cursor`, `source_id`, `scope`, `state`.

```json
{
  "items": [
    {
      "id": "9f4c2a7e...",
      "source_id": "sg-gateway",
      "policy_id": "sg-gateway-admin-login",
      "scope": "admin-login",
      "ip": "203.0.113.10",
      "backend": "application",
      "state": "active",
      "reason_code": "threshold_exceeded",
      "strike": 1,
      "starts_at": "2026-08-29T14:00:00Z",
      "expires_at": "2026-08-29T14:30:00Z",
      "created_at": "2026-08-29T14:00:00Z",
      "updated_at": "2026-08-29T14:00:00Z"
    }
  ],
  "next_cursor": "optional-opaque-value"
}
```

### `POST /v1/decisions/manual`

Required permission: `write_admin`.

```json
{
  "source_id": "sg-gateway",
  "scope": "admin-login",
  "ip": "203.0.113.10",
  "duration": "30m",
  "reason": "incident response",
  "override_allowlist": false
}
```

Duration must be positive and no longer than 168 hours. The response is the created decision with `201 Created`. An allowlisted address requires `override_allowlist: true`. An already active decision returns `409 Conflict`.

### `POST /v1/decisions/{id}/revoke`

Required permission: `write_admin`. The request has no body.

```json
{"changed":true,"request_id":"..."}
```

Revocation is idempotent. Repeating it returns success with `changed: false` and does not add a second revoke audit entry.

### `GET /v1/allowlist`

Required permission: `read_admin`. Query parameters: `limit`, `cursor`.

### `POST /v1/allowlist`

Required permission: `write_admin`.

```json
{
  "prefix": "2001:db8:abcd::/48",
  "scope": "admin-login",
  "description": "office network",
  "expires_at": "2026-09-01T00:00:00Z"
}
```

A single IP is normalized to `/32` or `/128`. `scope` and `expires_at` are optional. Description is required and limited to 256 bytes.

### `DELETE /v1/allowlist/{id}`

Required permission: `write_admin`. Deletion returns `ActionResponse` and is audited.

### `GET /v1/audit`

Required permission: `read_admin`. Query parameters: `limit`, `cursor`.

Audit responses include administrative actor, action, target, request ID and result. They do not expose security-event metadata, request bodies, passwords, tokens or cookies.

## Allowlist and decisions

Automatic policies check allowlist in the same transaction that would create the decision. Allowlist suppresses automatic decisions. A manual decision may override allowlist only through the explicit boolean flag and is audited.

Active decisions expire when `expires_at <= now`. A check that encounters an elapsed active decision marks it expired atomically and returns `blocked: false`.

## Failure behavior

A caller should use a short local timeout. Panel middleware is expected to fail open when SG InfoSec is unavailable; this behavior belongs to the panel adapter, not the daemon API.

The CLI uses a two-second default timeout and distinguishes permission errors from an unavailable daemon.

## Compatibility

Protocol v1 permits additive optional response fields. Existing field meanings, route methods, authorization semantics and required request fields cannot be removed or changed within v1. Incompatible changes require protocol v2.

## Enforcer socket

The privileged enforcer listens only on `/run/sg-infosec/enforcer.sock`. The peer UID is read from `SO_PEERCRED`. Only UID `0` and the configured non-root `sg-infosec` UID are authorized.

The enforcer owns only `inet sg_infosec`. Every mutation is validated against a fixed target policy and the exact owned schema before a netlink transaction is sent. It never accepts an nftables expression, table name, chain name or set name from a client.

### `POST /v1/ensure`

```json
{
  "request_id": "ctl.ensure-1",
  "schema_version": "v1"
}
```

Creates missing owned objects. Modified or unknown objects inside `inet sg_infosec` return an error and no mutation is applied.

### `POST /v1/add`

```json
{
  "request_id": "ctl.add-1",
  "entry": {
    "scope": "ssh",
    "protocol": "tcp",
    "port": 22,
    "ip": "203.0.113.10",
    "expires_at": "2026-08-29T20:00:00Z"
  }
}
```

### `POST /v1/remove`

```json
{
  "request_id": "ctl.remove-1",
  "key": {
    "scope": "ssh",
    "protocol": "tcp",
    "port": 22,
    "ip": "203.0.113.10"
  }
}
```

### `GET /v1/list`

```json
{
  "entries": [
    {
      "scope": "ssh",
      "protocol": "tcp",
      "port": 22,
      "ip": "203.0.113.10",
      "expires_at": "2026-08-29T20:00:00Z"
    }
  ]
}
```

### `POST /v1/reconcile`

```json
{
  "request_id": "core-reconcile-1",
  "entries": [
    {
      "scope": "ssh",
      "protocol": "tcp",
      "port": 22,
      "ip": "2001:db8::10",
      "expires_at": "2026-08-29T20:00:00Z"
    }
  ]
}
```

The complete desired state is validated before a single atomic element transaction is applied. The response reports `created`, `updated`, `removed` and `unchanged` counts.

The default enforcer target policy accepts only `ssh/tcp/22`. A `panel-port` entry is accepted only when that exact TCP port was explicitly configured in the enforcer process. VPN ports `585`, `586` and `587`, application scopes and UDP are rejected.
