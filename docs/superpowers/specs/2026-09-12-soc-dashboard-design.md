# SG InfoSec SOC Dashboard Design

## Status

Approved by the product owner from the SOC mockup shown in chat on 2026-09-12. This design extends the existing standalone SG InfoSec web UI on `feature/standalone-web-ui`; it does not move SG InfoSec back into SG-Gateway.

## Goal

Turn the standalone SG InfoSec web panel into a dense, useful SOC-style security console that explains what is happening on the server at a glance and makes the existing protection controls understandable without exposing raw internal IDs as the primary UI.

## Product boundary

- SG InfoSec remains a standalone product and service.
- Public path remains `/infosec/` behind nginx on TCP 64443.
- SG-Gateway is optional; the UI must work when SG-Gateway is absent.
- VLESS/REALITY and TCP 443 are outside this change and must not be touched.
- Existing local `admin` authentication, secure session cookie and CSRF protection stay in place.
- Existing block/allowlist/audit mutations keep their current authorization model.
- UI must not fabricate security events, countries, attack counts or source health. Empty or unavailable data is shown explicitly.

## Visual direction

The approved direction is a professional SOC console, not a game HUD. Use the existing dark navy base but make the interface denser and more structured:

- fixed left navigation rail;
- top operational status strip;
- compact KPI cards;
- circular gauges rendered without client-side JavaScript;
- sparklines/line charts rendered server-side as inline SVG;
- status beads, badges and severity colors;
- dense tables with understandable Russian labels;
- technical IDs only in secondary/detail text;
- responsive collapse for narrow screens.

Primary palette: dark navy/blue-black surfaces, cyan/teal accents, green healthy states, amber warning states, red high-risk states. The UI remains self-contained: no CDN fonts, no remote JS, no remote CSS.

## Navigation

The authenticated navigation becomes:

1. **Обзор** — SOC dashboard.
2. **Атаки** — recent security events.
3. **Блокировки** — active decisions and manual blocking.
4. **Белый список** — allowlist management.
5. **Аудит** — administrative/system actions in human-readable form.
6. **Источники** — event-source activity and freshness.
7. **Настройки** — read-only product/session/security information in this phase; no new policy editor yet.

`Журнал` is intentionally not a separate raw-journal browser in this phase. The existing audit and source activity cover what the backend can expose safely today. A raw diagnostic journal can be a later feature.

## Data model exposed to the web UI

The current control API exposes health, decisions, allowlist and audit, but not event history. The SOC dashboard needs real event data, so this change adds an authenticated, read-only event listing endpoint.

### Event list

Add `GET /v1/events` on the existing Unix-socket control API. It is authorized with `read_admin`, the same permission already granted to `sg-infosec-web`.

Supported query parameters:

- `limit` — 1..200, default 100;
- `source_id` — optional exact source filter;
- `scope` — optional exact scope filter;
- `event_type` — optional supported event type filter;
- `since` — optional RFC3339 lower bound on `received_at`.

The response contains newest-first `EventView` records with:

- numeric DB id;
- source id;
- event id;
- event type;
- scope;
- IP;
- subject;
- occurred_at;
- received_at.

Metadata is deliberately not exposed by this endpoint in v1 because it can contain source-specific fields that are not required for the dashboard.

### SOC summary

Add `GET /v1/overview?window=24h` on the same control API. The first release accepts `1h` or `24h` and defaults to `24h`.

The summary is computed in SQLite, not from a truncated event page. It returns:

- `events_total`;
- `failed_events` (`auth.failed` + `api.auth_failed`);
- `unique_ips` among failed events;
- `active_decisions`;
- `automatic_decisions` among active decisions (non-`manual` policy/reason paths as represented by stored decisions);
- event counts grouped by scope;
- event counts grouped by event type;
- hourly buckets for the requested window;
- source activity: source id, event count in window, latest received_at.

The summary endpoint is read-only and requires `read_admin`.

## Dashboard semantics

The dashboard must only show metrics supported by real data.

Top KPI cards:

- **События угроз** — failed events in the selected 24h window;
- **Активные блокировки** — current active decisions;
- **Подозрительные IP** — unique IPs with failed events in the selected 24h window;
- **Всего событий** — all events in the selected 24h window.

Circular gauges:

- **Индекс угрозы** — display-only operational index, not an enforcement rule. Formula: `min(100, failed_events_1h*4 + active_decisions*8)`. Labels: 0–24 низкий, 25–49 умеренный, 50–74 высокий, 75–100 критический. The UI text must state that this is an operational indicator.
- **SSH доля** — percentage of failed events in scope `ssh` during the selected window.
- **Web/API доля** — percentage of failed events in scopes `panel-port`, `admin-login`, `admin-api` during the selected window.
- **Автоблокировки** — percentage of active decisions that were created automatically where the stored decision data allows reliable classification; when classification is unavailable, show an em dash instead of inventing a value.

Charts:

- hourly event dynamics from real summary buckets;
- attack/event-type donut based on real event-type counts;
- source activity panel from real source stats;
- top attacking IPs computed from the recent event list only and clearly labeled `последние N событий`, not as a global historical ranking.

The approved mockup contained a geographic world map. GeoIP is not currently a trusted backend capability, so v1 replaces it with a **Радар источников** panel: deterministic visual nodes derived from real IP addresses and recent events, without country labels or geographic claims. A true world map comes only after an explicit GeoIP data source is added.

## Attacks page

`/infosec/attacks` shows recent failed events from `GET /v1/events`:

- received time in local human-readable format;
- understandable event name;
- source IP;
- scope/service;
- source id;
- status derived from current active decisions for the same IP/scope when available: `Заблокировано` or `Наблюдение`.

Human labels:

- `auth.failed` + `ssh` → `Ошибка SSH-аутентификации`;
- `api.auth_failed` → `Ошибка API-аутентификации`;
- `auth.failed` + panel/admin scopes → `Ошибка входа в панель`;
- unknown supported combinations fall back to a safe Russian label plus technical code in secondary text.

No claim such as `RCE`, `SQL injection`, country, ASN, botnet or malware family may be shown unless the backend actually provides that classification.

## Existing pages

### Blockings

Keep all current functionality: list active decisions, create manual decision, revoke. Restyle into SOC tables/cards. Show strike count, source, backend, human reason label, start time and remaining time where present.

### Allowlist

Keep create/delete functionality. Restyle and show IP/CIDR, scope, description, expiry and creator.

### Audit

Translate known action codes such as `decision.auto_created`, `decision.manual_created`, `decision.revoked`, `allowlist.created`, `allowlist.deleted` to understandable Russian sentences. Keep actor/result visible. Raw action and target ID move into secondary text/details rather than being the main columns.

### Sources

Show summary source records with count in the selected window and last event time. A source is `Активен` when it has a recent event in the selected window, `Нет событий` when configured but silent, and `Нет данных` when the backend cannot report it. Do not equate `no recent events` with a broken collector.

### Settings

This phase shows current web session TTL, base path, core build/protocol metadata and a note that detection thresholds are managed by SG InfoSec configuration. It does not expose a writeable policy editor.

## Rendering and security

- Continue server-side HTML rendering in Go.
- No client-side JavaScript is required for the first SOC release.
- Charts are inline SVG generated from bounded integer arrays.
- All user/data-derived strings are escaped with `html.EscapeString`.
- Do not surface raw backend error messages in the browser. Use generic UI messages; detailed errors stay in service logs.
- Existing CSP remains restrictive; update only if required for inline SVG, not for remote assets.
- All mutating forms continue to require CSRF.
- Read routes still require an authenticated session.

## TLS/installer follow-up included in this pass

The standalone installer currently prefers explicit TLS source files, then existing SG InfoSec TLS files, then self-signed fallback. Extend it to reuse an already-present Let's Encrypt certificate when `SG_INFOSEC_WEB_DOMAIN` is supplied and both `/etc/letsencrypt/live/$DOMAIN/fullchain.pem` and `privkey.pem` exist. Do not invoke Certbot, do not request another certificate, and do not modify port 443.

The installer result URL must prefer `SG_INFOSEC_WEB_DOMAIN`; otherwise it may print the detected host address but must label private RFC1918 addresses as local/private rather than public.

## Testing

TDD is required.

1. Store tests for event filters and exact aggregate counts.
2. Control API tests for `/v1/events` and `/v1/overview`, including permissions and invalid filters.
3. Client/coreclient tests for new read calls.
4. Web tests for authenticated SOC dashboard content, attacks route, no fabricated geographic claims, human audit labels, and protected routes.
5. Packaging contract tests for Let's Encrypt reuse with `SG_INFOSEC_WEB_DOMAIN` and no Certbot invocation.
6. Existing complete gate plus standalone real installation smoke must remain green.

## Non-goals

- No GeoIP/ASN download or external enrichment.
- No browser JavaScript framework.
- No WebSocket/live streaming in this pass.
- No WAF, Suricata, IDS packet capture or packet inspection.
- No SG-Gateway code changes.
- No new listener on 80 or 443.
- No role system or multi-user administration.
- No writeable detection-policy editor yet.
