CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(source_id, event_id)
);

CREATE INDEX IF NOT EXISTS events_window_idx
ON events(source_id, event_type, scope, ip, received_at);

CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    ip TEXT NOT NULL,
    backend TEXT NOT NULL,
    state TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    strike_count INTEGER NOT NULL CHECK(strike_count >= 1),
    starts_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT
);

CREATE INDEX IF NOT EXISTS decisions_active_idx
ON decisions(source_id, scope, ip, state, expires_at);

CREATE INDEX IF NOT EXISTS decisions_page_idx
ON decisions(created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS allowlist_entries (
    id TEXT PRIMARY KEY,
    prefix TEXT NOT NULL,
    scope TEXT,
    description TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    result TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}'
);

INSERT OR IGNORE INTO schema_migrations(version, applied_at)
VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
