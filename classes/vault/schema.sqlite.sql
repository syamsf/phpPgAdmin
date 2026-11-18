CREATE TABLE servers (
  "key" TEXT PRIMARY KEY CHECK ("key" GLOB '[a-z0-9]*' AND length("key") BETWEEN 1 AND 63),
  name TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('env', 'ui')),
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 5432 CHECK (port BETWEEN 1 AND 65535),
  sslmode TEXT NOT NULL DEFAULT '',
  default_db TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'removed')),
  created_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  -- 1: connects through PgBouncer, which rejects startup options it can't track.
  pgbouncer INTEGER NOT NULL DEFAULT 0 CHECK (pgbouncer IN (0, 1))
);
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('personal', 'shared')),
  owner TEXT NOT NULL,
  label TEXT NOT NULL,
  server_id TEXT NOT NULL REFERENCES servers("key") ON DELETE CASCADE,
  "database" TEXT NOT NULL,
  pg_username TEXT NOT NULL,
  password_enc BLOB NOT NULL,
  nonce BLOB NOT NULL,
  key_version INTEGER NOT NULL,
  access_label TEXT NOT NULL CHECK (access_label IN ('read-only', 'read-write')),
  last_used_at TEXT,
  last_status TEXT NOT NULL DEFAULT 'ok' CHECK (last_status IN ('ok', 'auth_failed')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX credentials_scope ON credentials (server_id, "database");
CREATE INDEX credentials_owner ON credentials (owner, kind);
CREATE TABLE credential_shares (
  credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE CASCADE,
  principal_type TEXT NOT NULL CHECK (principal_type IN ('user', 'group')),
  principal TEXT NOT NULL,
  expires_at TEXT,
  granted_by TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (credential_id, principal_type, principal)
);
CREATE INDEX credential_shares_principal ON credential_shares (principal_type, principal);
CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  credential_id TEXT,            -- no FK: rows outlive the credential
  server_id TEXT,
  "database" TEXT,
  client_ip TEXT,
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_actor ON audit_log (actor, action, at);
CREATE INDEX audit_credential ON audit_log (credential_id, id);
CREATE TABLE users (
  username TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT,
  disabled INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  last_seen_at TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE user_groups (
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  group_name TEXT NOT NULL,
  PRIMARY KEY (username, group_name)
);
