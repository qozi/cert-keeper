-- CertKeeper 初始 schema

CREATE TABLE IF NOT EXISTS tokens (
  id           TEXT PRIMARY KEY,
  secret       TEXT NOT NULL,
  note         TEXT,
  enabled      INTEGER NOT NULL DEFAULT 1,
  is_admin     INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS certs (
  domain         TEXT PRIMARY KEY,
  san            TEXT,
  ca             TEXT NOT NULL DEFAULT 'letsencrypt',
  challenge_mode TEXT NOT NULL,
  dns_provider   TEXT,
  webroot_path   TEXT,
  keylength      TEXT NOT NULL DEFAULT 'ec-256',
  renew_days     INTEGER NOT NULL DEFAULT 30,
  reload_cmd     TEXT,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL,
  source         TEXT NOT NULL DEFAULT 'preset'
);

CREATE TABLE IF NOT EXISTS dns_secrets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  provider   TEXT NOT NULL,
  env_key    TEXT NOT NULL,
  env_value  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(provider, env_key)
);

CREATE TABLE IF NOT EXISTS clients (
  token_id      TEXT PRIMARY KEY REFERENCES tokens(id) ON DELETE CASCADE,
  hostname      TEXT,
  os_info       TEXT,
  registered_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS issue_logs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  domain       TEXT NOT NULL,
  client_token TEXT,
  action       TEXT NOT NULL,
  success      INTEGER NOT NULL,
  duration_ms  INTEGER,
  message      TEXT,
  created_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_issue_logs_domain     ON issue_logs(domain);
CREATE INDEX IF NOT EXISTS idx_issue_logs_created_at ON issue_logs(created_at);

CREATE TABLE IF NOT EXISTS nonces (
  nonce       TEXT PRIMARY KEY,
  created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces(created_at);
