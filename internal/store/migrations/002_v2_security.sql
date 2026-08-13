-- v2 安全数据层：保留 v1 数据以便应用层兼容读取，不回写明文机密。
-- 重建 tokens/clients，使旧的 NOT NULL tokens.secret 可变为空。

CREATE TABLE tokens_v2 (
  id                TEXT PRIMARY KEY,
  secret            TEXT,
  secret_ciphertext TEXT,
  secret_version    INTEGER NOT NULL DEFAULT 0,
  secret_rotated_at INTEGER,
  note              TEXT,
  enabled           INTEGER NOT NULL DEFAULT 1,
  is_admin          INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL,
  last_used_at      INTEGER
);

INSERT INTO tokens_v2(id, secret, note, enabled, is_admin, created_at, last_used_at)
  SELECT id, secret, note, enabled, is_admin, created_at, last_used_at FROM tokens;

CREATE TABLE clients_v2 (
  token_id      TEXT PRIMARY KEY REFERENCES tokens_v2(id) ON DELETE CASCADE,
  hostname      TEXT,
  os_info       TEXT,
  registered_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL
);

INSERT INTO clients_v2(token_id, hostname, os_info, registered_at, last_seen_at)
  SELECT token_id, hostname, os_info, registered_at, last_seen_at FROM clients;

DROP TABLE clients;
DROP TABLE tokens;
ALTER TABLE tokens_v2 RENAME TO tokens;
ALTER TABLE clients_v2 RENAME TO clients;

CREATE TABLE IF NOT EXISTS token_certificate_grants (
  token_id    TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
  domain      TEXT NOT NULL REFERENCES certs(domain) ON DELETE CASCADE,
  permission  TEXT NOT NULL CHECK (permission IN ('apply', 'status', 'read_cert', 'read_private_key', 'force')),
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (token_id, domain, permission)
);

CREATE INDEX IF NOT EXISTS idx_token_certificate_grants_domain
  ON token_certificate_grants(domain, token_id);

-- profile 是同一 DNS provider 下独立账号或用途的稳定标识。
CREATE TABLE IF NOT EXISTS dns_profiles (
  id          TEXT PRIMARY KEY,
  provider    TEXT NOT NULL,
  profile     TEXT NOT NULL,
  account     TEXT NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE(provider, profile)
);

CREATE TABLE IF NOT EXISTS dns_profile_secrets (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  profile_id          TEXT NOT NULL REFERENCES dns_profiles(id) ON DELETE CASCADE,
  env_key             TEXT NOT NULL,
  secret_ciphertext   TEXT NOT NULL,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL,
  UNIQUE(profile_id, env_key)
);

CREATE INDEX IF NOT EXISTS idx_dns_profile_secrets_profile
  ON dns_profile_secrets(profile_id, env_key);

CREATE TABLE IF NOT EXISTS certificate_jobs (
  id                TEXT PRIMARY KEY,
  domain            TEXT NOT NULL REFERENCES certs(domain) ON DELETE CASCADE,
  operation         TEXT NOT NULL,
  idempotency_key   TEXT NOT NULL,
  status            TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  requested_by      TEXT REFERENCES tokens(id) ON DELETE SET NULL,
  error_message     TEXT,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL,
  started_at        INTEGER,
  finished_at       INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_jobs_active_idempotency
  ON certificate_jobs(domain, operation, idempotency_key)
  WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS idx_certificate_jobs_domain_created
  ON certificate_jobs(domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificate_jobs_status_created
  ON certificate_jobs(status, created_at);

CREATE TABLE IF NOT EXISTS certificate_generations (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id            TEXT NOT NULL REFERENCES certificate_jobs(id) ON DELETE CASCADE,
  domain            TEXT NOT NULL REFERENCES certs(domain) ON DELETE CASCADE,
  generation        INTEGER NOT NULL,
  status            TEXT NOT NULL CHECK (status IN ('pending', 'issued', 'failed', 'revoked')),
  certificate_ref   TEXT,
  private_key_ref   TEXT,
  not_before        INTEGER,
  not_after         INTEGER,
  error_message     TEXT,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL,
  UNIQUE(job_id, generation),
  UNIQUE(domain, generation)
);

CREATE INDEX IF NOT EXISTS idx_certificate_generations_domain_created
  ON certificate_generations(domain, created_at DESC);

CREATE TABLE IF NOT EXISTS deployment_reports (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  generation_id     INTEGER NOT NULL REFERENCES certificate_generations(id) ON DELETE CASCADE,
  target            TEXT NOT NULL,
  status            TEXT NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
  detail            TEXT,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL,
  completed_at      INTEGER,
  UNIQUE(generation_id, target)
);

CREATE INDEX IF NOT EXISTS idx_deployment_reports_generation
  ON deployment_reports(generation_id, status);

CREATE TABLE IF NOT EXISTS audit_events (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_token_id    TEXT REFERENCES tokens(id) ON DELETE SET NULL,
  domain            TEXT REFERENCES certs(domain) ON DELETE SET NULL,
  action            TEXT NOT NULL,
  outcome           TEXT NOT NULL,
  detail            TEXT,
  created_at        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_domain_created
  ON audit_events(domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_created
  ON audit_events(actor_token_id, created_at DESC);
