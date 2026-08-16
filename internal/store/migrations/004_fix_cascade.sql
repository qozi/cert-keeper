-- 修复审计相关表的级联删除问题：将 ON DELETE CASCADE 改为 ON DELETE RESTRICT
-- 防止删除证书配置时级联清除 certificate_jobs、certificate_generations、deployment_reports 历史记录。
-- 迁移运行器已在事务内执行 PRAGMA defer_foreign_keys = ON，外键约束在提交时统一校验；
-- DROP TABLE 为 DDL 操作，不触发 FK 约束检查，因此无需关闭 foreign_keys。

-- ── 1. 重建 certificate_jobs ─────────────────────────────────────────────────
-- 将 domain 外键从 ON DELETE CASCADE 改为 ON DELETE RESTRICT

CREATE TABLE certificate_jobs_new (
  id              TEXT    PRIMARY KEY,
  domain          TEXT    NOT NULL REFERENCES certs(domain) ON DELETE RESTRICT,
  operation       TEXT    NOT NULL,
  idempotency_key TEXT    NOT NULL,
  status          TEXT    NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  requested_by    TEXT    REFERENCES tokens(id) ON DELETE SET NULL,
  error_message   TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  started_at      INTEGER,
  finished_at     INTEGER,
  attempts        INTEGER NOT NULL DEFAULT 0,
  max_attempts    INTEGER NOT NULL DEFAULT 3,
  next_attempt_at INTEGER,
  lease_owner     TEXT,
  lease_until     INTEGER,
  last_error_code TEXT,
  last_error_at   INTEGER
);

INSERT INTO certificate_jobs_new
  SELECT id, domain, operation, idempotency_key, status, requested_by,
         error_message, created_at, updated_at, started_at, finished_at,
         attempts, max_attempts, next_attempt_at, lease_owner, lease_until,
         last_error_code, last_error_at
  FROM certificate_jobs;

DROP TABLE certificate_jobs;
ALTER TABLE certificate_jobs_new RENAME TO certificate_jobs;

-- 重建 certificate_jobs 的全部索引（DROP TABLE 时已自动删除原索引）
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_jobs_idempotency
  ON certificate_jobs(domain, operation, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_certificate_jobs_domain_created
  ON certificate_jobs(domain, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificate_jobs_status_created
  ON certificate_jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_certificate_jobs_recoverable
  ON certificate_jobs(status, next_attempt_at, lease_until, created_at);

-- ── 2. 重建 certificate_generations ─────────────────────────────────────────
-- 将 job_id 和 domain 外键均从 ON DELETE CASCADE 改为 ON DELETE RESTRICT

CREATE TABLE certificate_generations_new (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id          TEXT    NOT NULL REFERENCES certificate_jobs(id) ON DELETE RESTRICT,
  domain          TEXT    NOT NULL REFERENCES certs(domain) ON DELETE RESTRICT,
  generation      INTEGER NOT NULL,
  status          TEXT    NOT NULL CHECK (status IN ('pending', 'issued', 'failed', 'revoked')),
  certificate_ref TEXT,
  private_key_ref TEXT,
  not_before      INTEGER,
  not_after       INTEGER,
  error_message   TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  revision        INTEGER NOT NULL DEFAULT 1,
  manifest_digest TEXT,
  serial          TEXT,
  fingerprint     TEXT,
  current         INTEGER NOT NULL DEFAULT 0,
  UNIQUE(job_id, generation),
  UNIQUE(domain, generation)
);

INSERT INTO certificate_generations_new
  SELECT id, job_id, domain, generation, status, certificate_ref, private_key_ref,
         not_before, not_after, error_message, created_at, updated_at,
         revision, manifest_digest, serial, fingerprint, current
  FROM certificate_generations;

DROP TABLE certificate_generations;
ALTER TABLE certificate_generations_new RENAME TO certificate_generations;

-- 重建 certificate_generations 的全部索引
CREATE INDEX IF NOT EXISTS idx_certificate_generations_domain_created
  ON certificate_generations(domain, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_generations_current
  ON certificate_generations(domain) WHERE current = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_generations_domain_revision
  ON certificate_generations(domain, revision);

-- ── 3. 重建 deployment_reports ───────────────────────────────────────────────
-- 将 generation_id 外键从 ON DELETE CASCADE 改为 ON DELETE RESTRICT

CREATE TABLE deployment_reports_new (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  generation_id   INTEGER NOT NULL REFERENCES certificate_generations(id) ON DELETE RESTRICT,
  target          TEXT    NOT NULL,
  status          TEXT    NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
  detail          TEXT,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  completed_at    INTEGER,
  generation_ref  TEXT,
  revision        INTEGER NOT NULL DEFAULT 0,
  manifest_digest TEXT,
  UNIQUE(generation_id, target)
);

INSERT INTO deployment_reports_new
  SELECT id, generation_id, target, status, detail, created_at, updated_at,
         completed_at, generation_ref, revision, manifest_digest
  FROM deployment_reports;

DROP TABLE deployment_reports;
ALTER TABLE deployment_reports_new RENAME TO deployment_reports;

-- 重建 deployment_reports 的全部索引
CREATE INDEX IF NOT EXISTS idx_deployment_reports_generation
  ON deployment_reports(generation_id, status);
