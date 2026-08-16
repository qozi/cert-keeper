-- 添加 "publishing" 中间状态：文件发布意图已记录但 SQLite 尚未 finalize。
-- 用于崩溃恢复：若服务在文件发布后、SQLite 更新前崩溃，重启时可通过此状态检测并补全。
-- SQLite 不支持原地修改 CHECK 约束，须重建表。

CREATE TABLE certificate_generations_new (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id          TEXT    NOT NULL REFERENCES certificate_jobs(id) ON DELETE RESTRICT,
  domain          TEXT    NOT NULL REFERENCES certs(domain) ON DELETE RESTRICT,
  generation      INTEGER NOT NULL,
  status          TEXT    NOT NULL CHECK (status IN ('pending', 'publishing', 'issued', 'failed', 'revoked')),
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

-- 重建全部索引
CREATE INDEX IF NOT EXISTS idx_certificate_generations_domain_created
  ON certificate_generations(domain, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_generations_current
  ON certificate_generations(domain) WHERE current = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_generations_domain_revision
  ON certificate_generations(domain, revision);
