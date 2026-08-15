-- v2 生产存储：任务租约、重试、版本产物和密钥元数据。

ALTER TABLE certs ADD COLUMN dns_profile TEXT;

CREATE TRIGGER IF NOT EXISTS trg_certs_dns_profile_insert
BEFORE INSERT ON certs
WHEN NEW.dns_profile IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM dns_profiles
  WHERE provider = NEW.dns_provider AND profile = NEW.dns_profile
)
BEGIN
  SELECT RAISE(ABORT, 'referenced DNS profile does not exist');
END;

CREATE TRIGGER IF NOT EXISTS trg_certs_dns_profile_update
BEFORE UPDATE OF dns_provider, dns_profile ON certs
WHEN NEW.dns_profile IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM dns_profiles
  WHERE provider = NEW.dns_provider AND profile = NEW.dns_profile
)
BEGIN
  SELECT RAISE(ABORT, 'referenced DNS profile does not exist');
END;

CREATE TRIGGER IF NOT EXISTS trg_dns_profile_delete_restrict
BEFORE DELETE ON dns_profiles
WHEN EXISTS (
  SELECT 1 FROM certs
  WHERE dns_provider = OLD.provider AND dns_profile = OLD.profile
)
BEGIN
  SELECT RAISE(ABORT, 'DNS profile is referenced by certificate config');
END;

ALTER TABLE certificate_jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE certificate_jobs ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3;
ALTER TABLE certificate_jobs ADD COLUMN next_attempt_at INTEGER;
ALTER TABLE certificate_jobs ADD COLUMN lease_owner TEXT;
ALTER TABLE certificate_jobs ADD COLUMN lease_until INTEGER;
ALTER TABLE certificate_jobs ADD COLUMN last_error_code TEXT;
ALTER TABLE certificate_jobs ADD COLUMN last_error_at INTEGER;

-- 旧版本只限制活动态幂等键。保留最后一条记录的原键，并为更早记录追加
-- 不冲突的历史后缀，从而保留所有任务、generation 和审计关联。
UPDATE certificate_jobs
SET idempotency_key = idempotency_key || '#legacy:' || id
WHERE rowid NOT IN (
  SELECT MAX(rowid)
  FROM certificate_jobs
  GROUP BY domain, operation, idempotency_key
);

DROP INDEX IF EXISTS idx_certificate_jobs_active_idempotency;
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_jobs_idempotency
  ON certificate_jobs(domain, operation, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_certificate_jobs_recoverable
  ON certificate_jobs(status, next_attempt_at, lease_until, created_at);

ALTER TABLE certificate_generations ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE certificate_generations ADD COLUMN manifest_digest TEXT;
ALTER TABLE certificate_generations ADD COLUMN serial TEXT;
ALTER TABLE certificate_generations ADD COLUMN fingerprint TEXT;
ALTER TABLE certificate_generations ADD COLUMN current INTEGER NOT NULL DEFAULT 0;

UPDATE certificate_generations SET revision = generation WHERE revision = 1 AND generation > 1;
UPDATE certificate_generations
SET current = 1
WHERE id IN (
  SELECT id FROM certificate_generations issued
  WHERE issued.status = 'issued'
    AND issued.generation = (
      SELECT MAX(newer.generation)
      FROM certificate_generations newer
      WHERE newer.domain = issued.domain AND newer.status = 'issued'
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_generations_current
  ON certificate_generations(domain) WHERE current = 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_certificate_generations_domain_revision
  ON certificate_generations(domain, revision);

ALTER TABLE deployment_reports ADD COLUMN generation_ref TEXT;
ALTER TABLE deployment_reports ADD COLUMN revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE deployment_reports ADD COLUMN manifest_digest TEXT;

UPDATE deployment_reports
SET generation_ref = (
      SELECT certificate_ref FROM certificate_generations
      WHERE certificate_generations.id = deployment_reports.generation_id
    ),
    revision = (
      SELECT revision FROM certificate_generations
      WHERE certificate_generations.id = deployment_reports.generation_id
    ),
    manifest_digest = (
      SELECT manifest_digest FROM certificate_generations
      WHERE certificate_generations.id = deployment_reports.generation_id
    );

CREATE TABLE IF NOT EXISTS encryption_metadata (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  key_source  TEXT NOT NULL,
  key_version INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
