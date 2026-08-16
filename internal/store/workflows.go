// 本文件提供证书任务、代次、部署报告和审计事件的最小存储接口。
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const defaultMaxAttempts = 3

// CertificateJob 表示证书申请、续期或部署等异步任务。
type CertificateJob struct {
	ID             string         `json:"id"`
	Domain         string         `json:"domain"`
	Operation      string         `json:"operation"`
	IdempotencyKey string         `json:"idempotency_key"`
	Status         string         `json:"status"`
	Attempts       int            `json:"attempts"`
	MaxAttempts    int            `json:"max_attempts"`
	NextAttemptAt  sql.NullInt64  `json:"next_attempt_at"`
	LeaseOwner     string         `json:"lease_owner,omitempty"`
	LeaseUntil     sql.NullInt64  `json:"lease_until"`
	LastErrorCode  JSONNullString `json:"last_error_code"`
	LastErrorAt    sql.NullInt64  `json:"last_error_at"`
	RequestedBy    JSONNullString `json:"requested_by"`
	ErrorMessage   JSONNullString `json:"error_message"`
	CreatedAt      int64          `json:"created_at"`
	UpdatedAt      int64          `json:"updated_at"`
	StartedAt      sql.NullInt64  `json:"started_at"`
	FinishedAt     sql.NullInt64  `json:"finished_at"`
}

// CertificateGeneration 表示一次证书产物代次，引用由上层证书库解释。
type CertificateGeneration struct {
	ID             int64          `json:"id"`
	JobID          string         `json:"job_id"`
	Domain         string         `json:"domain"`
	Generation     int            `json:"generation"`
	Revision       int64          `json:"revision"`
	Status         string         `json:"status"`
	CertificateRef JSONNullString `json:"certificate_ref"`
	PrivateKeyRef  JSONNullString `json:"private_key_ref"`
	ManifestDigest JSONNullString `json:"manifest_digest"`
	Serial         JSONNullString `json:"serial"`
	Fingerprint    JSONNullString `json:"fingerprint"`
	Current        bool           `json:"current"`
	NotBefore      sql.NullInt64  `json:"not_before"`
	NotAfter       sql.NullInt64  `json:"not_after"`
	ErrorMessage   JSONNullString `json:"error_message"`
	CreatedAt      int64          `json:"created_at"`
	UpdatedAt      int64          `json:"updated_at"`
}

// GenerationArtifact 描述已发布代次的不可变产物元数据。
type GenerationArtifact struct {
	Revision       int64
	ManifestDigest string
	Serial         string
	Fingerprint    string
	Current        bool
}

// DeploymentReport 表示一个代次发往某个部署目标的结果。
type DeploymentReport struct {
	ID             int64          `json:"id"`
	GenerationID   int64          `json:"generation_id"`
	Generation     string         `json:"generation,omitempty"`
	Revision       int64          `json:"revision"`
	ManifestDigest JSONNullString `json:"manifest_digest"`
	Target         string         `json:"target"`
	Status         string         `json:"status"`
	Detail         JSONNullString `json:"detail"`
	CreatedAt      int64          `json:"created_at"`
	UpdatedAt      int64          `json:"updated_at"`
	CompletedAt    sql.NullInt64  `json:"completed_at"`
}

// AuditEvent 表示不可变的安全或业务审计记录。
type AuditEvent struct {
	ID           int64          `json:"id"`
	ActorTokenID JSONNullString `json:"actor_token_id"`
	Domain       JSONNullString `json:"domain"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome"`
	Detail       JSONNullString `json:"detail"`
	CreatedAt    int64          `json:"created_at"`
}

// JobFilter 定义证书任务的查询条件。
type JobFilter struct {
	Domain string
	Status string
	Limit  int
	Offset int
}

// AuditFilter 定义审计事件的查询条件。
type AuditFilter struct {
	ActorTokenID string
	Domain       string
	Action       string
	Limit        int
	Offset       int
}

// CreateCertificateJob 创建任务；活动任务的幂等键冲突时返回既有任务。
func (s *Store) CreateCertificateJob(ctx context.Context, job *CertificateJob) (*CertificateJob, error) {
	if job == nil {
		return nil, errors.New("证书任务不能为空")
	}
	if err := validateCertificateDomain(job.Domain); err != nil {
		return nil, err
	}
	if strings.TrimSpace(job.Operation) == "" || strings.TrimSpace(job.IdempotencyKey) == "" {
		return nil, errors.New("任务 operation 和 idempotency_key 不能为空")
	}
	if job.ID == "" {
		id, err := newStoreID()
		if err != nil {
			return nil, err
		}
		job.ID = id
	}
	if job.Status == "" {
		job.Status = "queued"
	}
	if !validJobStatus(job.Status) {
		return nil, errors.New("无效的任务状态")
	}
	if job.MaxAttempts == 0 {
		job.MaxAttempts = defaultMaxAttempts
	}
	if job.MaxAttempts < 1 || job.Attempts < 0 || job.Attempts > job.MaxAttempts {
		return nil, errors.New("任务 attempts/max_attempts 范围无效")
	}
	now := time.Now().Unix()
	if job.CreatedAt == 0 {
		job.CreatedAt = now
	}
	job.UpdatedAt = now

	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO certificate_jobs(id, domain, operation, idempotency_key, status, attempts, max_attempts,
			next_attempt_at, lease_owner, lease_until, last_error_code, last_error_at, requested_by,
			error_message, created_at, updated_at, started_at, finished_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.Domain, job.Operation, job.IdempotencyKey, job.Status, job.Attempts, job.MaxAttempts,
		nullableInt64Value(job.NextAttemptAt), nullString(job.LeaseOwner), nullableInt64Value(job.LeaseUntil),
		job.LastErrorCode, nullableInt64Value(job.LastErrorAt), job.RequestedBy, job.ErrorMessage,
		job.CreatedAt, job.UpdatedAt, job.StartedAt, job.FinishedAt)
	if err == nil {
		return job, nil
	}
	if !isUniqueConstraint(err) {
		return nil, err
	}
	existing, getErr := s.GetByIdempotency(ctx, job.Domain, job.Operation, job.IdempotencyKey)
	if getErr != nil {
		return nil, getErr
	}
	if existing != nil {
		return existing, nil
	}
	return nil, err
}

// CreateJob 是 CreateCertificateJob 的简短别名。
func (s *Store) CreateJob(ctx context.Context, job *CertificateJob) (*CertificateJob, error) {
	return s.CreateCertificateJob(ctx, job)
}

// GetCertificateJob 按 ID 获取任务，不存在时返回 nil。
func (s *Store) GetCertificateJob(ctx context.Context, id string) (*CertificateJob, error) {
	return scanCertificateJob(s.DB.QueryRowContext(ctx, certificateJobSelect+` WHERE id=?`, id))
}

// GetJob 是 GetCertificateJob 的简短别名。
func (s *Store) GetJob(ctx context.Context, id string) (*CertificateJob, error) {
	return s.GetCertificateJob(ctx, id)
}

func (s *Store) getActiveCertificateJob(ctx context.Context, domain, operation, idempotencyKey string) (*CertificateJob, error) {
	return scanCertificateJob(s.DB.QueryRowContext(ctx, certificateJobSelect+` WHERE domain=? AND operation=? AND idempotency_key=? AND status IN ('queued', 'running')`,
		domain, operation, idempotencyKey))
}

// GetByIdempotency 按域名、操作和幂等键查询全部生命周期的任务。
func (s *Store) GetByIdempotency(ctx context.Context, domain, operation, idempotencyKey string) (*CertificateJob, error) {
	return scanCertificateJob(s.DB.QueryRowContext(ctx, certificateJobSelect+`
		WHERE domain=? AND operation=? AND idempotency_key=?
		ORDER BY created_at ASC, id ASC LIMIT 1`, domain, operation, idempotencyKey))
}

const certificateJobSelect = `
	SELECT id, domain, operation, idempotency_key, status, attempts, max_attempts,
		next_attempt_at, COALESCE(lease_owner, ''), lease_until, last_error_code, last_error_at,
		requested_by, error_message, created_at, updated_at, started_at, finished_at
	FROM certificate_jobs`

func scanCertificateJob(row *sql.Row) (*CertificateJob, error) {
	var job CertificateJob
	err := row.Scan(&job.ID, &job.Domain, &job.Operation, &job.IdempotencyKey, &job.Status, &job.Attempts, &job.MaxAttempts,
		&job.NextAttemptAt, &job.LeaseOwner, &job.LeaseUntil, &job.LastErrorCode, &job.LastErrorAt,
		&job.RequestedBy, &job.ErrorMessage, &job.CreatedAt, &job.UpdatedAt, &job.StartedAt, &job.FinishedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &job, nil
}

// ListCertificateJobs 按时间倒序列出任务。
func (s *Store) ListCertificateJobs(ctx context.Context, filter JobFilter) ([]CertificateJob, error) {
	q := certificateJobSelect + ` WHERE 1=1`
	args := []any{}
	if filter.Domain != "" {
		q += ` AND domain=?`
		args = append(args, filter.Domain)
	}
	if filter.Status != "" {
		q += ` AND status=?`
		args = append(args, filter.Status)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, boundedLimit(filter.Limit), nonNegative(filter.Offset))
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []CertificateJob
	for rows.Next() {
		var job CertificateJob
		if err := rows.Scan(&job.ID, &job.Domain, &job.Operation, &job.IdempotencyKey, &job.Status, &job.Attempts, &job.MaxAttempts,
			&job.NextAttemptAt, &job.LeaseOwner, &job.LeaseUntil, &job.LastErrorCode, &job.LastErrorAt,
			&job.RequestedBy, &job.ErrorMessage, &job.CreatedAt, &job.UpdatedAt, &job.StartedAt, &job.FinishedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// ListJobs 是 ListCertificateJobs 的简短别名。
func (s *Store) ListJobs(ctx context.Context, filter JobFilter) ([]CertificateJob, error) {
	return s.ListCertificateJobs(ctx, filter)
}

// Claim 原子领取一个已到执行时间的任务，也允许接管租约已过期的运行中任务。
func (s *Store) Claim(ctx context.Context, owner string, leaseDuration time.Duration) (*CertificateJob, error) {
	if strings.TrimSpace(owner) == "" || leaseDuration <= 0 {
		return nil, errors.New("任务 owner 和 lease duration 必须有效")
	}
	now := time.Now().Unix()
	leaseUntil := now + durationSeconds(leaseDuration)
	if _, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_jobs SET status='failed', lease_owner=NULL, lease_until=NULL,
			last_error_code='attempts_exhausted', last_error_at=?,
			error_message='任务达到最大尝试次数', finished_at=?, updated_at=?
		WHERE status='running' AND attempts>=max_attempts AND (lease_until IS NULL OR lease_until<=?)`,
		now, now, now, now); err != nil {
		return nil, err
	}
	return scanCertificateJob(s.DB.QueryRowContext(ctx, `
		UPDATE certificate_jobs
		SET status='running', attempts=attempts+1, lease_owner=?, lease_until=?,
			next_attempt_at=NULL, started_at=COALESCE(started_at, ?), updated_at=?
		WHERE id=(
			SELECT id FROM certificate_jobs
			WHERE attempts < max_attempts AND (
				(status='queued' AND (next_attempt_at IS NULL OR next_attempt_at<=?)) OR
				(status='running' AND (lease_until IS NULL OR lease_until<=?))
			)
			ORDER BY COALESCE(next_attempt_at, created_at), created_at, id LIMIT 1
		)
		RETURNING id, domain, operation, idempotency_key, status, attempts, max_attempts,
			next_attempt_at, COALESCE(lease_owner, ''), lease_until, last_error_code, last_error_at,
			requested_by, error_message, created_at, updated_at, started_at, finished_at`,
		owner, leaseUntil, now, now, now, now))
}

// ClaimJob 是 Claim 的任务命名别名。
func (s *Store) ClaimJob(ctx context.Context, owner string, leaseDuration time.Duration) (*CertificateJob, error) {
	return s.Claim(ctx, owner, leaseDuration)
}

// RenewLease 仅允许当前且未过期的 owner 续租运行中任务。
func (s *Store) RenewLease(ctx context.Context, id, owner string, leaseDuration time.Duration) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(owner) == "" || leaseDuration <= 0 {
		return errors.New("任务 ID、owner 和 lease duration 必须有效")
	}
	now := time.Now().Unix()
	result, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_jobs SET lease_until=?, updated_at=?
		WHERE id=? AND status='running' AND lease_owner=? AND lease_until>?`,
		now+durationSeconds(leaseDuration), now, id, owner, now)
	return requireAffected(result, err)
}

// RenewJobLease 是 RenewLease 的任务命名别名。
func (s *Store) RenewJobLease(ctx context.Context, id, owner string, leaseDuration time.Duration) error {
	return s.RenewLease(ctx, id, owner, leaseDuration)
}

// ReleaseLease 释放当前 owner 的租约，并将任务重新排队供后续领取。
func (s *Store) ReleaseLease(ctx context.Context, id, owner string) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(owner) == "" {
		return errors.New("任务 ID 和 owner 不能为空")
	}
	now := time.Now().Unix()
	result, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_jobs SET
			status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
			lease_owner=NULL, lease_until=NULL,
			next_attempt_at=CASE WHEN attempts>=max_attempts THEN NULL ELSE ? END,
			last_error_code=CASE WHEN attempts>=max_attempts THEN 'attempts_exhausted' ELSE last_error_code END,
			last_error_at=CASE WHEN attempts>=max_attempts THEN ? ELSE last_error_at END,
			finished_at=CASE WHEN attempts>=max_attempts THEN ? ELSE NULL END, updated_at=?
		WHERE id=? AND status='running' AND lease_owner=? AND lease_until>?`, now, now, now, now, id, owner, now)
	return requireAffected(result, err)
}

// ReleaseJobLease 是 ReleaseLease 的任务命名别名。
func (s *Store) ReleaseJobLease(ctx context.Context, id, owner string) error {
	return s.ReleaseLease(ctx, id, owner)
}

// ListRecoverable 列出可领取的排队任务及租约已过期的运行中任务。
func (s *Store) ListRecoverable(ctx context.Context, now time.Time, limit int) ([]CertificateJob, error) {
	rows, err := s.DB.QueryContext(ctx, certificateJobSelect+`
		WHERE attempts < max_attempts AND (
			(status='queued' AND (next_attempt_at IS NULL OR next_attempt_at<=?)) OR
			(status='running' AND (lease_until IS NULL OR lease_until<=?))
		)
		ORDER BY COALESCE(next_attempt_at, created_at), created_at, id LIMIT ?`,
		now.Unix(), now.Unix(), boundedLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanCertificateJobs(rows)
}

// ListRecoverableJobs 是 ListRecoverable 的任务命名别名。
func (s *Store) ListRecoverableJobs(ctx context.Context, now time.Time, limit int) ([]CertificateJob, error) {
	return s.ListRecoverable(ctx, now, limit)
}

// Retry 记录当前尝试的错误并按 backoff 重新排队；达到上限时转为 failed 终态。
func (s *Store) Retry(ctx context.Context, id, owner, errorCode, errorMessage string, backoff time.Duration) error {
	if backoff < 0 {
		return errors.New("任务 backoff 不能为负数")
	}
	now := time.Now()
	return s.retryAt(ctx, id, owner, errorCode, errorMessage, now.Add(backoff), now)
}

// RetryAt 与 Retry 相同，但由调用方提供下次执行时间，便于调度恢复。
func (s *Store) RetryAt(ctx context.Context, id, owner, errorCode, errorMessage string, nextAttemptAt time.Time) error {
	return s.retryAt(ctx, id, owner, errorCode, errorMessage, nextAttemptAt, time.Now())
}

func (s *Store) retryAt(ctx context.Context, id, owner, errorCode, errorMessage string, nextAttemptAt, now time.Time) error {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(owner) == "" || nextAttemptAt.Unix() < now.Unix() {
		return errors.New("任务 ID、owner 和 next attempt 必须有效")
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_jobs SET
			status=CASE WHEN attempts>=max_attempts THEN 'failed' ELSE 'queued' END,
			next_attempt_at=CASE WHEN attempts>=max_attempts THEN NULL ELSE ? END,
			lease_owner=NULL, lease_until=NULL, last_error_code=?, last_error_at=?,
			error_message=?, finished_at=CASE WHEN attempts>=max_attempts THEN ? ELSE NULL END,
			updated_at=?
		WHERE id=? AND status='running' AND lease_owner=? AND lease_until>?`,
		nextAttemptAt.Unix(), nullString(errorCode), now.Unix(), nullString(errorMessage),
		now.Unix(), now.Unix(), id, owner, now.Unix())
	return requireAffected(result, err)
}

// UpdateCertificateJobStatus 更新任务状态并维护开始/结束时间。
func (s *Store) UpdateCertificateJobStatus(ctx context.Context, id, status, errorMessage string) error {
	if !validJobStatus(status) {
		return errors.New("无效的任务状态")
	}
	now := time.Now().Unix()
	start := any(nil)
	finish := any(nil)
	if status == "running" {
		start = now
	}
	if status == "succeeded" || status == "failed" || status == "cancelled" {
		finish = now
	}
	terminal := isTerminalJobStatus(status)
	result, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_jobs SET status=?, error_message=?, updated_at=?,
			started_at=COALESCE(started_at, ?), finished_at=?,
			lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END,
			lease_until=CASE WHEN ? THEN NULL ELSE lease_until END,
			next_attempt_at=CASE WHEN ? THEN NULL ELSE next_attempt_at END WHERE id=?`,
		status, nullString(errorMessage), now, start, finish, terminal, terminal, terminal, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateJobStatus 是 UpdateCertificateJobStatus 的简短别名。
func (s *Store) UpdateJobStatus(ctx context.Context, id, status, errorMessage string) error {
	return s.UpdateCertificateJobStatus(ctx, id, status, errorMessage)
}

// DeleteCertificateJob 删除任务及其关联的代次和部署报告。
func (s *Store) DeleteCertificateJob(ctx context.Context, id string) error {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM certificate_jobs WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteJob 是 DeleteCertificateJob 的简短别名。
func (s *Store) DeleteJob(ctx context.Context, id string) error {
	return s.DeleteCertificateJob(ctx, id)
}

// CreateCertificateGeneration 创建一个证书代次；未指定 generation 时自动递增。
func (s *Store) CreateCertificateGeneration(ctx context.Context, generation *CertificateGeneration) (*CertificateGeneration, error) {
	if generation == nil {
		return nil, errors.New("证书代次不能为空")
	}
	if generation.JobID == "" || generation.Domain == "" {
		return nil, errors.New("证书代次 job_id 和 domain 不能为空")
	}
	if err := validateCertificateDomain(generation.Domain); err != nil {
		return nil, err
	}
	if generation.Status == "" {
		generation.Status = "pending"
	}
	if !validGenerationStatus(generation.Status) {
		return nil, errors.New("无效的证书代次状态")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if generation.Generation == 0 {
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(generation), 0)+1 FROM certificate_generations WHERE domain=?`, generation.Domain).Scan(&generation.Generation); err != nil {
			return nil, err
		}
	}
	if generation.Revision == 0 {
		generation.Revision = int64(generation.Generation)
	}
	if generation.Revision < 1 {
		return nil, errors.New("证书 revision 必须大于 0")
	}
	now := time.Now().Unix()
	if generation.CreatedAt == 0 {
		generation.CreatedAt = now
	}
	generation.UpdatedAt = now
	var jobDomain string
	if err := tx.QueryRowContext(ctx, `SELECT domain FROM certificate_jobs WHERE id=?`, generation.JobID).Scan(&jobDomain); err != nil {
		return nil, err
	}
	if jobDomain != generation.Domain {
		return nil, errors.New("证书代次与任务域名不一致")
	}
	if generation.Current {
		if generation.Status != "issued" {
			return nil, errors.New("只有 issued 代次可标记为 current")
		}
		if _, err := tx.ExecContext(ctx, `UPDATE certificate_generations SET current=0, updated_at=? WHERE domain=? AND current=1`, now, generation.Domain); err != nil {
			return nil, err
		}
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO certificate_generations(job_id, domain, generation, revision, status, certificate_ref,
			private_key_ref, manifest_digest, serial, fingerprint, current, not_before, not_after,
			error_message, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		generation.JobID, generation.Domain, generation.Generation, generation.Revision, generation.Status,
		generation.CertificateRef, generation.PrivateKeyRef, generation.ManifestDigest, generation.Serial,
		generation.Fingerprint, boolToInt(generation.Current), generation.NotBefore, generation.NotAfter,
		generation.ErrorMessage, generation.CreatedAt, generation.UpdatedAt)
	if err != nil {
		return nil, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}
	generation.ID = id
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return generation, nil
}

// GetCertificateGeneration 按 ID 获取代次，不存在时返回 nil。
func (s *Store) GetCertificateGeneration(ctx context.Context, id int64) (*CertificateGeneration, error) {
	generation, err := scanCertificateGeneration(s.DB.QueryRowContext(ctx, certificateGenerationSelect+` WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return generation, nil
}

const certificateGenerationSelect = `
	SELECT id, job_id, domain, generation, revision, status, certificate_ref, private_key_ref,
		manifest_digest, serial, fingerprint, current, not_before, not_after, error_message,
		created_at, updated_at
	FROM certificate_generations`

func scanCertificateGeneration(row *sql.Row) (*CertificateGeneration, error) {
	var generation CertificateGeneration
	var current int
	err := row.Scan(&generation.ID, &generation.JobID, &generation.Domain, &generation.Generation,
		&generation.Revision, &generation.Status, &generation.CertificateRef, &generation.PrivateKeyRef,
		&generation.ManifestDigest, &generation.Serial, &generation.Fingerprint, &current,
		&generation.NotBefore, &generation.NotAfter, &generation.ErrorMessage,
		&generation.CreatedAt, &generation.UpdatedAt)
	if err != nil {
		return nil, err
	}
	generation.Current = current == 1
	return &generation, nil
}

// ListCertificateGenerations 按域名列出证书代次。
func (s *Store) ListCertificateGenerations(ctx context.Context, domain string) ([]CertificateGeneration, error) {
	rows, err := s.DB.QueryContext(ctx, certificateGenerationSelect+` WHERE domain=? ORDER BY generation DESC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var generations []CertificateGeneration
	for rows.Next() {
		var generation CertificateGeneration
		var current int
		if err := rows.Scan(&generation.ID, &generation.JobID, &generation.Domain, &generation.Generation,
			&generation.Revision, &generation.Status, &generation.CertificateRef, &generation.PrivateKeyRef,
			&generation.ManifestDigest, &generation.Serial, &generation.Fingerprint, &current,
			&generation.NotBefore, &generation.NotAfter, &generation.ErrorMessage,
			&generation.CreatedAt, &generation.UpdatedAt); err != nil {
			return nil, err
		}
		generation.Current = current == 1
		generations = append(generations, generation)
	}
	return generations, rows.Err()
}

// UpdateCertificateGenerationStatus 更新代次状态和引用。
func (s *Store) UpdateCertificateGenerationStatus(ctx context.Context, id int64, status string, certificateRef, privateKeyRef, errorMessage string, notBefore, notAfter *int64) error {
	if !validGenerationStatus(status) {
		return errors.New("无效的证书代次状态")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var domain string
	if err := tx.QueryRowContext(ctx, `SELECT domain FROM certificate_generations WHERE id=?`, id).Scan(&domain); err != nil {
		return err
	}
	now := time.Now().Unix()
	current := status == "issued" && certificateRef != ""
	if current {
		if _, err := tx.ExecContext(ctx, `UPDATE certificate_generations SET current=0, updated_at=? WHERE domain=? AND id<>? AND current=1`, now, domain, id); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE certificate_generations SET status=?, certificate_ref=?, private_key_ref=?, error_message=?,
			not_before=?, not_after=?, current=?, updated_at=? WHERE id=?`,
		status, nullString(certificateRef), nullString(privateKeyRef), nullString(errorMessage),
		nullableInt64(notBefore), nullableInt64(notAfter), boolToInt(current), now, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// UpdateCertificateGenerationArtifact 保存 revision 和摘要元数据，并可原子切换 current。
func (s *Store) UpdateCertificateGenerationArtifact(ctx context.Context, id int64, artifact GenerationArtifact) error {
	if artifact.Revision < 1 || !validSHA256Digest(artifact.ManifestDigest) || !validSHA256Digest(artifact.Fingerprint) {
		return errors.New("证书 revision、manifest digest 或 fingerprint 无效")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var domain, status string
	if err := tx.QueryRowContext(ctx, `SELECT domain, status FROM certificate_generations WHERE id=?`, id).Scan(&domain, &status); err != nil {
		return err
	}
	if artifact.Current && status != "issued" {
		return errors.New("只有 issued 代次可标记为 current")
	}
	now := time.Now().Unix()
	if artifact.Current {
		if _, err := tx.ExecContext(ctx, `UPDATE certificate_generations SET current=0, updated_at=? WHERE domain=? AND id<>? AND current=1`, now, domain, id); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE certificate_generations SET revision=?, manifest_digest=?, serial=?, fingerprint=?, current=?, updated_at=?
		WHERE id=?`, artifact.Revision, artifact.ManifestDigest, nullString(artifact.Serial), artifact.Fingerprint,
		boolToInt(artifact.Current), now, id)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// GetCurrentCertificateGeneration 返回域名当前代次。
func (s *Store) GetCurrentCertificateGeneration(ctx context.Context, domain string) (*CertificateGeneration, error) {
	generation, err := scanCertificateGeneration(s.DB.QueryRowContext(ctx, certificateGenerationSelect+` WHERE domain=? AND current=1`, domain))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return generation, err
}

// DeleteCertificateGeneration 删除指定证书代次及其部署报告。
func (s *Store) DeleteCertificateGeneration(ctx context.Context, id int64) error {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM certificate_generations WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// CreateDeploymentReport 创建或覆盖一个目标的部署报告。
func (s *Store) CreateDeploymentReport(ctx context.Context, report *DeploymentReport) (*DeploymentReport, error) {
	if report == nil || report.GenerationID <= 0 || strings.TrimSpace(report.Target) == "" {
		return nil, errors.New("部署报告 generation_id 和 target 不能为空")
	}
	if report.Status == "" {
		report.Status = "pending"
	}
	if !validDeploymentStatus(report.Status) {
		return nil, errors.New("无效的部署状态")
	}
	generation, err := s.GetCertificateGeneration(ctx, report.GenerationID)
	if err != nil {
		return nil, err
	}
	if generation == nil {
		return nil, sql.ErrNoRows
	}
	storedGeneration := ""
	if generation.CertificateRef.Valid {
		storedGeneration = generation.CertificateRef.String
	}
	if report.Generation != "" && report.Generation != storedGeneration {
		return nil, errors.New("部署报告 generation 与证书代次不一致")
	}
	if report.Revision != 0 && report.Revision != generation.Revision {
		return nil, errors.New("部署报告 revision 与证书代次不一致")
	}
	if report.ManifestDigest.Valid && (!generation.ManifestDigest.Valid || report.ManifestDigest.String != generation.ManifestDigest.String) {
		return nil, errors.New("部署报告 manifest digest 与证书代次不一致")
	}
	report.Generation = storedGeneration
	report.Revision = generation.Revision
	report.ManifestDigest = generation.ManifestDigest
	now := time.Now().Unix()
	if report.CreatedAt == 0 {
		report.CreatedAt = now
	}
	report.UpdatedAt = now
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO deployment_reports(generation_id, generation_ref, revision, manifest_digest,
			target, status, detail, created_at, updated_at, completed_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(generation_id, target) DO UPDATE SET
			generation_ref=excluded.generation_ref, revision=excluded.revision,
			manifest_digest=excluded.manifest_digest, status=excluded.status,
			detail=excluded.detail, updated_at=excluded.updated_at, completed_at=excluded.completed_at`,
		report.GenerationID, nullString(report.Generation), report.Revision, report.ManifestDigest,
		report.Target, report.Status, report.Detail, report.CreatedAt, report.UpdatedAt, report.CompletedAt)
	if err != nil {
		return nil, err
	}
	if report.ID == 0 {
		report.ID, _ = result.LastInsertId()
		if report.ID == 0 {
			_ = s.DB.QueryRowContext(ctx, `SELECT id FROM deployment_reports WHERE generation_id=? AND target=?`, report.GenerationID, report.Target).Scan(&report.ID)
		}
	}
	return report, nil
}

// UpdateDeploymentReportStatus 更新部署目标状态。
func (s *Store) UpdateDeploymentReportStatus(ctx context.Context, id int64, status, detail string) error {
	if !validDeploymentStatus(status) {
		return errors.New("无效的部署状态")
	}
	now := time.Now().Unix()
	completed := any(nil)
	if status == "succeeded" || status == "failed" {
		completed = now
	}
	result, err := s.DB.ExecContext(ctx,
		`UPDATE deployment_reports SET status=?, detail=?, updated_at=?, completed_at=? WHERE id=?`,
		status, nullString(detail), now, completed, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetDeploymentReport 按 ID 获取部署报告，不存在时返回 nil。
func (s *Store) GetDeploymentReport(ctx context.Context, id int64) (*DeploymentReport, error) {
	var report DeploymentReport
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, generation_id, COALESCE(generation_ref, ''), revision, manifest_digest,
			target, status, detail, created_at, updated_at, completed_at
		FROM deployment_reports WHERE id=?`, id).
		Scan(&report.ID, &report.GenerationID, &report.Generation, &report.Revision, &report.ManifestDigest,
			&report.Target, &report.Status, &report.Detail, &report.CreatedAt, &report.UpdatedAt, &report.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &report, nil
}

// DeleteDeploymentReport 删除部署报告。
func (s *Store) DeleteDeploymentReport(ctx context.Context, id int64) error {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM deployment_reports WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ListDeploymentReports 列出一个证书代次的部署报告。
func (s *Store) ListDeploymentReports(ctx context.Context, generationID int64) ([]DeploymentReport, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, generation_id, COALESCE(generation_ref, ''), revision, manifest_digest,
			target, status, detail, created_at, updated_at, completed_at
		FROM deployment_reports WHERE generation_id=? ORDER BY target`, generationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []DeploymentReport
	for rows.Next() {
		var report DeploymentReport
		if err := rows.Scan(&report.ID, &report.GenerationID, &report.Generation, &report.Revision, &report.ManifestDigest,
			&report.Target, &report.Status, &report.Detail, &report.CreatedAt, &report.UpdatedAt, &report.CompletedAt); err != nil {
			return nil, err
		}
		reports = append(reports, report)
	}
	return reports, rows.Err()
}

// AddAuditEvent 追加审计事件。调用方不得传入任何 Token 或 DNS 明文机密。
func (s *Store) AddAuditEvent(ctx context.Context, event *AuditEvent) error {
	if event == nil || strings.TrimSpace(event.Action) == "" || strings.TrimSpace(event.Outcome) == "" {
		return errors.New("审计事件 action 和 outcome 不能为空")
	}
	if event.Domain.Valid {
		if err := validateCertificateDomain(event.Domain.String); err != nil {
			return err
		}
	}
	if event.CreatedAt == 0 {
		event.CreatedAt = time.Now().Unix()
	}
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO audit_events(actor_token_id, domain, action, outcome, detail, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		event.ActorTokenID, event.Domain, event.Action, event.Outcome, event.Detail, event.CreatedAt)
	if err != nil {
		return err
	}
	event.ID, _ = result.LastInsertId()
	return nil
}

// ListAuditEvents 按时间倒序列出审计事件。
func (s *Store) ListAuditEvents(ctx context.Context, filter AuditFilter) ([]AuditEvent, error) {
	q := `SELECT id, actor_token_id, domain, action, outcome, detail, created_at FROM audit_events WHERE 1=1`
	args := []any{}
	if filter.ActorTokenID != "" {
		q += ` AND actor_token_id=?`
		args = append(args, filter.ActorTokenID)
	}
	if filter.Domain != "" {
		q += ` AND domain=?`
		args = append(args, filter.Domain)
	}
	if filter.Action != "" {
		q += ` AND action=?`
		args = append(args, filter.Action)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, boundedLimit(filter.Limit), nonNegative(filter.Offset))
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []AuditEvent
	for rows.Next() {
		var event AuditEvent
		if err := rows.Scan(&event.ID, &event.ActorTokenID, &event.Domain, &event.Action, &event.Outcome, &event.Detail, &event.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// GetAuditEvent 按 ID 获取审计事件，不存在时返回 nil。
func (s *Store) GetAuditEvent(ctx context.Context, id int64) (*AuditEvent, error) {
	var event AuditEvent
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, actor_token_id, domain, action, outcome, detail, created_at FROM audit_events WHERE id=?`, id).
		Scan(&event.ID, &event.ActorTokenID, &event.Domain, &event.Action, &event.Outcome, &event.Detail, &event.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &event, nil
}

// DeleteAuditEvent 删除审计事件，供已授权的保留策略执行。
func (s *Store) DeleteAuditEvent(ctx context.Context, id int64) error {
	result, err := s.DB.ExecContext(ctx, `DELETE FROM audit_events WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func validJobStatus(status string) bool {
	switch status {
	case "queued", "running", "succeeded", "failed", "cancelled":
		return true
	default:
		return false
	}
}

func isTerminalJobStatus(status string) bool {
	return status == "succeeded" || status == "failed" || status == "cancelled"
}

func validGenerationStatus(status string) bool {
	switch status {
	case "pending", "publishing", "issued", "failed", "revoked":
		return true
	default:
		return false
	}
}

func validDeploymentStatus(status string) bool {
	switch status {
	case "pending", "running", "succeeded", "failed":
		return true
	default:
		return false
	}
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableInt64Value(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func validSHA256Digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func durationSeconds(value time.Duration) int64 {
	seconds := int64(value / time.Second)
	if value%time.Second != 0 || seconds < 1 {
		seconds++
	}
	return seconds
}

func requireAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	if count, countErr := result.RowsAffected(); countErr != nil {
		return countErr
	} else if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanCertificateJobs(rows *sql.Rows) ([]CertificateJob, error) {
	var jobs []CertificateJob
	for rows.Next() {
		var job CertificateJob
		if err := rows.Scan(&job.ID, &job.Domain, &job.Operation, &job.IdempotencyKey, &job.Status, &job.Attempts, &job.MaxAttempts,
			&job.NextAttemptAt, &job.LeaseOwner, &job.LeaseUntil, &job.LastErrorCode, &job.LastErrorAt,
			&job.RequestedBy, &job.ErrorMessage, &job.CreatedAt, &job.UpdatedAt, &job.StartedAt, &job.FinishedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func boundedLimit(limit int) int {
	if limit <= 0 || limit > 500 {
		return 100
	}
	return limit
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func newStoreID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成存储 ID 失败: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
