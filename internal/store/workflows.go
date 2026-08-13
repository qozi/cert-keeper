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

// CertificateJob 表示证书申请、续期或部署等异步任务。
type CertificateJob struct {
	ID             string         `json:"id"`
	Domain         string         `json:"domain"`
	Operation      string         `json:"operation"`
	IdempotencyKey string         `json:"idempotency_key"`
	Status         string         `json:"status"`
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
	Status         string         `json:"status"`
	CertificateRef JSONNullString `json:"certificate_ref"`
	PrivateKeyRef  JSONNullString `json:"private_key_ref"`
	NotBefore      sql.NullInt64  `json:"not_before"`
	NotAfter       sql.NullInt64  `json:"not_after"`
	ErrorMessage   JSONNullString `json:"error_message"`
	CreatedAt      int64          `json:"created_at"`
	UpdatedAt      int64          `json:"updated_at"`
}

// DeploymentReport 表示一个代次发往某个部署目标的结果。
type DeploymentReport struct {
	ID           int64          `json:"id"`
	GenerationID int64          `json:"generation_id"`
	Target       string         `json:"target"`
	Status       string         `json:"status"`
	Detail       JSONNullString `json:"detail"`
	CreatedAt    int64          `json:"created_at"`
	UpdatedAt    int64          `json:"updated_at"`
	CompletedAt  sql.NullInt64  `json:"completed_at"`
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
	now := time.Now().Unix()
	if job.CreatedAt == 0 {
		job.CreatedAt = now
	}
	job.UpdatedAt = now

	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO certificate_jobs(id, domain, operation, idempotency_key, status, requested_by, error_message, created_at, updated_at, started_at, finished_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.Domain, job.Operation, job.IdempotencyKey, job.Status, job.RequestedBy, job.ErrorMessage,
		job.CreatedAt, job.UpdatedAt, job.StartedAt, job.FinishedAt)
	if err == nil {
		return job, nil
	}
	if !isUniqueConstraint(err) {
		return nil, err
	}
	existing, getErr := s.getActiveCertificateJob(ctx, job.Domain, job.Operation, job.IdempotencyKey)
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
	return scanCertificateJob(s.DB.QueryRowContext(ctx, `
		SELECT id, domain, operation, idempotency_key, status, requested_by, error_message, created_at, updated_at, started_at, finished_at
		FROM certificate_jobs WHERE id=?`, id))
}

// GetJob 是 GetCertificateJob 的简短别名。
func (s *Store) GetJob(ctx context.Context, id string) (*CertificateJob, error) {
	return s.GetCertificateJob(ctx, id)
}

func (s *Store) getActiveCertificateJob(ctx context.Context, domain, operation, idempotencyKey string) (*CertificateJob, error) {
	return scanCertificateJob(s.DB.QueryRowContext(ctx, `
		SELECT id, domain, operation, idempotency_key, status, requested_by, error_message, created_at, updated_at, started_at, finished_at
		FROM certificate_jobs WHERE domain=? AND operation=? AND idempotency_key=? AND status IN ('queued', 'running')`,
		domain, operation, idempotencyKey))
}

func scanCertificateJob(row *sql.Row) (*CertificateJob, error) {
	var job CertificateJob
	err := row.Scan(&job.ID, &job.Domain, &job.Operation, &job.IdempotencyKey, &job.Status, &job.RequestedBy, &job.ErrorMessage,
		&job.CreatedAt, &job.UpdatedAt, &job.StartedAt, &job.FinishedAt)
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
	q := `SELECT id, domain, operation, idempotency_key, status, requested_by, error_message, created_at, updated_at, started_at, finished_at FROM certificate_jobs WHERE 1=1`
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
		if err := rows.Scan(&job.ID, &job.Domain, &job.Operation, &job.IdempotencyKey, &job.Status, &job.RequestedBy, &job.ErrorMessage,
			&job.CreatedAt, &job.UpdatedAt, &job.StartedAt, &job.FinishedAt); err != nil {
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
	result, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_jobs SET status=?, error_message=?, updated_at=?,
		started_at=COALESCE(started_at, ?), finished_at=? WHERE id=?`,
		status, nullString(errorMessage), now, start, finish, id)
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
	now := time.Now().Unix()
	if generation.CreatedAt == 0 {
		generation.CreatedAt = now
	}
	generation.UpdatedAt = now
	result, err := tx.ExecContext(ctx, `
		INSERT INTO certificate_generations(job_id, domain, generation, status, certificate_ref, private_key_ref, not_before, not_after, error_message, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		generation.JobID, generation.Domain, generation.Generation, generation.Status, generation.CertificateRef, generation.PrivateKeyRef,
		generation.NotBefore, generation.NotAfter, generation.ErrorMessage, generation.CreatedAt, generation.UpdatedAt)
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
	var generation CertificateGeneration
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, job_id, domain, generation, status, certificate_ref, private_key_ref, not_before, not_after, error_message, created_at, updated_at
		FROM certificate_generations WHERE id=?`, id).
		Scan(&generation.ID, &generation.JobID, &generation.Domain, &generation.Generation, &generation.Status, &generation.CertificateRef,
			&generation.PrivateKeyRef, &generation.NotBefore, &generation.NotAfter, &generation.ErrorMessage, &generation.CreatedAt, &generation.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &generation, nil
}

// ListCertificateGenerations 按域名列出证书代次。
func (s *Store) ListCertificateGenerations(ctx context.Context, domain string) ([]CertificateGeneration, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, job_id, domain, generation, status, certificate_ref, private_key_ref, not_before, not_after, error_message, created_at, updated_at
		FROM certificate_generations WHERE domain=? ORDER BY generation DESC`, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var generations []CertificateGeneration
	for rows.Next() {
		var generation CertificateGeneration
		if err := rows.Scan(&generation.ID, &generation.JobID, &generation.Domain, &generation.Generation, &generation.Status, &generation.CertificateRef,
			&generation.PrivateKeyRef, &generation.NotBefore, &generation.NotAfter, &generation.ErrorMessage, &generation.CreatedAt, &generation.UpdatedAt); err != nil {
			return nil, err
		}
		generations = append(generations, generation)
	}
	return generations, rows.Err()
}

// UpdateCertificateGenerationStatus 更新代次状态和引用。
func (s *Store) UpdateCertificateGenerationStatus(ctx context.Context, id int64, status string, certificateRef, privateKeyRef, errorMessage string, notBefore, notAfter *int64) error {
	if !validGenerationStatus(status) {
		return errors.New("无效的证书代次状态")
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE certificate_generations SET status=?, certificate_ref=?, private_key_ref=?, error_message=?, not_before=?, not_after=?, updated_at=? WHERE id=?`,
		status, nullString(certificateRef), nullString(privateKeyRef), nullString(errorMessage), nullableInt64(notBefore), nullableInt64(notAfter), time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
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
	now := time.Now().Unix()
	if report.CreatedAt == 0 {
		report.CreatedAt = now
	}
	report.UpdatedAt = now
	result, err := s.DB.ExecContext(ctx, `
		INSERT INTO deployment_reports(generation_id, target, status, detail, created_at, updated_at, completed_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(generation_id, target) DO UPDATE SET status=excluded.status, detail=excluded.detail, updated_at=excluded.updated_at, completed_at=excluded.completed_at`,
		report.GenerationID, report.Target, report.Status, report.Detail, report.CreatedAt, report.UpdatedAt, report.CompletedAt)
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
		SELECT id, generation_id, target, status, detail, created_at, updated_at, completed_at
		FROM deployment_reports WHERE id=?`, id).
		Scan(&report.ID, &report.GenerationID, &report.Target, &report.Status, &report.Detail, &report.CreatedAt, &report.UpdatedAt, &report.CompletedAt)
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
		SELECT id, generation_id, target, status, detail, created_at, updated_at, completed_at
		FROM deployment_reports WHERE generation_id=? ORDER BY target`, generationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reports []DeploymentReport
	for rows.Next() {
		var report DeploymentReport
		if err := rows.Scan(&report.ID, &report.GenerationID, &report.Target, &report.Status, &report.Detail, &report.CreatedAt, &report.UpdatedAt, &report.CompletedAt); err != nil {
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

func validGenerationStatus(status string) bool {
	switch status {
	case "pending", "issued", "failed", "revoked":
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
