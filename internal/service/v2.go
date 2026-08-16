// 本文件实现 v2 证书服务方法：按预置配置 reconcile、状态查询、
// generation manifest/文件下载、部署回报、任务查询与续期候选列表。
// v2 请求不允许覆盖 SAN/CA/provider/webroot/keylength，只按预置配置执行。
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/certstore"
	"github.com/siidoo/certkeeper/internal/scheduler"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/certproto"
)

// PermissionError 表示 v2 授权检查未通过。
type PermissionError struct {
	Message string
}

func (e *PermissionError) Error() string { return e.Message }

// v2SafeError 包装可以安全返回给调用方的错误消息。
type v2SafeError struct{ msg string }

func (e *v2SafeError) Error() string { return e.msg }

// V2ReconcileRequest 定义 v2 reconcile 请求。
// 请求刻意不包含 SAN/CA/provider/webroot/keylength 等签发参数，
// 执行时只使用服务端预置的证书配置。
type V2ReconcileRequest struct {
	TokenID        string `json:"token_id"`
	IsAdmin        bool   `json:"is_admin"`
	Domain         string `json:"domain"`
	Operation      string `json:"operation,omitempty"`
	Reason         string `json:"reason,omitempty"`
	IdempotencyKey string `json:"idempotency_key"`
	Force          bool   `json:"force,omitempty"`
}

// ReconcileJob 执行一个已由持久 worker claim 的任务。actor 是内部主体，不经过 HTTP 授权。
func (s *Service) ReconcileJob(ctx context.Context, actor scheduler.Actor, queued scheduler.Job) (scheduler.Result, error) {
	job, err := s.Store.GetCertificateJob(ctx, queued.ID)
	if err != nil || job == nil {
		return scheduler.Result{}, fmt.Errorf("读取证书任务失败: %w", err)
	}
	owner := queued.LeaseOwner
	if owner == "" {
		return scheduler.Result{}, errors.New("任务缺少 lease owner")
	}
	return s.executeClaimedV2Job(ctx, actor, owner, job)
}

// ExecuteCertificateJob 领取并执行一个可恢复任务，供未使用 scheduler 适配器的 worker 调用。
func (s *Service) ExecuteCertificateJob(ctx context.Context, owner string, actor scheduler.Actor) error {
	job, err := s.Store.ClaimJob(ctx, owner, time.Minute)
	if err != nil || job == nil {
		return err
	}
	_, err = s.executeClaimedV2Job(ctx, actor, owner, job)
	return err
}

func (s *Service) executeClaimedV2Job(ctx context.Context, actor scheduler.Actor, owner string, job *store.CertificateJob) (scheduler.Result, error) {
	mu := s.v2DomainLock(job.Domain)
	mu.Lock()
	defer mu.Unlock()
	// 领取后再次读取配置和 current，防止重启恢复时使用过期输入。
	preset, err := s.Store.GetCert(ctx, job.Domain)
	if err != nil || preset == nil {
		return s.finishV2Failure(job, owner, actor, errOr(err, errors.New("证书配置不存在")))
	}
	cs, err := s.v2CertStore()
	if err != nil {
		return s.finishV2Failure(job, owner, actor, err)
	}
	state, err := s.readV2CurrentState(cs, job.Domain)
	if err != nil {
		return s.finishV2Failure(job, owner, actor, err)
	}
	force := strings.HasSuffix(job.Operation, ":force")
	renewDays := preset.RenewDays
	if renewDays <= 0 {
		renewDays = s.Cfg.Acme.DefaultRenewDays
	}
	if !force && state.exists && !acme.ShouldRenew(state.notAfter, renewDays) {
		_ = s.Store.UpdateJobStatus(context.Background(), job.ID, "succeeded", "")
		s.auditV2("", job.Domain, "reconcile_v2", "succeeded", "证书未到期，跳过签发")
		return scheduler.Result{}, nil
	}
	// 崩溃恢复：检查是否有同域名且处于 "publishing" 状态的遗留代次。
	// 若 certstore 中已有该代次的文件，则补全 SQLite 状态后跳过重新签发。
	if recovered, recErr := s.recoverPublishingGeneration(ctx, cs, job); recErr != nil {
		_ = s.Store.UpdateJobStatus(context.Background(), job.ID, "failed", "崩溃恢复失败: "+recErr.Error())
		return scheduler.Result{}, recErr
	} else if recovered {
		_ = s.Store.UpdateJobStatus(context.Background(), job.ID, "succeeded", "")
		s.auditV2("", job.Domain, "reconcile_v2", "succeeded", "崩溃恢复：已补全上次发布的代次状态")
		return scheduler.Result{}, nil
	}
	generation, err := s.Store.CreateCertificateGeneration(ctx, &store.CertificateGeneration{JobID: job.ID, Domain: job.Domain})
	if err != nil {
		return s.finishV2Failure(job, owner, actor, err)
	}
	profile := "default"
	if preset.DNSProfile.Valid && preset.DNSProfile.String != "" {
		profile = preset.DNSProfile.String
	}
	dnsEnv, err := s.Store.ListDNSProfileSecretsWithValues(ctx, preset.DNSProvider.String, profile)
	if err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, &v2SafeError{msg: "读取 DNS 凭据失败"})
	}
	stagingRoot, err := os.MkdirTemp("", "certkeeper-v2-*")
	if err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, err)
	}
	defer os.RemoveAll(stagingRoot)
	stagingDir := filepath.Join(stagingRoot, job.Domain)
	issuer := s.V2Issuer
	if issuer == nil {
		issuer = &acmeV2Issuer{cfg: s.Cfg}
	}
	err = issuer.Issue(ctx, V2IssueParams{Domain: job.Domain, SAN: splitCSV(preset.SAN), CA: v2OrDefault(preset.CA, s.Cfg.Acme.DefaultCA), Keylength: v2OrDefault(preset.Keylength, s.Cfg.Acme.DefaultKeylength), DNSProvider: preset.DNSProvider.String, DNSProfile: profile, DNSEnv: dnsEnv, StagingDir: stagingDir, Force: force})
	if err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, err)
	}
	// 记录发布意图：进入 publishing 状态，崩溃后可通过恢复逻辑检测。
	if err = s.Store.UpdateCertificateGenerationStatus(ctx, generation.ID, "publishing", "", "", "", nil, nil); err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, fmt.Errorf("记录发布意图失败: %w", err))
	}
	published, _, err := cs.PublishWithSAN(job.Domain, stagingDir, splitCSV(preset.SAN))
	if err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, err)
	}
	manifest, err := cs.LoadGenerationManifest(job.Domain, published)
	if err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, err)
	}
	var notAfterUnix *int64
	if fullchain, readErr := cs.ReadFile(job.Domain, published, certproto.FileFullchain); readErr == nil {
		if t, parseErr := acme.ParsePemExpiry(fullchain); parseErr == nil {
			v := t.Unix()
			notAfterUnix = &v
		}
	}
	if err = s.Store.UpdateCertificateGenerationStatus(ctx, generation.ID, "issued", string(published), string(published), "", nil, notAfterUnix); err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, err)
	}
	if err = s.Store.UpdateCertificateGenerationArtifact(ctx, generation.ID, store.GenerationArtifact{Revision: int64(manifest.Revision), ManifestDigest: manifestDigest(manifest), Serial: manifest.Serial, Fingerprint: manifest.Fingerprint, Current: true}); err != nil {
		return s.finishV2GenerationFailure(job, generation, owner, actor, fmt.Errorf("更新 generation artifact 失败: %w", err))
	}
	if err = s.Store.UpdateJobStatus(context.Background(), job.ID, "succeeded", ""); err != nil {
		return scheduler.Result{}, err
	}
	s.auditV2("", job.Domain, "reconcile_v2", "succeeded", "异步任务完成")
	return scheduler.Result{}, nil
}

func (s *Service) finishV2Failure(job *store.CertificateJob, owner string, actor scheduler.Actor, cause error) (scheduler.Result, error) {
	return s.finishV2GenerationFailure(job, nil, owner, actor, cause)
}

func (s *Service) finishV2GenerationFailure(job *store.CertificateJob, generation *store.CertificateGeneration, owner string, actor scheduler.Actor, cause error) (scheduler.Result, error) {
	public := v2PublicErrorMessage(cause)
	background := context.Background()
	if generation != nil {
		_ = s.Store.UpdateCertificateGenerationStatus(background, generation.ID, "failed", "", "", public, nil, nil)
	}
	code := "permanent"
	if v2Retryable(cause) {
		code = "retryable"
	}
	if code == "retryable" {
		_ = s.Store.Retry(background, job.ID, owner, code, public, time.Minute)
	} else {
		_ = s.Store.UpdateJobStatus(background, job.ID, "failed", public)
	}
	s.auditV2("", job.Domain, "reconcile_v2", "failed", public)
	return scheduler.Result{}, errors.New(public)
}

func v2Retryable(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		scheduler.ClassifyError(err) == scheduler.ErrorTemporary
}

func errOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func manifestDigest(manifest certstore.GenerationManifest) string {
	b, _ := json.Marshal(manifest)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// v2CurrentState 是 certstore current generation 的快照。
type v2CurrentState struct {
	generation       certproto.GenerationID
	manifest         certproto.CertificateManifest
	manifestRevision certproto.Revision
	notAfter         time.Time
	timeLog          int64
	exists           bool
}

// v2CertStore 惰性初始化并返回 generation 证书仓储。
func (s *Service) v2CertStore() (*certstore.Store, error) {
	s.v2csOnce.Do(func() {
		s.v2cs, s.v2csErr = certstore.Open(s.Cfg.Acme.CertsDir)
	})
	return s.v2cs, s.v2csErr
}

// ReconcileV2 校验请求并创建持久任务。证书签发由 worker 执行。
func (s *Service) ReconcileV2(ctx context.Context, req V2ReconcileRequest) (certproto.ReconcileResponse, error) {
	if err := v2ValidateDomain(req.Domain); err != nil {
		return certproto.ReconcileResponse{}, err
	}
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = "reconcile"
	}
	if len(operation) > 64 || v2HasControl(operation) {
		return certproto.ReconcileResponse{}, &ValidationError{Message: "operation 格式不合法"}
	}
	if len(req.Reason) > 256 || v2HasControl(req.Reason) {
		return certproto.ReconcileResponse{}, &ValidationError{Message: "reason 格式不合法"}
	}
	if strings.TrimSpace(req.IdempotencyKey) == "" || len(req.IdempotencyKey) > 128 || v2HasControl(req.IdempotencyKey) {
		return certproto.ReconcileResponse{}, &ValidationError{Message: "idempotency_key 必填、长度不能超过 128 且不能包含控制字符"}
	}
	preset, err := s.Store.GetCert(ctx, req.Domain)
	if err != nil {
		return certproto.ReconcileResponse{}, fmt.Errorf("读取证书配置失败: %w", err)
	}
	if preset == nil {
		return certproto.ReconcileResponse{}, &ValidationError{Message: "证书配置不存在: " + req.Domain}
	}
	// v2 只支持 dns_api，其余挑战模式一律拒绝。
	if preset.ChallengeMode != "dns_api" {
		return certproto.ReconcileResponse{}, &ValidationError{Message: "v2 仅支持 challenge_mode=dns_api，当前配置: " + preset.ChallengeMode}
	}
	if !preset.DNSProvider.Valid || preset.DNSProvider.String == "" {
		return certproto.ReconcileResponse{}, &ValidationError{Message: "dns_api 模式需要预置 dns_provider"}
	}
	// 普通 token 必须具备 apply grant；deny-by-default，admin 也不绕过。
	if err := s.requireV2Permission(ctx, req.TokenID, req.Domain, "apply"); err != nil {
		return certproto.ReconcileResponse{}, err
	}
	if req.Force {
		if !req.IsAdmin {
			return certproto.ReconcileResponse{}, &PermissionError{Message: "force 仅管理员可用"}
		}
		if err := s.requireV2Permission(ctx, req.TokenID, req.Domain, "force"); err != nil {
			return certproto.ReconcileResponse{}, err
		}
	}
	if req.Force {
		operation += ":force"
	}

	jobID, err := v2NewJobID()
	if err != nil {
		return certproto.ReconcileResponse{}, err
	}
	job, err := s.Store.CreateCertificateJob(ctx, &store.CertificateJob{
		ID:             jobID,
		Domain:         req.Domain,
		Operation:      operation,
		IdempotencyKey: req.IdempotencyKey,
		RequestedBy:    nullable(req.TokenID),
	})
	if err != nil {
		return certproto.ReconcileResponse{}, fmt.Errorf("创建证书任务失败: %w", err)
	}
	auditDetail := operation
	if req.Reason != "" {
		auditDetail += ": " + req.Reason
	}

	state := &v2CurrentState{}
	if cs, openErr := s.v2CertStore(); openErr == nil {
		state = s.readV2CurrentStateSafe(cs, req.Domain)
	}
	revision, _ := s.v2GenerationRevision(ctx, req.Domain, state.generation)
	return certproto.ReconcileResponse{Success: true, Domain: req.Domain, Generation: state.generation,
		Revision: revision, Changed: false, Job: v2BuildJobStatus(job, state.generation, revision),
		Status: v2BuildCertificateStatus(req.Domain, state, time.Now()), Message: "任务已排队，等待 worker 执行"}, nil
}

// StatusV2 基于 certstore current generation 返回证书状态，需要 status 授权。
func (s *Service) StatusV2(ctx context.Context, tokenID, domain string) (certproto.CertificateStatus, error) {
	if err := v2ValidateDomain(domain); err != nil {
		return certproto.CertificateStatus{}, err
	}
	if err := s.requireV2Permission(ctx, tokenID, domain, "status"); err != nil {
		return certproto.CertificateStatus{}, err
	}
	cs, err := s.v2CertStore()
	if err != nil {
		return certproto.CertificateStatus{}, fmt.Errorf("打开证书仓储失败: %w", err)
	}
	state, err := s.readV2CurrentState(cs, domain)
	if err != nil {
		return certproto.CertificateStatus{}, errors.New(v2PublicErrorMessage(err))
	}
	return v2BuildCertificateStatus(domain, state, time.Now()), nil
}

// ManifestV2 返回指定 generation 的 manifest；generation 为空时读取 current。需要 read_cert 授权。
func (s *Service) ManifestV2(ctx context.Context, tokenID, domain string, generation certproto.GenerationID) (certproto.CertificateManifest, error) {
	if err := v2ValidateDomain(domain); err != nil {
		return nil, err
	}
	if generation != "" {
		if err := generation.Validate(); err != nil {
			return nil, &ValidationError{Message: "generation 格式不合法"}
		}
	}
	if err := s.requireV2Permission(ctx, tokenID, domain, "read_cert"); err != nil {
		return nil, err
	}
	cs, err := s.v2CertStore()
	if err != nil {
		return nil, fmt.Errorf("打开证书仓储失败: %w", err)
	}
	manifest, err := cs.LoadManifest(domain, generation)
	if errors.Is(err, certstore.ErrNotFound) {
		return nil, &certproto.ErrorResponse{Code: certproto.ErrorCodeNotFound, Message: "证书产物不存在"}
	}
	if err != nil {
		return nil, errors.New(v2PublicErrorMessage(err))
	}
	return manifest, nil
}

// ReadGenerationFileV2 读取指定 generation 的固定证书文件；generation 为空时读取 current。
// key.pem 需要 read_private_key 授权，其余文件需要 read_cert 授权。
func (s *Service) ReadGenerationFileV2(ctx context.Context, tokenID, domain string, generation certproto.GenerationID, fileName string) ([]byte, error) {
	if err := v2ValidateDomain(domain); err != nil {
		return nil, err
	}
	if err := certproto.ValidateFileName(fileName); err != nil {
		return nil, &ValidationError{Message: "不允许的证书文件名"}
	}
	if generation != "" {
		if err := generation.Validate(); err != nil {
			return nil, &ValidationError{Message: "generation 格式不合法"}
		}
	}
	permission := "read_cert"
	if fileName == string(certproto.FileKey) {
		permission = "read_private_key"
	}
	if err := s.requireV2Permission(ctx, tokenID, domain, permission); err != nil {
		return nil, err
	}
	cs, err := s.v2CertStore()
	if err != nil {
		return nil, fmt.Errorf("打开证书仓储失败: %w", err)
	}
	data, err := cs.ReadFile(domain, generation, certproto.FileName(fileName))
	if errors.Is(err, certstore.ErrNotFound) {
		return nil, &certproto.ErrorResponse{Code: certproto.ErrorCodeNotFound, Message: "证书产物不存在"}
	}
	if err != nil {
		return nil, errors.New(v2PublicErrorMessage(err))
	}
	return data, nil
}

// ReportDeploymentV2 记录客户端部署回报，写入 Store 部署报告与审计。需要 apply 授权。
func (s *Service) ReportDeploymentV2(ctx context.Context, tokenID, domain string, report certproto.DeploymentReport) error {
	if err := v2ValidateDomain(domain); err != nil {
		return err
	}
	if strings.TrimSpace(report.Target) == "" || len(report.Target) > 128 || v2HasControl(report.Target) {
		return &ValidationError{Message: "部署目标 target 必填、长度不能超过 128 且不能包含控制字符"}
	}
	status, err := v2MapDeploymentState(report.State)
	if err != nil {
		return err
	}
	if err := s.requireV2Permission(ctx, tokenID, domain, "apply"); err != nil {
		return err
	}
	generations, err := s.Store.ListCertificateGenerations(ctx, domain)
	if err != nil {
		return fmt.Errorf("读取证书代次失败: %w", err)
	}
	if report.Generation == "" || report.Revision < 1 {
		return &ValidationError{Message: "部署回报必须提供 generation 和 revision"}
	}
	var matched *store.CertificateGeneration
	for i := range generations {
		if generations[i].CertificateRef.Valid && generations[i].CertificateRef.String == string(report.Generation) && generations[i].Revision == int64(report.Revision) {
			matched = &generations[i]
			break
		}
	}
	if matched == nil {
		return &ValidationError{Message: "部署回报 generation/revision 不匹配"}
	}
	detail := fmt.Sprintf("state=%s verified=%t reloaded=%t", report.State, report.Verified, report.Reloaded)
	if report.Message != "" {
		detail += " " + v2SanitizeDetail(report.Message, 256)
	}
	if _, err := s.Store.CreateDeploymentReport(ctx, &store.DeploymentReport{
		GenerationID: matched.ID,
		Generation:   string(report.Generation),
		Revision:     int64(report.Revision),
		Target:       report.Target,
		Status:       status,
		Detail:       nullable(detail),
	}); err != nil {
		return fmt.Errorf("写入部署报告失败: %w", err)
	}
	s.auditV2(tokenID, domain, "deployment_report_v2", "succeeded", "target="+report.Target+" status="+status)
	return nil
}

// GetJobV2 按任务 ID 查询任务状态，并按任务所属域名检查 status 授权。
func (s *Service) GetJobV2(ctx context.Context, tokenID, jobID string) (certproto.JobStatus, error) {
	if strings.TrimSpace(jobID) == "" || v2HasControl(jobID) {
		return certproto.JobStatus{}, &ValidationError{Message: "job_id 必填"}
	}
	job, err := s.Store.GetCertificateJob(ctx, jobID)
	if err != nil {
		return certproto.JobStatus{}, fmt.Errorf("读取证书任务失败: %w", err)
	}
	if job == nil {
		return certproto.JobStatus{}, &certproto.ErrorResponse{Code: certproto.ErrorCodeNotFound, Message: "任务不存在"}
	}
	if err := s.requireV2Permission(ctx, tokenID, job.Domain, "status"); err != nil {
		return certproto.JobStatus{}, err
	}
	generation, revision := s.v2JobGeneration(ctx, job)
	return v2BuildJobStatus(job, generation, revision), nil
}

// ListRenewalCandidates 返回全部已配置证书的调度候选列表，供调度器使用。
func (s *Service) ListRenewalCandidates(ctx context.Context) ([]scheduler.Candidate, error) {
	certs, err := s.Store.ListCerts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]scheduler.Candidate, 0, len(certs))
	for _, c := range certs {
		out = append(out, scheduler.Candidate{Domain: c.Domain, ChallengeMode: c.ChallengeMode})
	}
	return out, nil
}

// requireV2Permission 按拒绝优先检查域名授权；任何 token（含 admin）无 grant 均拒绝。
func (s *Service) requireV2Permission(ctx context.Context, tokenID, domain, permission string) error {
	ok, err := s.Store.HasCertificatePermission(ctx, tokenID, domain, permission)
	if err != nil {
		return fmt.Errorf("检查证书授权失败: %w", err)
	}
	if !ok {
		return &PermissionError{Message: "token 缺少 " + permission + " 权限"}
	}
	return nil
}

// failV2Job 统一收尾失败的 reconcile：标记 generation/job 失败、写审计，并返回脱敏错误。
func (s *Service) failV2Job(ctx context.Context, jobID string, generationID int64, tokenID, domain, detail string, cause error) error {
	public := v2PublicErrorMessage(cause)
	if generationID > 0 {
		_ = s.Store.UpdateCertificateGenerationStatus(ctx, generationID, "failed", "", "", public, nil, nil)
	}
	_ = s.Store.UpdateJobStatus(ctx, jobID, "failed", public)
	s.auditV2(tokenID, domain, "reconcile_v2", "failed", detail+": "+public)
	return errors.New(public)
}

// auditV2 追加 v2 审计事件；内容绝不包含明文机密、ACME 原始输出或内部路径。
func (s *Service) auditV2(tokenID, domain, action, outcome, detail string) {
	event := &store.AuditEvent{
		ActorTokenID: nullable(tokenID),
		Action:       action,
		Outcome:      outcome,
		Detail:       nullable(detail),
	}
	if domain != "" {
		event.Domain = nullable(domain)
	}
	// 使用独立 context，避免请求取消导致审计丢失；审计失败不阻断主流程。
	_ = s.Store.AddAuditEvent(context.Background(), event)
}

// v2DomainLock 返回指定域名的互斥锁。
func (s *Service) v2DomainLock(domain string) *sync.Mutex {
	value, _ := s.v2Locks.LoadOrStore(domain, &sync.Mutex{})
	return value.(*sync.Mutex)
}

// readV2CurrentState 读取 current generation 的 manifest、有效期与签发时间。
func (s *Service) readV2CurrentState(cs *certstore.Store, domain string) (*v2CurrentState, error) {
	state := &v2CurrentState{}
	generation, err := cs.GetCurrent(domain)
	if errors.Is(err, certstore.ErrNotFound) {
		return state, nil
	}
	if err != nil {
		return nil, err
	}
	manifest, err := cs.LoadManifest(domain, generation)
	if err != nil {
		return nil, err
	}
	fullchain, err := cs.ReadFile(domain, generation, certproto.FileFullchain)
	if err != nil {
		return nil, err
	}
	notAfter, err := acme.ParsePemExpiry(fullchain)
	if err != nil {
		return nil, err
	}
	state.generation = generation
	state.manifest = manifest
	if fullManifest, manifestErr := cs.LoadGenerationManifest(domain, generation); manifestErr == nil {
		state.manifestRevision = fullManifest.Revision
	}
	state.notAfter = notAfter
	state.exists = true
	if data, err := cs.ReadFile(domain, generation, certproto.FileTimeLog); err == nil {
		state.timeLog, _ = strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	}
	return state, nil
}

// readV2CurrentStateSafe 是 readV2CurrentState 的容错版本，失败时返回空状态。
func (s *Service) readV2CurrentStateSafe(cs *certstore.Store, domain string) *v2CurrentState {
	state, err := s.readV2CurrentState(cs, domain)
	if err != nil {
		return &v2CurrentState{}
	}
	return state
}

// v2BuildCertificateStatus 把仓储快照组装为协议状态。
func v2BuildCertificateStatus(domain string, state *v2CurrentState, now time.Time) certproto.CertificateStatus {
	status := certproto.CertificateStatus{
		Domain: domain,
		State:  certproto.CertificateStateMissing,
		Files:  certproto.CertificateManifest{},
	}
	if !state.exists {
		return status
	}
	status.Exists = true
	status.Generation = state.generation
	status.Files = state.manifest
	status.Revision = state.manifestRevision
	status.NotAfter = state.notAfter
	status.TimeLog = state.timeLog
	if now.Before(state.notAfter) {
		status.State = certproto.CertificateStateValid
	} else {
		status.State = certproto.CertificateStateExpired
	}
	return status
}

// v2BuildJobStatus 把 Store 任务组装为协议任务状态。
func v2BuildJobStatus(job *store.CertificateJob, generation certproto.GenerationID, revision certproto.Revision) certproto.JobStatus {
	out := certproto.JobStatus{
		ID:         job.ID,
		State:      certproto.JobState(job.Status),
		Generation: generation,
		Revision:   revision,
		CreatedAt:  time.Unix(job.CreatedAt, 0),
	}
	if job.StartedAt.Valid {
		started := time.Unix(job.StartedAt.Int64, 0)
		out.StartedAt = &started
	}
	if job.FinishedAt.Valid {
		finished := time.Unix(job.FinishedAt.Int64, 0)
		out.FinishedAt = &finished
	}
	if job.ErrorMessage.Valid && job.ErrorMessage.String != "" {
		out.Error = &certproto.ErrorResponse{Code: certproto.ErrorCodeJobFailed, Message: job.ErrorMessage.String}
	}
	return out
}

// v2FinalJobStatus 重新读取任务并组装协议状态；读取失败时退化为内存中的任务。
func (s *Service) v2FinalJobStatus(ctx context.Context, job *store.CertificateJob, generation certproto.GenerationID, revision certproto.Revision) certproto.JobStatus {
	if finalJob, err := s.Store.GetCertificateJob(ctx, job.ID); err == nil && finalJob != nil {
		job = finalJob
	}
	return v2BuildJobStatus(job, generation, revision)
}

// v2GenerationRevision 按 certstore generation ID 反查 Store 代次记录的序号。
func (s *Service) v2GenerationRevision(ctx context.Context, domain string, generation certproto.GenerationID) (certproto.Revision, *store.CertificateGeneration) {
	if generation == "" {
		return 0, nil
	}
	records, err := s.Store.ListCertificateGenerations(ctx, domain)
	if err != nil {
		return 0, nil
	}
	for i := range records {
		if records[i].CertificateRef.Valid && records[i].CertificateRef.String == string(generation) {
			return certproto.Revision(records[i].Revision), &records[i]
		}
	}
	return 0, nil
}

// v2JobGeneration 查找任务关联的最新代次，返回其 certstore generation ID 与序号。
func (s *Service) v2JobGeneration(ctx context.Context, job *store.CertificateJob) (certproto.GenerationID, certproto.Revision) {
	records, err := s.Store.ListCertificateGenerations(ctx, job.Domain)
	if err != nil {
		return "", 0
	}
	for i := range records {
		if records[i].JobID == job.ID {
			revision := certproto.Revision(records[i].Revision)
			if records[i].CertificateRef.Valid {
				return certproto.GenerationID(records[i].CertificateRef.String), revision
			}
			return "", revision
		}
	}
	return "", 0
}

// v2PublicErrorMessage 把内部错误转换为可返回给调用方的消息，剥离内部路径与敏感细节。
func v2PublicErrorMessage(err error) string {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr.Message
	}
	var safeErr *v2SafeError
	if errors.As(err, &safeErr) {
		return safeErr.msg
	}
	var opErr *acme.OperationError
	if errors.As(err, &opErr) {
		return opErr.Error()
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "操作已取消"
	case errors.Is(err, context.DeadlineExceeded):
		return "操作超时"
	case errors.Is(err, certstore.ErrInvalidCertificate):
		return "证书内容校验失败"
	case errors.Is(err, certstore.ErrInvalidManifest):
		return "证书产物不完整"
	case errors.Is(err, certstore.ErrUnsafePath):
		return "证书仓储路径不安全"
	case errors.Is(err, certstore.ErrNotFound):
		return "证书产物不存在"
	}
	return "内部处理失败"
}

// v2MapDeploymentState 把协议部署状态映射为 Store 部署状态。
func v2MapDeploymentState(state certproto.DeploymentState) (string, error) {
	switch state {
	case certproto.DeploymentStatePending:
		return "pending", nil
	case certproto.DeploymentStateDeploying:
		return "running", nil
	case certproto.DeploymentStateSucceeded, certproto.DeploymentStateSkipped:
		return "succeeded", nil
	case certproto.DeploymentStateFailed:
		return "failed", nil
	default:
		return "", &ValidationError{Message: "无效的部署状态: " + string(state)}
	}
}

// v2ValidateDomain 校验 v2 域名：小写 FQDN，拒绝通配符、IP、路径与控制字符。
func v2ValidateDomain(domain string) error {
	if domain == "" {
		return &ValidationError{Message: "domain 必填"}
	}
	invalid := &ValidationError{Message: "domain 格式不合法"}
	if domain != strings.ToLower(domain) || strings.TrimSpace(domain) != domain || len(domain) > 253 ||
		strings.Contains(domain, "*") || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return invalid
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return invalid
			}
		}
	}
	return nil
}

// v2HasControl 判断字符串是否包含控制字符。
func v2HasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// v2SanitizeDetail 移除控制字符并截断过长的外部输入，用于写入 Store/审计。
func v2SanitizeDetail(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}

// v2NewJobID 生成随机任务 ID。
func v2NewJobID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("生成任务 ID 失败: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// v2OrDefault 返回 value；value 为空时返回 fallback。
func v2OrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// recoverPublishingGeneration 检查该域名是否存在处于 "publishing" 状态的遗留代次。
// 若 certstore 已有对应文件，则补全 SQLite 状态（finalize），返回 true；
// 否则将遗留代次标为 failed，返回 false。
func (s *Service) recoverPublishingGeneration(ctx context.Context, cs *certstore.Store, job *store.CertificateJob) (bool, error) {
	generations, err := s.Store.ListCertificateGenerations(ctx, job.Domain)
	if err != nil {
		return false, err
	}
	for i := range generations {
		gen := &generations[i]
		if gen.Status != "publishing" {
			continue
		}
		// 检查 certstore 中 current 是否已是此代次
		currentGenID, certErr := cs.GetCurrent(job.Domain)
		if certErr != nil {
			// certstore 无 current，说明发布未完成，标记为 failed
			_ = s.Store.UpdateCertificateGenerationStatus(context.Background(), gen.ID, "failed", "", "", "崩溃恢复：certstore 无 current generation", nil, nil)
			continue
		}
		// certstore 有 current，尝试补全 SQLite 状态
		manifest, manifestErr := cs.LoadManifest(job.Domain, currentGenID)
		if manifestErr != nil {
			_ = s.Store.UpdateCertificateGenerationStatus(context.Background(), gen.ID, "failed", "", "", "崩溃恢复：无法读取 manifest", nil, nil)
			continue
		}
		fullManifest, fullManifestErr := cs.LoadGenerationManifest(job.Domain, currentGenID)
		if fullManifestErr != nil {
			_ = s.Store.UpdateCertificateGenerationStatus(context.Background(), gen.ID, "failed", "", "", "崩溃恢复：无法读取完整 manifest", nil, nil)
			continue
		}
		_ = manifest // 仅用于确认可读
		var notAfterUnix *int64
		if fullchain, readErr := cs.ReadFile(job.Domain, currentGenID, certproto.FileFullchain); readErr == nil {
			if t, parseErr := acme.ParsePemExpiry(fullchain); parseErr == nil {
				v := t.Unix()
				notAfterUnix = &v
			}
		}
		genIDStr := string(currentGenID)
		if err := s.Store.UpdateCertificateGenerationStatus(ctx, gen.ID, "issued", genIDStr, genIDStr, "", nil, notAfterUnix); err != nil {
			return false, fmt.Errorf("崩溃恢复：补全代次状态失败: %w", err)
		}
		if err := s.Store.UpdateCertificateGenerationArtifact(ctx, gen.ID, store.GenerationArtifact{
			Revision:       int64(fullManifest.Revision),
			ManifestDigest: manifestDigest(fullManifest),
			Serial:         fullManifest.Serial,
			Fingerprint:    fullManifest.Fingerprint,
			Current:        true,
		}); err != nil {
			return false, fmt.Errorf("崩溃恢复：补全 artifact 失败: %w", err)
		}
		return true, nil
	}
	return false, nil
}
