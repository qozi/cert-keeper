package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/internal/certstore"
	"github.com/siidoo/certkeeper/internal/scheduler"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/certproto"
)

// fakeV2Issuer 是测试用的假签发器，默认生成自签名证书 staging。
type fakeV2Issuer struct {
	calls atomic.Int32
	fn    func(V2IssueParams) error
}

func (f *fakeV2Issuer) Issue(_ context.Context, params V2IssueParams) error {
	f.calls.Add(1)
	if f.fn != nil {
		return f.fn(params)
	}
	return v2WriteTestStaging(params.StagingDir, params.Domain, time.Now().Add(90*24*time.Hour))
}

// v2WriteTestStaging 生成满足 certstore 校验的自签名证书 staging 文件。
func v2WriteTestStaging(dir, domain string, notAfter time.Time) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files := map[string][]byte{
		"cert.pem":      certPEM,
		"key.pem":       keyPEM,
		"fullchain.pem": certPEM,
		"ca.pem":        certPEM,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func presetV2Cert(t *testing.T, svc *Service, domain, challengeMode string) {
	t.Helper()
	cert := &store.Cert{
		Domain:        domain,
		ChallengeMode: challengeMode,
		CA:            "letsencrypt",
		Keylength:     "ec-256",
		RenewDays:     30,
		Source:        "preset",
	}
	if challengeMode == "dns_api" {
		cert.DNSProvider = store.JSONNullString{String: "dns_cf", Valid: true}
	}
	if err := svc.Store.UpsertCert(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
}

func createV2Token(t *testing.T, svc *Service, id string, isAdmin bool) {
	t.Helper()
	if err := svc.Store.CreateToken(context.Background(), &store.Token{
		ID: id, Secret: id + "-secret", Enabled: true, IsAdmin: isAdmin,
	}); err != nil {
		t.Fatal(err)
	}
}

func grantV2(t *testing.T, svc *Service, tokenID, domain, permission string) {
	t.Helper()
	if err := svc.Store.Grant(context.Background(), tokenID, domain, permission); err != nil {
		t.Fatal(err)
	}
}

func requirePermissionError(t *testing.T, err error) {
	t.Helper()
	var permErr *PermissionError
	if !errors.As(err, &permErr) {
		t.Fatalf("错误 = %v (%T)，期望 PermissionError", err, err)
	}
}

func requireValidationError(t *testing.T, err error) {
	t.Helper()
	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("错误 = %v (%T)，期望 ValidationError", err, err)
	}
}

func TestReconcileV2DeniesWithoutGrant(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	issuer := &fakeV2Issuer{}
	svc.V2Issuer = issuer

	_, err := svc.ReconcileV2(context.Background(), V2ReconcileRequest{
		TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1",
	})
	requirePermissionError(t, err)
	if issuer.calls.Load() != 0 {
		t.Fatalf("无授权时调用了签发器 %d 次", issuer.calls.Load())
	}
}

func TestReconcileV2RejectsNonDNSAPI(t *testing.T) {
	for _, mode := range []string{"dns_manual", "standalone", "webroot"} {
		t.Run(mode, func(t *testing.T) {
			svc, _, cleanup := newTestService(t)
			defer cleanup()
			presetV2Cert(t, svc, "example.com", mode)
			createV2Token(t, svc, "client-a", false)
			grantV2(t, svc, "client-a", "example.com", "apply")
			issuer := &fakeV2Issuer{}
			svc.V2Issuer = issuer

			_, err := svc.ReconcileV2(context.Background(), V2ReconcileRequest{
				TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1",
			})
			requireValidationError(t, err)
			if issuer.calls.Load() != 0 {
				t.Fatalf("非 dns_api 模式调用了签发器 %d 次", issuer.calls.Load())
			}
		})
	}
}

func TestReconcileV2RejectsMissingPreset(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	createV2Token(t, svc, "client-a", false)

	_, err := svc.ReconcileV2(context.Background(), V2ReconcileRequest{
		TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1",
	})
	requireValidationError(t, err)
}

func TestReconcileV2ForceAuth(t *testing.T) {
	ctx := context.Background()

	t.Run("非管理员即使有 force 授权也拒绝", func(t *testing.T) {
		svc, _, cleanup := newTestService(t)
		defer cleanup()
		presetV2Cert(t, svc, "example.com", "dns_api")
		createV2Token(t, svc, "client-a", false)
		grantV2(t, svc, "client-a", "example.com", "apply")
		grantV2(t, svc, "client-a", "example.com", "force")
		svc.V2Issuer = &fakeV2Issuer{}

		_, err := svc.ReconcileV2(ctx, V2ReconcileRequest{
			TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1", Force: true,
		})
		requirePermissionError(t, err)
	})

	t.Run("管理员无 force 授权拒绝", func(t *testing.T) {
		svc, _, cleanup := newTestService(t)
		defer cleanup()
		presetV2Cert(t, svc, "example.com", "dns_api")
		createV2Token(t, svc, "admin-a", true)
		grantV2(t, svc, "admin-a", "example.com", "apply")
		svc.V2Issuer = &fakeV2Issuer{}

		_, err := svc.ReconcileV2(ctx, V2ReconcileRequest{
			TokenID: "admin-a", IsAdmin: true, Domain: "example.com", IdempotencyKey: "k1", Force: true,
		})
		requirePermissionError(t, err)
	})

	t.Run("管理员且具备 force 授权时放行", func(t *testing.T) {
		svc, _, cleanup := newTestService(t)
		defer cleanup()
		presetV2Cert(t, svc, "example.com", "dns_api")
		createV2Token(t, svc, "admin-a", true)
		grantV2(t, svc, "admin-a", "example.com", "apply")
		grantV2(t, svc, "admin-a", "example.com", "force")
		svc.V2Issuer = &fakeV2Issuer{}

		resp, err := svc.ReconcileV2(ctx, V2ReconcileRequest{
			TokenID: "admin-a", IsAdmin: true, Domain: "example.com", IdempotencyKey: "k1", Force: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Success || resp.Changed || resp.Job.State != certproto.JobStateQueued {
			t.Fatalf("force reconcile 结果异常: %+v", resp)
		}
	})
}

func TestReconcileV2IssuesPublishesAndAudits(t *testing.T) {
	svc, cfg, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	grantV2(t, svc, "client-a", "example.com", "apply")
	issuer := &fakeV2Issuer{}
	svc.V2Issuer = issuer

	resp, err := svc.ReconcileV2(ctx, V2ReconcileRequest{
		TokenID: "client-a", Domain: "example.com", Operation: "issue", Reason: "首次签发", IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Success || resp.Changed || resp.Job.State != certproto.JobStateQueued {
		t.Fatalf("reconcile 结果异常: %+v", resp)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	job, _ := svc.Store.GetCertificateJob(ctx, resp.Job.ID)
	resp.Job = v2BuildJobStatus(job, "", 0)
	resp.Generation, resp.Revision = svc.v2JobGeneration(ctx, job)
	cs, err := certstore.Open(cfg.Acme.CertsDir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := svc.readV2CurrentState(cs, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	resp.Status = v2BuildCertificateStatus("example.com", state, time.Now())
	if resp.Job.State != certproto.JobStateSucceeded {
		t.Fatalf("任务状态 = %q，期望 succeeded", resp.Job.State)
	}
	if resp.Status.State != certproto.CertificateStateValid || len(resp.Status.Files) != 5 {
		t.Fatalf("证书状态异常: %+v", resp.Status)
	}
	if issuer.calls.Load() != 1 {
		t.Fatalf("签发器调用次数 = %d，期望 1", issuer.calls.Load())
	}

	// certstore current 必须指向新发布的 generation。
	cs, err = certstore.Open(cfg.Acme.CertsDir)
	if err != nil {
		t.Fatal(err)
	}
	current, err := cs.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if current != resp.Generation {
		t.Fatalf("current = %q，期望 %q", current, resp.Generation)
	}

	// Store generation 记录必须是 issued 且引用 certstore generation ID。
	generations, err := svc.Store.ListCertificateGenerations(ctx, "example.com")
	if err != nil || len(generations) != 1 {
		t.Fatalf("代次记录异常: %+v err=%v", generations, err)
	}
	if generations[0].Status != "issued" || generations[0].CertificateRef.String != string(resp.Generation) {
		t.Fatalf("代次记录内容异常: %+v", generations[0])
	}
	job, err = svc.Store.GetCertificateJob(ctx, resp.Job.ID)
	if err != nil || job == nil || job.Status != "succeeded" {
		t.Fatalf("任务记录异常: %+v err=%v", job, err)
	}
	events, err := svc.Store.ListAuditEvents(ctx, store.AuditFilter{Domain: "example.com"})
	if err != nil || len(events) != 1 || events[0].Action != "reconcile_v2" || events[0].Outcome != "succeeded" {
		t.Fatalf("审计事件异常: %+v err=%v", events, err)
	}
}

func TestReconcileV2SkipsWhenFresh(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	grantV2(t, svc, "client-a", "example.com", "apply")
	issuer := &fakeV2Issuer{}
	svc.V2Issuer = issuer

	first, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1"})
	if err != nil || first.Changed || first.Job.State != certproto.JobStateQueued {
		t.Fatalf("首次 reconcile 异常: %+v err=%v", first, err)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	job, err := svc.Store.GetCertificateJob(ctx, first.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	first.Generation, first.Revision = svc.v2JobGeneration(ctx, job)
	second, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k2"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.Generation != first.Generation {
		t.Fatalf("未到期应跳过且 generation 不变: %+v", second)
	}
	if second.Job.State != certproto.JobStateSucceeded {
		if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
			t.Fatal(err)
		}
		secondJob, getErr := svc.Store.GetCertificateJob(ctx, second.Job.ID)
		if getErr != nil {
			t.Fatal(getErr)
		}
		second.Job = v2BuildJobStatus(secondJob, second.Generation, second.Revision)
	}
	if second.Job.State != certproto.JobStateSucceeded {
		t.Fatalf("跳过的任务状态 = %q，期望 succeeded", second.Job.State)
	}
	if issuer.calls.Load() != 1 {
		t.Fatalf("签发器调用次数 = %d，期望 1", issuer.calls.Load())
	}
}

func TestReconcileV2IdempotentReuse(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	grantV2(t, svc, "client-a", "example.com", "apply")

	issuer := &fakeV2Issuer{}
	svc.V2Issuer = issuer
	first, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "same-key"})
	if err != nil {
		t.Fatal(err)
	}
	// 相同幂等键复用 queued 任务，不重复签发。
	second, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "same-key"})
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.Job.ID == "" {
		t.Fatalf("幂等复用结果异常: %+v", second)
	}
	if second.Job.ID != first.Job.ID {
		t.Fatalf("幂等复用任务 ID = %q，期望 %q", second.Job.ID, first.Job.ID)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	if issuer.calls.Load() != 1 {
		t.Fatalf("签发器调用次数 = %d，期望 1", issuer.calls.Load())
	}
}

func TestReconcileV2ConcurrentIssuesOnce(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	grantV2(t, svc, "client-a", "example.com", "apply")
	issuer := &fakeV2Issuer{}
	svc.V2Issuer = issuer

	var wg sync.WaitGroup
	results := make([]certproto.ReconcileResponse, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	for i, key := range []string{"k1", "k2"} {
		wg.Add(1)
		go func(i int, key string) {
			defer wg.Done()
			<-start
			results[i], errs[i] = svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: key})
		}(i, key)
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("并发 reconcile %d 失败: %v", i, err)
		}
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	// 锁内二次检查保证两个 queued job 只签发一次。
	if issuer.calls.Load() != 1 {
		t.Fatalf("签发器调用次数 = %d，期望 1", issuer.calls.Load())
	}
	for _, resp := range results {
		if resp.Job.State != certproto.JobStateQueued {
			t.Fatalf("任务未入队: %+v", resp)
		}
	}
}

func TestReconcileV2FailureKeepsCurrent(t *testing.T) {
	svc, cfg, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "admin-a", true)
	grantV2(t, svc, "admin-a", "example.com", "apply")
	grantV2(t, svc, "admin-a", "example.com", "force")
	issuer := &fakeV2Issuer{}
	svc.V2Issuer = issuer

	first, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "admin-a", IsAdmin: true, Domain: "example.com", IdempotencyKey: "k1"})
	if err != nil || first.Job.State != certproto.JobStateQueued {
		t.Fatalf("首次 reconcile 异常: %+v err=%v", first, err)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	cs, err := certstore.Open(cfg.Acme.CertsDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := cs.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 第二次 force reconcile 的签发器失败，且错误文本模拟携带敏感信息。
	var stagingDir string
	issuer.fn = func(params V2IssueParams) error {
		stagingDir = params.StagingDir
		return errors.New("acme 签发失败: secret-token-leak")
	}
	_, err = svc.ReconcileV2(ctx, V2ReconcileRequest{
		TokenID: "admin-a", IsAdmin: true, Domain: "example.com", IdempotencyKey: "k2", Force: true,
	})
	err = svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"})
	if err == nil {
		t.Fatal("签发失败应返回错误")
	}
	// 返回的错误绝不泄露 ACME 原始输出。
	if strings.Contains(err.Error(), "secret-token-leak") {
		t.Fatalf("错误泄露了敏感信息: %v", err)
	}

	// 旧 current 不变。
	after, err := cs.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("失败后 current = %q，期望保持 %q", after, before)
	}
	// staging 已清理。
	if _, statErr := os.Stat(stagingDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("staging 目录未清理: %s", stagingDir)
	}
	// 任务与代次都标记为 failed，且错误消息已脱敏。
	jobs, err := svc.Store.ListCertificateJobs(ctx, store.JobFilter{Domain: "example.com"})
	if err != nil || len(jobs) != 2 {
		t.Fatalf("任务记录异常: %+v err=%v", jobs, err)
	}
	var failedJob *store.CertificateJob
	for i := range jobs {
		if jobs[i].IdempotencyKey == "k2" {
			failedJob = &jobs[i]
		}
	}
	if failedJob == nil || failedJob.Status != "failed" || !failedJob.ErrorMessage.Valid || strings.Contains(failedJob.ErrorMessage.String, "secret-token-leak") {
		t.Fatalf("失败任务记录异常: %+v", jobs)
	}
	generations, err := svc.Store.ListCertificateGenerations(ctx, "example.com")
	if err != nil || len(generations) != 2 {
		t.Fatalf("代次记录异常: %+v err=%v", generations, err)
	}
	var failedGeneration *store.CertificateGeneration
	for i := range generations {
		if generations[i].JobID == failedJob.ID {
			failedGeneration = &generations[i]
		}
	}
	if failedGeneration == nil || failedGeneration.Status != "failed" {
		t.Fatalf("失败代次记录异常: %+v", generations)
	}
	events, err := svc.Store.ListAuditEvents(ctx, store.AuditFilter{Domain: "example.com", Action: "reconcile_v2"})
	if err != nil || len(events) != 2 {
		t.Fatalf("审计事件异常: %+v err=%v", events, err)
	}
	for _, event := range events {
		if strings.Contains(event.Detail.String, "secret-token-leak") {
			t.Fatalf("审计泄露了敏感信息: %+v", event)
		}
	}
}

func TestStatusV2AndManifestV2(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	svc.V2Issuer = &fakeV2Issuer{}

	// 无 status 授权拒绝。
	if _, err := svc.StatusV2(ctx, "client-a", "example.com"); err != nil {
		requirePermissionError(t, err)
	} else {
		t.Fatal("无 status 授权应被拒绝")
	}
	grantV2(t, svc, "client-a", "example.com", "status")

	// 未发布时为 missing。
	status, err := svc.StatusV2(ctx, "client-a", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if status.Exists || status.State != certproto.CertificateStateMissing {
		t.Fatalf("空仓储状态异常: %+v", status)
	}

	grantV2(t, svc, "client-a", "example.com", "apply")
	resp, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	jobRecord, err := svc.Store.GetCertificateJob(ctx, resp.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp.Generation, resp.Revision = svc.v2JobGeneration(ctx, jobRecord)
	status, err = svc.StatusV2(ctx, "client-a", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Exists || status.State != certproto.CertificateStateValid || status.Generation != resp.Generation || len(status.Files) != 5 {
		t.Fatalf("发布后状态异常: %+v", status)
	}

	// Manifest 需要 read_cert 授权。
	if _, err := svc.ManifestV2(ctx, "client-a", "example.com", ""); err != nil {
		requirePermissionError(t, err)
	} else {
		t.Fatal("无 read_cert 授权应被拒绝")
	}
	grantV2(t, svc, "client-a", "example.com", "read_cert")
	manifest, err := svc.ManifestV2(ctx, "client-a", "example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) != 5 {
		t.Fatalf("manifest 文件数 = %d，期望 5", len(manifest))
	}
	if _, err := svc.ManifestV2(ctx, "client-a", "example.com", "g-not-exist"); err == nil {
		t.Fatal("不存在的 generation 应返回错误")
	}
}

func TestReadGenerationFileV2Permissions(t *testing.T) {
	svc, cfg, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	grantV2(t, svc, "client-a", "example.com", "apply")
	svc.V2Issuer = &fakeV2Issuer{}

	if _, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	cs, err := certstore.Open(cfg.Acme.CertsDir)
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := cs.ReadFile("example.com", "", certproto.FileKey)
	if err != nil {
		t.Fatal(err)
	}

	// 私钥需要 read_private_key：无任何授权与仅 read_cert 都拒绝。
	if _, err := svc.ReadGenerationFileV2(ctx, "client-a", "example.com", "", "key.pem"); err != nil {
		requirePermissionError(t, err)
	} else {
		t.Fatal("无授权读取私钥应被拒绝")
	}
	grantV2(t, svc, "client-a", "example.com", "read_cert")
	if _, err := svc.ReadGenerationFileV2(ctx, "client-a", "example.com", "", "key.pem"); err != nil {
		requirePermissionError(t, err)
	} else {
		t.Fatal("仅 read_cert 读取私钥应被拒绝")
	}
	grantV2(t, svc, "client-a", "example.com", "read_private_key")
	data, err := svc.ReadGenerationFileV2(ctx, "client-a", "example.com", "", "key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(wantKey) {
		t.Fatal("下载的私钥内容与仓储不一致")
	}

	// 普通证书文件 read_cert 即可。
	if _, err := svc.ReadGenerationFileV2(ctx, "client-a", "example.com", "", "cert.pem"); err != nil {
		t.Fatal(err)
	}
	// 未知文件名与非固定文件名拒绝。
	if _, err := svc.ReadGenerationFileV2(ctx, "client-a", "example.com", "", "../key.pem"); err != nil {
		requireValidationError(t, err)
	} else {
		t.Fatal("路径穿越文件名应被拒绝")
	}
	if _, err := svc.ReadGenerationFileV2(ctx, "client-a", "example.com", "", "other.pem"); err != nil {
		requireValidationError(t, err)
	} else {
		t.Fatal("未知文件名应被拒绝")
	}
}

func TestReportDeploymentV2(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	svc.V2Issuer = &fakeV2Issuer{}

	// 无 apply 授权拒绝。
	err := svc.ReportDeploymentV2(ctx, "client-a", "example.com", certproto.DeploymentReport{
		Target: "edge-1", State: certproto.DeploymentStateSucceeded, Success: true,
	})
	requirePermissionError(t, err)

	grantV2(t, svc, "client-a", "example.com", "apply")
	// 尚无代次时拒绝。
	if err := svc.ReportDeploymentV2(ctx, "client-a", "example.com", certproto.DeploymentReport{
		Target: "edge-1", State: certproto.DeploymentStateSucceeded, Success: true,
	}); err != nil {
		requireValidationError(t, err)
	} else {
		t.Fatal("无代次时应拒绝部署回报")
	}

	resp, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	jobRecord, err := svc.Store.GetCertificateJob(ctx, resp.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	resp.Generation, resp.Revision = svc.v2JobGeneration(ctx, jobRecord)
	if err := svc.ReportDeploymentV2(ctx, "client-a", "example.com", certproto.DeploymentReport{
		Target: "edge-1", State: certproto.DeploymentStateSucceeded, Success: true,
		Generation: resp.Generation, Revision: resp.Revision, Verified: true, Reloaded: true, Message: "部署完成",
	}); err != nil {
		t.Fatal(err)
	}

	generations, err := svc.Store.ListCertificateGenerations(ctx, "example.com")
	if err != nil || len(generations) != 1 {
		t.Fatalf("代次记录异常: %+v err=%v", generations, err)
	}
	reports, err := svc.Store.ListDeploymentReports(ctx, generations[0].ID)
	if err != nil || len(reports) != 1 {
		t.Fatalf("部署报告异常: %+v err=%v", reports, err)
	}
	if reports[0].Status != "succeeded" || reports[0].Target != "edge-1" || !reports[0].Detail.Valid {
		t.Fatalf("部署报告内容异常: %+v", reports[0])
	}
	events, err := svc.Store.ListAuditEvents(ctx, store.AuditFilter{Domain: "example.com", Action: "deployment_report_v2"})
	if err != nil || len(events) != 1 {
		t.Fatalf("部署审计异常: %+v err=%v", events, err)
	}

	// 无效部署状态拒绝。
	if err := svc.ReportDeploymentV2(ctx, "client-a", "example.com", certproto.DeploymentReport{
		Target: "edge-1", State: "bogus",
	}); err != nil {
		requireValidationError(t, err)
	} else {
		t.Fatal("无效部署状态应被拒绝")
	}
}

func TestGetJobV2(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "example.com", "dns_api")
	createV2Token(t, svc, "client-a", false)
	grantV2(t, svc, "client-a", "example.com", "apply")
	svc.V2Issuer = &fakeV2Issuer{}

	resp, err := svc.ReconcileV2(ctx, V2ReconcileRequest{TokenID: "client-a", Domain: "example.com", IdempotencyKey: "k1"})
	if err != nil {
		t.Fatal(err)
	}

	// 无 status 授权拒绝。
	if _, err := svc.GetJobV2(ctx, "client-a", resp.Job.ID); err != nil {
		requirePermissionError(t, err)
	} else {
		t.Fatal("无 status 授权应被拒绝")
	}
	grantV2(t, svc, "client-a", "example.com", "status")
	if err := svc.ExecuteCertificateJob(ctx, "service-test-worker", scheduler.Actor{ID: "worker", Kind: "system"}); err != nil {
		t.Fatal(err)
	}
	job, err := svc.GetJobV2(ctx, "client-a", resp.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.State != certproto.JobStateSucceeded || job.Generation == "" || job.Revision < 1 {
		t.Fatalf("任务状态异常: %+v", job)
	}

	// 不存在的任务返回 not_found。
	_, err = svc.GetJobV2(ctx, "client-a", "no-such-job")
	var protoErr *certproto.ErrorResponse
	if !errors.As(err, &protoErr) || protoErr.Code != certproto.ErrorCodeNotFound {
		t.Fatalf("错误 = %v，期望 not_found", err)
	}
}

func TestListRenewalCandidates(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()
	ctx := context.Background()
	presetV2Cert(t, svc, "a.example.com", "dns_api")
	presetV2Cert(t, svc, "b.example.com", "standalone")

	candidates, err := svc.ListRenewalCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("候选数量 = %d，期望 2: %+v", len(candidates), candidates)
	}
	byDomain := map[string]string{}
	for _, candidate := range candidates {
		byDomain[candidate.Domain] = candidate.ChallengeMode
	}
	if byDomain["a.example.com"] != "dns_api" || byDomain["b.example.com"] != "standalone" {
		t.Fatalf("候选内容异常: %+v", candidates)
	}
}
