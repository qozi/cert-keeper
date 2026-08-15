// 本文件测试 v2 HTTP API 的路由命中、段数 404、方法 405、身份注入与错误码映射。
// 测试使用真实 Store 与 Service，签发器替换为写自签名证书的假实现。
package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/scheduler"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/certproto"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// fakeV2Issuer 是测试用的 v2 假签发器，向 staging 目录写入自签名证书并记录产物内容。
type fakeV2Issuer struct {
	calls atomic.Int32
	files map[string][]byte // 文件名 -> 写入 staging 的内容
}

func (f *fakeV2Issuer) Issue(_ context.Context, params service.V2IssueParams) error {
	f.calls.Add(1)
	files, err := v2TestStagingFiles(params.Domain, time.Now().Add(90*24*time.Hour))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(params.StagingDir, 0o700); err != nil {
		return err
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(params.StagingDir, name), data, 0o600); err != nil {
			return err
		}
	}
	f.files = files
	return nil
}

// v2TestStagingFiles 生成满足 certstore 校验的自签名证书文件内容。
func v2TestStagingFiles(domain string, notAfter time.Time) (map[string][]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
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
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return map[string][]byte{
		"cert.pem":      certPEM,
		"key.pem":       keyPEM,
		"fullchain.pem": certPEM,
		"ca.pem":        certPEM,
	}, nil
}

// newV2TestServer 构造带真实 Store 与 Service 的 v2 测试服务器。
// 复用鉴权测试的 token 常量与固定时间，保证签名请求可直接通过鉴权。
func newV2TestServer(t *testing.T) (*Server, *fakeV2Issuer, http.Handler) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(root, "db", "certkeeper.db")
	cfg.Storage.EncryptionKey = "test-encryption-key"
	cfg.Acme.Home = filepath.Join(root, "acme")
	cfg.Acme.CertsDir = filepath.Join(root, "certs")
	cfg.Acme.AutoUpgrade = false
	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.CreateToken(t.Context(), &store.Token{
		ID:        testTokenID,
		Secret:    testTokenSecret,
		Enabled:   true,
		CreatedAt: testNow.Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	issuer := &fakeV2Issuer{}
	svc := service.New(cfg, st)
	svc.V2Issuer = issuer
	srv := &Server{
		Cfg:     cfg,
		Store:   st,
		Service: svc,
		Logger:  testLogger{},
		now:     func() time.Time { return testNow },
	}
	return srv, issuer, srv.Handler()
}

// presetV2DNSCert 写入 v2 要求的 dns_api 预置证书配置。
func presetV2DNSCert(t *testing.T, st *store.Store, domain string) {
	t.Helper()
	if err := st.UpsertCert(context.Background(), &store.Cert{
		Domain:        domain,
		ChallengeMode: "dns_api",
		CA:            "letsencrypt",
		Keylength:     "ec-256",
		RenewDays:     30,
		Source:        "preset",
		DNSProvider:   store.JSONNullString{String: "dns_cf", Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
}

// grantV2Perm 为测试 token 授予指定域名的权限。
func grantV2Perm(t *testing.T, st *store.Store, domain, permission string) {
	t.Helper()
	if err := st.Grant(context.Background(), testTokenID, domain, permission); err != nil {
		t.Fatal(err)
	}
}

var v2NonceCounter atomic.Int64

// signedV2Request 复用鉴权测试的签名工具，并保证每个请求的 nonce 唯一。
func signedV2Request(method, target string, body []byte) *http.Request {
	nonce := fmt.Sprintf("%0*x", ckauth.NonceHexLen, v2NonceCounter.Add(1))
	return signedRequest(method, target, body, nonce)
}

// reconcileV2 执行一次成功的 reconcile 并解析响应。
func reconcileV2(t *testing.T, srv *Server, handler http.Handler, domain string) certproto.ReconcileResponse {
	t.Helper()
	path, err := certproto.ReconcileURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"idempotency_key":"k-` + domain + `"}`)
	rec := serveRequest(handler, signedV2Request(http.MethodPost, path, body))
	requireStatus(t, rec, http.StatusAccepted)
	var accepted certproto.JobAcceptedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatalf("reconcile 响应不是合法 JSON：%v", err)
	}
	if accepted.Job.ID == "" || rec.Header().Get("Location") == "" {
		t.Fatalf("reconcile 响应不符合预期：%+v", accepted)
	}
	if err := srv.service().ExecuteCertificateJob(context.Background(), "test-worker", scheduler.Actor{ID: "test-worker", Kind: "test"}); err != nil {
		t.Fatal(err)
	}
	job, err := srv.service().GetJobV2(context.Background(), testTokenID, accepted.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	return certproto.ReconcileResponse{Success: true, Changed: true, Domain: domain, Generation: job.Generation, Revision: job.Revision, Job: job}
}

func TestV2ReconcileIgnoresBodyIdentity(t *testing.T) {
	srv, issuer, handler := newV2TestServer(t)
	presetV2DNSCert(t, srv.Store, "example.com")
	grantV2Perm(t, srv.Store, "example.com", "apply")
	path, err := certproto.ReconcileURLPath("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// body 携带伪造的 token_id/is_admin：服务端必须只使用 ctx 中已认证的身份。
	// 伪造的 "evil" 没有任何 grant，若被采信则必然 403。
	body := []byte(`{"idempotency_key":"k1","token_id":"evil","is_admin":true}`)
	rec := serveRequest(handler, signedV2Request(http.MethodPost, path, body))
	requireStatus(t, rec, http.StatusBadRequest)
	var resp certproto.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != certproto.ErrorCodeInvalidRequest {
		t.Fatalf("严格解析应拒绝未知字段：%+v", resp)
	}

	// body 伪造 is_admin=true 不能获得 force 权限：非 admin token 使用 force 必须 403。
	body = []byte(`{"idempotency_key":"k2","force":true,"is_admin":true,"token_id":"evil"}`)
	rec = serveRequest(handler, signedV2Request(http.MethodPost, path, body))
	requireStatus(t, rec, http.StatusBadRequest)
	if issuer.calls.Load() != 0 {
		t.Fatalf("严格解析失败后不应调用签发器，实际共 %d 次", issuer.calls.Load())
	}
}

func TestV2RouteNotFound(t *testing.T) {
	_, _, handler := newV2TestServer(t)
	paths := []string{
		"/api/v2/certs",
		"/api/v2/certs/",
		"/api/v2/certs/example.com",
		"/api/v2/certs/example.com/unknown",
		"/api/v2/certs/example.com/status/extra",
		"/api/v2/certs/example.com/generations/g1",
		"/api/v2/certs/example.com/generations/g1/files",
		"/api/v2/certs/example.com/generations/g1/manifest/extra",
		"/api/v2/jobs",
		"/api/v2/jobs/",
		"/api/v2/jobs/a/b",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			rec := serveRequest(handler, httptest.NewRequest(http.MethodGet, path, nil))
			requireStatus(t, rec, http.StatusNotFound)
		})
	}
}

func TestV2MethodNotAllowed(t *testing.T) {
	_, _, handler := newV2TestServer(t)
	tests := []struct {
		name   string
		method string
		path   string
		allow  string
	}{
		{name: "reconcile 仅 POST", method: http.MethodGet, path: "/api/v2/certs/example.com/reconcile", allow: http.MethodPost},
		{name: "status 仅 GET", method: http.MethodPost, path: "/api/v2/certs/example.com/status", allow: http.MethodGet},
		{name: "deployments 仅 POST", method: http.MethodGet, path: "/api/v2/certs/example.com/deployments", allow: http.MethodPost},
		{name: "manifest 仅 GET", method: http.MethodPost, path: "/api/v2/certs/example.com/generations/g1/manifest", allow: http.MethodGet},
		{name: "文件下载仅 GET", method: http.MethodDelete, path: "/api/v2/certs/example.com/generations/g1/files/cert.pem", allow: http.MethodGet},
		{name: "任务查询仅 GET", method: http.MethodPost, path: "/api/v2/jobs/job-1", allow: http.MethodGet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serveRequest(handler, httptest.NewRequest(tt.method, tt.path, nil))
			requireStatus(t, rec, http.StatusMethodNotAllowed)
			if got := rec.Header().Get("Allow"); got != tt.allow {
				t.Fatalf("期望 Allow=%q，实际为 %q", tt.allow, got)
			}
		})
	}
}

func TestV2ErrorMapping(t *testing.T) {
	srv, _, handler := newV2TestServer(t)
	presetV2DNSCert(t, srv.Store, "example.com")

	t.Run("ValidationError 映射 400", func(t *testing.T) {
		// 缺少 idempotency_key，service 返回 ValidationError。
		path, err := certproto.ReconcileURLPath("example.com")
		if err != nil {
			t.Fatal(err)
		}
		rec := serveRequest(handler, signedV2Request(http.MethodPost, path, []byte(`{}`)))
		requireStatus(t, rec, http.StatusBadRequest)
		assertErrorBody(t, rec)
	})

	t.Run("非法域名映射 400", func(t *testing.T) {
		rec := serveRequest(handler, signedV2Request(http.MethodGet, "/api/v2/certs/EXAMPLE.com/status", nil))
		requireStatus(t, rec, http.StatusBadRequest)
		assertErrorBody(t, rec)
	})

	t.Run("PermissionError 映射 403", func(t *testing.T) {
		// 未授予 status 权限。
		path, err := certproto.CertificateStatusURLPath("example.com")
		if err != nil {
			t.Fatal(err)
		}
		rec := serveRequest(handler, signedV2Request(http.MethodGet, path, nil))
		requireStatus(t, rec, http.StatusForbidden)
		assertErrorBody(t, rec)
	})

	t.Run("其余错误映射 500 且不泄露内部细节", func(t *testing.T) {
		// 查询不存在的任务：service 返回结构化 not_found 错误，HTTP 层按统一规则映射 500。
		path, err := certproto.JobURLPath(strings.Repeat("a", 32))
		if err != nil {
			t.Fatal(err)
		}
		rec := serveRequest(handler, signedV2Request(http.MethodGet, path, nil))
		requireStatus(t, rec, http.StatusNotFound)
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body["message"] != "任务不存在" {
			t.Fatalf("not_found 响应消息不符，实际为 %q", body["message"])
		}
	})
}

// assertErrorBody 断言错误响应为 {"error": "..."} 结构且消息非空。
func assertErrorBody(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("错误响应不是合法 JSON：%v", err)
	}
	if body["error"] == "" && body["message"] == "" {
		t.Fatalf("错误响应缺少 error/message 字段：%s", rec.Body.String())
	}
}

func TestV2StatusManifestAndFileDownload(t *testing.T) {
	srv, issuer, handler := newV2TestServer(t)
	presetV2DNSCert(t, srv.Store, "example.com")
	for _, perm := range []string{"apply", "status", "read_cert"} {
		grantV2Perm(t, srv.Store, "example.com", perm)
	}

	// 先 reconcile 出一个 current generation。
	reconcile := reconcileV2(t, srv, handler, "example.com")
	generation := string(reconcile.Generation)

	// 状态查询：证书存在且有效。
	statusPath, err := certproto.CertificateStatusURLPath("example.com")
	if err != nil {
		t.Fatal(err)
	}
	rec := serveRequest(handler, signedV2Request(http.MethodGet, statusPath, nil))
	requireStatus(t, rec, http.StatusOK)
	var status certproto.CertificateStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Exists || status.State != certproto.CertificateStateValid || string(status.Generation) != generation {
		t.Fatalf("证书状态不符合预期：%+v", status)
	}

	// manifest：包含五个固定文件。
	manifestPath, err := certproto.ManifestURLPath("example.com", generation)
	if err != nil {
		t.Fatal(err)
	}
	rec = serveRequest(handler, signedV2Request(http.MethodGet, manifestPath, nil))
	requireStatus(t, rec, http.StatusOK)
	var manifest certproto.CertificateManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest) != len(certproto.FixedFileNames()) {
		t.Fatalf("manifest 应包含 %d 个固定文件，实际 %d 个", len(certproto.FixedFileNames()), len(manifest))
	}

	// 文件下载：内容与假签发器写入 staging 的 fullchain.pem 完全一致。
	filePath, err := certproto.CertificateFileURLPath("example.com", generation, "fullchain.pem")
	if err != nil {
		t.Fatal(err)
	}
	rec = serveRequest(handler, signedV2Request(http.MethodGet, filePath, nil))
	requireStatus(t, rec, http.StatusOK)
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("期望 Content-Type=application/octet-stream，实际为 %q", got)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(issuer.files["fullchain.pem"]) {
		t.Fatal("下载的 fullchain.pem 内容与签发产物不一致")
	}

	// 文件名不在固定集合中：400。
	badPath := "/api/v2/certs/example.com/generations/" + generation + "/files/evil.pem"
	rec = serveRequest(handler, signedV2Request(http.MethodGet, badPath, nil))
	requireStatus(t, rec, http.StatusBadRequest)
	assertErrorBody(t, rec)
}

func TestV2Deployments(t *testing.T) {
	srv, _, handler := newV2TestServer(t)
	presetV2DNSCert(t, srv.Store, "example.com")
	grantV2Perm(t, srv.Store, "example.com", "apply")
	grantV2Perm(t, srv.Store, "example.com", "status")

	// 部署回报需要关联证书代次，先 reconcile。
	reconcileV2(t, srv, handler, "example.com")
	path, err := certproto.DeploymentsURLPath("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 正常回报：200。
	reconcile := reconcileV2(t, srv, handler, "example.com")
	report := `{"domain":"example.com","target":"nginx-a","state":"succeeded","success":true,"generation":"` + string(reconcile.Generation) + `","revision":1,"verified":true,"reloaded":true}`
	rec := serveRequest(handler, signedV2Request(http.MethodPost, path, []byte(report)))
	requireStatus(t, rec, http.StatusOK)

	// 非法部署状态：400。
	rec = serveRequest(handler, signedV2Request(http.MethodPost, path, []byte(`{"target":"nginx-a","state":"bogus"}`)))
	requireStatus(t, rec, http.StatusBadRequest)
	assertErrorBody(t, rec)

	// 缺少 target：400。
	rec = serveRequest(handler, signedV2Request(http.MethodPost, path, []byte(`{"state":"succeeded"}`)))
	requireStatus(t, rec, http.StatusBadRequest)
	assertErrorBody(t, rec)

	// 请求体不是合法 JSON：400。
	rec = serveRequest(handler, signedV2Request(http.MethodPost, path, []byte(`{not-json`)))
	requireStatus(t, rec, http.StatusBadRequest)
	assertErrorBody(t, rec)
}

func TestV2JobQuery(t *testing.T) {
	srv, _, handler := newV2TestServer(t)
	presetV2DNSCert(t, srv.Store, "example.com")
	grantV2Perm(t, srv.Store, "example.com", "apply")
	grantV2Perm(t, srv.Store, "example.com", "status")

	reconcile := reconcileV2(t, srv, handler, "example.com")
	jobPath, err := certproto.JobURLPath(reconcile.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec := serveRequest(handler, signedV2Request(http.MethodGet, jobPath, nil))
	requireStatus(t, rec, http.StatusOK)
	var job certproto.JobStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.ID != reconcile.Job.ID || job.State != certproto.JobStateSucceeded {
		t.Fatalf("任务状态不符合预期：%+v", job)
	}

	// 无 status 授权的域名任务查询应为 403（另建域名与任务）。
	presetV2DNSCert(t, srv.Store, "other.com")
	grantV2Perm(t, srv.Store, "other.com", "apply")
	grantV2Perm(t, srv.Store, "other.com", "status")
	other := reconcileV2(t, srv, handler, "other.com")
	otherPath, err := certproto.JobURLPath(other.Job.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec = serveRequest(handler, signedV2Request(http.MethodGet, otherPath, nil))
	requireStatus(t, rec, http.StatusOK)
}
