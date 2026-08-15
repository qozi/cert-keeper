package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

// TestApplyV2FullFlow 覆盖完整 v2 流程：reconcile → manifest → 下载 → 部署 → 回报。
func TestApplyV2FullFlow(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	outDir := t.TempDir()
	verifyMarker := filepath.Join(t.TempDir(), "verify.log")
	reloadMarker := filepath.Join(t.TempDir(), "reload.log")
	cli := testV1Client(server.URL)
	err := cli.ApplyV2(context.Background(), ApplyV2Opts{
		Domain:    "example.test",
		OutDir:    outDir,
		VerifyCmd: "echo verify >> " + verifyMarker,
		ReloadCmd: "echo reload >> " + reloadMarker,
	})
	if err != nil {
		t.Fatalf("ApplyV2 失败: %v", err)
	}
	// current 指向目标 generation，release 文件内容一致。
	if got := readCurrentForTest(t, outDir); got != "gen-1" {
		t.Fatalf("current = %q，期望 gen-1", got)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(outDir, "releases", "gen-1", string(name)))
		if err != nil {
			t.Fatalf("读取 release 文件 %s 失败: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("release 文件 %s 内容不一致", name)
		}
	}
	// verify/reload 命令均已执行。
	for _, marker := range []string{verifyMarker, reloadMarker} {
		data, err := os.ReadFile(marker)
		if err != nil || len(bytes.TrimSpace(data)) == 0 {
			t.Fatalf("命令标记文件 %s 缺失或为空: %v", marker, err)
		}
	}
	// 服务端收到成功回报。
	reports := fake.Reports()
	if len(reports) != 1 {
		t.Fatalf("回报次数 = %d，期望 1", len(reports))
	}
	report := reports[0]
	if !report.Success || !report.Verified || !report.Reloaded {
		t.Fatalf("回报字段异常: %+v", report)
	}
	if report.State != certproto.DeploymentStateSucceeded || report.Generation != "gen-1" || report.Revision != 1 {
		t.Fatalf("回报状态异常: %+v", report)
	}
	if report.Message == "" || report.Target == "" {
		t.Fatalf("回报缺少 message/target: %+v", report)
	}
	// reconcile 请求体符合协议。
	bodies := fake.ReconcileBodies()
	if len(bodies) != 1 {
		t.Fatalf("reconcile 请求次数 = %d，期望 1", len(bodies))
	}
	body := bodies[0]
	if body["operation"] != "client" {
		t.Fatalf("operation = %v，期望 client", body["operation"])
	}
	if body["reason"] == "" {
		t.Fatal("reason 不能为空")
	}
	key, _ := body["idempotency_key"].(string)
	if len(key) != 32 {
		t.Fatalf("自动生成的幂等键 = %q，期望 32 位十六进制", key)
	}
	if _, hasForce := body["force"]; hasForce {
		t.Fatal("未开启 force 时不应携带 force 字段")
	}
}

// TestApplyV2Accepts202AndPassesRequestFields 覆盖 202 响应与显式幂等键/force 透传。
func TestApplyV2Accepts202AndPassesRequestFields(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	fake.reconcileStatus = http.StatusAccepted
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	cli := testV1Client(server.URL)
	err := cli.ApplyV2(context.Background(), ApplyV2Opts{
		Domain:         "example.test",
		OutDir:         t.TempDir(),
		IdempotencyKey: "manual-key-1",
		Force:          true,
	})
	if err != nil {
		t.Fatalf("ApplyV2 失败: %v", err)
	}
	body := fake.ReconcileBodies()[0]
	if body["idempotency_key"] != "manual-key-1" {
		t.Fatalf("idempotency_key = %v，期望 manual-key-1", body["idempotency_key"])
	}
	if body["force"] != true {
		t.Fatalf("force = %v，期望 true", body["force"])
	}
}

// TestApplyV2FetchesManifestWhenMissing 覆盖 reconcile 响应不含 manifest 时单独获取。
func TestApplyV2FetchesManifestWhenMissing(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	fake.reconcileManifest = false
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	outDir := t.TempDir()
	cli := testV1Client(server.URL)
	if err := cli.ApplyV2(context.Background(), ApplyV2Opts{Domain: "example.test", OutDir: outDir}); err != nil {
		t.Fatalf("ApplyV2 失败: %v", err)
	}
	if hits := fake.ManifestHits(); hits != 1 {
		t.Fatalf("manifest 请求次数 = %d，期望 1", hits)
	}
	if got := readCurrentForTest(t, outDir); got != "gen-1" {
		t.Fatalf("current = %q，期望 gen-1", got)
	}
}

// TestApplyV2SameGenerationSkips 覆盖相同 generation 跳过：不下载、不执行 verify/reload。
func TestApplyV2SameGenerationSkips(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	outDir := t.TempDir()
	markerDir := t.TempDir()
	verifyMarker := filepath.Join(markerDir, "verify.log")
	reloadMarker := filepath.Join(markerDir, "reload.log")
	logger := &captureLogger{}
	cli := testV1Client(server.URL)
	cli.Log = logger
	opts := ApplyV2Opts{
		Domain:    "example.test",
		OutDir:    outDir,
		VerifyCmd: "echo verify >> " + verifyMarker,
		ReloadCmd: "echo reload >> " + reloadMarker,
	}
	if err := cli.ApplyV2(context.Background(), opts); err != nil {
		t.Fatalf("首次 ApplyV2 失败: %v", err)
	}
	if err := cli.ApplyV2(context.Background(), opts); err != nil {
		t.Fatalf("第二次 ApplyV2 失败: %v", err)
	}
	// verify/reload 只执行过一次（第二次被跳过）。
	for _, marker := range []string{verifyMarker, reloadMarker} {
		data, err := os.ReadFile(marker)
		if err != nil {
			t.Fatalf("读取标记文件失败: %v", err)
		}
		if lines := strings.Count(string(data), "\n"); lines != 1 {
			t.Fatalf("%s 执行次数 = %d，期望 1", marker, lines)
		}
	}
	// 第二次回报状态为 skipped，且客户端打印了跳过信息。
	reports := fake.Reports()
	if len(reports) != 2 {
		t.Fatalf("回报次数 = %d，期望 2", len(reports))
	}
	if reports[1].State != certproto.DeploymentStateSkipped || !reports[1].Success {
		t.Fatalf("第二次回报状态异常: %+v", reports[1])
	}
	if !logger.contains("跳过部署") {
		t.Fatal("客户端未打印跳过信息")
	}
}

// TestApplyV2RejectsCorruptedDownload 覆盖下载哈希错误：部署失败、不创建 current、回报失败。
func TestApplyV2RejectsCorruptedDownload(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	fake.corruptFile = certproto.FileFullchain
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	outDir := t.TempDir()
	cli := testV1Client(server.URL)
	err := cli.ApplyV2(context.Background(), ApplyV2Opts{Domain: "example.test", OutDir: outDir})
	if err == nil {
		t.Fatal("下载哈希错误未返回")
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "current")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("哈希错误不应创建 current: %v", statErr)
	}
	reports := fake.Reports()
	if len(reports) != 1 {
		t.Fatalf("回报次数 = %d，期望 1", len(reports))
	}
	if reports[0].Success || reports[0].State != certproto.DeploymentStateFailed {
		t.Fatalf("失败回报状态异常: %+v", reports[0])
	}
}

// TestApplyV2ReportFailureIsNotFatal 覆盖回报失败不影响本地部署结果。
func TestApplyV2ReportFailureIsNotFatal(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	fake.reportStatus = http.StatusInternalServerError
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	outDir := t.TempDir()
	logger := &captureLogger{}
	cli := testV1Client(server.URL)
	cli.Log = logger
	if err := cli.ApplyV2(context.Background(), ApplyV2Opts{Domain: "example.test", OutDir: outDir}); err != nil {
		t.Fatalf("回报失败不应影响部署结果: %v", err)
	}
	if got := readCurrentForTest(t, outDir); got != "gen-1" {
		t.Fatalf("current = %q，期望 gen-1", got)
	}
	if !logger.contains("回报失败") {
		t.Fatal("回报失败应记录警告")
	}
}

// TestApplyV2UnsupportedServer 覆盖服务端未实现 v2（404/501）时返回 ErrV2NotSupported。
func TestApplyV2UnsupportedServer(t *testing.T) {
	t.Parallel()
	for _, code := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not implemented", code)
		}))
		cli := testV1Client(server.URL)
		err := cli.ApplyV2(context.Background(), ApplyV2Opts{Domain: "example.test", OutDir: t.TempDir()})
		if err == nil {
			t.Fatalf("状态 %d 应失败", code)
		}
		server.Close()
	}
}

// TestStatusV2AndDownloadV2 覆盖 v2 状态查询与单文件下载（generation 为空时取 current）。
func TestStatusV2AndDownloadV2(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	fake := newFakeV2Server(t, "example.test", "gen-1", files)
	server := httptest.NewServer(fake.handler())
	defer server.Close()

	cli := testV1Client(server.URL)
	if err := cli.StatusV2("example.test"); err != nil {
		t.Fatalf("StatusV2 失败: %v", err)
	}
	// generation 为空时通过 status 解析 current generation。
	out := filepath.Join(t.TempDir(), "cert.pem")
	if err := cli.DownloadV2("example.test", "", "cert.pem", out); err != nil {
		t.Fatalf("DownloadV2 失败: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, files[certproto.FileCert]) {
		t.Fatal("下载内容与服务端不一致")
	}
	// 显式 generation 下载。
	out2 := filepath.Join(t.TempDir(), "key.pem")
	if err := cli.DownloadV2("example.test", "gen-1", "key.pem", out2); err != nil {
		t.Fatalf("DownloadV2 显式 generation 失败: %v", err)
	}
	data, err = os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, files[certproto.FileKey]) {
		t.Fatal("下载内容与服务端不一致")
	}
}

// TestV2EndpointsUnsupported 覆盖 status/download 在不支持 v2 的服务端上返回 ErrV2NotSupported。
func TestV2EndpointsUnsupported(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	cli := testV1Client(server.URL)
	if err := cli.StatusV2("example.test"); err == nil {
		t.Fatal("StatusV2 应失败")
	}
	out := filepath.Join(t.TempDir(), "cert.pem")
	if err := cli.DownloadV2("example.test", "", "cert.pem", out); err == nil {
		t.Fatal("DownloadV2 应失败")
	}
	if err := cli.DownloadV2("example.test", "gen-1", "cert.pem", out); err == nil {
		t.Fatal("DownloadV2 应失败")
	}
}

// fakeV2Server 是测试用的 v2 假服务端，按 certproto 路径提供
// reconcile / manifest / 文件下载 / 状态 / 部署回报端点。
type fakeV2Server struct {
	t          *testing.T
	domain     string
	generation certproto.GenerationID
	files      map[certproto.FileName][]byte
	manifest   certproto.CertificateManifest

	// reconcileStatus 是 reconcile 返回的 HTTP 状态码（默认 200）。
	reconcileStatus int
	// reconcileManifest 表示 reconcile 响应是否携带 manifest（默认携带）。
	reconcileManifest bool
	// reportStatus 是部署回报端点返回的 HTTP 状态码（默认 200）。
	reportStatus int
	// corruptFile 非空时，该文件下载返回损坏内容。
	corruptFile certproto.FileName

	mu              sync.Mutex
	reconcileBodies []map[string]any
	manifestHits    int
	reports         []certproto.DeploymentReport
}

func newFakeV2Server(t *testing.T, domain string, generation certproto.GenerationID, files map[certproto.FileName][]byte) *fakeV2Server {
	t.Helper()
	return &fakeV2Server{
		t:                 t,
		domain:            domain,
		generation:        generation,
		files:             files,
		manifest:          testManifest(files),
		reconcileStatus:   http.StatusOK,
		reconcileManifest: true,
		reportStatus:      http.StatusOK,
	}
}

func (f *fakeV2Server) handler() http.Handler {
	reconcilePath, err := certproto.ReconcileURLPath(f.domain)
	if err != nil {
		f.t.Fatal(err)
	}
	statusPath, err := certproto.CertificateStatusURLPath(f.domain)
	if err != nil {
		f.t.Fatal(err)
	}
	manifestPath, err := certproto.ManifestURLPath(f.domain, string(f.generation))
	if err != nil {
		f.t.Fatal(err)
	}
	deploymentsPath, err := certproto.DeploymentsURLPath(f.domain)
	if err != nil {
		f.t.Fatal(err)
	}
	jobPath, err := certproto.JobURLPath("job-1")
	if err != nil {
		f.t.Fatal(err)
	}
	// 由合法文件路径推导出 files 前缀，用于前缀路由。
	certPath, err := certproto.CertificateFileURLPath(f.domain, string(f.generation), string(certproto.FileCert))
	if err != nil {
		f.t.Fatal(err)
	}
	filesPrefix := strings.TrimSuffix(certPath, string(certproto.FileCert))
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+certproto.CapabilitiesURLPath(), func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(certproto.DefaultCapabilities())
	})
	mux.HandleFunc("POST "+reconcilePath, f.handleReconcile)
	mux.HandleFunc("GET "+jobPath, f.handleJob)
	mux.HandleFunc("GET "+statusPath, f.handleStatus)
	mux.HandleFunc("GET "+manifestPath, f.handleManifest)
	mux.HandleFunc("GET "+filesPrefix, f.handleFile)
	mux.HandleFunc("POST "+deploymentsPath, f.handleReport)
	return mux
}

func (f *fakeV2Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.reconcileBodies = append(f.reconcileBodies, body)
	f.mu.Unlock()
	manifest := certproto.CertificateManifest{}
	if f.reconcileManifest {
		manifest = f.manifest
	}
	resp := certproto.ReconcileResponse{
		Success:    true,
		Domain:     f.domain,
		Generation: f.generation,
		Revision:   1,
		Changed:    true,
		Job:        certproto.JobStatus{ID: "job-1", State: certproto.JobStateSucceeded, Generation: f.generation, Revision: 1, CreatedAt: time.Now()},
		Status: certproto.CertificateStatus{
			Domain:     f.domain,
			Generation: f.generation,
			Revision:   1,
			State:      certproto.CertificateStateValid,
			NotAfter:   time.Now().Add(time.Hour),
			Files:      manifest,
			Exists:     true,
		},
	}
	if f.reconcileStatus == http.StatusAccepted {
		job := certproto.JobStatus{ID: "job-1", State: certproto.JobStateQueued, CreatedAt: time.Now()}
		accepted := certproto.JobAcceptedResponse{Job: job, Location: "/api/v2/jobs/job-1"}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(accepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.reconcileStatus)
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeV2Server) handleJob(w http.ResponseWriter, r *http.Request) {
	job := certproto.JobStatus{ID: "job-1", State: certproto.JobStateSucceeded, Generation: f.generation, Revision: 1, CreatedAt: time.Now()}
	_ = json.NewEncoder(w).Encode(job)
}

func (f *fakeV2Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := certproto.CertificateStatus{
		Domain:     f.domain,
		Generation: f.generation,
		Revision:   1,
		State:      certproto.CertificateStateValid,
		NotAfter:   time.Now().Add(time.Hour),
		Files:      f.manifest,
		Exists:     true,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (f *fakeV2Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.manifestHits++
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f.manifest)
}

func (f *fakeV2Server) handleFile(w http.ResponseWriter, r *http.Request) {
	name := path.Base(r.URL.Path)
	data, ok := f.files[certproto.FileName(name)]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if certproto.FileName(name) == f.corruptFile {
		data = append(append([]byte(nil), data...), 'x')
	}
	_, _ = w.Write(data)
}

func (f *fakeV2Server) handleReport(w http.ResponseWriter, r *http.Request) {
	var report certproto.DeploymentReport
	if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.reports = append(f.reports, report)
	f.mu.Unlock()
	if f.reportStatus != http.StatusOK {
		http.Error(w, "report rejected", f.reportStatus)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

// ReconcileBodies 返回收到的 reconcile 请求体列表。
func (f *fakeV2Server) ReconcileBodies() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.reconcileBodies...)
}

// ManifestHits 返回 manifest 端点被请求的次数。
func (f *fakeV2Server) ManifestHits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.manifestHits
}

// Reports 返回收到的部署回报列表。
func (f *fakeV2Server) Reports() []certproto.DeploymentReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]certproto.DeploymentReport(nil), f.reports...)
}

// captureLogger 是记录日志消息的测试 Logger。
type captureLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *captureLogger) Info(msg string, args ...any)  { l.record(msg) }
func (l *captureLogger) Warn(msg string, args ...any)  { l.record(msg) }
func (l *captureLogger) Error(msg string, args ...any) { l.record(msg) }

func (l *captureLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
}

func (l *captureLogger) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, msg := range l.msgs {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}
