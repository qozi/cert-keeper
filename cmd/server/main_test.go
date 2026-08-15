// 本文件覆盖服务端启动接线的可测试部分：
// HTTP 超时配置、调度器 worker 适配、系统 token 确保逻辑、就绪检查聚合与指标端点。
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/internal/api"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/observability"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
)

// testConfig 返回使用临时目录的测试配置。
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(root, "db", "certkeeper.db")
	cfg.Storage.EncryptionKey = "test-encryption-key"
	cfg.Acme.Home = filepath.Join(root, "acme")
	cfg.Acme.CertsDir = filepath.Join(root, "certs")
	cfg.Log.File = filepath.Join(root, "logs", "server.log")
	for _, dir := range []string{cfg.Acme.Home, cfg.Acme.CertsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

// testLogger 返回丢弃输出的日志记录器。
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// openTestStore 打开测试用 SQLite 存储。
func openTestStore(t *testing.T, cfg *config.Config) *store.Store {
	t.Helper()
	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// fakeV2Issuer 是测试用的假签发器，生成满足 certstore 校验的自签名证书 staging。
type fakeV2Issuer struct {
	calls atomic.Int32
}

func (f *fakeV2Issuer) Issue(_ context.Context, params service.V2IssueParams) error {
	f.calls.Add(1)
	return writeTestStaging(params.StagingDir, params.Domain, time.Now().Add(90*24*time.Hour))
}

// writeTestStaging 生成自签名证书 staging 文件（cert/key/fullchain/ca）。
func writeTestStaging(dir, domain string, notAfter time.Time) error {
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

// presetDNSAPICert 写入一个 dns_api 模式的预置证书配置。
func presetDNSAPICert(t *testing.T, st *store.Store, domain string) {
	t.Helper()
	if err := st.UpsertCert(context.Background(), &store.Cert{
		Domain:        domain,
		ChallengeMode: "dns_api",
		DNSProvider:   store.JSONNullString{String: "dns_cf", Valid: true},
		CA:            "letsencrypt",
		Keylength:     "ec-256",
		RenewDays:     30,
		Source:        "preset",
	}); err != nil {
		t.Fatal(err)
	}
}

// TestNewHTTPServerTimeouts 确认 HTTP 服务器的超时字段来自配置。
func TestNewHTTPServerTimeouts(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Listen = ":18443"
	cfg.Server.ReadHeaderTimeout = 3 * time.Second
	cfg.Server.ReadTimeout = 17 * time.Second
	cfg.Server.WriteTimeout = 61 * time.Second
	cfg.Server.IdleTimeout = 29 * time.Second

	srv := newHTTPServer(cfg, http.NewServeMux())
	if srv.Addr != ":18443" {
		t.Fatalf("Addr 应为 :18443，实际 %s", srv.Addr)
	}
	if srv.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("ReadHeaderTimeout 应为 3s，实际 %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout != 17*time.Second {
		t.Fatalf("ReadTimeout 应为 17s，实际 %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 61*time.Second {
		t.Fatalf("WriteTimeout 应为 61s，实际 %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 29*time.Second {
		t.Fatalf("IdleTimeout 应为 29s，实际 %v", srv.IdleTimeout)
	}
	if srv.Handler == nil {
		t.Fatal("Handler 不应为 nil")
	}
}

// TestReadyzEndpoint 确认 /readyz 聚合就绪检查：全部通过返回 200，任一失败返回 503。
func TestReadyzEndpoint(t *testing.T) {
	cfg := testConfig(t)

	newServer := func(registry *observability.Registry) *api.Server {
		return &api.Server{Cfg: cfg, Metrics: registry, Logger: testLogger()}
	}

	t.Run("全部通过返回 200", func(t *testing.T) {
		registry := observability.NewRegistry()
		if err := registry.RegisterReadiness("ok", func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		newServer(registry).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", rec.Code)
		}
	})

	t.Run("任一失败返回 503", func(t *testing.T) {
		registry := observability.NewRegistry()
		if err := registry.RegisterReadiness("ok", func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if err := registry.RegisterReadiness("broken", func(context.Context) error { return errors.New("故障") }); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		newServer(registry).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", rec.Code)
		}
		body, _ := io.ReadAll(rec.Result().Body)
		// 响应包含检查名与通过状态，但不泄露内部错误文本。
		if !strings.Contains(string(body), "broken") {
			t.Fatalf("响应应包含失败检查名: %s", body)
		}
		if strings.Contains(string(body), "故障") {
			t.Fatalf("响应不应泄露内部错误: %s", body)
		}
	})

	t.Run("ready_enabled 为 false 时不注册", func(t *testing.T) {
		disabled := *cfg
		disabled.Observability.ReadyEnabled = false
		srv := &api.Server{Cfg: &disabled, Metrics: observability.NewRegistry(), Logger: testLogger()}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("期望 404，实际 %d", rec.Code)
		}
	})
}

// TestMetricsEndpoint 确认 /metrics 暴露 Prometheus 文本，且请求计数中间件生效。
func TestMetricsEndpoint(t *testing.T) {
	cfg := testConfig(t)
	registry := observability.NewRegistry()
	if _, err := registry.StandardMetrics(); err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Cfg: cfg, Metrics: registry, Logger: testLogger()}
	handler := srv.Handler()

	// 先产生一个非 /metrics 请求，供后续断言计数。
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz 期望 200，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics 期望 200，实际 %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	text := string(body)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("/metrics Content-Type 应为 text/plain，实际 %s", ct)
	}
	// 请求计数只带 method+status 标签，不含域名/token。
	if !strings.Contains(text, `certkeeper_requests_total{method="GET",status="200"}`) {
		t.Fatalf("指标输出缺少请求计数:\n%s", text)
	}

	t.Run("metrics_enabled 为 false 时不注册", func(t *testing.T) {
		disabled := *cfg
		disabled.Observability.MetricsEnabled = false
		srv := &api.Server{Cfg: &disabled, Metrics: observability.NewRegistry(), Logger: testLogger()}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("期望 404，实际 %d", rec.Code)
		}
	})
}

// TestRegisterReadinessChecks 确认启动时注册的就绪检查在健康环境下全部通过。
func TestRegisterReadinessChecks(t *testing.T) {
	cfg := testConfig(t)
	workerHeartbeat.Store(time.Now().Unix())
	st := openTestStore(t, cfg)
	registry := observability.NewRegistry()
	if err := registerReadinessChecks(registry, cfg, st); err != nil {
		t.Fatal(err)
	}
	report, err := registry.CheckReadiness(context.Background())
	if err != nil {
		t.Fatalf("健康环境下就绪检查应全部通过: %v", err)
	}
	if !report.Ready || len(report.Checks) < 7 {
		t.Fatalf("就绪报告不符预期: %+v", report)
	}
}
