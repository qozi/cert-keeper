// Package e2e 提供 CertKeeper v2 全链路端到端集成测试。
//
// 测试使用全部真实组件：store（临时 SQLite）、service（注入假 v2 签发器）、
// api.Server（httptest 真实 HTTP）、internal/client（真实 HMAC 客户端）。
// 唯一替换的外部依赖是 ACME 签发器：fakeV2Issuer 在 StagingDir 生成
// 覆盖域名与 SAN 的自签 ECC 证书，避免依赖真实 CA。
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/internal/api"
	"github.com/siidoo/certkeeper/internal/client"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// discardLogger 同时满足 api.Logger 与 client.Logger，测试中丢弃日志输出。
type discardLogger struct{}

func (discardLogger) Info(string, ...any)  {}
func (discardLogger) Warn(string, ...any)  {}
func (discardLogger) Error(string, ...any) {}

// fakeV2Issuer 是端到端测试用的假 v2 签发器。
// 它在 StagingDir 生成满足 certstore 校验的自签 ECC 证书（覆盖域名与全部 SAN、
// 未过期、私钥匹配），并用原子计数器记录实际签发次数，供并发/幂等断言使用；
// fail 置位后签发恒失败，用于故障场景测试。
type fakeV2Issuer struct {
	calls atomic.Int32
	fail  atomic.Bool
}

// Issue 实现 service.V2Issuer 接口。
func (f *fakeV2Issuer) Issue(_ context.Context, params service.V2IssueParams) error {
	f.calls.Add(1)
	if f.fail.Load() {
		return errors.New("假签发器故障")
	}
	return writeSelfSignedStaging(params.StagingDir, params.Domain, params.SAN)
}

// writeSelfSignedStaging 在 dir 下生成一套自签 ECC 证书产物：
// cert.pem、key.pem、fullchain.pem、ca.pem、time.log。
// 叶子证书覆盖 domain 与全部 SAN，有效期为当前前后一段时间内，私钥与证书匹配。
func writeSelfSignedStaging(dir, domain string, san []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              append([]string{domain}, san...),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
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
		"time.log":      []byte(strconv.FormatInt(now.Unix(), 10) + "\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// e2eEnv 封装一套完整的端到端测试环境：真实 Store/Service/HTTP 服务与假签发器。
type e2eEnv struct {
	cfg        *config.Config
	store      *store.Store
	service    *service.Service
	issuer     *fakeV2Issuer
	server     *httptest.Server
	httpClient *http.Client
}

// newE2EEnv 构造端到端测试环境：临时 SQLite、临时 certstore、真实 api.Server
// 挂在 httptest.Server 上，v2 签发器替换为 fakeV2Issuer。
func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(root, "db", "certkeeper.db")
	cfg.Storage.EncryptionKey = "e2e-encryption-key"
	cfg.Acme.Home = filepath.Join(root, "acme")
	cfg.Acme.CertsDir = filepath.Join(root, "certs")
	cfg.Acme.AutoUpgrade = false

	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatalf("打开测试 Store 失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	issuer := &fakeV2Issuer{}
	svc := service.New(cfg, st)
	svc.V2Issuer = issuer
	srv := &api.Server{Cfg: cfg, Store: st, Service: svc, Logger: discardLogger{}}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return &e2eEnv{
		cfg:        cfg,
		store:      st,
		service:    svc,
		issuer:     issuer,
		server:     ts,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// createToken 通过 Store.CreateTokenWithSecret 直接创建 token（不走 HTTP admin API），
// 返回明文机密供客户端签名使用。
func (e *e2eEnv) createToken(t *testing.T, id string, isAdmin bool) string {
	t.Helper()
	secret, err := ckauth.GenSecret()
	if err != nil {
		t.Fatalf("生成 token secret 失败: %v", err)
	}
	err = e.store.CreateTokenWithSecret(t.Context(), &store.Token{
		ID: id, Enabled: true, IsAdmin: isAdmin,
	}, secret)
	if err != nil {
		t.Fatalf("创建 token %s 失败: %v", id, err)
	}
	return secret
}

// presetDNSAPICert 通过 Store.UpsertCert 直接预置 dns_api 证书配置（v2 唯一支持的模式）。
func (e *e2eEnv) presetDNSAPICert(t *testing.T, domain string, san ...string) {
	t.Helper()
	err := e.store.UpsertCert(t.Context(), &store.Cert{
		Domain:        domain,
		SAN:           strings.Join(san, ","),
		CA:            "letsencrypt",
		ChallengeMode: "dns_api",
		DNSProvider:   store.JSONNullString{String: "dns_cf", Valid: true},
		Keylength:     "ec-256",
		RenewDays:     30,
		Source:        "preset",
	})
	if err != nil {
		t.Fatalf("预置证书配置 %s 失败: %v", domain, err)
	}
}

// grant 为 token 授予指定域名的权限集合。
func (e *e2eEnv) grant(t *testing.T, tokenID, domain string, permissions ...string) {
	t.Helper()
	for _, permission := range permissions {
		if err := e.store.Grant(t.Context(), tokenID, domain, permission); err != nil {
			t.Fatalf("授权 %s %s %s 失败: %v", tokenID, domain, permission, err)
		}
	}
}

// newClient 创建指向测试服务器的真实 HMAC 客户端。
func (e *e2eEnv) newClient(tokenID, secret string) *client.Client {
	return &client.Client{
		Cfg:  &client.Config{Server: e.server.URL, TokenID: tokenID, TokenSecret: secret},
		HTTP: e.httpClient,
		Log:  discardLogger{},
	}
}

// signHeaders 按 ckauth 协议为请求计算签名头（时间戳、nonce、body 摘要、HMAC 签名）。
func signHeaders(t *testing.T, tokenID, secret, method, path string, body []byte) http.Header {
	t.Helper()
	bodyHash := ckauth.EmptyBodyHash
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(sum[:])
	}
	ts := ckauth.Now()
	nonce, err := ckauth.GenNonce()
	if err != nil {
		t.Fatalf("生成 nonce 失败: %v", err)
	}
	header := http.Header{}
	header.Set(ckauth.HeaderTokenID, tokenID)
	header.Set(ckauth.HeaderTimestamp, strconv.FormatInt(ts, 10))
	header.Set(ckauth.HeaderNonce, nonce)
	header.Set(ckauth.HeaderBodyHash, bodyHash)
	header.Set(ckauth.HeaderSignature, ckauth.Sign(method, path, ts, nonce, bodyHash, secret))
	if len(body) > 0 {
		header.Set("Content-Type", "application/json")
	}
	return header
}

// doRaw 发送一个带预制请求头的原始 HTTP 请求，返回状态码与响应体。
func (e *e2eEnv) doRaw(t *testing.T, method, path string, body []byte, header http.Header) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, e.server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	req.Header = header
	resp, err := e.httpClient.Do(req)
	if err != nil {
		t.Fatalf("请求 %s %s 失败: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	return resp.StatusCode, data
}

// signedDo 发送一个正确签名的 HTTP 请求，返回状态码与响应体。
func (e *e2eEnv) signedDo(t *testing.T, tokenID, secret, method, path string, body []byte) (int, []byte) {
	t.Helper()
	return e.doRaw(t, method, path, body, signHeaders(t, tokenID, secret, method, path, body))
}

// readLocalCurrent 读取客户端部署目录中的 current generation 指针。
func readLocalCurrent(t *testing.T, outDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(outDir, "current"))
	if err != nil {
		t.Fatalf("读取客户端 current 失败: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// readServerCurrent 读取服务端 certstore 中的 current generation 指针。
func (e *e2eEnv) readServerCurrent(t *testing.T, domain string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(e.cfg.Acme.CertsDir, domain, "current"))
	if err != nil {
		t.Fatalf("读取服务端 current 失败: %v", err)
	}
	return strings.TrimSpace(string(data))
}
