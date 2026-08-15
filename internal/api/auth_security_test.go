package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

const (
	testTokenID     = "client-1"
	testTokenSecret = "0123456789abcdef0123456789abcdef"
)

var testNow = time.Unix(2_000_000_000, 0)

func newAuthTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	cfg := config.Default()
	cfg.Auth.LegacyAPIEnabled = true
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "db", "certkeeper.db")
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
	srv := &Server{
		Cfg:    cfg,
		Store:  st,
		Logger: testLogger{},
		now:    func() time.Time { return testNow },
	}
	return srv, srv.Handler()
}

func signedRequest(method, target string, body []byte, nonce string) *http.Request {
	bodyHash := ckauth.EmptyBodyHash
	if len(body) > 0 {
		h := sha256.Sum256(body)
		bodyHash = hex.EncodeToString(h[:])
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set(ckauth.HeaderTokenID, testTokenID)
	req.Header.Set(ckauth.HeaderTimestamp, fmt.Sprintf("%d", testNow.Unix()))
	req.Header.Set(ckauth.HeaderNonce, nonce)
	req.Header.Set(ckauth.HeaderBodyHash, bodyHash)
	req.Header.Set(ckauth.HeaderSignature, ckauth.Sign(method, target, testNow.Unix(), nonce, bodyHash, testTokenSecret))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func serveRequest(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func nonceCount(t *testing.T, srv *Server, nonce string) int {
	t.Helper()
	var count int
	if err := srv.Store.DB.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM nonces WHERE nonce = ?`, nonce).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		body, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("期望状态码 %d，实际为 %d：%s", want, rec.Code, body)
	}
}

func TestTamperedBodyDoesNotConsumeNonce(t *testing.T) {
	srv, handler := newAuthTestServer(t)
	nonce := strings.Repeat("1", ckauth.NonceHexLen)
	original := []byte(`{"hostname":"original","os_info":"linux"}`)
	tampered := []byte(`{"hostname":"tampered","os_info":"linux"}`)

	req := signedRequest(http.MethodPost, "/api/v1/client/register", original, nonce)
	req.Body = io.NopCloser(bytes.NewReader(tampered))
	req.ContentLength = int64(len(tampered))
	rec := serveRequest(handler, req)
	requireStatus(t, rec, http.StatusUnauthorized)
	if got := nonceCount(t, srv, nonce); got != 0 {
		t.Fatalf("篡改请求不应写入 nonce，实际写入 %d 条", got)
	}

	rec = serveRequest(handler, signedRequest(http.MethodPost, "/api/v1/client/register", original, nonce))
	requireStatus(t, rec, http.StatusOK)
	if got := nonceCount(t, srv, nonce); got != 1 {
		t.Fatalf("原请求成功后应写入一个 nonce，实际为 %d", got)
	}
	clients, err := srv.Store.ListClients(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].Hostname.String != "original" || clients[0].OSInfo.String != "linux" {
		t.Fatalf("handler 未读取到恢复后的原始 JSON：%+v", clients)
	}
}

func TestInvalidSignatureDoesNotConsumeNonce(t *testing.T) {
	srv, handler := newAuthTestServer(t)
	nonce := strings.Repeat("2", ckauth.NonceHexLen)
	req := signedRequest(http.MethodGet, "/api/v1/ping", nil, nonce)
	req.Header.Set(ckauth.HeaderSignature, strings.Repeat("0", ckauth.HashHexLen))

	rec := serveRequest(handler, req)
	requireStatus(t, rec, http.StatusUnauthorized)
	if got := nonceCount(t, srv, nonce); got != 0 {
		t.Fatalf("错误签名不应写入 nonce，实际写入 %d 条", got)
	}

	rec = serveRequest(handler, signedRequest(http.MethodGet, "/api/v1/ping", nil, nonce))
	requireStatus(t, rec, http.StatusOK)
}

func TestConcurrentRequestsConsumeNonceOnce(t *testing.T) {
	_, handler := newAuthTestServer(t)
	nonce := strings.Repeat("3", ckauth.NonceHexLen)
	const requests = 12

	start := make(chan struct{})
	results := make(chan int, requests)
	var wg sync.WaitGroup
	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := serveRequest(handler, signedRequest(http.MethodGet, "/api/v1/ping", nil, nonce))
			results <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for code := range results {
		switch code {
		case http.StatusOK:
			successes++
		case http.StatusUnauthorized:
		default:
			t.Fatalf("并发请求返回了非预期状态码 %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("同一 nonce 应仅成功一次，实际成功 %d 次", successes)
	}
}

func TestRawQueryParticipatesInSignature(t *testing.T) {
	_, handler := newAuthTestServer(t)
	nonce := strings.Repeat("4", ckauth.NonceHexLen)
	signedTarget := "/api/v1/ping?domain=one&mode=full"
	req := signedRequest(http.MethodGet, signedTarget, nil, nonce)
	req.URL.RawQuery = "domain=two&mode=full"

	rec := serveRequest(handler, req)
	requireStatus(t, rec, http.StatusUnauthorized)

	rec = serveRequest(handler, signedRequest(http.MethodGet, signedTarget, nil, nonce))
	requireStatus(t, rec, http.StatusOK)
}

func TestOversizedBodyRejected(t *testing.T) {
	_, handler := newAuthTestServer(t)
	body := bytes.Repeat([]byte("a"), maxRequestBodySize+1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/client/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := serveRequest(handler, req)

	requireStatus(t, rec, http.StatusRequestEntityTooLarge)
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("缺少 nosniff 安全头，实际值为 %q", got)
	}
}

func TestWriteBodyRequiresJSONContentType(t *testing.T) {
	_, handler := newAuthTestServer(t)
	nonce := strings.Repeat("5", ckauth.NonceHexLen)
	body := []byte(`{"hostname":"client"}`)
	req := signedRequest(http.MethodPost, "/api/v1/client/register", body, nonce)
	req.Header.Del("Content-Type")

	rec := serveRequest(handler, req)
	requireStatus(t, rec, http.StatusUnsupportedMediaType)

	rec = serveRequest(handler, signedRequest(http.MethodPost, "/api/v1/client/register", body, nonce))
	requireStatus(t, rec, http.StatusOK)
}

func TestRouteMethodsReturnAllowHeader(t *testing.T) {
	_, handler := newAuthTestServer(t)
	tests := []struct {
		name   string
		method string
		path   string
		allow  string
	}{
		{name: "健康检查", method: http.MethodPost, path: "/healthz", allow: http.MethodGet},
		{name: "客户端注册", method: http.MethodGet, path: "/api/v1/client/register", allow: http.MethodPost},
		{name: "管理员 provider", method: http.MethodPost, path: "/api/v1/admin/providers", allow: http.MethodGet},
		{name: "证书重签", method: http.MethodDelete, path: "/api/v1/admin/certs/example.com/reissue", allow: http.MethodPost},
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
