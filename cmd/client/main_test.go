package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/siidoo/certkeeper/internal/client"
)

// TestApplyAutoFallsBackToV1 覆盖服务端不支持 v2（404）时自动回退 v1 申请流程。
func TestApplyAutoFallsBackToV1(t *testing.T) {
	t.Parallel()
	domain := "example.test"
	files := map[string][]byte{
		"cert.pem":      []byte("cert data"),
		"key.pem":       []byte("key data"),
		"fullchain.pem": []byte("fullchain data"),
		"ca.pem":        []byte("ca data"),
		"time.log":      []byte("1234567890\n"),
	}
	var v2Hits atomic.Int32
	server := httptest.NewServer(v1OnlyMux(t, domain, files, &v2Hits))
	defer server.Close()

	outDir := t.TempDir()
	cli := newTestClient(server.URL)
	v2Opts := client.ApplyV2Opts{Domain: domain, OutDir: outDir}
	v1Opts := client.ApplyOpts{
		Domain:        domain,
		OutDir:        outDir,
		CertFile:      "cert.pem",
		KeyFile:       "key.pem",
		FullchainFile: "fullchain.pem",
		CAFile:        "ca.pem",
	}
	if err := applyAuto(cli, v2Opts, v1Opts, false); err != nil {
		t.Fatalf("applyAuto 回退 v1 失败: %v", err)
	}
	if v2Hits.Load() == 0 {
		t.Fatal("回退前应先尝试 v2 reconcile")
	}
	// v1 流程把文件直接下载到输出目录。
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s 内容 = %q，期望 %q", name, got, want)
		}
	}
}

// TestApplyAutoForcedV1 覆盖 --v1 强制旧流程：完全不请求 v2 端点。
func TestApplyAutoForcedV1(t *testing.T) {
	t.Parallel()
	domain := "example.test"
	files := map[string][]byte{
		"cert.pem":      []byte("cert data"),
		"key.pem":       []byte("key data"),
		"fullchain.pem": []byte("fullchain data"),
		"ca.pem":        []byte("ca data"),
		"time.log":      []byte("1234567890\n"),
	}
	var v2Hits atomic.Int32
	server := httptest.NewServer(v1OnlyMux(t, domain, files, &v2Hits))
	defer server.Close()

	outDir := t.TempDir()
	cli := newTestClient(server.URL)
	v1Opts := client.ApplyOpts{
		Domain:        domain,
		OutDir:        outDir,
		CertFile:      "cert.pem",
		KeyFile:       "key.pem",
		FullchainFile: "fullchain.pem",
		CAFile:        "ca.pem",
	}
	if err := applyAuto(cli, client.ApplyV2Opts{}, v1Opts, true); err != nil {
		t.Fatalf("--v1 申请失败: %v", err)
	}
	if v2Hits.Load() != 0 {
		t.Fatal("--v1 不应请求 v2 端点")
	}
	if _, err := os.Stat(filepath.Join(outDir, "cert.pem")); err != nil {
		t.Fatalf("v1 下载产物缺失: %v", err)
	}
}

// TestStatusAutoFallsBackToV1 覆盖 status 在 v2 不可用时回退 v1。
func TestStatusAutoFallsBackToV1(t *testing.T) {
	t.Parallel()
	domain := "example.test"
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /api/v1/certs/"+domain+"/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	if err := statusAuto(newTestClient(server.URL), domain, false); err != nil {
		t.Fatalf("statusAuto 回退 v1 失败: %v", err)
	}
}

// TestDownloadAutoFallsBackToV1 覆盖 download 在 v2 不可用时回退 v1。
func TestDownloadAutoFallsBackToV1(t *testing.T) {
	t.Parallel()
	domain := "example.test"
	content := []byte("cert data")
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("GET /api/v1/certs/"+domain+"/files/", func(w http.ResponseWriter, r *http.Request) {
		if path.Base(r.URL.Path) != "cert.pem" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(content)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	out := filepath.Join(t.TempDir(), "cert.pem")
	if err := downloadAuto(newTestClient(server.URL), domain, "", "cert.pem", out, false); err != nil {
		t.Fatalf("downloadAuto 回退 v1 失败: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("下载内容 = %q，期望 %q", got, content)
	}
}

// v1OnlyMux 构造仅支持 v1 API 的假服务端：/api/v2/ 一律 404，并统计命中次数。
func v1OnlyMux(t *testing.T, domain string, files map[string][]byte, v2Hits *atomic.Int32) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/", func(w http.ResponseWriter, r *http.Request) {
		v2Hits.Add(1)
		http.NotFound(w, r)
	})
	mux.HandleFunc("POST /api/v1/certs/apply", func(w http.ResponseWriter, r *http.Request) {
		metas := make([]map[string]any, 0, len(files))
		for name, data := range files {
			digest := sha256.Sum256(data)
			metas = append(metas, map[string]any{
				"name":   name,
				"size":   len(data),
				"sha256": hex.EncodeToString(digest[:]),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "domain": domain, "files": metas})
	})
	mux.HandleFunc("GET /api/v1/certs/"+domain+"/files/", func(w http.ResponseWriter, r *http.Request) {
		data, ok := files[path.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	})
	return mux
}

// newTestClient 构造指向测试服务端的客户端。
func newTestClient(serverURL string) *client.Client {
	return &client.Client{
		Cfg:  &client.Config{Server: serverURL, TokenID: "test-id", TokenSecret: "test-secret"},
		HTTP: &http.Client{},
		Log:  testLogger{},
	}
}

// testLogger 是丢弃日志的测试 Logger。
type testLogger struct{}

func (testLogger) Info(string, ...any)  {}
func (testLogger) Warn(string, ...any)  {}
func (testLogger) Error(string, ...any) {}
