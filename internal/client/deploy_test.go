package client

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

func TestDeployGenerationRejectsUnsafeManifest(t *testing.T) {
	t.Parallel()
	for _, manifest := range []certproto.CertificateManifest{
		{{Name: "../key.pem", Size: 0, SHA256: sha256Hex(nil)}},
		{{Name: "unknown.pem", Size: 0, SHA256: sha256Hex(nil)}},
		{
			{Name: string(certproto.FileCert), Size: 0, SHA256: sha256Hex(nil)},
			{Name: string(certproto.FileCert), Size: 0, SHA256: sha256Hex(nil)},
		},
	} {
		_, err := DeployGeneration(context.Background(), GenerationDeployOpts{
			Domain:     "example.test",
			OutDir:     t.TempDir(),
			Generation: "generation-1",
			Manifest:   manifest,
			Fetch: func(context.Context, certproto.FileName) ([]byte, error) {
				t.Fatal("不应调用下载函数")
				return nil, nil
			},
		})
		if err == nil {
			t.Fatalf("不安全 manifest 未被拒绝: %#v", manifest)
		}
	}
}

func TestDeployGenerationRejectsHashMismatch(t *testing.T) {
	t.Parallel()
	files := testCertificateFiles(t, "example.test")
	manifest := testManifest(files)
	manifest[0].SHA256 = sha256Hex([]byte("different"))
	outDir := t.TempDir()
	_, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-1", manifest, files))
	if err == nil {
		t.Fatal("哈希不符未返回错误")
	}
	if _, err := os.Stat(filepath.Join(outDir, "current")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("哈希不符不应创建 current: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(outDir, "releases"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == "generation-1" {
			t.Fatal("哈希不符不应发布 release")
		}
	}
}

func TestDeployGenerationRejectsInvalidCertificateBundle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		files  func(*testing.T) map[certproto.FileName][]byte
		adjust func(*GenerationDeployOpts)
	}{
		{
			name: "无效 PEM",
			files: func(t *testing.T) map[certproto.FileName][]byte {
				files := testCertificateFiles(t, "example.test")
				files[certproto.FileCert] = []byte("not a PEM")
				return files
			},
		},
		{
			name: "私钥不匹配",
			files: func(t *testing.T) map[certproto.FileName][]byte {
				files := testCertificateFiles(t, "example.test")
				other := testCertificateFiles(t, "example.test")
				files[certproto.FileKey] = other[certproto.FileKey]
				return files
			},
		},
		{
			name: "目标 SAN 不匹配",
			files: func(t *testing.T) map[certproto.FileName][]byte {
				return testCertificateFiles(t, "example.test")
			},
			adjust: func(opts *GenerationDeployOpts) {
				opts.SAN = []string{"missing.example.test"}
			},
		},
		{
			name: "证书过期",
			files: func(t *testing.T) map[certproto.FileName][]byte {
				now := time.Now()
				return testCertificateFilesWithValidity(t, "example.test", now.Add(-2*time.Hour), now.Add(-time.Hour))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			files := test.files(t)
			outDir := t.TempDir()
			opts := deploymentOptions(outDir, "generation-1", testManifest(files), files)
			if test.adjust != nil {
				test.adjust(&opts)
			}
			if _, err := DeployGeneration(context.Background(), opts); err == nil {
				t.Fatal("无效证书包未被拒绝")
			}
			if _, err := os.Stat(filepath.Join(outDir, "current")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("失败部署不应创建 current: %v", err)
			}
		})
	}
}

func TestDeployGenerationRejectsSymlinkCurrent(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	if err := os.Symlink(filepath.Join(outDir, "other"), filepath.Join(outDir, "current")); err != nil {
		t.Fatal(err)
	}
	files := testCertificateFiles(t, "example.test")
	_, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-1", testManifest(files), files))
	if err == nil {
		t.Fatal("符号链接 current 未被拒绝")
	}
}

func TestDeployGenerationVerifyFailureRestoresPreviousCurrent(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	previousFiles := testCertificateFiles(t, "example.test")
	previousManifest := testManifest(previousFiles)
	if _, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-old", previousManifest, previousFiles)); err != nil {
		t.Fatalf("部署旧版本失败: %v", err)
	}
	newFiles := testCertificateFiles(t, "example.test")
	opts := deploymentOptions(outDir, "generation-new", testManifest(newFiles), newFiles)
	opts.Verify = func(context.Context, string) error { return errors.New("校验错误") }
	if _, err := DeployGeneration(context.Background(), opts); err == nil {
		t.Fatal("校验失败未返回错误")
	}
	current := readCurrentForTest(t, outDir)
	if current != "generation-old" {
		t.Fatalf("校验失败后 current = %q，期望 generation-old", current)
	}
	if _, err := os.Stat(filepath.Join(outDir, "releases", "generation-new")); err != nil {
		t.Fatalf("新 release 应保留供排查: %v", err)
	}
}

func TestDeployGenerationReloadFailureKeepsNewCurrent(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	oldFiles := testCertificateFiles(t, "example.test")
	if _, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-old", testManifest(oldFiles), oldFiles)); err != nil {
		t.Fatalf("部署旧版本失败: %v", err)
	}
	newFiles := testCertificateFiles(t, "example.test")
	opts := deploymentOptions(outDir, "generation-new", testManifest(newFiles), newFiles)
	opts.Reload = func(context.Context, string) error { return errors.New("reload 错误") }
	report, err := DeployGeneration(context.Background(), opts)
	var retryable *RetryableError
	if !errors.As(err, &retryable) {
		t.Fatalf("reload 错误应为可重试错误: %v", err)
	}
	if !report.Error.Retryable {
		t.Fatal("reload 错误报告应标记可重试")
	}
	if current := readCurrentForTest(t, outDir); current != "generation-new" {
		t.Fatalf("reload 失败后 current = %q，期望 generation-new", current)
	}
}

func TestDeployGenerationSameGenerationSkipsFetchAndCommands(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	files := testCertificateFiles(t, "example.test")
	if _, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-1", testManifest(files), files)); err != nil {
		t.Fatalf("首次部署失败: %v", err)
	}
	called := false
	opts := deploymentOptions(outDir, "generation-1", testManifest(files), files)
	opts.Fetch = func(context.Context, certproto.FileName) ([]byte, error) {
		called = true
		return nil, errors.New("不应下载")
	}
	opts.Verify = func(context.Context, string) error {
		called = true
		return errors.New("不应校验")
	}
	opts.Reload = func(context.Context, string) error {
		called = true
		return errors.New("不应 reload")
	}
	report, err := DeployGeneration(context.Background(), opts)
	if err != nil {
		t.Fatalf("同 generation 应跳过: %v", err)
	}
	if called {
		t.Fatal("同 generation 不应下载、校验或 reload")
	}
	if report.State != certproto.DeploymentStateSkipped {
		t.Fatalf("状态 = %q，期望 skipped", report.State)
	}
}

func TestDeployGenerationSerializesConcurrentDeployment(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	files := testCertificateFiles(t, "example.test")
	entered := make(chan struct{})
	release := make(chan struct{})
	first := deploymentOptions(outDir, "generation-one", testManifest(files), files)
	first.Verify = func(context.Context, string) error {
		close(entered)
		<-release
		return nil
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := DeployGeneration(context.Background(), first)
		firstDone <- err
	}()
	<-entered

	secondFiles := testCertificateFiles(t, "example.test")
	secondDone := make(chan error, 1)
	go func() {
		_, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-two", testManifest(secondFiles), secondFiles))
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("第二个部署在锁释放前完成: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("第一个部署失败: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("第二个部署失败: %v", err)
	}
	if current := readCurrentForTest(t, outDir); current != "generation-two" {
		t.Fatalf("current = %q，期望 generation-two", current)
	}
}

func TestDeployGenerationUsesPrivatePermissions(t *testing.T) {
	t.Parallel()
	outDir := t.TempDir()
	files := testCertificateFiles(t, "example.test")
	if _, err := DeployGeneration(context.Background(), deploymentOptions(outDir, "generation-1", testManifest(files), files)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		outDir,
		filepath.Join(outDir, "releases"),
		filepath.Join(outDir, "releases", "generation-1"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("%s 权限 = %o，期望 0700", path, info.Mode().Perm())
		}
	}
	for _, path := range []string{
		filepath.Join(outDir, "releases", "generation-1", string(certproto.FileKey)),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s 权限 = %o，期望 0600", path, info.Mode().Perm())
		}
	}
}

func TestApplyRejectsUnknownResponseFileBeforeDownloading(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/certs/apply" {
			t.Fatalf("不应下载未知文件，收到路径 %q", r.URL.Path)
		}
		writeApplyResponse(t, w, []fileMeta{{Name: "../outside.pem", Size: 0, SHA256: sha256Hex(nil)}})
	}))
	defer server.Close()

	cli := testV1Client(server.URL)
	err := cli.Apply(ApplyOpts{Domain: "example.test", OutDir: t.TempDir(), CertFile: "cert.pem"})
	if err == nil {
		t.Fatal("未知文件名未被拒绝")
	}
}

func TestApplyRestoresBackupOnDownloadHTTPFailure(t *testing.T) {
	oldData := []byte("old certificate")
	newData := []byte("new certificate")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/certs/apply":
			writeApplyResponse(t, w, []fileMeta{{Name: "cert.pem", Size: int64(len(newData)), SHA256: sha256Hex(newData)}})
		case "/api/v1/certs/example.test/files/cert.pem":
			http.Error(w, "temporary failure", http.StatusBadGateway)
		default:
			t.Fatalf("意外请求路径 %q", r.URL.Path)
		}
	}))
	defer server.Close()

	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "cert.pem"), oldData, 0o600); err != nil {
		t.Fatal(err)
	}
	err := testV1Client(server.URL).Apply(ApplyOpts{Domain: "example.test", OutDir: outDir, CertFile: "cert.pem"})
	if err == nil {
		t.Fatal("下载 HTTP 错误未返回")
	}
	data, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, oldData) {
		t.Fatalf("下载 HTTP 失败后旧文件被改变: %q", data)
	}
}

func TestApplyRetainsBackupUntilVerifyCompletes(t *testing.T) {
	oldData := []byte("old certificate")
	newData := []byte("new certificate")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/certs/apply":
			writeApplyResponse(t, w, []fileMeta{{Name: "cert.pem", Size: int64(len(newData)), SHA256: sha256Hex(newData)}})
		case "/api/v1/certs/example.test/files/cert.pem":
			_, _ = w.Write(newData)
		default:
			t.Fatalf("意外请求路径 %q", r.URL.Path)
		}
	}))
	defer server.Close()

	outDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(outDir, "cert.pem"), oldData, 0o600); err != nil {
		t.Fatal(err)
	}
	err := testV1Client(server.URL).Apply(ApplyOpts{
		Domain:    "example.test",
		OutDir:    outDir,
		CertFile:  "cert.pem",
		VerifyCmd: "false",
	})
	if err == nil {
		t.Fatal("verify 失败未返回")
	}
	data, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, oldData) {
		t.Fatalf("verify 失败后未恢复备份: %q", data)
	}
}

func deploymentOptions(outDir string, generation certproto.GenerationID, manifest certproto.CertificateManifest, files map[certproto.FileName][]byte) GenerationDeployOpts {
	return GenerationDeployOpts{
		Domain:     "example.test",
		OutDir:     outDir,
		Generation: generation,
		Manifest:   manifest,
		Fetch: func(_ context.Context, fileName certproto.FileName) ([]byte, error) {
			return append([]byte(nil), files[fileName]...), nil
		},
	}
}

func testCertificateFiles(t *testing.T, domain string) map[certproto.FileName][]byte {
	now := time.Now()
	return testCertificateFilesWithValidity(t, domain, now.Add(-time.Hour), now.Add(time.Hour))
}

func testCertificateFilesWithValidity(t *testing.T, domain string, notBefore, notAfter time.Time) map[certproto.FileName][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(notAfter.UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return map[certproto.FileName][]byte{
		certproto.FileCert:      cert,
		certproto.FileKey:       keyPEM,
		certproto.FileFullchain: cert,
		certproto.FileCA:        cert,
		certproto.FileTimeLog:   []byte("1234567890\n"),
	}
}

func testManifest(files map[certproto.FileName][]byte) certproto.CertificateManifest {
	manifest := make(certproto.CertificateManifest, 0, len(certproto.FixedFileNames()))
	for _, name := range certproto.FixedFileNames() {
		data := files[name]
		manifest = append(manifest, certproto.FileManifest{
			Name:   string(name),
			Size:   int64(len(data)),
			SHA256: sha256Hex(data),
		})
	}
	return manifest
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func readCurrentForTest(t *testing.T, outDir string) string {
	t.Helper()
	if info, err := os.Lstat(filepath.Join(outDir, "current")); err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(filepath.Join(outDir, "current"))
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Base(target)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "current"))
	if err != nil {
		t.Fatal(err)
	}
	return string(bytes.TrimSpace(data))
}

func testV1Client(serverURL string) *Client {
	return &Client{
		Cfg:  &Config{Server: serverURL, TokenID: "test-id", TokenSecret: "test-secret", Development: true},
		HTTP: &http.Client{Timeout: time.Second},
		Log:  discardLogger{},
	}
}

func writeApplyResponse(t *testing.T, w http.ResponseWriter, files []fileMeta) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(applyResp{Success: true, Files: files}); err != nil {
		t.Fatal(err)
	}
}

type discardLogger struct{}

func (discardLogger) Info(string, ...any)  {}
func (discardLogger) Warn(string, ...any)  {}
func (discardLogger) Error(string, ...any) {}
