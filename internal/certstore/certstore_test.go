package certstore

import (
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
	"testing"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

func TestPublishAndReadCurrentGeneration(t *testing.T) {
	root := t.TempDir()
	staging := createStaging(t, "example.com", nil)
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	generation, manifest, err := store.Publish("example.com", staging)
	if err != nil {
		t.Fatal(err)
	}
	if err := generation.Validate(); err != nil {
		t.Fatalf("generation 不符合 certproto 契约: %v", err)
	}
	if len(manifest) != len(certproto.FixedFileNames()) {
		t.Fatalf("manifest 文件数 = %d，期望 %d", len(manifest), len(certproto.FixedFileNames()))
	}
	current, err := store.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if current != generation {
		t.Fatalf("current = %q，期望 %q", current, generation)
	}
	certData, err := store.ReadFile("example.com", "", certproto.FileCert)
	if err != nil {
		t.Fatal(err)
	}
	stagingCert, err := os.ReadFile(filepath.Join(staging, string(certproto.FileCert)))
	if err != nil {
		t.Fatal(err)
	}
	if string(certData) != string(stagingCert) {
		t.Fatal("读取的 cert.pem 与 staging 内容不一致")
	}
	loaded, err := store.LoadManifest("example.com", generation)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(manifest) || loaded[0] != manifest[0] {
		t.Fatal("加载的 manifest 不正确")
	}
	timeLog, err := store.ReadFile("example.com", generation, certproto.FileTimeLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeLog) == 0 {
		t.Fatal("仓储未生成 time.log")
	}

	generationDir := filepath.Join(root, "example.com", GenerationsDirectory, string(generation))
	info, err := os.Stat(generationDir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("generation 目录权限 = %o，期望 700", info.Mode().Perm())
	}
	info, err = os.Stat(filepath.Join(generationDir, string(certproto.FileKey)))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key.pem 权限 = %o，期望 600", info.Mode().Perm())
	}
}

func TestPublishRejectsMismatchedPrivateKey(t *testing.T) {
	staging := createStaging(t, "example.com", nil)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(staging, string(certproto.FileKey)), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyData}))

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Publish("example.com", staging)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("错误 = %v，期望私钥不匹配错误", err)
	}
}

func TestPublishRejectsSANMismatch(t *testing.T) {
	staging := createStaging(t, "other.example", nil)
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.Publish("example.com", staging)
	if !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("错误 = %v，期望 SAN 校验错误", err)
	}
}

func TestFailedPublishDoesNotChangeCurrent(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	firstStaging := createStaging(t, "example.com", nil)
	first, _, err := store.Publish("example.com", firstStaging)
	if err != nil {
		t.Fatal(err)
	}

	brokenStaging := createStaging(t, "example.com", nil)
	if err := os.Remove(filepath.Join(brokenStaging, string(certproto.FileKey))); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Publish("example.com", brokenStaging); err == nil {
		t.Fatal("缺少 key.pem 的发布应失败")
	}
	current, err := store.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if current != first {
		t.Fatalf("失败发布修改了 current: %q，期望 %q", current, first)
	}
}

func TestRejectsUnknownFileAndTraversal(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	staging := createStaging(t, "example.com", nil)
	writeFile(t, filepath.Join(staging, "unexpected.pem"), []byte("unexpected"))
	if _, _, err := store.Publish("example.com", staging); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("错误 = %v，期望未知文件错误", err)
	}
	if _, err := store.GetCurrent("../example.com"); !errors.Is(err, ErrInvalidDomain) {
		t.Fatalf("域名穿越错误 = %v", err)
	}
	if _, err := store.ReadFile("example.com", certproto.GenerationID("../bad"), certproto.FileCert); !errors.Is(err, ErrInvalidGeneration) {
		t.Fatalf("generation 穿越错误 = %v", err)
	}
	if _, err := store.ReadFile("example.com", "", certproto.FileName("../key.pem")); !errors.Is(err, ErrInvalidFile) {
		t.Fatalf("文件名穿越错误 = %v", err)
	}
}

func TestPublishRejectsStagingSymlink(t *testing.T) {
	staging := createStaging(t, "example.com", nil)
	keyPath := filepath.Join(staging, string(certproto.FileKey))
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "key.pem")
	writeFile(t, target, keyData)
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, keyPath); err != nil {
		t.Skipf("当前平台不支持创建符号链接: %v", err)
	}

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Publish("example.com", staging); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("错误 = %v，期望符号链接错误", err)
	}
}

func createStaging(t *testing.T, domain string, modify func(*x509.Certificate)) string {
	t.Helper()
	directory := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	if modify != nil {
		modify(template)
	}
	certificateData, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateData})
	keyData, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyData})
	writeFile(t, filepath.Join(directory, string(certproto.FileCert)), certificatePEM)
	writeFile(t, filepath.Join(directory, string(certproto.FileKey)), keyPEM)
	writeFile(t, filepath.Join(directory, string(certproto.FileFullchain)), certificatePEM)
	writeFile(t, filepath.Join(directory, string(certproto.FileCA)), certificatePEM)
	return directory
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
