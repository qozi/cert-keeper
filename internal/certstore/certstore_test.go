package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
	currentPath, err := store.ResolveCurrentPath("example.com")
	if err != nil {
		t.Fatal(err)
	}
	expectedCurrentPath := filepath.Join(root, "example.com", CurrentFileName)
	if currentPath != expectedCurrentPath {
		t.Fatalf("current 路径 = %q，期望 %q", currentPath, expectedCurrentPath)
	}
	currentInfo, err := os.Lstat(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if currentInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("current 必须是符号链接")
	}
	currentTarget, err := os.Readlink(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedTarget := filepath.Join(ReleasesDirectory, string(generation))
	if currentTarget != expectedTarget {
		t.Fatalf("current 目标 = %q，期望 %q", currentTarget, expectedTarget)
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
	directCert, err := os.ReadFile(filepath.Join(currentPath, string(certproto.FileCert)))
	if err != nil {
		t.Fatalf("通过 current/cert.pem 读取失败: %v", err)
	}
	currentCert, err := store.ReadCurrent("example.com", certproto.FileCert)
	if err != nil {
		t.Fatal(err)
	}
	if string(directCert) != string(stagingCert) || string(currentCert) != string(stagingCert) {
		t.Fatal("current 稳定路径读取的证书不一致")
	}
	version, err := store.CurrentVersion("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if version.Generation != generation || version.Revision != 1 || version.Serial != "1" || len(version.Fingerprint) != 64 {
		t.Fatalf("current 版本元数据不正确: %+v", version)
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

func TestLegacyTextCurrentMigratesToStableSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	generation, filesManifest, err := store.Publish("example.com", createStaging(t, "example.com", nil))
	if err != nil {
		t.Fatal(err)
	}
	domainDir := filepath.Join(root, "example.com")
	releaseDir := filepath.Join(domainDir, ReleasesDirectory, string(generation))
	legacyParent := filepath.Join(domainDir, legacyGenerationsDirectory)
	legacyDir := filepath.Join(legacyParent, string(generation))
	legacyManifest, err := json.Marshal(filesManifest)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(releaseDir, manifestFileName), append(legacyManifest, '\n'))
	if err := os.Remove(filepath.Join(domainDir, CurrentFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(legacyParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(releaseDir, legacyDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(domainDir, ReleasesDirectory)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(domainDir, CurrentFileName), []byte(string(generation)+"\n"))

	current, err := store.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if current != generation {
		t.Fatalf("旧文本 current = %q，期望 %q", current, generation)
	}
	info, err := os.Lstat(filepath.Join(domainDir, CurrentFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatal("兼容读取不应立即改写旧文本 current")
	}
	currentPath, err := store.ResolveCurrentPath("example.com")
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if target != filepath.Join(ReleasesDirectory, string(generation)) {
		t.Fatalf("迁移后 current 目标 = %q", target)
	}
	if _, err := os.Stat(filepath.Join(domainDir, ReleasesDirectory, string(generation), string(certproto.FileCert))); err != nil {
		t.Fatalf("旧 generation 未迁移到 releases: %v", err)
	}
	if _, err := os.Lstat(legacyDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("旧 generation 目录仍存在: %v", err)
	}
	version, err := store.CurrentVersion("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if version.Generation != generation || version.Revision != 1 || version.Serial != "1" || len(version.Fingerprint) != 64 {
		t.Fatalf("旧 manifest 推导的版本不正确: %+v", version)
	}
}

func TestManifestRevisionAndAdditionalSANValidation(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	withSAN := func(certificate *x509.Certificate) {
		certificate.DNSNames = append(certificate.DNSNames, "www.example.com")
	}
	first, _, err := store.Publish("example.com", createStaging(t, "example.com", withSAN), []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	firstManifest, err := store.LoadGenerationManifest("example.com", first)
	if err != nil {
		t.Fatal(err)
	}
	if firstManifest.Revision != 1 || firstManifest.Serial != "1" || len(firstManifest.Fingerprint) != 64 {
		t.Fatalf("首代 manifest 元数据不正确: %+v", firstManifest)
	}
	if !sameStringSet(firstManifest.SANs, []string{"example.com", "www.example.com"}) {
		t.Fatalf("manifest SAN = %v", firstManifest.SANs)
	}
	second, _, err := store.Publish("example.com", createStaging(t, "example.com", withSAN), []string{"www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := store.LoadGenerationManifest("example.com", second)
	if err != nil {
		t.Fatal(err)
	}
	if secondManifest.Revision != 2 {
		t.Fatalf("第二代 revision = %d，期望 2", secondManifest.Revision)
	}
	if _, _, err := store.Publish("example.com", createStaging(t, "example.com", nil), []string{"www.example.com"}); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("缺少传入 SAN 的错误 = %v", err)
	}
	current, err := store.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if current != second {
		t.Fatalf("SAN 校验失败改变了 current: %q", current)
	}
}

func TestPublishRejectsBrokenCertificateChain(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := store.Publish("example.com", createStaging(t, "example.com", nil))
	if err != nil {
		t.Fatal(err)
	}
	broken := createStaging(t, "example.com", nil)
	unrelated := createStaging(t, "unrelated.example", nil)
	unrelatedCA, err := os.ReadFile(filepath.Join(unrelated, string(certproto.FileCA)))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(broken, string(certproto.FileCA)), unrelatedCA)
	if _, _, err := store.Publish("example.com", broken); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("断裂证书链错误 = %v", err)
	}
	current, err := store.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if current != first {
		t.Fatalf("证书链校验失败改变了 current: %q", current)
	}
}

func TestGarbageCollectRetentionRules(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	var generations []certproto.GenerationID
	for i := int64(1); i <= 5; i++ {
		serial := i
		staging := createStaging(t, "example.com", func(certificate *x509.Certificate) {
			certificate.SerialNumber = big.NewInt(serial)
		})
		generation, _, err := store.Publish("example.com", staging)
		if err != nil {
			t.Fatal(err)
		}
		generations = append(generations, generation)
	}
	currentBefore, err := os.Readlink(filepath.Join(root, "example.com", CurrentFileName))
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.GC("example.com", GCOptions{
		KeepRecent:           2,
		ReportReferences:     []certproto.GenerationID{generations[0]},
		ProtectedGenerations: []certproto.GenerationID{generations[1]},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 1 || result.Removed[0] != generations[2] {
		t.Fatalf("GC 清理结果 = %v，期望仅清理 %s", result.Removed, generations[2])
	}
	for _, generation := range []certproto.GenerationID{generations[0], generations[1], generations[3], generations[4]} {
		if _, err := os.Stat(filepath.Join(root, "example.com", ReleasesDirectory, string(generation))); err != nil {
			t.Fatalf("应保留 generation %s: %v", generation, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "example.com", ReleasesDirectory, string(generations[2]))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("待清理 generation 仍存在: %v", err)
	}
	currentAfter, err := os.Readlink(filepath.Join(root, "example.com", CurrentFileName))
	if err != nil {
		t.Fatal(err)
	}
	if currentAfter != currentBefore {
		t.Fatalf("GC 改变了 current: %q -> %q", currentBefore, currentAfter)
	}
}

func TestGarbageCollectRejectsSymlinkWithoutChangingCurrent(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := store.Publish("example.com", createStaging(t, "example.com", nil))
	if err != nil {
		t.Fatal(err)
	}
	unsafeGeneration := certproto.GenerationID("g-unsafe")
	unsafePath := filepath.Join(root, "example.com", ReleasesDirectory, string(unsafeGeneration))
	if err := os.Symlink(t.TempDir(), unsafePath); err != nil {
		t.Skipf("当前平台不支持创建符号链接: %v", err)
	}
	result, err := store.GC("example.com", GCOptions{KeepRecent: 0})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(result.Failed[unsafeGeneration], ErrUnsafePath) {
		t.Fatalf("symlink generation 未被拒绝: %v", result.Failed)
	}
	currentAfter, err := store.GetCurrent("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if currentAfter != current {
		t.Fatalf("GC 失败改变了 current: %q", currentAfter)
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
	currentPath := filepath.Join(root, "example.com", CurrentFileName)
	beforeTarget, err := os.Readlink(currentPath)
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
	afterTarget, err := os.Readlink(currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if afterTarget != beforeTarget {
		t.Fatalf("失败发布修改了 current 目标: %q -> %q", beforeTarget, afterTarget)
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

func TestResolveCurrentPathRejectsUnmanagedSymlink(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Publish("example.com", createStaging(t, "example.com", nil)); err != nil {
		t.Fatal(err)
	}
	currentPath := filepath.Join(root, "example.com", CurrentFileName)
	if err := os.Remove(currentPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "outside"), currentPath); err != nil {
		t.Skipf("当前平台不支持创建符号链接: %v", err)
	}
	if _, err := store.ResolveCurrentPath("example.com"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("非受管 current symlink 错误 = %v", err)
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
