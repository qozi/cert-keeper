// Package certstore 提供证书 generation 的原子文件仓储。
package certstore

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

const (
	// GenerationsDirectory 是域名目录下存放不可变 generation 的目录名。
	GenerationsDirectory = "generations"
	// CurrentFileName 是保存当前 generation ID 的原子指针文件名。
	CurrentFileName = "current"

	manifestFileName = "manifest.json"
)

var (
	// ErrNotFound 表示请求的域名、generation 或文件不存在。
	ErrNotFound = errors.New("证书产物不存在")
	// ErrInvalidDomain 表示域名不能安全地作为仓储目录名。
	ErrInvalidDomain = errors.New("域名不合法")
	// ErrInvalidGeneration 表示 generation 不符合 certproto 契约。
	ErrInvalidGeneration = errors.New("generation 不合法")
	// ErrInvalidFile 表示文件名不属于固定证书文件集合。
	ErrInvalidFile = errors.New("证书文件名不合法")
	// ErrUnsafePath 表示遇到符号链接、非预期目录或非普通文件。
	ErrUnsafePath = errors.New("不安全的仓储路径")
	// ErrInvalidCertificate 表示导入的证书或私钥校验失败。
	ErrInvalidCertificate = errors.New("证书内容校验失败")
	// ErrInvalidManifest 表示 generation 内的 manifest 或文件集合不完整。
	ErrInvalidManifest = errors.New("证书 manifest 不合法")
	// ErrCurrentGeneration 表示请求清理的 generation 仍为当前版本。
	ErrCurrentGeneration = errors.New("不能清理当前 generation")
)

// Store 是以根目录为边界的 generation 证书仓储。
type Store struct {
	root string
	now  func() time.Time
}

// Open 打开或创建根目录为 root 的证书仓储。
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: 根目录不能为空", ErrUnsafePath)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("解析仓储根目录失败: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o700); err != nil {
		return nil, fmt.Errorf("创建仓储根目录失败: %w", err)
	}
	if err := assertDirectory(absRoot); err != nil {
		return nil, fmt.Errorf("校验仓储根目录失败: %w", err)
	}
	if err := os.Chmod(absRoot, 0o700); err != nil {
		return nil, fmt.Errorf("设置仓储根目录权限失败: %w", err)
	}
	return &Store{root: absRoot, now: time.Now}, nil
}

// Publish 校验 stagingDir 并将其发布为 domain 的新当前 generation。
//
// stagingDir 必须只包含 cert.pem、key.pem、fullchain.pem、ca.pem，以及可选的
// time.log。缺少 time.log 时由仓储生成 Unix 时间戳。返回的 manifest 始终包含五个
// 固定文件。
func (s *Store) Publish(domain, stagingDir string) (certproto.GenerationID, certproto.CertificateManifest, error) {
	files, err := s.readStaging(domain, stagingDir)
	if err != nil {
		return "", nil, err
	}

	domainDir, generationsDir, err := s.domainPaths(domain, true)
	if err != nil {
		return "", nil, err
	}
	generation, generationDir, err := s.newGenerationPath(generationsDir)
	if err != nil {
		return "", nil, err
	}

	temporaryDir, err := os.MkdirTemp(generationsDir, ".tmp-")
	if err != nil {
		return "", nil, fmt.Errorf("创建临时 generation 目录失败: %w", err)
	}
	if err := os.Chmod(temporaryDir, 0o700); err != nil {
		_ = os.RemoveAll(temporaryDir)
		return "", nil, fmt.Errorf("设置临时 generation 目录权限失败: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporaryDir)
		}
	}()

	manifest, err := buildManifest(files)
	if err != nil {
		return "", nil, err
	}
	for _, fileName := range certproto.FixedFileNames() {
		if err := writeFileSync(filepath.Join(temporaryDir, string(fileName)), files[fileName]); err != nil {
			return "", nil, fmt.Errorf("写入 %s 失败: %w", fileName, err)
		}
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return "", nil, fmt.Errorf("编码 manifest 失败: %w", err)
	}
	manifestData = append(manifestData, '\n')
	if err := writeFileSync(filepath.Join(temporaryDir, manifestFileName), manifestData); err != nil {
		return "", nil, fmt.Errorf("写入 manifest 失败: %w", err)
	}
	if err := syncDirectory(temporaryDir); err != nil {
		return "", nil, fmt.Errorf("同步临时 generation 目录失败: %w", err)
	}

	if err := os.Rename(temporaryDir, generationDir); err != nil {
		return "", nil, fmt.Errorf("发布 generation 失败: %w", err)
	}
	if err := syncDirectory(generationsDir); err != nil {
		_ = os.RemoveAll(generationDir)
		return "", nil, fmt.Errorf("同步 generation 目录失败: %w", err)
	}
	if err := writeCurrent(domainDir, generation); err != nil {
		_ = os.RemoveAll(generationDir)
		return "", nil, err
	}

	committed = true
	return generation, manifest, nil
}

// GetCurrent 返回 domain 当前发布的 generation。
func (s *Store) GetCurrent(domain string) (certproto.GenerationID, error) {
	domainDir, _, err := s.domainPaths(domain, false)
	if err != nil {
		return "", err
	}
	return readCurrent(domainDir)
}

// ReadFile 读取 domain 指定 generation 的固定文件。
//
// generation 为空时读取 current 指向的 generation。
func (s *Store) ReadFile(domain string, generation certproto.GenerationID, fileName certproto.FileName) ([]byte, error) {
	if err := validateFileName(fileName); err != nil {
		return nil, err
	}
	_, generationDir, _, err := s.resolveGeneration(domain, generation)
	if err != nil {
		return nil, err
	}
	_, files, err := loadGeneration(generationDir)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), files[fileName]...), nil
}

// LoadManifest 返回 domain 指定 generation 的 manifest，并校验其与文件内容一致。
// generation 为空时读取 current 指向的 generation。
func (s *Store) LoadManifest(domain string, generation certproto.GenerationID) (certproto.CertificateManifest, error) {
	_, generationDir, _, err := s.resolveGeneration(domain, generation)
	if err != nil {
		return nil, err
	}
	manifest, _, err := loadGeneration(generationDir)
	if err != nil {
		return nil, err
	}
	return append(certproto.CertificateManifest(nil), manifest...), nil
}

// Abort 删除尚未成为 current 的 generation，用于清理已发布但未采用的产物。
func (s *Store) Abort(domain string, generation certproto.GenerationID) error {
	if err := validateGeneration(generation); err != nil {
		return err
	}
	domainDir, generationsDir, err := s.domainPaths(domain, false)
	if err != nil {
		return err
	}
	current, err := readCurrent(domainDir)
	if err == nil && current == generation {
		return fmt.Errorf("%w: %s", ErrCurrentGeneration, generation)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	generationDir := filepath.Join(generationsDir, string(generation))
	if err := assertDirectory(generationDir); err != nil {
		return err
	}
	if err := os.RemoveAll(generationDir); err != nil {
		return fmt.Errorf("清理 generation 失败: %w", err)
	}
	if err := syncDirectory(generationsDir); err != nil {
		return fmt.Errorf("同步 generation 目录失败: %w", err)
	}
	return nil
}

func (s *Store) readStaging(domain, stagingDir string) (map[certproto.FileName][]byte, error) {
	if _, err := normalizeDomain(domain); err != nil {
		return nil, err
	}
	if err := assertDirectory(stagingDir); err != nil {
		return nil, fmt.Errorf("校验 staging 目录失败: %w", err)
	}
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return nil, fmt.Errorf("读取 staging 目录失败: %w", err)
	}

	files := make(map[certproto.FileName][]byte, len(certproto.FixedFileNames()))
	for _, entry := range entries {
		fileName := certproto.FileName(entry.Name())
		if err := validateFileName(fileName); err != nil {
			return nil, fmt.Errorf("staging 包含未知文件: %w", err)
		}
		data, err := readRegularFile(filepath.Join(stagingDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("读取 staging 文件 %s 失败: %w", entry.Name(), err)
		}
		files[fileName] = data
	}

	for _, fileName := range []certproto.FileName{
		certproto.FileCert,
		certproto.FileKey,
		certproto.FileFullchain,
		certproto.FileCA,
	} {
		if _, exists := files[fileName]; !exists {
			return nil, fmt.Errorf("%w: staging 缺少 %s", ErrInvalidManifest, fileName)
		}
	}
	if _, exists := files[certproto.FileTimeLog]; !exists {
		files[certproto.FileTimeLog] = []byte(strconv.FormatInt(s.now().Unix(), 10) + "\n")
	}
	if err := validateCertificateFiles(domain, files, s.now()); err != nil {
		return nil, err
	}
	return files, nil
}

func (s *Store) domainPaths(domain string, create bool) (string, string, error) {
	safeDomain, err := normalizeDomain(domain)
	if err != nil {
		return "", "", err
	}
	if err := assertDirectory(s.root); err != nil {
		return "", "", fmt.Errorf("校验仓储根目录失败: %w", err)
	}
	domainDir := filepath.Join(s.root, safeDomain)
	generationsDir := filepath.Join(domainDir, GenerationsDirectory)
	if create {
		if err := ensureDirectory(domainDir); err != nil {
			return "", "", fmt.Errorf("创建域名目录失败: %w", err)
		}
		if err := ensureDirectory(generationsDir); err != nil {
			return "", "", fmt.Errorf("创建 generation 目录失败: %w", err)
		}
		return domainDir, generationsDir, nil
	}
	if err := assertDirectory(domainDir); err != nil {
		return "", "", err
	}
	if err := assertDirectory(generationsDir); err != nil {
		return "", "", err
	}
	return domainDir, generationsDir, nil
}

func (s *Store) newGenerationPath(generationsDir string) (certproto.GenerationID, string, error) {
	for range 8 {
		generation, err := newGenerationID()
		if err != nil {
			return "", "", err
		}
		path := filepath.Join(generationsDir, string(generation))
		_, err = os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return generation, path, nil
		}
		if err != nil {
			return "", "", fmt.Errorf("检查 generation 路径失败: %w", err)
		}
	}
	return "", "", fmt.Errorf("生成唯一 generation ID 失败")
}

func (s *Store) resolveGeneration(domain string, requested certproto.GenerationID) (string, string, certproto.GenerationID, error) {
	if requested != "" {
		if err := validateGeneration(requested); err != nil {
			return "", "", "", err
		}
	}
	_, generationsDir, err := s.domainPaths(domain, false)
	if err != nil {
		return "", "", "", err
	}
	generation := requested
	if generation == "" {
		domainDir := filepath.Dir(generationsDir)
		generation, err = readCurrent(domainDir)
		if err != nil {
			return "", "", "", err
		}
	}
	generationDir := filepath.Join(generationsDir, string(generation))
	if err := assertDirectory(generationDir); err != nil {
		return "", "", "", err
	}
	return filepath.Dir(generationsDir), generationDir, generation, nil
}

func normalizeDomain(domain string) (string, error) {
	if domain == "" || domain != strings.TrimSpace(domain) || len(domain) > 253 {
		return "", fmt.Errorf("%w: 域名不能为空、不能含空白且长度不能超过 253", ErrInvalidDomain)
	}
	safeDomain := strings.ToLower(domain)
	for _, label := range strings.Split(safeDomain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: 域名标签不合法", ErrInvalidDomain)
		}
		for i := 0; i < len(label); i++ {
			char := label[i]
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return "", fmt.Errorf("%w: 域名只能包含 ASCII 字母、数字、连字符和点", ErrInvalidDomain)
			}
		}
	}
	return safeDomain, nil
}

func validateGeneration(generation certproto.GenerationID) error {
	if err := generation.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidGeneration, err)
	}
	return nil
}

func validateFileName(fileName certproto.FileName) error {
	if err := fileName.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFile, err)
	}
	return nil
}

func newGenerationID() (certproto.GenerationID, error) {
	var token [20]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("读取随机 generation ID 失败: %w", err)
	}
	generation := certproto.GenerationID("g-" + hex.EncodeToString(token[:]))
	if err := validateGeneration(generation); err != nil {
		return "", err
	}
	return generation, nil
}

func validateCertificateFiles(domain string, files map[certproto.FileName][]byte, now time.Time) error {
	leafCertificates, err := parseCertificatePEM(files[certproto.FileCert])
	if err != nil {
		return fmt.Errorf("%w: 解析 cert.pem 失败: %v", ErrInvalidCertificate, err)
	}
	if len(leafCertificates) != 1 {
		return fmt.Errorf("%w: cert.pem 必须只包含一张叶子证书", ErrInvalidCertificate)
	}
	leaf := leafCertificates[0]
	fullchain, err := parseCertificatePEM(files[certproto.FileFullchain])
	if err != nil {
		return fmt.Errorf("%w: 解析 fullchain.pem 失败: %v", ErrInvalidCertificate, err)
	}
	if !bytes.Equal(leaf.Raw, fullchain[0].Raw) {
		return fmt.Errorf("%w: fullchain.pem 的第一张证书必须与 cert.pem 一致", ErrInvalidCertificate)
	}
	caCertificates, err := parseCertificatePEM(files[certproto.FileCA])
	if err != nil {
		return fmt.Errorf("%w: 解析 ca.pem 失败: %v", ErrInvalidCertificate, err)
	}
	for _, certificate := range append(append([]*x509.Certificate{}, leafCertificates...), append(fullchain, caCertificates...)...) {
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return fmt.Errorf("%w: 证书不在有效期内", ErrInvalidCertificate)
		}
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return fmt.Errorf("%w: 叶子证书 SAN 未覆盖 %q: %v", ErrInvalidCertificate, domain, err)
	}
	privateKey, err := parsePrivateKeyPEM(files[certproto.FileKey])
	if err != nil {
		return fmt.Errorf("%w: 解析 key.pem 失败: %v", ErrInvalidCertificate, err)
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: 编码叶子证书公钥失败: %v", ErrInvalidCertificate, err)
	}
	privatePublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("%w: 编码私钥公钥失败: %v", ErrInvalidCertificate, err)
	}
	if !bytes.Equal(certificatePublicKey, privatePublicKey) {
		return fmt.Errorf("%w: 私钥与叶子证书不匹配", ErrInvalidCertificate)
	}
	return nil
}

func parseCertificatePEM(data []byte) ([]*x509.Certificate, error) {
	blocks, err := decodePEMBlocks(data)
	if err != nil {
		return nil, err
	}
	certificates := make([]*x509.Certificate, 0, len(blocks))
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("包含非证书 PEM 块 %q", block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	return certificates, nil
}

func parsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	blocks, err := decodePEMBlocks(data)
	if err != nil {
		return nil, err
	}
	if len(blocks) != 1 {
		return nil, errors.New("私钥文件必须只包含一个 PEM 块")
	}
	block := blocks[0]
	var privateKey any
	switch block.Type {
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("不支持的私钥 PEM 块 %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("私钥不支持签名")
	}
	return signer, nil
}

func decodePEMBlocks(data []byte) ([]*pem.Block, error) {
	remaining := bytes.TrimSpace(data)
	if len(remaining) == 0 {
		return nil, errors.New("PEM 内容为空")
	}
	var blocks []*pem.Block
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, errors.New("PEM 包含无效或额外内容")
		}
		blocks = append(blocks, block)
		remaining = bytes.TrimSpace(rest)
	}
	return blocks, nil
}

func buildManifest(files map[certproto.FileName][]byte) (certproto.CertificateManifest, error) {
	manifest := make(certproto.CertificateManifest, 0, len(certproto.FixedFileNames()))
	for _, fileName := range certproto.FixedFileNames() {
		data, exists := files[fileName]
		if !exists {
			return nil, fmt.Errorf("%w: 缺少 %s", ErrInvalidManifest, fileName)
		}
		digest := sha256.Sum256(data)
		manifest = append(manifest, certproto.FileManifest{
			Name:   string(fileName),
			Size:   int64(len(data)),
			SHA256: hex.EncodeToString(digest[:]),
		})
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func loadGeneration(generationDir string) (certproto.CertificateManifest, map[certproto.FileName][]byte, error) {
	if err := assertGenerationContents(generationDir); err != nil {
		return nil, nil, err
	}
	manifestData, err := readRegularFile(filepath.Join(generationDir, manifestFileName))
	if err != nil {
		return nil, nil, fmt.Errorf("读取 manifest 失败: %w", err)
	}
	var manifest certproto.CertificateManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, nil, fmt.Errorf("%w: 解码 manifest 失败: %v", ErrInvalidManifest, err)
	}
	if err := validateManifest(manifest); err != nil {
		return nil, nil, err
	}
	files := make(map[certproto.FileName][]byte, len(manifest))
	for _, item := range manifest {
		fileName := certproto.FileName(item.Name)
		data, err := readRegularFile(filepath.Join(generationDir, item.Name))
		if err != nil {
			return nil, nil, fmt.Errorf("读取 generation 文件 %s 失败: %w", item.Name, err)
		}
		digest := sha256.Sum256(data)
		if item.Size != int64(len(data)) || item.SHA256 != hex.EncodeToString(digest[:]) {
			return nil, nil, fmt.Errorf("%w: %s 的大小或 SHA256 不匹配", ErrInvalidManifest, item.Name)
		}
		files[fileName] = data
	}
	return manifest, files, nil
}

func validateManifest(manifest certproto.CertificateManifest) error {
	if err := manifest.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if len(manifest) != len(certproto.FixedFileNames()) {
		return fmt.Errorf("%w: manifest 必须包含五个固定文件", ErrInvalidManifest)
	}
	seen := make(map[string]struct{}, len(manifest))
	for _, item := range manifest {
		seen[item.Name] = struct{}{}
	}
	for _, fileName := range certproto.FixedFileNames() {
		if _, exists := seen[string(fileName)]; !exists {
			return fmt.Errorf("%w: manifest 缺少 %s", ErrInvalidManifest, fileName)
		}
	}
	return nil
}

func assertGenerationContents(generationDir string) error {
	if err := assertDirectory(generationDir); err != nil {
		return err
	}
	entries, err := os.ReadDir(generationDir)
	if err != nil {
		return fmt.Errorf("读取 generation 目录失败: %w", err)
	}
	expected := make(map[string]struct{}, len(certproto.FixedFileNames())+1)
	for _, fileName := range certproto.FixedFileNames() {
		expected[string(fileName)] = struct{}{}
	}
	expected[manifestFileName] = struct{}{}
	if len(entries) != len(expected) {
		return fmt.Errorf("%w: generation 文件集合不完整或包含多余文件", ErrInvalidManifest)
	}
	for _, entry := range entries {
		if _, exists := expected[entry.Name()]; !exists {
			return fmt.Errorf("%w: generation 包含未知文件 %q", ErrInvalidManifest, entry.Name())
		}
		if _, err := readRegularFile(filepath.Join(generationDir, entry.Name())); err != nil {
			return fmt.Errorf("校验 generation 文件 %s 失败: %w", entry.Name(), err)
		}
	}
	return nil
}

func readCurrent(domainDir string) (certproto.GenerationID, error) {
	data, err := readRegularFile(filepath.Join(domainDir, CurrentFileName))
	if err != nil {
		return "", fmt.Errorf("读取 current 失败: %w", err)
	}
	generation := certproto.GenerationID(strings.TrimSpace(string(data)))
	if err := validateGeneration(generation); err != nil {
		return "", fmt.Errorf("current 内容无效: %w", err)
	}
	return generation, nil
}

func writeCurrent(domainDir string, generation certproto.GenerationID) error {
	if err := validateGeneration(generation); err != nil {
		return err
	}
	currentPath := filepath.Join(domainDir, CurrentFileName)
	if info, err := os.Lstat(currentPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("更新 current 失败: %w", ErrUnsafePath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("检查 current 失败: %w", err)
	}

	file, err := os.CreateTemp(domainDir, ".current-")
	if err != nil {
		return fmt.Errorf("创建 current 临时文件失败: %w", err)
	}
	temporaryPath := file.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("设置 current 临时文件权限失败: %w", err)
	}
	if _, err := io.WriteString(file, string(generation)+"\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("写入 current 临时文件失败: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("同步 current 临时文件失败: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭 current 临时文件失败: %w", err)
	}
	if err := os.Rename(temporaryPath, currentPath); err != nil {
		return fmt.Errorf("原子更新 current 失败: %w", err)
	}
	if err := syncDirectory(domainDir); err != nil {
		return fmt.Errorf("同步域名目录失败: %w", err)
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	data, readErr := io.ReadAll(file)
	stat, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	after, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !stat.Mode().IsRegular() {
		return nil, ErrUnsafePath
	}
	if !os.SameFile(before, stat) || !os.SameFile(stat, after) {
		return nil, fmt.Errorf("文件在读取期间发生变化")
	}
	return data, nil
}

func ensureDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := assertDirectory(path); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func assertDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafePath
	}
	return nil
}

func writeFileSync(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	// Windows 不支持同步目录句柄，文件内容已在重命名前单独同步。
	if runtime.GOOS == "windows" {
		return nil
	}
	return directory.Sync()
}
