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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

const (
	// ReleasesDirectory 是域名目录下存放不可变 generation 的目录名。
	ReleasesDirectory = "releases"
	// GenerationsDirectory 保留旧名称，值指向新的稳定目录。
	GenerationsDirectory = ReleasesDirectory
	// legacyGenerationsDirectory 是旧版本仓储使用的目录名。
	legacyGenerationsDirectory = "generations"
	// CurrentFileName 是指向当前 generation 目录的稳定符号链接名。
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
	// ErrInvalidGCOptions 表示 generation GC 参数不合法。
	ErrInvalidGCOptions = errors.New("generation GC 参数不合法")
)

// GenerationManifest 描述一个不可变 generation 的证书元数据和文件摘要。
//
// Files 保持与旧接口相同的固定文件清单；新 manifest 以对象形式落盘，旧的
// 仅包含文件数组的 manifest 仍可读取。
type GenerationManifest struct {
	// Generation 是 manifest 所属的 generation。
	Generation certproto.GenerationID `json:"generation"`
	// Revision 是该域名下递增的发布序号。
	Revision certproto.Revision `json:"revision"`
	// Domain 是证书校验时使用的主域名。
	Domain string `json:"domain"`
	// SANs 是叶子证书实际包含的规范化 SAN 集合。
	SANs []string `json:"sans"`
	// Serial 是叶子证书序列号的十进制表示。
	Serial string `json:"serial"`
	// Fingerprint 是叶子证书 DER 内容的 SHA-256 指纹。
	Fingerprint string `json:"fingerprint"`
	// Files 是固定证书文件的大小和 SHA-256 摘要。
	Files certproto.CertificateManifest `json:"files"`
}

// GenerationVersion 是 current 指向的完整版本信息。
type GenerationVersion struct {
	Generation  certproto.GenerationID
	Revision    certproto.Revision
	Domain      string
	SANs        []string
	Serial      string
	Fingerprint string
}

// GCOptions 定义 generation GC 的保留规则。
type GCOptions struct {
	// KeepRecent 保留最近的 generation 数量，其中包括 current。
	KeepRecent int
	// ReportReferences 是部署报告仍引用的 generation。
	ReportReferences []certproto.GenerationID
	// DeploymentReferences 是 ReportReferences 的语义别名。
	DeploymentReferences []certproto.GenerationID
	// DeploymentReports 是需要保留其 generation 的部署报告。
	DeploymentReports []certproto.DeploymentReport
	// ProtectedGenerations 是显式保护的 generation。
	ProtectedGenerations []certproto.GenerationID
	// Protected 是 ProtectedGenerations 的简短兼容字段。
	Protected []certproto.GenerationID
}

// GCResult 描述一次 generation GC 的结果。
type GCResult struct {
	// Removed 是成功清理的 generation。
	Removed []certproto.GenerationID
	// Retained 是按照规则保留的 generation。
	Retained []certproto.GenerationID
	// Failed 是清理失败但未影响 current 的 generation 错误。
	Failed map[certproto.GenerationID]error
}

// Store 是以根目录为边界的 generation 证书仓储。
type Store struct {
	root string
	now  func() time.Time
	mu   sync.Mutex
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
func (s *Store) Publish(domain, stagingDir string, sanSets ...[]string) (certproto.GenerationID, certproto.CertificateManifest, error) {
	if len(sanSets) > 1 {
		return "", nil, fmt.Errorf("%w: SAN 集合只能传入一次", ErrInvalidCertificate)
	}
	var sans []string
	if len(sanSets) == 1 {
		sans = sanSets[0]
	}
	return s.publish(domain, stagingDir, sans)
}

// PublishWithSAN 发布证书，并校验主域名和额外 SAN 集合。
func (s *Store) PublishWithSAN(domain, stagingDir string, sans []string) (certproto.GenerationID, certproto.CertificateManifest, error) {
	return s.publish(domain, stagingDir, sans)
}

func (s *Store) publish(domain, stagingDir string, expectedSANs []string) (certproto.GenerationID, certproto.CertificateManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.readStaging(domain, stagingDir, expectedSANs)
	if err != nil {
		return "", nil, err
	}

	domainDir, releasesDir, err := s.domainPaths(domain, true)
	if err != nil {
		return "", nil, err
	}
	if _, _, err := s.currentState(domainDir, releasesDir, false); err != nil && !errors.Is(err, ErrNotFound) {
		return "", nil, fmt.Errorf("校验 current 失败: %w", err)
	}
	generation, generationDir, err := s.newGenerationPath(releasesDir)
	if err != nil {
		return "", nil, err
	}

	temporaryDir, err := os.MkdirTemp(releasesDir, ".tmp-")
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

	revision, err := nextRevision(domain, domainDir, releasesDir)
	if err != nil {
		return "", nil, err
	}
	manifest, err := buildGenerationManifest(domain, generation, revision, expectedSANs, files, s.now())
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
	if err := syncDirectory(releasesDir); err != nil {
		_ = os.RemoveAll(generationDir)
		return "", nil, fmt.Errorf("同步 generation 目录失败: %w", err)
	}
	if err := writeCurrent(domainDir, releasesDir, generation); err != nil {
		_ = os.RemoveAll(generationDir)
		_ = syncDirectory(releasesDir)
		return "", nil, err
	}

	committed = true
	return generation, manifest.Files, nil
}

// GetCurrent 返回 domain 当前发布的 generation。
func (s *Store) GetCurrent(domain string) (certproto.GenerationID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domainDir, _, err := s.domainPaths(domain, false)
	if err != nil {
		return "", err
	}
	return s.currentGeneration(domainDir)
}

// ResolveCurrentPath 返回可直接用于 Nginx/Caddy 的 current 目录路径。
// 返回路径末端始终是 current，发布成功后它是指向 releases/<generation> 的符号链接。
func (s *Store) ResolveCurrentPath(domain string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domainDir, releasesDir, err := s.domainPaths(domain, false)
	if err != nil {
		return "", err
	}
	if _, _, err := s.currentState(domainDir, releasesDir, true); err != nil {
		return "", err
	}
	return filepath.Join(domainDir, CurrentFileName), nil
}

// ReadCurrent 读取 current 下的固定证书文件，返回值可直接交给服务配置或 TLS 加载器。
func (s *Store) ReadCurrent(domain string, fileName certproto.FileName) ([]byte, error) {
	if err := validateFileName(fileName); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domainDir, releasesDir, err := s.domainPaths(domain, false)
	if err != nil {
		return nil, err
	}
	_, generationDir, err := s.currentState(domainDir, releasesDir, true)
	if err != nil {
		return nil, err
	}
	data, err := readRegularFile(filepath.Join(generationDir, string(fileName)))
	if err != nil {
		return nil, fmt.Errorf("读取 current 文件 %s 失败: %w", fileName, err)
	}
	return data, nil
}

// CurrentVersion 返回 current 指向的 generation manifest 元数据。
func (s *Store) CurrentVersion(domain string) (GenerationVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	domainDir, releasesDir, err := s.domainPaths(domain, false)
	if err != nil {
		return GenerationVersion{}, err
	}
	generation, generationDir, err := s.currentState(domainDir, releasesDir, true)
	if err != nil {
		return GenerationVersion{}, err
	}
	manifest, _, err := loadGeneration(domain, generation, generationDir)
	if err != nil {
		return GenerationVersion{}, err
	}
	return generationVersion(manifest), nil
}

func generationVersion(manifest GenerationManifest) GenerationVersion {
	return GenerationVersion{
		Generation:  manifest.Generation,
		Revision:    manifest.Revision,
		Domain:      manifest.Domain,
		SANs:        append([]string(nil), manifest.SANs...),
		Serial:      manifest.Serial,
		Fingerprint: manifest.Fingerprint,
	}
}

// LoadGenerationManifest 返回指定 generation 的完整 manifest 元数据。
func (s *Store) LoadGenerationManifest(domain string, generation certproto.GenerationID) (GenerationManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, generationDir, resolved, err := s.resolveGenerationLocked(domain, generation)
	if err != nil {
		return GenerationManifest{}, err
	}
	manifest, _, err := loadGeneration(domain, resolved, generationDir)
	return manifest, err
}

// ReadFile 读取 domain 指定 generation 的固定文件。
//
// generation 为空时读取 current 指向的 generation。
func (s *Store) ReadFile(domain string, generation certproto.GenerationID, fileName certproto.FileName) ([]byte, error) {
	if err := validateFileName(fileName); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, generationDir, resolved, err := s.resolveGeneration(domain, generation)
	if err != nil {
		return nil, err
	}
	_, files, err := loadGeneration(domain, resolved, generationDir)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), files[fileName]...), nil
}

// LoadManifest 返回 domain 指定 generation 的 manifest，并校验其与文件内容一致。
// generation 为空时读取 current 指向的 generation。
func (s *Store) LoadManifest(domain string, generation certproto.GenerationID) (certproto.CertificateManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, generationDir, resolved, err := s.resolveGeneration(domain, generation)
	if err != nil {
		return nil, err
	}
	manifest, _, err := loadGeneration(domain, resolved, generationDir)
	if err != nil {
		return nil, err
	}
	return append(certproto.CertificateManifest(nil), manifest.Files...), nil
}

// GarbageCollect 清理不再需要的 generation。任何单个 generation 的清理失败
// 都记录在结果中并继续处理，current 指针不会参与删除或切换。
func (s *Store) GarbageCollect(domain string, options GCOptions) (GCResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if options.KeepRecent < 0 {
		return GCResult{}, fmt.Errorf("%w: KeepRecent 不能为负数", ErrInvalidGCOptions)
	}
	protected := make(map[certproto.GenerationID]struct{}, len(options.ReportReferences)+len(options.DeploymentReferences)+len(options.DeploymentReports)+len(options.ProtectedGenerations)+len(options.Protected))
	for _, generations := range [][]certproto.GenerationID{options.ReportReferences, options.DeploymentReferences, options.ProtectedGenerations, options.Protected} {
		for _, generation := range generations {
			if err := validateGeneration(generation); err != nil {
				return GCResult{}, fmt.Errorf("%w: %v", ErrInvalidGCOptions, err)
			}
			protected[generation] = struct{}{}
		}
	}
	for _, report := range options.DeploymentReports {
		if report.Generation == "" {
			continue
		}
		if err := validateGeneration(report.Generation); err != nil {
			return GCResult{}, fmt.Errorf("%w: %v", ErrInvalidGCOptions, err)
		}
		protected[report.Generation] = struct{}{}
	}
	domainDir, releasesDir, err := s.domainPaths(domain, false)
	if err != nil {
		return GCResult{}, err
	}
	current, currentErr := s.currentGeneration(domainDir)
	if currentErr != nil && !errors.Is(currentErr, ErrNotFound) {
		return GCResult{}, currentErr
	}
	entries, err := os.ReadDir(releasesDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return GCResult{Failed: map[certproto.GenerationID]error{}}, nil
		}
		return GCResult{}, fmt.Errorf("读取 releases 目录失败: %w", err)
	}
	type candidate struct {
		generation certproto.GenerationID
		manifest   GenerationManifest
		path       string
	}
	var candidates []candidate
	result := GCResult{Failed: make(map[certproto.GenerationID]error)}
	for _, entry := range entries {
		generation := certproto.GenerationID(entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			if validateGeneration(generation) == nil {
				result.Failed[generation] = ErrUnsafePath
			}
			continue
		}
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			continue
		}
		if err := validateGeneration(generation); err != nil {
			continue
		}
		path := filepath.Join(releasesDir, entry.Name())
		if err := assertDirectory(path); err != nil {
			result.Failed[generation] = err
			continue
		}
		manifest, _, err := loadGeneration(domain, generation, path)
		if err != nil {
			result.Failed[generation] = err
			result.Retained = append(result.Retained, generation)
			continue
		}
		candidates = append(candidates, candidate{generation: generation, manifest: manifest, path: path})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].manifest.Revision != candidates[j].manifest.Revision {
			return candidates[i].manifest.Revision > candidates[j].manifest.Revision
		}
		return candidates[i].generation > candidates[j].generation
	})
	for index, item := range candidates {
		_, isProtected := protected[item.generation]
		if item.generation == current || index < options.KeepRecent || isProtected {
			result.Retained = append(result.Retained, item.generation)
			continue
		}
		if err := os.RemoveAll(item.path); err != nil {
			result.Failed[item.generation] = fmt.Errorf("清理 generation 失败: %w", err)
			result.Retained = append(result.Retained, item.generation)
			continue
		}
		result.Removed = append(result.Removed, item.generation)
	}
	if len(result.Removed) > 0 {
		if err := syncDirectory(releasesDir); err != nil {
			return result, fmt.Errorf("同步 releases 目录失败: %w", err)
		}
	}
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i] < result.Removed[j] })
	sort.Slice(result.Retained, func(i, j int) bool { return result.Retained[i] < result.Retained[j] })
	return result, nil
}

// GC 是 GarbageCollect 的简短 API 名称。
func (s *Store) GC(domain string, options GCOptions) (GCResult, error) {
	return s.GarbageCollect(domain, options)
}

// Abort 删除尚未成为 current 的 generation，用于清理已发布但未采用的产物。
func (s *Store) Abort(domain string, generation certproto.GenerationID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateGeneration(generation); err != nil {
		return err
	}
	domainDir, releasesDir, err := s.domainPaths(domain, false)
	if err != nil {
		return err
	}
	current, err := s.currentGeneration(domainDir)
	if err == nil && current == generation {
		return fmt.Errorf("%w: %s", ErrCurrentGeneration, generation)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	generationDir := filepath.Join(releasesDir, string(generation))
	if err := assertDirectory(generationDir); err != nil {
		return err
	}
	if err := assertGenerationContents(generationDir); err != nil {
		return err
	}
	if err := os.RemoveAll(generationDir); err != nil {
		return fmt.Errorf("清理 generation 失败: %w", err)
	}
	if err := syncDirectory(releasesDir); err != nil {
		return fmt.Errorf("同步 generation 目录失败: %w", err)
	}
	return nil
}

func (s *Store) readStaging(domain, stagingDir string, sans []string) (map[certproto.FileName][]byte, error) {
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
	if err := validateCertificateFiles(domain, files, sans, s.now()); err != nil {
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
	releasesDir := filepath.Join(domainDir, ReleasesDirectory)
	if create {
		if err := ensureDirectory(domainDir); err != nil {
			return "", "", fmt.Errorf("创建域名目录失败: %w", err)
		}
		if err := ensureDirectory(releasesDir); err != nil {
			return "", "", fmt.Errorf("创建 releases 目录失败: %w", err)
		}
		return domainDir, releasesDir, nil
	}
	if err := assertDirectory(domainDir); err != nil {
		return "", "", err
	}
	if err := assertDirectory(releasesDir); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return "", "", err
		}
		legacyDir := filepath.Join(domainDir, legacyGenerationsDirectory)
		if err := assertDirectory(legacyDir); err != nil {
			return "", "", err
		}
		return domainDir, releasesDir, nil
	}
	return domainDir, releasesDir, nil
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
	return s.resolveGenerationLocked(domain, requested)
}

func (s *Store) resolveGenerationLocked(domain string, requested certproto.GenerationID) (string, string, certproto.GenerationID, error) {
	if requested != "" {
		if err := validateGeneration(requested); err != nil {
			return "", "", "", err
		}
	}
	domainDir, releasesDir, err := s.domainPaths(domain, false)
	if err != nil {
		return "", "", "", err
	}
	generation := requested
	if generation == "" {
		generation, _, err = s.currentState(domainDir, releasesDir, true)
		if err != nil {
			return "", "", "", err
		}
	}
	generationDir := filepath.Join(releasesDir, string(generation))
	if err := assertDirectory(generationDir); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return "", "", "", err
		}
		legacyDir := filepath.Join(domainDir, legacyGenerationsDirectory, string(generation))
		if legacyErr := assertDirectory(legacyDir); legacyErr != nil {
			return "", "", "", err
		}
		generationDir = legacyDir
	}
	return domainDir, generationDir, generation, nil
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

func validateCertificateFiles(domain string, files map[certproto.FileName][]byte, expectedSANs []string, now time.Time) error {
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
	if len(fullchain) == 0 {
		return fmt.Errorf("%w: fullchain.pem 不能为空", ErrInvalidCertificate)
	}
	if !bytes.Equal(leaf.Raw, fullchain[0].Raw) {
		return fmt.Errorf("%w: fullchain.pem 的第一张证书必须与 cert.pem 一致", ErrInvalidCertificate)
	}
	caCertificates, err := parseCertificatePEM(files[certproto.FileCA])
	if err != nil {
		return fmt.Errorf("%w: 解析 ca.pem 失败: %v", ErrInvalidCertificate, err)
	}
	if len(caCertificates) == 0 {
		return fmt.Errorf("%w: ca.pem 不能为空", ErrInvalidCertificate)
	}
	if !now.IsZero() {
		for _, certificate := range append(append([]*x509.Certificate{}, leafCertificates...), append(fullchain, caCertificates...)...) {
			if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
				return fmt.Errorf("%w: 证书不在有效期内", ErrInvalidCertificate)
			}
		}
	}
	if err := verifyCertificateChain(domain, leaf, fullchain[1:], caCertificates, now); err != nil {
		return fmt.Errorf("%w: 证书链验证失败: %v", ErrInvalidCertificate, err)
	}
	for _, name := range append([]string{domain}, expectedSANs...) {
		if err := validateSANInput(name); err != nil {
			return fmt.Errorf("%w: SAN 不合法: %v", ErrInvalidCertificate, err)
		}
		if err := leaf.VerifyHostname(name); err != nil {
			return fmt.Errorf("%w: 叶子证书 SAN 未覆盖 %q: %v", ErrInvalidCertificate, name, err)
		}
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

func verifyCertificateChain(domain string, leaf *x509.Certificate, intermediates, roots []*x509.Certificate, now time.Time) error {
	rootPool := x509.NewCertPool()
	for _, certificate := range roots {
		rootPool.AddCert(certificate)
	}
	intermediatePool := x509.NewCertPool()
	for _, certificate := range intermediates {
		intermediatePool.AddCert(certificate)
	}
	verifyOptions := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		DNSName:       domain,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	}
	if _, err := leaf.Verify(verifyOptions); err != nil {
		return err
	}
	return nil
}

func validateSANInput(name string) error {
	if name == "" || name != strings.TrimSpace(name) || strings.ContainsAny(name, "/\\\x00") {
		return errors.New("SAN 不能为空、不能包含空白或路径分隔符")
	}
	return nil
}

func buildGenerationManifest(domain string, generation certproto.GenerationID, revision certproto.Revision, expectedSANs []string, files map[certproto.FileName][]byte, now time.Time) (GenerationManifest, error) {
	if err := validateGeneration(generation); err != nil {
		return GenerationManifest{}, err
	}
	safeDomain, err := normalizeDomain(domain)
	if err != nil {
		return GenerationManifest{}, err
	}
	if err := revision.Validate(); err != nil {
		return GenerationManifest{}, fmt.Errorf("%w: revision 无效: %v", ErrInvalidManifest, err)
	}
	if err := validateCertificateFiles(safeDomain, files, expectedSANs, now); err != nil {
		return GenerationManifest{}, err
	}
	filesManifest, err := buildManifest(files)
	if err != nil {
		return GenerationManifest{}, err
	}
	leaf, err := firstCertificate(files[certproto.FileCert])
	if err != nil {
		return GenerationManifest{}, fmt.Errorf("%w: 读取叶子证书失败: %v", ErrInvalidManifest, err)
	}
	return GenerationManifest{
		Generation:  generation,
		Revision:    revision,
		Domain:      safeDomain,
		SANs:        certificateSANs(leaf),
		Serial:      leaf.SerialNumber.String(),
		Fingerprint: certificateFingerprint(leaf),
		Files:       filesManifest,
	}, nil
}

func nextRevision(domain, domainDir, releasesDir string) (certproto.Revision, error) {
	var revision certproto.Revision
	for _, parent := range []string{releasesDir, filepath.Join(domainDir, legacyGenerationsDirectory)} {
		if err := assertDirectory(parent); errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return 0, fmt.Errorf("校验 generation 父目录失败: %w", err)
		}
		entries, err := os.ReadDir(parent)
		if err != nil {
			return 0, fmt.Errorf("读取 generation 目录失败: %w", err)
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 {
				return 0, fmt.Errorf("generation %s 是符号链接: %w", entry.Name(), ErrUnsafePath)
			}
			if strings.HasPrefix(entry.Name(), ".tmp-") {
				continue
			}
			generation := certproto.GenerationID(entry.Name())
			if validateGeneration(generation) != nil {
				continue
			}
			path := filepath.Join(parent, entry.Name())
			if err := assertDirectory(path); err != nil {
				return 0, fmt.Errorf("generation %s 不是安全目录: %w", generation, err)
			}
			manifest, _, err := loadGeneration(domain, generation, path)
			if err != nil {
				return 0, fmt.Errorf("读取 generation %s revision 失败: %w", generation, err)
			}
			if manifest.Revision > revision {
				revision = manifest.Revision
			}
		}
	}
	if revision == ^certproto.Revision(0) {
		return 0, fmt.Errorf("%w: revision 已耗尽", ErrInvalidManifest)
	}
	return revision + 1, nil
}

func firstCertificate(data []byte) (*x509.Certificate, error) {
	certificates, err := parseCertificatePEM(data)
	if err != nil {
		return nil, err
	}
	if len(certificates) != 1 {
		return nil, errors.New("cert.pem 必须只包含一张叶子证书")
	}
	return certificates[0], nil
}

func certificateSANs(certificate *x509.Certificate) []string {
	set := make(map[string]struct{}, len(certificate.DNSNames)+len(certificate.IPAddresses))
	for _, name := range certificate.DNSNames {
		set[strings.ToLower(name)] = struct{}{}
	}
	for _, address := range certificate.IPAddresses {
		set[address.String()] = struct{}{}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
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

func loadGeneration(domain string, generation certproto.GenerationID, generationDir string) (GenerationManifest, map[certproto.FileName][]byte, error) {
	if err := assertGenerationContents(generationDir); err != nil {
		return GenerationManifest{}, nil, err
	}
	manifestData, err := readRegularFile(filepath.Join(generationDir, manifestFileName))
	if err != nil {
		return GenerationManifest{}, nil, fmt.Errorf("读取 manifest 失败: %w", err)
	}
	manifest, legacy, err := decodeGenerationManifest(manifestData)
	if err != nil {
		return GenerationManifest{}, nil, fmt.Errorf("%w: 解码 manifest 失败: %v", ErrInvalidManifest, err)
	}
	if legacy {
		manifest.Generation = generation
		manifest.Domain = domain
	}
	files := make(map[certproto.FileName][]byte, len(manifest.Files))
	for _, item := range manifest.Files {
		fileName := certproto.FileName(item.Name)
		data, err := readRegularFile(filepath.Join(generationDir, item.Name))
		if err != nil {
			return GenerationManifest{}, nil, fmt.Errorf("读取 generation 文件 %s 失败: %w", item.Name, err)
		}
		digest := sha256.Sum256(data)
		if item.Size != int64(len(data)) || item.SHA256 != hex.EncodeToString(digest[:]) {
			return GenerationManifest{}, nil, fmt.Errorf("%w: %s 的大小或 SHA256 不匹配", ErrInvalidManifest, item.Name)
		}
		files[fileName] = data
	}
	if legacy {
		leaf, err := firstCertificate(files[certproto.FileCert])
		if err != nil {
			return GenerationManifest{}, nil, fmt.Errorf("%w: 旧 manifest 的 cert.pem 无效: %v", ErrInvalidManifest, err)
		}
		manifest.Revision = 1
		manifest.SANs = certificateSANs(leaf)
		manifest.Serial = leaf.SerialNumber.String()
		manifest.Fingerprint = certificateFingerprint(leaf)
	}
	if err := validateGenerationManifest(domain, generation, manifest, files); err != nil {
		return GenerationManifest{}, nil, err
	}
	return manifest, files, nil
}

func decodeGenerationManifest(data []byte) (GenerationManifest, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return GenerationManifest{}, false, errors.New("manifest 为空")
	}
	if trimmed[0] == '[' {
		var files certproto.CertificateManifest
		if err := json.Unmarshal(trimmed, &files); err != nil {
			return GenerationManifest{}, true, err
		}
		if err := validateManifest(files); err != nil {
			return GenerationManifest{}, true, err
		}
		return GenerationManifest{Files: files}, true, nil
	}
	var manifest GenerationManifest
	if err := json.Unmarshal(trimmed, &manifest); err != nil {
		return GenerationManifest{}, false, err
	}
	return manifest, false, nil
}

func validateGenerationManifest(domain string, generation certproto.GenerationID, manifest GenerationManifest, files map[certproto.FileName][]byte) error {
	if generation != "" && manifest.Generation != generation {
		return fmt.Errorf("%w: generation 不匹配", ErrInvalidManifest)
	}
	if err := validateGeneration(manifest.Generation); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if err := manifest.Revision.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	safeDomain, err := normalizeDomain(domain)
	if err != nil {
		return err
	}
	manifestDomain, err := normalizeDomain(manifest.Domain)
	if err != nil || manifestDomain != safeDomain {
		return fmt.Errorf("%w: manifest 主域名不匹配", ErrInvalidManifest)
	}
	if err := validateManifest(manifest.Files); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	leaf, err := firstCertificate(files[certproto.FileCert])
	if err != nil {
		return fmt.Errorf("%w: cert.pem 无效: %v", ErrInvalidManifest, err)
	}
	if manifest.Serial != leaf.SerialNumber.String() {
		return fmt.Errorf("%w: serial 与证书不匹配", ErrInvalidManifest)
	}
	if manifest.Fingerprint != certificateFingerprint(leaf) {
		return fmt.Errorf("%w: fingerprint 与证书不匹配", ErrInvalidManifest)
	}
	actualSANs := certificateSANs(leaf)
	if !sameStringSet(manifest.SANs, actualSANs) {
		return fmt.Errorf("%w: SAN 集合与证书不匹配", ErrInvalidManifest)
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	set := make(map[string]struct{}, len(left))
	for _, value := range left {
		value = strings.ToLower(value)
		if _, exists := set[value]; exists {
			return false
		}
		set[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := set[strings.ToLower(value)]; !exists {
			return false
		}
	}
	return true
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

func (s *Store) currentGeneration(domainDir string) (certproto.GenerationID, error) {
	releasesDir := filepath.Join(domainDir, ReleasesDirectory)
	generation, _, err := s.currentState(domainDir, releasesDir, false)
	return generation, err
}

// currentState 读取 current，并在需要时把旧文本指针迁移为稳定符号链接。
func (s *Store) currentState(domainDir, releasesDir string, migrate bool) (certproto.GenerationID, string, error) {
	currentPath := filepath.Join(domainDir, CurrentFileName)
	info, err := os.Lstat(currentPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("检查 current 失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		generation, err := readCurrentLink(currentPath)
		if err != nil {
			return "", "", err
		}
		generationDir := filepath.Join(releasesDir, string(generation))
		if err := assertDirectory(generationDir); err != nil {
			return "", "", err
		}
		if _, _, err := loadGeneration(filepath.Base(domainDir), generation, generationDir); err != nil {
			return "", "", err
		}
		return generation, generationDir, nil
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("current 不是普通文件或受管符号链接: %w", ErrUnsafePath)
	}
	data, err := readRegularFile(currentPath)
	if err != nil {
		return "", "", fmt.Errorf("读取旧 current 失败: %w", err)
	}
	generation := certproto.GenerationID(strings.TrimSpace(string(data)))
	if err := validateGeneration(generation); err != nil {
		return "", "", fmt.Errorf("current 内容无效: %w", err)
	}
	generationDir := filepath.Join(releasesDir, string(generation))
	legacyDir := filepath.Join(domainDir, legacyGenerationsDirectory, string(generation))
	if err := assertDirectory(generationDir); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return "", "", err
		}
		if legacyErr := assertDirectory(legacyDir); legacyErr != nil {
			return "", "", err
		}
		generationDir = legacyDir
	}
	if _, _, err := loadGeneration(filepath.Base(domainDir), generation, generationDir); err != nil {
		return "", "", err
	}
	if !migrate {
		return generation, generationDir, nil
	}
	movedLegacy := false
	if filepath.Clean(generationDir) == filepath.Clean(legacyDir) {
		if err := ensureDirectory(releasesDir); err != nil {
			return "", "", fmt.Errorf("创建 releases 目录失败: %w", err)
		}
		target := filepath.Join(releasesDir, string(generation))
		if _, statErr := os.Lstat(target); errors.Is(statErr, os.ErrNotExist) {
			if err := os.Rename(generationDir, target); err != nil {
				return "", "", fmt.Errorf("迁移旧 generation 失败: %w", err)
			}
			generationDir = target
			movedLegacy = true
		} else if statErr != nil {
			return "", "", fmt.Errorf("检查迁移目标失败: %w", statErr)
		} else {
			if err := assertDirectory(target); err != nil {
				return "", "", err
			}
			generationDir = target
		}
	}
	if movedLegacy {
		if err := syncDirectory(releasesDir); err != nil {
			_ = os.Rename(generationDir, legacyDir)
			return "", "", fmt.Errorf("同步 releases 迁移结果失败: %w", err)
		}
		if err := syncDirectory(filepath.Dir(legacyDir)); err != nil {
			_ = os.Rename(generationDir, legacyDir)
			return "", "", fmt.Errorf("同步旧 generation 目录失败: %w", err)
		}
	}
	if err := writeCurrent(domainDir, releasesDir, generation); err != nil {
		if movedLegacy {
			_ = os.Rename(generationDir, legacyDir)
		}
		return "", "", err
	}
	return generation, generationDir, nil
}

func readCurrentLink(path string) (certproto.GenerationID, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", fmt.Errorf("读取 current 符号链接失败: %w", err)
	}
	if filepath.IsAbs(target) || target != filepath.Clean(target) || filepath.Dir(target) != ReleasesDirectory {
		return "", fmt.Errorf("current 符号链接目标无效: %w", ErrUnsafePath)
	}
	generation := certproto.GenerationID(filepath.Base(target))
	if err := validateGeneration(generation); err != nil {
		return "", fmt.Errorf("current 符号链接 generation 无效: %w", err)
	}
	if target != filepath.Join(ReleasesDirectory, string(generation)) {
		return "", fmt.Errorf("current 符号链接目标无效: %w", ErrUnsafePath)
	}
	return generation, nil
}

func writeCurrent(domainDir, releasesDir string, generation certproto.GenerationID) error {
	if err := validateGeneration(generation); err != nil {
		return err
	}
	generationDir := filepath.Join(releasesDir, string(generation))
	if err := assertDirectory(generationDir); err != nil {
		return fmt.Errorf("校验 current 目标失败: %w", err)
	}
	currentPath := filepath.Join(domainDir, CurrentFileName)
	snapshot, err := captureCurrent(currentPath)
	if err != nil {
		return fmt.Errorf("更新 current 失败: %w", err)
	}
	temporaryPath, err := randomTemporaryPath(domainDir, ".current-")
	if err != nil {
		return fmt.Errorf("创建 current 临时链接失败: %w", err)
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := os.Symlink(filepath.Join(ReleasesDirectory, string(generation)), temporaryPath); err != nil {
		return fmt.Errorf("创建 current 临时链接失败: %w", err)
	}
	if err := os.Rename(temporaryPath, currentPath); err != nil {
		return fmt.Errorf("原子更新 current 失败: %w", err)
	}
	if err := syncDirectory(domainDir); err != nil {
		if restoreErr := restoreCurrent(currentPath, snapshot); restoreErr != nil {
			return fmt.Errorf("同步域名目录失败: %w；恢复旧 current 失败: %v", err, restoreErr)
		}
		if restoreErr := syncDirectory(domainDir); restoreErr != nil {
			return fmt.Errorf("同步域名目录失败: %w；同步恢复后的 current 失败: %v", err, restoreErr)
		}
		return fmt.Errorf("同步域名目录失败: %w", err)
	}
	return nil
}

type currentSnapshot struct {
	exists  bool
	symlink bool
	link    string
	data    []byte
}

func captureCurrent(path string) (currentSnapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return currentSnapshot{}, nil
	}
	if err != nil {
		return currentSnapshot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		generation, err := readCurrentLink(path)
		if err != nil {
			return currentSnapshot{}, err
		}
		return currentSnapshot{exists: true, symlink: true, link: filepath.Join(ReleasesDirectory, string(generation))}, nil
	}
	if !info.Mode().IsRegular() {
		return currentSnapshot{}, ErrUnsafePath
	}
	data, err := readRegularFile(path)
	if err != nil {
		return currentSnapshot{}, err
	}
	generation := certproto.GenerationID(strings.TrimSpace(string(data)))
	if err := validateGeneration(generation); err != nil {
		return currentSnapshot{}, fmt.Errorf("旧 current 内容无效: %w", err)
	}
	return currentSnapshot{exists: true, data: data}, nil
}

func restoreCurrent(path string, snapshot currentSnapshot) error {
	if !snapshot.exists {
		return os.Remove(path)
	}
	temporaryPath, err := randomTemporaryPath(filepath.Dir(path), ".current-restore-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporaryPath) }()
	if snapshot.symlink {
		if err := os.Symlink(snapshot.link, temporaryPath); err != nil {
			return err
		}
	} else if err := writeFileSync(temporaryPath, snapshot.data); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func randomTemporaryPath(directory, prefix string) (string, error) {
	var token [12]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return filepath.Join(directory, prefix+hex.EncodeToString(token[:])), nil
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
