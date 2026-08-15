package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

// FetchCertificateFileFunc 按固定文件名获取 generation 的单个文件。
// 调用方负责将其接入后续的 v2 下载端点。
type FetchCertificateFileFunc func(ctx context.Context, fileName certproto.FileName) ([]byte, error)

// DeploymentCommand 在 current 切换后执行校验或 reload 命令。
// workDir 始终是输出目录，命令可通过 current 访问活动证书。
type DeploymentCommand func(ctx context.Context, workDir string) error

// GenerationDeployOpts 是一次 generation 原子部署的输入。
type GenerationDeployOpts struct {
	// Domain 是叶子证书必须覆盖的主域名。
	Domain string
	// SAN 是叶子证书额外必须覆盖的域名。
	SAN []string
	// OutDir 是部署根目录，活动 generation 由其中的 current 文件指向。
	OutDir string
	// Generation 是本次下载并发布的 generation。
	Generation certproto.GenerationID
	// Manifest 描述固定证书文件及其完整性信息。
	Manifest certproto.CertificateManifest
	// Fetch 按 manifest 中的固定文件名读取文件内容。
	Fetch FetchCertificateFileFunc
	// Verify 在 current 指向新 generation 后执行；失败会恢复 previous current。
	Verify DeploymentCommand
	// Reload 在 verify 成功后执行；失败保留新的 current，以便重试。
	Reload DeploymentCommand
}

// RetryableError 表示部署已完成但后续 reload 可安全重试。
type RetryableError struct {
	Err error
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("可重试的部署错误: %v", e.Err)
}

// Unwrap 返回原始 reload 错误。
func (e *RetryableError) Unwrap() error {
	return e.Err
}

// DeployGeneration 将一个完整 manifest 下载到 staging，校验证书后以 current 原子发布。
// 它不依赖具体 HTTP 协议，因此可由 v2 API 下载层直接复用并独立测试。
func DeployGeneration(ctx context.Context, opts GenerationDeployOpts) (certproto.DeploymentReport, error) {
	report := certproto.DeploymentReport{
		State:      certproto.DeploymentStateDeploying,
		Generation: opts.Generation,
	}
	if err := opts.Generation.Validate(); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("generation 无效: %w", err)
	}
	if opts.Domain == "" {
		return deploymentFailure(report, errors.New("目标域名不能为空"), false), errors.New("目标域名不能为空")
	}
	if opts.OutDir == "" {
		return deploymentFailure(report, errors.New("输出目录不能为空"), false), errors.New("输出目录不能为空")
	}
	if err := ensureSecureDirectory(opts.OutDir); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("准备输出目录失败: %w", err)
	}

	lock, err := lockDeployment(ctx, opts.OutDir)
	if err != nil {
		return deploymentFailure(report, err, false), err
	}
	defer lock.Close()

	releasesDir := filepath.Join(opts.OutDir, "releases")
	if err := ensureSecureDirectory(releasesDir); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("准备 releases 目录失败: %w", err)
	}

	previous, hasPrevious, err := readDeploymentCurrent(opts.OutDir)
	if err != nil {
		return deploymentFailure(report, err, false), err
	}
	if hasPrevious {
		if err := assertSafeRelease(releasesDir, previous); err != nil {
			return deploymentFailure(report, err, false), fmt.Errorf("当前 release 不安全: %w", err)
		}
	}
	if hasPrevious && previous == opts.Generation {
		report.State = certproto.DeploymentStateSkipped
		report.Success = true
		report.Verified = true
		report.Reloaded = true
		report.Message = "generation 已是当前版本"
		return report, nil
	}

	if opts.Fetch == nil {
		err := errors.New("文件获取函数不能为空")
		return deploymentFailure(report, err, false), err
	}
	if err := validateDeploymentManifest(opts.Manifest); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("manifest 无效: %w", err)
	}

	stagingDir, err := os.MkdirTemp(releasesDir, ".staging-"+string(opts.Generation)+"-")
	if err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("创建 staging 目录失败: %w", err)
	}
	if err := os.Chmod(stagingDir, 0o700); err != nil {
		_ = os.RemoveAll(stagingDir)
		return deploymentFailure(report, err, false), fmt.Errorf("设置 staging 目录权限失败: %w", err)
	}
	defer func() {
		if stagingDir != "" {
			_ = os.RemoveAll(stagingDir)
		}
	}()

	manifestByName := make(map[certproto.FileName]certproto.FileManifest, len(opts.Manifest))
	for _, item := range opts.Manifest {
		manifestByName[certproto.FileName(item.Name)] = item
	}
	for _, fileName := range certproto.FixedFileNames() {
		item := manifestByName[fileName]
		data, err := opts.Fetch(ctx, fileName)
		if err != nil {
			return deploymentFailure(report, err, false), fmt.Errorf("下载 %s 失败: %w", fileName, err)
		}
		if err := writeAndValidateStagedFile(stagingDir, fileName, item, data); err != nil {
			return deploymentFailure(report, err, false), err
		}
	}
	if err := validateStagedCertificate(stagingDir, opts.Domain, opts.SAN, time.Now()); err != nil {
		return deploymentFailure(report, err, false), err
	}

	releaseDir := filepath.Join(releasesDir, string(opts.Generation))
	if _, err := os.Lstat(releaseDir); err == nil {
		err := fmt.Errorf("release %s 已存在", opts.Generation)
		return deploymentFailure(report, err, false), err
	} else if !errors.Is(err, os.ErrNotExist) {
		return deploymentFailure(report, err, false), fmt.Errorf("检查目标 release 失败: %w", err)
	}
	if err := os.Rename(stagingDir, releaseDir); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("发布 release 失败: %w", err)
	}
	stagingDir = ""
	if err := os.Chmod(releaseDir, 0o700); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("设置 release 目录权限失败: %w", err)
	}
	if err := syncDirectory(releasesDir); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("同步 releases 目录失败: %w", err)
	}

	if err := writeDeploymentCurrent(opts.OutDir, opts.Generation); err != nil {
		return deploymentFailure(report, err, false), fmt.Errorf("切换 current 失败: %w", err)
	}
	if opts.Verify != nil {
		if err := opts.Verify(ctx, opts.OutDir); err != nil {
			report = deploymentFailure(report, err, false)
			if rollbackErr := restoreDeploymentCurrent(opts.OutDir, previous, hasPrevious); rollbackErr != nil {
				return report, fmt.Errorf("校验失败: %w；恢复 previous current 失败: %v", err, rollbackErr)
			}
			return report, fmt.Errorf("校验失败: %w", err)
		}
	}
	report.Verified = true

	if opts.Reload != nil {
		if err := opts.Reload(ctx, opts.OutDir); err != nil {
			report = deploymentFailure(report, err, true)
			return report, &RetryableError{Err: fmt.Errorf("reload 失败: %w", err)}
		}
	}
	report.Reloaded = true
	report.State = certproto.DeploymentStateSucceeded
	report.Success = true
	report.Message = "部署完成"
	return report, nil
}

func deploymentFailure(report certproto.DeploymentReport, err error, retryable bool) certproto.DeploymentReport {
	report.State = certproto.DeploymentStateFailed
	report.Success = false
	report.Error = &certproto.ErrorResponse{
		Code:      certproto.ErrorCodeDeploymentFailed,
		Message:   err.Error(),
		Retryable: retryable,
	}
	return report
}

func validateDeploymentManifest(manifest certproto.CertificateManifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	if len(manifest) != len(certproto.FixedFileNames()) {
		return errors.New("manifest 必须包含全部固定证书文件")
	}
	seen := make(map[certproto.FileName]struct{}, len(manifest))
	for _, item := range manifest {
		fileName := certproto.FileName(item.Name)
		seen[fileName] = struct{}{}
	}
	for _, fileName := range certproto.FixedFileNames() {
		if _, ok := seen[fileName]; !ok {
			return fmt.Errorf("manifest 缺少 %s", fileName)
		}
	}
	return nil
}

func ensureSecureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("路径必须是非符号链接目录")
	}
	return os.Chmod(path, 0o700)
}

func writeAndValidateStagedFile(dir string, fileName certproto.FileName, item certproto.FileManifest, data []byte) error {
	if int64(len(data)) != item.Size {
		return fmt.Errorf("%s 的大小不匹配: manifest %d，实际 %d", fileName, item.Size, len(data))
	}
	digest := sha256.Sum256(data)
	if got := hex.EncodeToString(digest[:]); got != item.SHA256 {
		return fmt.Errorf("%s 的 SHA256 不匹配", fileName)
	}
	path := filepath.Join(dir, string(fileName))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("创建 staging 文件 %s 失败: %w", fileName, err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("设置 staging 文件 %s 权限失败: %w", fileName, err)
	}
	if written, err := file.Write(data); err != nil || written != len(data) {
		_ = file.Close()
		if err != nil {
			return fmt.Errorf("写入 staging 文件 %s 失败: %w", fileName, err)
		}
		return fmt.Errorf("写入 staging 文件 %s 不完整", fileName)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("同步 staging 文件 %s 失败: %w", fileName, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭 staging 文件 %s 失败: %w", fileName, err)
	}
	stored, err := readRegularFile(path)
	if err != nil {
		return fmt.Errorf("读取 staging 文件 %s 失败: %w", fileName, err)
	}
	if int64(len(stored)) != item.Size {
		return fmt.Errorf("staging 文件 %s 的大小不匹配", fileName)
	}
	storedDigest := sha256.Sum256(stored)
	if hex.EncodeToString(storedDigest[:]) != item.SHA256 {
		return fmt.Errorf("staging 文件 %s 的 SHA256 不匹配", fileName)
	}
	return nil
}

func validateStagedCertificate(dir, domain string, san []string, now time.Time) error {
	certificates, err := parseCertificatePEMFile(filepath.Join(dir, string(certproto.FileCert)))
	if err != nil {
		return fmt.Errorf("解析 cert.pem 失败: %w", err)
	}
	if len(certificates) != 1 {
		return errors.New("cert.pem 必须只包含一张叶子证书")
	}
	leaf := certificates[0]
	fullchain, err := parseCertificatePEMFile(filepath.Join(dir, string(certproto.FileFullchain)))
	if err != nil {
		return fmt.Errorf("解析 fullchain.pem 失败: %w", err)
	}
	if !bytes.Equal(leaf.Raw, fullchain[0].Raw) {
		return errors.New("fullchain.pem 的第一张证书必须与 cert.pem 相同")
	}
	caCertificates, err := parseCertificatePEMFile(filepath.Join(dir, string(certproto.FileCA)))
	if err != nil {
		return fmt.Errorf("解析 ca.pem 失败: %w", err)
	}
	for _, certificate := range append(append(certificates, fullchain...), caCertificates...) {
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return errors.New("证书尚未生效或已过期")
		}
	}
	privateKeyData, err := readRegularFile(filepath.Join(dir, string(certproto.FileKey)))
	if err != nil {
		return fmt.Errorf("读取 key.pem 失败: %w", err)
	}
	privateKey, err := parsePrivateKeyPEM(privateKeyData)
	if err != nil {
		return fmt.Errorf("解析 key.pem 失败: %w", err)
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return fmt.Errorf("编码证书公钥失败: %w", err)
	}
	privatePublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return fmt.Errorf("编码私钥公钥失败: %w", err)
	}
	if !bytes.Equal(certificatePublicKey, privatePublicKey) {
		return errors.New("私钥与叶子证书不匹配")
	}
	for _, name := range append([]string{domain}, san...) {
		if name == "" {
			return errors.New("目标 SAN 不能为空")
		}
		if err := leaf.VerifyHostname(name); err != nil {
			return fmt.Errorf("叶子证书 SAN 未覆盖 %q: %w", name, err)
		}
	}
	return nil
}

func parseCertificatePEMFile(path string) ([]*x509.Certificate, error) {
	data, err := readRegularFile(path)
	if err != nil {
		return nil, err
	}
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
	var privateKey any
	switch blocks[0].Type {
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(blocks[0].Bytes)
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(blocks[0].Bytes)
	default:
		return nil, fmt.Errorf("不支持的私钥 PEM 块 %q", blocks[0].Type)
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

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("路径必须是非符号链接普通文件")
	}
	return os.ReadFile(path)
}

func assertSafeRelease(releasesDir string, generation certproto.GenerationID) error {
	path := filepath.Join(releasesDir, string(generation))
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("release 必须是非符号链接目录")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != len(certproto.FixedFileNames()) {
		return errors.New("release 文件集合不完整或包含未知文件")
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if !certproto.IsFixedFileName(entry.Name()) {
			return fmt.Errorf("release 包含未知文件 %q", entry.Name())
		}
		if _, err := readRegularFile(filepath.Join(path, entry.Name())); err != nil {
			return fmt.Errorf("release 文件 %s 不安全: %w", entry.Name(), err)
		}
		seen[entry.Name()] = struct{}{}
	}
	for _, fileName := range certproto.FixedFileNames() {
		if _, ok := seen[string(fileName)]; !ok {
			return fmt.Errorf("release 缺少 %s", fileName)
		}
	}
	return nil
}

func readDeploymentCurrent(outDir string) (certproto.GenerationID, bool, error) {
	path := filepath.Join(outDir, "current")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("读取 current 失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil || filepath.IsAbs(target) || filepath.Clean(target) != target || filepath.Dir(target) != "releases" {
			return "", false, errors.New("current 符号链接目标无效")
		}
		generation := certproto.GenerationID(filepath.Base(target))
		if err := generation.Validate(); err != nil {
			return "", false, err
		}
		return generation, true, nil
	}
	if !info.Mode().IsRegular() {
		return "", false, errors.New("current 必须是普通文件或受管符号链接")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, fmt.Errorf("读取 current 内容失败: %w", err)
	}
	generation := certproto.GenerationID(strings.TrimSpace(string(data)))
	if err := generation.Validate(); err != nil {
		return "", false, fmt.Errorf("current 内容无效: %w", err)
	}
	return generation, true, nil
}

func writeDeploymentCurrent(outDir string, generation certproto.GenerationID) error {
	if err := generation.Validate(); err != nil {
		return err
	}
	currentPath := filepath.Join(outDir, "current")
	if info, err := os.Lstat(currentPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() {
			return errors.New("current 必须是普通文件或受管符号链接")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporaryPath := filepath.Join(outDir, ".current-"+string(generation))
	_ = os.Remove(temporaryPath)
	if err := os.Symlink(filepath.Join("releases", string(generation)), temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, currentPath); err != nil {
		return err
	}
	return syncDirectory(outDir)
}

func restoreDeploymentCurrent(outDir string, previous certproto.GenerationID, hasPrevious bool) error {
	if hasPrevious {
		return writeDeploymentCurrent(outDir, previous)
	}
	path := filepath.Join(outDir, "current")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() {
		return errors.New("current 必须是普通文件或受管符号链接")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(outDir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
