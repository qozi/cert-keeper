// Package acme 提供 ACME 证书签发相关的功能。
// 封装 acme.sh 命令行工具，支持证书申请、续签和管理操作。
package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultOutputLimit = 16 * 1024

var (
	validKeylength  = map[string]struct{}{"ec-256": {}, "ec-384": {}, "ec-521": {}, "2048": {}, "3072": {}, "4096": {}}
	dnsProviderName = regexp.MustCompile(`^dns_[a-z0-9]+(?:_[a-z0-9]+)*$`)
	domainName      = regexp.MustCompile(`^(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Runner 封装 acme.sh 调用，提供证书签发和管理功能。
type Runner struct {
	AcmeShPath          string
	Home                string
	CertsDir            string
	ConfigHome          string
	EphemeralConfigHome bool
	Timeout             time.Duration
	OutputLimit         int
	Executor            CommandExecutor
}

// IssueParams 定义证书签发的参数。
type IssueParams struct {
	Domain        string
	SAN           []string
	CA            string
	ChallengeMode string // dns_api / standalone / webroot / dns_manual
	DNSProvider   string // dns_cf / dns_dp ... dns_api 模式必填
	WebrootPath   string // webroot 模式必填
	Keylength     string
	DNSEnv        map[string]string // 已解密的环境变量
	CertsDir      string            // 可选，指定本次签发产物的根目录
}

// OperationStatus 表示 acme.sh 操作的归类状态。
type OperationStatus string

const (
	OperationSucceeded     OperationStatus = "succeeded"
	OperationSkipped       OperationStatus = "skipped"
	OperationManualPending OperationStatus = "manual_pending"
	OperationFailed        OperationStatus = "failed"
	OperationTimedOut      OperationStatus = "timed_out"
	OperationCanceled      OperationStatus = "canceled"
)

// OperationResult 是一次 acme.sh 操作的结构化结果。
type OperationResult struct {
	Operation       string
	Args            []string
	ExitCode        int
	Duration        time.Duration
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Status          OperationStatus
}

// OperationError 表示执行失败、超时或被取消的 acme.sh 操作。
// 错误文本刻意不包含命令输出，避免泄露 DNS 环境变量中的敏感值。
type OperationError struct {
	Operation string
	ExitCode  int
	Status    OperationStatus
}

func (e *OperationError) Error() string {
	switch e.Status {
	case OperationTimedOut:
		return fmt.Sprintf("acme.sh %s 操作超时", e.Operation)
	case OperationCanceled:
		return fmt.Sprintf("acme.sh %s 操作已取消", e.Operation)
	default:
		return fmt.Sprintf("acme.sh %s 操作失败，退出码: %d", e.Operation, e.ExitCode)
	}
}

// Unwrap 支持调用方使用 errors.Is 判断上下文超时或取消。
func (e *OperationError) Unwrap() error {
	switch e.Status {
	case OperationTimedOut:
		return context.DeadlineExceeded
	case OperationCanceled:
		return context.Canceled
	default:
		return nil
	}
}

// OperationParams 定义已有证书的生命周期操作参数。
type OperationParams struct {
	Domain    string
	CA        string
	Keylength string
	DNSEnv    map[string]string
}

// RenewParams 是续签参数的语义别名。
type RenewParams = OperationParams

// ReissueParams 是重新签发参数的语义别名。
type ReissueParams = OperationParams

// InfoParams 是证书查询参数的语义别名。
type InfoParams = OperationParams

// RevokeParams 是吊销参数的语义别名。
type RevokeParams = OperationParams

// RemoveParams 是删除参数的语义别名。
type RemoveParams = OperationParams

// IssueResult 定义证书签发的结果。
type IssueResult struct {
	Domain       string
	OutDir       string
	Files        []string // 实际产物文件名
	NotAfter     time.Time
	StdoutStderr string
	Duration     time.Duration
	Status       OperationStatus
	Issue        OperationResult
	Install      OperationResult
}

// Issue 签发并安装证书。签发和安装步骤共享同一个总超时。
func (r *Runner) Issue(ctx context.Context, p *IssueParams) (*IssueResult, error) {
	if err := validateIssueParams(p); err != nil {
		return nil, fmt.Errorf("签发参数无效: %w", err)
	}
	if err := r.validateReady(); err != nil {
		return nil, err
	}

	started := time.Now()
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()

	certsDir := r.CertsDir
	if p.CertsDir != "" {
		certsDir = p.CertsDir
	}
	if certsDir == "" {
		return nil, errors.New("证书目录不能为空")
	}
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	outDir := filepath.Join(certsDir, p.Domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建域名证书目录失败: %w", err)
	}

	res := &IssueResult{Domain: p.Domain, OutDir: outDir}
	err := r.withIsolatedConfig(cctx, "issue", p.DNSEnv, []string{certsDir}, func(configHome string) error {
		issue, issueErr := r.execute(cctx, "issue", r.buildIssueArgs(p), p.DNSEnv, configHome)
		res.Issue = issue
		res.Status = issue.Status
		res.StdoutStderr = r.combineOutput(issue)
		if issueErr != nil || issue.Status != OperationSucceeded {
			return issueErr
		}

		install, installErr := r.installCert(cctx, p, outDir, configHome)
		res.Install = install
		res.Status = install.Status
		res.StdoutStderr = r.combineOutput(issue, install)
		if installErr != nil || install.Status != OperationSucceeded {
			return installErr
		}
		if err := cctx.Err(); err != nil {
			return contextOperationError("issue", err)
		}

		if err := writeIssueMetadata(res, outDir); err != nil {
			return err
		}
		return nil
	})
	res.Duration = time.Since(started)
	if err != nil {
		return res, safeError(err, p.DNSEnv)
	}
	return res, nil
}

// Renew 续签已有证书。退出码 2 表示跳过，退出码 3 表示等待人工处理。
func (r *Runner) Renew(ctx context.Context, p *RenewParams) (*OperationResult, error) {
	return r.certificateOperation(ctx, "renew", p, false)
}

// Reissue 强制重新签发已有证书。
func (r *Runner) Reissue(ctx context.Context, p *ReissueParams) (*OperationResult, error) {
	return r.certificateOperation(ctx, "reissue", p, true)
}

// Info 查询已有证书的信息。
func (r *Runner) Info(ctx context.Context, p *InfoParams) (*OperationResult, error) {
	return r.namedCertificateOperation(ctx, "info", "--info", p)
}

// Revoke 吊销已有证书。
func (r *Runner) Revoke(ctx context.Context, p *RevokeParams) (*OperationResult, error) {
	return r.namedCertificateOperation(ctx, "revoke", "--revoke", p)
}

// Remove 从 acme.sh 主目录移除已有证书。
func (r *Runner) Remove(ctx context.Context, p *RemoveParams) (*OperationResult, error) {
	return r.namedCertificateOperation(ctx, "remove", "--remove", p)
}

// Version 查询 acme.sh 版本，不会执行升级。
func (r *Runner) Version(ctx context.Context) (*OperationResult, error) {
	if err := r.validateReady(); err != nil {
		return nil, err
	}
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()
	var result OperationResult
	err := r.withIsolatedConfig(cctx, "version", nil, nil, func(configHome string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, "version", []string{"--version"}, nil, configHome)
		return executeErr
	})
	return &result, err
}

// RenewAndInstall 续签证书并将结果安装到调用方指定的 staging 目录。
// renew 跳过时仍会执行安装，人工待处理时则不会安装。
func (r *Runner) RenewAndInstall(ctx context.Context, p *IssueParams, force bool) (*IssueResult, error) {
	if err := validateRenewInstallParams(p); err != nil {
		return nil, fmt.Errorf("续签参数无效: %w", err)
	}
	if err := r.validateReady(); err != nil {
		return nil, err
	}

	started := time.Now()
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()
	certsDir := r.CertsDir
	if p.CertsDir != "" {
		certsDir = p.CertsDir
	}
	if certsDir == "" {
		return nil, errors.New("证书目录不能为空")
	}
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	outDir := filepath.Join(certsDir, p.Domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建域名证书目录失败: %w", err)
	}

	res := &IssueResult{Domain: p.Domain, OutDir: outDir}
	err := r.withIsolatedConfig(cctx, "renew", p.DNSEnv, []string{certsDir}, func(configHome string) error {
		args := r.appendCertificateOptions([]string{"--renew", "-d", p.Domain}, &OperationParams{
			Domain: p.Domain, CA: p.CA, Keylength: p.Keylength,
		})
		if force {
			args = insertForce(args)
		}
		renew, renewErr := r.execute(cctx, "renew", args, p.DNSEnv, configHome)
		res.Issue = renew
		res.Status = renew.Status
		res.StdoutStderr = r.combineOutput(renew)
		if renewErr != nil || renew.Status == OperationManualPending || renew.Status == OperationFailed || renew.Status == OperationTimedOut || renew.Status == OperationCanceled {
			return renewErr
		}
		if renew.Status != OperationSucceeded && renew.Status != OperationSkipped {
			return nil
		}

		install, installErr := r.installCert(cctx, p, outDir, configHome)
		res.Install = install
		res.StdoutStderr = r.combineOutput(renew, install)
		if installErr != nil || install.Status != OperationSucceeded {
			res.Status = install.Status
			return installErr
		}
		if err := cctx.Err(); err != nil {
			return contextOperationError("renew", err)
		}
		if err := writeIssueMetadata(res, outDir); err != nil {
			return err
		}
		if renew.Status == OperationSkipped {
			res.Status = OperationSkipped
		} else {
			res.Status = OperationSucceeded
		}
		return nil
	})
	res.Duration = time.Since(started)
	if err != nil {
		return res, safeError(err, p.DNSEnv)
	}
	return res, nil
}

func (r *Runner) certificateOperation(ctx context.Context, operation string, p *OperationParams, force bool) (*OperationResult, error) {
	if err := validateOperationParams(p); err != nil {
		return nil, fmt.Errorf("%s 参数无效: %w", operation, err)
	}
	if err := r.validateReady(); err != nil {
		return nil, err
	}
	args := []string{"--renew", "-d", p.Domain}
	if force {
		args = append(args, "--force")
	}
	args = r.appendCertificateOptions(args, p)
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()
	var result OperationResult
	err := r.withIsolatedConfig(cctx, operation, p.DNSEnv, []string{r.CertsDir}, func(configHome string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, operation, args, p.DNSEnv, configHome)
		return executeErr
	})
	return &result, err
}

func (r *Runner) namedCertificateOperation(ctx context.Context, operation, command string, p *OperationParams) (*OperationResult, error) {
	if err := validateOperationParams(p); err != nil {
		return nil, fmt.Errorf("%s 参数无效: %w", operation, err)
	}
	if err := r.validateReady(); err != nil {
		return nil, err
	}
	args := r.appendCertificateOptions([]string{command, "-d", p.Domain}, p)
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()
	var result OperationResult
	err := r.withIsolatedConfig(cctx, operation, p.DNSEnv, []string{r.CertsDir}, func(configHome string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, operation, args, p.DNSEnv, configHome)
		return executeErr
	})
	return &result, err
}

func (r *Runner) buildIssueArgs(p *IssueParams) []string {
	args := []string{"--issue", "-d", p.Domain}
	for _, s := range p.SAN {
		args = append(args, "-d", s)
	}
	switch p.ChallengeMode {
	case "dns_api":
		args = append(args, "--dns", p.DNSProvider)
	case "dns_manual":
		args = append(args, "--dns", "--yes-I-know-dns-manual-mode-enough-go-ahead-please")
	case "standalone":
		args = append(args, "--standalone", "--httpport", "80")
	case "webroot":
		args = append(args, "--webroot", p.WebrootPath)
	}
	if p.Keylength != "" {
		args = append(args, "--keylength", p.Keylength)
	}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	return r.appendHome(args)
}

func (r *Runner) installCert(ctx context.Context, p *IssueParams, outDir, configHome string) (OperationResult, error) {
	args := []string{"--install-cert", "-d", p.Domain}
	if isECC(p.Keylength) {
		args = append(args, "--ecc")
	}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	args = r.appendHome(args)
	args = append(args,
		"--cert-file", filepath.Join(outDir, "cert.pem"),
		"--key-file", filepath.Join(outDir, "key.pem"),
		"--fullchain-file", filepath.Join(outDir, "fullchain.pem"),
		"--ca-file", filepath.Join(outDir, "ca.pem"),
	)
	return r.execute(ctx, "install-cert", args, p.DNSEnv, configHome)
}

func (r *Runner) appendCertificateOptions(args []string, p *OperationParams) []string {
	if isECC(p.Keylength) {
		args = append(args, "--ecc")
	}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	return r.appendHome(args)
}

func (r *Runner) appendHome(args []string) []string {
	if r.Home != "" {
		args = append(args, "--home", r.Home)
	}
	return args
}

func appendConfigHome(args []string, configHome string) []string {
	if configHome != "" {
		args = append(args, "--config-home", configHome)
	}
	return args
}

func (r *Runner) execute(ctx context.Context, operation string, args []string, dnsEnv map[string]string, configHome string) (OperationResult, error) {
	args = appendConfigHome(args, configHome)
	result := OperationResult{
		Operation: operation,
		Args:      append([]string(nil), args...),
		ExitCode:  -1,
	}
	if err := validateDNSEnv(dnsEnv); err != nil {
		result.Status = OperationFailed
		return result, fmt.Errorf("DNS 环境变量无效: %w", err)
	}
	if err := ctx.Err(); err != nil {
		result.Status = contextStatus(err)
		return result, contextOperationError(operation, err)
	}

	started := time.Now()
	raw := r.commandExecutor().Execute(ctx, CommandSpec{
		Path:        r.AcmeShPath,
		Args:        append([]string(nil), args...),
		Env:         buildEnv(dnsEnv, r.Home),
		OutputLimit: r.outputLimit(),
	})
	result.Duration = time.Since(started)
	result.ExitCode = raw.ExitCode
	result.Stdout, result.StdoutTruncated = redactAndLimit(raw.Stdout, dnsEnv, r.outputLimit())
	result.Stderr, result.StderrTruncated = redactAndLimit(raw.Stderr, dnsEnv, r.outputLimit())
	result.StdoutTruncated = result.StdoutTruncated || raw.StdoutTruncated
	result.StderrTruncated = result.StderrTruncated || raw.StderrTruncated

	if err := ctx.Err(); err != nil {
		result.Status = contextStatus(err)
		return result, contextOperationError(operation, err)
	}
	if raw.ExitCode == 0 && raw.Err == nil {
		result.Status = OperationSucceeded
		return result, nil
	}
	switch raw.ExitCode {
	case 2:
		result.Status = OperationSkipped
		return result, nil
	case 3:
		result.Status = OperationManualPending
		return result, nil
	default:
		result.Status = OperationFailed
		return result, &OperationError{Operation: operation, ExitCode: raw.ExitCode, Status: result.Status}
	}
}

func (r *Runner) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return context.WithTimeout(ctx, timeout)
}

func (r *Runner) commandExecutor() CommandExecutor {
	if r.Executor != nil {
		return r.Executor
	}
	return OSCommandExecutor{}
}

func (r *Runner) outputLimit() int {
	if r.OutputLimit > 0 {
		return r.OutputLimit
	}
	return defaultOutputLimit
}

func (r *Runner) combineOutput(results ...OperationResult) string {
	var output strings.Builder
	for _, result := range results {
		for _, part := range []string{result.Stdout, result.Stderr} {
			if part == "" {
				continue
			}
			if output.Len() > 0 {
				output.WriteByte('\n')
			}
			output.WriteString(part)
			if output.Len() >= r.outputLimit() {
				return output.String()[:r.outputLimit()]
			}
		}
	}
	return output.String()
}

func (r *Runner) validateReady() error {
	if r.AcmeShPath == "" {
		return ErrAcmeNotReady
	}
	return nil
}

func validateIssueParams(p *IssueParams) error {
	if p == nil {
		return errors.New("参数不能为空")
	}
	if err := validateDomain(p.Domain); err != nil {
		return err
	}
	for _, san := range p.SAN {
		if err := validateDomain(san); err != nil {
			return fmt.Errorf("SAN 无效: %w", err)
		}
	}
	if err := validateKeylength(p.Keylength); err != nil {
		return err
	}
	if err := validateDNSEnv(p.DNSEnv); err != nil {
		return fmt.Errorf("DNS 环境变量无效: %w", err)
	}
	switch p.ChallengeMode {
	case "dns_api":
		if !dnsProviderName.MatchString(p.DNSProvider) {
			return errors.New("DNS provider 必须是 dns_ 前缀的小写标识符")
		}
	case "dns_manual", "standalone":
	case "webroot":
		if strings.TrimSpace(p.WebrootPath) == "" {
			return errors.New("webroot 模式必须指定目录")
		}
	default:
		return errors.New("不支持的 challenge mode")
	}
	return nil
}

func validateOperationParams(p *OperationParams) error {
	if p == nil {
		return errors.New("参数不能为空")
	}
	if err := validateDomain(p.Domain); err != nil {
		return err
	}
	if err := validateKeylength(p.Keylength); err != nil {
		return err
	}
	if err := validateDNSEnv(p.DNSEnv); err != nil {
		return fmt.Errorf("DNS 环境变量无效: %w", err)
	}
	return nil
}

func validateRenewInstallParams(p *IssueParams) error {
	if p == nil {
		return errors.New("参数不能为空")
	}
	if err := validateDomain(p.Domain); err != nil {
		return err
	}
	if err := validateKeylength(p.Keylength); err != nil {
		return err
	}
	if err := validateDNSEnv(p.DNSEnv); err != nil {
		return fmt.Errorf("DNS 环境变量无效: %w", err)
	}
	return nil
}

func validateDomain(domain string) error {
	if !domainName.MatchString(domain) {
		return errors.New("域名格式无效")
	}
	return nil
}

func validateKeylength(keylength string) error {
	if keylength == "" {
		return nil
	}
	if _, ok := validKeylength[keylength]; !ok {
		return errors.New("不支持的密钥算法")
	}
	return nil
}

func validateDNSEnv(dnsEnv map[string]string) error {
	for name := range dnsEnv {
		if !environmentName.MatchString(name) {
			return fmt.Errorf("环境变量名无效: %s", name)
		}
	}
	return nil
}

func isECC(keylength string) bool {
	return strings.HasPrefix(keylength, "ec-")
}

func contextStatus(err error) OperationStatus {
	if errors.Is(err, context.DeadlineExceeded) {
		return OperationTimedOut
	}
	return OperationCanceled
}

func contextOperationError(operation string, err error) error {
	return &OperationError{Operation: operation, ExitCode: -1, Status: contextStatus(err)}
}

func insertForce(args []string) []string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-d" {
			return append(append(append([]string(nil), args[:i+2]...), "--force"), args[i+2:]...)
		}
	}
	return append(args, "--force")
}

func writeIssueMetadata(result *IssueResult, outDir string) error {
	// 只有安装成功后才写入 staging 的完成标记。
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.WriteFile(filepath.Join(outDir, "time.log"), []byte(ts), 0o644); err != nil {
		return fmt.Errorf("写入 time.log 失败: %w", err)
	}
	if na, err := readNotAfter(outDir); err == nil {
		result.NotAfter = na
	}
	result.Files = []string{"cert.pem", "key.pem", "fullchain.pem", "ca.pem", "time.log"}
	return nil
}

type sanitizedError struct {
	message string
	cause   error
}

func (e *sanitizedError) Error() string { return e.message }

func (e *sanitizedError) Unwrap() error { return e.cause }

func safeError(err error, dnsEnv map[string]string) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for _, value := range dnsEnv {
		if value != "" {
			message = strings.ReplaceAll(message, value, "***")
		}
	}
	if message == err.Error() {
		return err
	}
	return &sanitizedError{message: message, cause: err}
}

func buildEnv(dnsEnv map[string]string, home string) []string {
	overrides := make(map[string]string, len(dnsEnv)+1)
	if home != "" {
		overrides["ACME_HOME"] = home
	}
	for name, value := range dnsEnv {
		overrides[name] = value
	}

	envs := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if _, overridden := overrides[name]; !overridden {
			envs = append(envs, entry)
		}
	}
	for name, value := range overrides {
		envs = append(envs, name+"="+value)
	}
	return envs
}

func redactAndLimit(output string, dnsEnv map[string]string, limit int) (string, bool) {
	for _, value := range dnsEnv {
		if value == "" {
			continue
		}
		output = strings.ReplaceAll(output, value, "***")
		// 命令输出在敏感值中间截断时，也不能保留其前缀。
		for n := len(value) - 1; n > 0; n-- {
			if strings.HasSuffix(output, value[:n]) {
				output = strings.TrimSuffix(output, value[:n]) + "***"
				break
			}
		}
	}
	if len(output) <= limit {
		return output, false
	}
	return output[:limit], true
}

func readNotAfter(dir string) (time.Time, error) {
	full := filepath.Join(dir, "fullchain.pem")
	data, err := os.ReadFile(full)
	if err != nil {
		return time.Time{}, err
	}
	return parseCertExpiry(data)
}

func parseCertExpiry(pem []byte) (time.Time, error) {
	// 最简实现：用 crypto/tls 解析第一张证书。
	return parseCertExpiryImpl(pem)
}

// FileSHA256 计算文件的 SHA256 哈希值，供 API 返回校验信息。
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// ShouldRenew 判断证书是否需要续签：在 renewDays 天内到期则返回 true。
func ShouldRenew(notAfter time.Time, renewDays int) bool {
	if notAfter.IsZero() {
		return true
	}
	return time.Until(notAfter) < time.Duration(renewDays)*24*time.Hour
}

func parseCertExpiryImpl(pem []byte) (time.Time, error) {
	// 复用 cert 包解析。
	return ParsePemExpiry(pem)
}

// ErrAcmeNotReady 表示 acme.sh 未就绪的错误。
var ErrAcmeNotReady = errors.New("acme.sh 未就绪，请检查安装路径")

// AutoUpgrade 调用 acme.sh --upgrade --auto-upgrade 升级 acme.sh。
// Deprecated: 不应在新流程中调用此方法，acme.sh 升级应由运维流程显式执行。
func (r *Runner) AutoUpgrade(ctx context.Context) error {
	if err := r.validateReady(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var err error
	err = r.withIsolatedConfig(cctx, "upgrade", nil, nil, func(configHome string) error {
		_, executeErr := r.execute(cctx, "upgrade", r.appendHome([]string{"--upgrade", "--auto-upgrade"}), nil, configHome)
		return executeErr
	})
	return err
}

// SetDefaultCA 设置默认的证书颁发机构（CA）。
func (r *Runner) SetDefaultCA(ctx context.Context, ca string) error {
	if ca == "" {
		return nil
	}
	if err := r.validateReady(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var err error
	err = r.withIsolatedConfig(cctx, "set-default-ca", nil, nil, func(configHome string) error {
		_, executeErr := r.execute(cctx, "set-default-ca", r.appendHome([]string{"--set-default-ca", "--server", ca}), nil, configHome)
		return executeErr
	})
	return err
}

// AccountRegistered 检查是否已注册 ACME 账户（粗略检查 home 目录下有账号文件）。
func (r *Runner) AccountRegistered() bool {
	if r.Home == "" {
		return false
	}
	// acme.sh 账户文件在 ca/<domain>:/ 目录下。
	entries, err := os.ReadDir(filepath.Join(r.Home, "ca"))
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// RegisterAccount 注册 ACME 账户。
func (r *Runner) RegisterAccount(ctx context.Context, email string) error {
	if email == "" {
		return nil
	}
	if err := r.validateReady(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var result OperationResult
	err := r.withIsolatedConfig(cctx, "register-account", nil, nil, func(configHome string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, "register-account", r.appendHome([]string{"--register-account", "-m", email}), nil, configHome)
		return executeErr
	})
	if err != nil && strings.Contains(result.Stdout+"\n"+result.Stderr, "already") {
		return nil
	}
	return err
}
