// Package acme 提供 ACME 证书签发相关的功能。
// 封装 acme.sh 命令行工具，支持证书申请、续签和管理操作。
package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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
	profileName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	caName          = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

// Runner 封装 acme.sh 调用，提供证书签发和管理功能。
type Runner struct {
	AcmeShPath          string
	Home                string // 兼容字段，作为 acme.sh --home 和默认持久 config-home
	StateHome           string // 可选的 acme.sh --home；为空时使用 Home
	CertsDir            string
	ConfigHome          string // 持久账户、CA 和域名状态目录；为空时使用 StateHome/Home
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
	StagingDir    string            // 可选，指定本次安装产物的准确目录
	Profile       string            // DNS 凭据 profile 标识，不传递给 acme.sh
	Env           map[string]string // DNSEnv 的新名称，优先与 DNSEnv 合并
	KeyType       string            // 可选：ecc 或 rsa
	Staging       bool              // 使用 ACME CA 的 staging 端点
	EABKID        string            // External Account Binding 的 KID
	EABHMACKey    string            // External Account Binding 的 HMAC key
	EABKid        string            // EABKID 的兼容拼写
	EABHmacKey    string            // EABHMACKey 的兼容拼写
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
	Domain     string
	CA         string
	Keylength  string
	DNSEnv     map[string]string
	Profile    string
	Env        map[string]string
	KeyType    string
	Staging    bool
	EABKID     string
	EABHMACKey string
	EABKid     string
	EABHmacKey string
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
	res, err := r.issueWithContext(cctx, p)
	if res != nil {
		res.Duration = time.Since(started)
	}
	if err != nil {
		return res, safeError(err, issueEnv(p))
	}
	return res, nil
}

func (r *Runner) issueWithContext(cctx context.Context, p *IssueParams) (*IssueResult, error) {
	started := time.Now()

	outDir, certsDir, err := r.outputDir(p)
	if err != nil {
		return nil, err
	}

	res := &IssueResult{Domain: p.Domain, OutDir: outDir}
	env := issueEnv(p)
	err = r.withIsolatedConfig(cctx, "issue", env, []string{certsDir}, func(configHome, accountConf string) error {
		issue, issueErr := r.execute(cctx, "issue", r.buildIssueArgs(p), env, configHome, accountConf)
		res.Issue = issue
		res.Status = issue.Status
		res.StdoutStderr = r.combineOutput(issue)
		if issueErr != nil || issue.Status != OperationSucceeded {
			return issueErr
		}

		install, installErr := r.installCert(cctx, p, outDir, configHome, accountConf)
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
	return res, err
}

// IssueOrRenew 首次调用使用 issue，检测到持久 config-home 中已有域名状态时使用 renew。
// 可选 force 参数为 true 时，已有证书续签会带 --force；省略时等同于 false。
func (r *Runner) IssueOrRenew(ctx context.Context, p *IssueParams, force ...bool) (*IssueResult, error) {
	if len(force) > 1 {
		return nil, errors.New("force 参数只能提供一次")
	}
	if p == nil {
		return nil, errors.New("签发或续签参数无效: 参数不能为空")
	}
	if err := validateRenewInstallParams(p); err != nil {
		return nil, fmt.Errorf("签发或续签参数无效: %w", err)
	}
	if err := r.validateReady(); err != nil {
		return nil, err
	}
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()
	if r.hasDomainState(p.Domain, p.KeyType, p.Keylength) {
		result, err := r.renewAndInstallWithContext(cctx, p, len(force) == 1 && force[0])
		if err != nil {
			return result, safeError(err, issueEnv(p))
		}
		return result, nil
	}
	if err := validateChallengeParams(p); err != nil {
		return nil, fmt.Errorf("签发或续签参数无效: %w", err)
	}
	result, err := r.issueWithContext(cctx, p)
	if err != nil {
		return result, safeError(err, issueEnv(p))
	}
	return result, nil
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
	err := r.withIsolatedConfig(cctx, "version", nil, nil, func(configHome, accountConf string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, "version", []string{"--version"}, nil, configHome, accountConf)
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
	res, err := r.renewAndInstallWithContext(cctx, p, force)
	if res != nil {
		res.Duration = time.Since(started)
	}
	if err != nil {
		return res, safeError(err, issueEnv(p))
	}
	return res, nil
}

func (r *Runner) renewAndInstallWithContext(cctx context.Context, p *IssueParams, force bool) (*IssueResult, error) {
	started := time.Now()
	outDir, certsDir, err := r.outputDir(p)
	if err != nil {
		return nil, err
	}

	res := &IssueResult{Domain: p.Domain, OutDir: outDir}
	env := issueEnv(p)
	err = r.withIsolatedConfig(cctx, "renew", env, []string{certsDir}, func(configHome, accountConf string) error {
		args := r.appendCertificateOptions([]string{"--renew", "-d", p.Domain}, &OperationParams{
			Domain: p.Domain, CA: p.CA, Keylength: p.Keylength, KeyType: p.KeyType, Staging: p.Staging,
			EABKID: p.EABKID, EABHMACKey: p.EABHMACKey, EABKid: p.EABKid, EABHmacKey: p.EABHmacKey,
		})
		if force {
			args = insertForce(args)
		}
		renew, renewErr := r.execute(cctx, "renew", args, env, configHome, accountConf)
		res.Issue = renew
		res.Status = renew.Status
		res.StdoutStderr = r.combineOutput(renew)
		if renewErr != nil || renew.Status == OperationManualPending || renew.Status == OperationFailed || renew.Status == OperationTimedOut || renew.Status == OperationCanceled {
			return renewErr
		}
		if renew.Status != OperationSucceeded && renew.Status != OperationSkipped {
			return nil
		}

		install, installErr := r.installCert(cctx, p, outDir, configHome, accountConf)
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
	return res, err
}

// InstallCert 仅执行安装步骤，将已有证书复制到 StagingDir 或 CertsDir/<domain>。
func (r *Runner) InstallCert(ctx context.Context, p *IssueParams) (*OperationResult, error) {
	if err := validateRenewInstallParams(p); err != nil {
		return nil, fmt.Errorf("安装参数无效: %w", err)
	}
	if err := r.validateReady(); err != nil {
		return nil, err
	}
	outDir, certsDir, err := r.outputDir(p)
	if err != nil {
		return nil, err
	}
	cctx, cancel := r.withTimeout(ctx)
	defer cancel()
	var result OperationResult
	env := issueEnv(p)
	err = r.withIsolatedConfig(cctx, "install-cert", env, []string{certsDir}, func(configHome, accountConf string) error {
		var executeErr error
		result, executeErr = r.installCert(cctx, p, outDir, configHome, accountConf)
		return executeErr
	})
	if err != nil {
		return &result, safeError(err, env)
	}
	return &result, nil
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
	env := operationEnv(p)
	err := r.withIsolatedConfig(cctx, operation, env, []string{r.CertsDir}, func(configHome, accountConf string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, operation, args, env, configHome, accountConf)
		return executeErr
	})
	return &result, safeError(err, env)
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
	env := operationEnv(p)
	err := r.withIsolatedConfig(cctx, operation, env, []string{r.CertsDir}, func(configHome, accountConf string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, operation, args, env, configHome, accountConf)
		return executeErr
	})
	return &result, safeError(err, env)
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
	keylength := p.Keylength
	if keylength == "" {
		switch p.KeyType {
		case "ecc":
			keylength = "ec-256"
		case "rsa":
			keylength = "2048"
		}
	}
	if keylength != "" {
		args = append(args, "--keylength", keylength)
	}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	args = appendACMEOptions(args, p.Staging, p.EABKID, p.EABHMACKey, p.EABKid, p.EABHmacKey)
	return r.appendHome(args)
}

func (r *Runner) installCert(ctx context.Context, p *IssueParams, outDir, configHome, accountConf string) (OperationResult, error) {
	args := []string{"--install-cert", "-d", p.Domain}
	if p.KeyType == "ecc" || (p.KeyType == "" && isECC(p.Keylength)) {
		args = append(args, "--ecc")
	}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	args = appendACMEOptions(args, p.Staging, "", "", "", "")
	args = r.appendHome(args)
	args = append(args,
		"--cert-file", filepath.Join(outDir, "cert.pem"),
		"--key-file", filepath.Join(outDir, "key.pem"),
		"--fullchain-file", filepath.Join(outDir, "fullchain.pem"),
		"--ca-file", filepath.Join(outDir, "ca.pem"),
	)
	return r.execute(ctx, "install-cert", args, issueEnv(p), configHome, accountConf)
}

func (r *Runner) appendCertificateOptions(args []string, p *OperationParams) []string {
	if p.KeyType == "ecc" || (p.KeyType == "" && isECC(p.Keylength)) {
		args = append(args, "--ecc")
	}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	args = appendACMEOptions(args, p.Staging, "", "", "", "")
	return r.appendHome(args)
}

func appendACMEOptions(args []string, staging bool, eabKID, eabHMACKey, eabKid, eabHmacKey string) []string {
	if staging {
		args = append(args, "--staging")
	}
	if eabKID == "" {
		eabKID = eabKid
	}
	if eabHMACKey == "" {
		eabHMACKey = eabHmacKey
	}
	if eabKID != "" {
		args = append(args, "--eab-kid", eabKID)
	}
	if eabHMACKey != "" {
		args = append(args, "--eab-hmac-key", eabHMACKey)
	}
	return args
}

func (r *Runner) appendHome(args []string) []string {
	if home := r.stateHome(); home != "" {
		args = append(args, "--home", home)
	}
	return args
}

func (r *Runner) stateHome() string {
	if r.StateHome != "" {
		return r.StateHome
	}
	return r.Home
}

func (r *Runner) persistentConfigHome() string {
	if r.ConfigHome != "" {
		return r.ConfigHome
	}
	return r.stateHome()
}

func appendConfigHome(args []string, configHome string) []string {
	if configHome != "" {
		args = append(args, "--config-home", configHome)
	}
	return args
}

func appendAccountConf(args []string, accountConf string) []string {
	if accountConf != "" {
		args = append(args, "--accountconf", accountConf)
	}
	return args
}

func (r *Runner) execute(ctx context.Context, operation string, args []string, dnsEnv map[string]string, configHome string, accountConf ...string) (OperationResult, error) {
	args = appendConfigHome(args, configHome)
	if len(accountConf) > 0 {
		args = appendAccountConf(args, accountConf[0])
	}
	redactions := commandRedactions(args, dnsEnv)
	result := OperationResult{
		Operation: operation,
		Args:      redactArgs(args, redactions),
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
		Env:         buildEnv(dnsEnv, r.stateHome()),
		OutputLimit: r.outputLimit(),
	})
	result.Duration = time.Since(started)
	result.ExitCode = raw.ExitCode
	result.Stdout, result.StdoutTruncated = redactAndLimit(raw.Stdout, redactions, r.outputLimit())
	result.Stderr, result.StderrTruncated = redactAndLimit(raw.Stderr, redactions, r.outputLimit())
	result.StdoutTruncated = result.StdoutTruncated || raw.StdoutTruncated
	result.StderrTruncated = result.StderrTruncated || raw.StderrTruncated

	if err := ctx.Err(); err != nil {
		result.Status = contextStatus(err)
		return result, contextOperationError(operation, err)
	}
	if errors.Is(raw.Err, context.DeadlineExceeded) || errors.Is(raw.Err, context.Canceled) {
		result.Status = contextStatus(raw.Err)
		return result, contextOperationError(operation, raw.Err)
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
	if err := validateIssueCommon(p); err != nil {
		return err
	}
	return validateChallengeParams(p)
}

func validateIssueCommon(p *IssueParams) error {
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
	if err := validateKeyType(p.KeyType, p.Keylength); err != nil {
		return err
	}
	if err := validateCA(p.CA); err != nil {
		return err
	}
	if err := validateProfile(p.Profile); err != nil {
		return err
	}
	if err := validateEAB(p.EABKID, p.EABHMACKey, p.EABKid, p.EABHmacKey); err != nil {
		return err
	}
	if err := validateStagingDir(p.StagingDir); err != nil {
		return err
	}
	if err := validateDNSEnv(issueEnv(p)); err != nil {
		return fmt.Errorf("DNS 环境变量无效: %w", err)
	}
	return nil
}

func validateChallengeParams(p *IssueParams) error {
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
	if err := validateKeyType(p.KeyType, p.Keylength); err != nil {
		return err
	}
	if err := validateCA(p.CA); err != nil {
		return err
	}
	if err := validateProfile(p.Profile); err != nil {
		return err
	}
	if err := validateEAB(p.EABKID, p.EABHMACKey, p.EABKid, p.EABHmacKey); err != nil {
		return err
	}
	if err := validateDNSEnv(operationEnv(p)); err != nil {
		return fmt.Errorf("DNS 环境变量无效: %w", err)
	}
	return nil
}

func validateRenewInstallParams(p *IssueParams) error {
	if p == nil {
		return errors.New("参数不能为空")
	}
	return validateIssueCommon(p)
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

func validateKeyType(keyType, keylength string) error {
	if keyType != "" && keyType != "ecc" && keyType != "rsa" {
		return errors.New("密钥类型必须是 ecc 或 rsa")
	}
	if keyType == "ecc" && keylength != "" && !isECC(keylength) {
		return errors.New("ecc 密钥类型与 RSA keylength 不匹配")
	}
	if keyType == "rsa" && isECC(keylength) {
		return errors.New("rsa 密钥类型与 ECC keylength 不匹配")
	}
	return nil
}

func validateCA(ca string) error {
	if ca == "" {
		return nil
	}
	if caName.MatchString(ca) {
		return nil
	}
	u, err := url.Parse(ca)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("CA 必须是小写标识符或 HTTPS URL")
	}
	return nil
}

func validateProfile(profile string) error {
	if profile != "" && !profileName.MatchString(profile) {
		return errors.New("DNS profile 格式无效")
	}
	return nil
}

func validateEAB(kid, hmac, compatKid, compatHMAC string) error {
	if kid != "" && compatKid != "" && kid != compatKid {
		return errors.New("EAB KID 参数重复且不一致")
	}
	if hmac != "" && compatHMAC != "" && hmac != compatHMAC {
		return errors.New("EAB HMAC key 参数重复且不一致")
	}
	if kid == "" {
		kid = compatKid
	}
	if hmac == "" {
		hmac = compatHMAC
	}
	if (kid == "") != (hmac == "") {
		return errors.New("EAB KID 和 HMAC key 必须同时提供")
	}
	if len(kid) > 1024 || len(hmac) > 4096 || strings.TrimSpace(kid) != kid || strings.TrimSpace(hmac) != hmac ||
		strings.ContainsAny(kid, "\x00\r\n\t") || strings.ContainsAny(hmac, "\x00\r\n\t") {
		return errors.New("EAB 参数格式无效")
	}
	return nil
}

func validateStagingDir(dir string) error {
	if strings.ContainsRune(dir, '\x00') {
		return errors.New("staging 目录格式无效")
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

func redactArgs(args []string, dnsEnv map[string]string) []string {
	redacted := append([]string(nil), args...)
	secrets := dnsCanaries(dnsEnv)
	for i, arg := range redacted {
		for _, secret := range secrets {
			if secret != "" {
				redacted[i] = strings.ReplaceAll(redacted[i], secret, "***")
			}
		}
		if (arg == "--eab-kid" || arg == "--eab-hmac-key") && i+1 < len(redacted) {
			redacted[i+1] = "***"
		}
	}
	return redacted
}

func commandRedactions(args []string, dnsEnv map[string]string) map[string]string {
	redactions := mergeEnv(dnsEnv, nil)
	if redactions == nil {
		redactions = make(map[string]string)
	}
	for i, arg := range args {
		if (arg == "--eab-kid" || arg == "--eab-hmac-key") && i+1 < len(args) {
			redactions[fmt.Sprintf("EAB_%d", i)] = args[i+1]
		}
	}
	return redactions
}

func issueEnv(p *IssueParams) map[string]string {
	return mergeEnv(p.DNSEnv, p.Env)
}

func operationEnv(p *OperationParams) map[string]string {
	return mergeEnv(p.DNSEnv, p.Env)
}

func mergeEnv(legacy, current map[string]string) map[string]string {
	if len(legacy) == 0 && len(current) == 0 {
		return nil
	}
	merged := make(map[string]string, len(legacy)+len(current))
	for name, value := range legacy {
		merged[name] = value
	}
	for name, value := range current {
		merged[name] = value
	}
	return merged
}

func (r *Runner) outputDir(p *IssueParams) (string, string, error) {
	if p.StagingDir != "" {
		if err := os.MkdirAll(p.StagingDir, 0o755); err != nil {
			return "", "", fmt.Errorf("创建 staging 目录失败: %w", err)
		}
		return p.StagingDir, p.StagingDir, nil
	}
	certsDir := r.CertsDir
	if p.CertsDir != "" {
		certsDir = p.CertsDir
	}
	if certsDir == "" {
		return "", "", errors.New("证书目录不能为空")
	}
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		return "", "", fmt.Errorf("创建证书目录失败: %w", err)
	}
	outDir := filepath.Join(certsDir, p.Domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", "", fmt.Errorf("创建域名证书目录失败: %w", err)
	}
	return outDir, certsDir, nil
}

func (r *Runner) hasDomainState(domain, keyType, keylength string) bool {
	homes := []string{r.persistentConfigHome(), r.stateHome()}
	if homes[0] == "" && homes[1] == "" {
		return false
	}
	seen := make(map[string]struct{}, len(homes))
	for _, home := range homes {
		if home == "" {
			continue
		}
		if _, ok := seen[home]; ok {
			continue
		}
		seen[home] = struct{}{}
		bases := []string{filepath.Join(home, domain), filepath.Join(home, domain+"_ecc")}
		if keyType == "rsa" || (keyType == "" && !isECC(keylength) && keylength != "") {
			bases = bases[:1]
		}
		for _, base := range bases {
			candidates := []string{
				base + ".conf",
				filepath.Join(base, domain+".conf"),
				filepath.Join(base, domain+"_ecc.conf"),
			}
			for _, candidate := range candidates {
				if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
					return true
				}
			}
		}
	}
	return false
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
	err = r.withIsolatedConfig(cctx, "upgrade", nil, nil, func(configHome, accountConf string) error {
		_, executeErr := r.execute(cctx, "upgrade", r.appendHome([]string{"--upgrade", "--auto-upgrade"}), nil, configHome, accountConf)
		return executeErr
	})
	return err
}

// SetDefaultCA 设置默认的证书颁发机构（CA）。
func (r *Runner) SetDefaultCA(ctx context.Context, ca string) error {
	if ca == "" {
		return nil
	}
	if err := validateCA(ca); err != nil {
		return err
	}
	if err := r.validateReady(); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var err error
	err = r.withIsolatedConfig(cctx, "set-default-ca", nil, nil, func(configHome, accountConf string) error {
		_, executeErr := r.execute(cctx, "set-default-ca", r.appendHome([]string{"--set-default-ca", "--server", ca}), nil, configHome, accountConf)
		return executeErr
	})
	return err
}

// AccountRegistered 检查是否已注册 ACME 账户（粗略检查 home 目录下有账号文件）。
func (r *Runner) AccountRegistered() bool {
	for _, home := range []string{r.persistentConfigHome(), r.stateHome()} {
		if home == "" {
			continue
		}
		// acme.sh 账户文件在 ca/<domain>:/ 目录下。
		entries, err := os.ReadDir(filepath.Join(home, "ca"))
		if err == nil && len(entries) > 0 {
			return true
		}
	}
	return false
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
	err := r.withIsolatedConfig(cctx, "register-account", nil, nil, func(configHome, accountConf string) error {
		var executeErr error
		result, executeErr = r.execute(cctx, "register-account", r.appendHome([]string{"--register-account", "-m", email}), nil, configHome, accountConf)
		return executeErr
	})
	if err != nil && strings.Contains(result.Stdout+"\n"+result.Stderr, "already") {
		return nil
	}
	return err
}
