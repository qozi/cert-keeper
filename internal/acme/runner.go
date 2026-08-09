// Package acme 提供 ACME 证书签发相关的功能。
// 封装 acme.sh 命令行工具，支持证书申请、续签、安装等操作。
package acme

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Runner 封装 acme.sh 调用，提供证书签发和管理功能。
type Runner struct {
	AcmeShPath string
	Home       string
	CertsDir   string
	Timeout    time.Duration
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
}

// IssueResult 定义证书签发的结果。
type IssueResult struct {
	Domain       string
	OutDir       string
	Files        []string // 实际产物文件名
	NotAfter     time.Time
	StdoutStderr string
	Duration     time.Duration
}

// Issue 签发并安装证书。
func (r *Runner) Issue(ctx context.Context, p *IssueParams) (*IssueResult, error) {
	if err := os.MkdirAll(r.CertsDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建证书目录失败: %w", err)
	}
	outDir := filepath.Join(r.CertsDir, p.Domain)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建域名证书目录失败: %w", err)
	}

	args := r.buildIssueArgs(p)
	cctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	envs := buildEnv(p.DNSEnv, r.Home)
	cmd := exec.CommandContext(cctx, r.AcmeShPath, args...)
	cmd.Env = envs
	out, err := cmd.CombinedOutput()
	res := &IssueResult{
		Domain:       p.Domain,
		OutDir:       outDir,
		StdoutStderr: string(out),
	}
	if err != nil {
		res.StdoutStderr += "\n" + err.Error()
		return res, fmt.Errorf("acme.sh 执行失败: %w", err)
	}

	if err := r.installCert(ctx, p, outDir); err != nil {
		res.StdoutStderr += "\n" + err.Error()
		return res, fmt.Errorf("安装证书产物失败: %w", err)
	}

	// 写时间戳
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if err := os.WriteFile(filepath.Join(outDir, "time.log"), []byte(ts), 0o644); err != nil {
		return res, fmt.Errorf("写入 time.log 失败: %w", err)
	}

	// 解析有效期
	if na, err := readNotAfter(outDir); err == nil {
		res.NotAfter = na
	}
	res.Files = []string{"cert.pem", "key.pem", "fullchain.pem", "ca.pem", "time.log"}
	res.Duration = time.Since(time.Now())
	return res, nil
}

func (r *Runner) buildIssueArgs(p *IssueParams) []string {
	args := []string{"--issue"}
	args = append(args, "-d", p.Domain)
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
	args = append(args, "--home", r.Home)
	return args
}

func (r *Runner) installCert(ctx context.Context, p *IssueParams, outDir string) error {
	args := []string{"--install-cert", "-d", p.Domain, "--home", r.Home}
	if p.CA != "" {
		args = append(args, "--server", p.CA)
	}
	args = append(args,
		"--cert-file", filepath.Join(outDir, "cert.pem"),
		"--key-file", filepath.Join(outDir, "key.pem"),
		"--fullchain-file", filepath.Join(outDir, "fullchain.pem"),
		"--ca-file", filepath.Join(outDir, "ca.pem"),
	)
	cctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	envs := buildEnv(p.DNSEnv, r.Home)
	cmd := exec.CommandContext(cctx, r.AcmeShPath, args...)
	cmd.Env = envs
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install-cert 失败: %w, 输出: %s", err, string(out))
	}
	return nil
}

func buildEnv(dnsEnv map[string]string, home string) []string {
	envs := os.Environ()
	if home != "" {
		envs = append(envs, "ACME_HOME="+home)
	}
	for k, v := range dnsEnv {
		envs = append(envs, k+"="+v)
	}
	return envs
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
	// 最简实现：用 crypto/tls 解析第一张证书
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

var _ = errors.New

func parseCertExpiryImpl(pem []byte) (time.Time, error) {
	// 复用 cert 包解析
	return ParsePemExpiry(pem)
}

// ErrAcmeNotReady 表示 acme.sh 未就绪的错误。
var ErrAcmeNotReady = errors.New("acme.sh 未就绪，请检查安装路径")

// AutoUpgrade 调用 acme.sh --upgrade --auto-upgrade 升级 acme.sh。
func (r *Runner) AutoUpgrade(ctx context.Context) error {
	if r.AcmeShPath == "" {
		return ErrAcmeNotReady
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	args := []string{"--upgrade", "--auto-upgrade", "--home", r.Home}
	cmd := exec.CommandContext(cctx, r.AcmeShPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("acme.sh 升级失败: %w, 输出: %s", err, string(out))
	}
	return nil
}

// SetDefaultCA 设置默认的证书颁发机构（CA）。
func (r *Runner) SetDefaultCA(ctx context.Context, ca string) error {
	if ca == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"--set-default-ca", "--server", ca, "--home", r.Home}
	cmd := exec.CommandContext(cctx, r.AcmeShPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("设置默认 CA 失败: %w, 输出: %s", err, string(out))
	}
	return nil
}

// AccountRegistered 检查是否已注册 ACME 账户（粗略检查 home 目录下有账号文件）。
func (r *Runner) AccountRegistered() bool {
	if r.Home == "" {
		return false
	}
	// acme.sh 账户文件在 ca/<domain>:/  目录下
	entries, err := os.ReadDir(filepath.Join(r.Home, "ca"))
	if err != nil {
		return false
	}
	return len(entries) > 0
}

// RegisterAccount 注册 ACME 账户（自动执行首次 --issue 会自动注册，这里提供空实现保证可调）。
func (r *Runner) RegisterAccount(ctx context.Context, email string) error {
	if email == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"--register-account", "-m", email, "--home", r.Home}
	cmd := exec.CommandContext(cctx, r.AcmeShPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already") {
		return fmt.Errorf("注册账户失败: %w, 输出: %s", err, string(out))
	}
	return nil
}
