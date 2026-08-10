// Package service 提供服务端 API 与本地 CLI 共用的业务操作。
package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/lock"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// ValidationError 表示可以直接返回给调用方的参数错误。
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

// IssueFunc 是证书签发函数，测试时可替换为假的签发器。
type IssueFunc func(context.Context, *acme.IssueParams) (*acme.IssueResult, error)

// Service 封装服务端本地资源和业务操作。
type Service struct {
	Cfg       *config.Config
	Store     *store.Store
	IssueFunc IssueFunc
}

// New 创建服务操作对象。
func New(cfg *config.Config, st *store.Store) *Service {
	return &Service{Cfg: cfg, Store: st}
}

// ApplyRequest 定义申请或续签证书的参数。
type ApplyRequest struct {
	Domain        string
	SAN           []string
	CA            string
	ChallengeMode string
	DNSProvider   string
	WebrootPath   string
	Keylength     string
	Force         bool
	Actor         string
}

// FileMeta 是证书产物的元数据。
type FileMeta struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ApplyResult 是申请或续签的结果。
type ApplyResult struct {
	Success  bool       `json:"success"`
	Domain   string     `json:"domain"`
	Renewed  bool       `json:"renewed"`
	NotAfter time.Time  `json:"not_after"`
	Files    []FileMeta `json:"files"`
	TimeLog  int64      `json:"time_log"`
	Message  string     `json:"message,omitempty"`
}

// CertStatus 是单个证书的状态。
type CertStatus struct {
	Domain   string     `json:"domain"`
	NotAfter time.Time  `json:"not_after"`
	TimeLog  int64      `json:"time_log"`
	Files    []FileMeta `json:"files"`
	Exists   bool       `json:"exists"`
}

// CertStatusSummary 是管理端证书总览中的一项。
type CertStatusSummary struct {
	Domain        string    `json:"domain"`
	NotAfter      time.Time `json:"not_after"`
	TimeLog       int64     `json:"time_log"`
	RenewDays     int       `json:"renew_days"`
	ChallengeMode string    `json:"challenge_mode"`
	Exists        bool      `json:"exists"`
}

var allowedFiles = map[string]struct{}{
	"cert.pem":      {},
	"key.pem":       {},
	"fullchain.pem": {},
	"ca.pem":        {},
	"time.log":      {},
}

// Apply 申请或续签证书，并记录操作日志。
func (s *Service) Apply(ctx context.Context, req ApplyRequest) (result ApplyResult, err error) {
	if err := validateDomain(req.Domain); err != nil {
		return result, err
	}
	preset, err := s.Store.GetCert(ctx, req.Domain)
	if err != nil {
		return result, fmt.Errorf("读取证书配置失败: %w", err)
	}
	params, err := s.buildIssueParams(req, preset)
	if err != nil {
		return result, err
	}

	outDir := filepath.Join(s.Cfg.Acme.CertsDir, req.Domain)
	notAfter, _ := readCertExpiry(outDir)
	needRenew := req.Force || acme.ShouldRenew(notAfter, params.RenewDays)
	actor := req.Actor
	if actor == "" {
		actor = "server-cli"
	}
	log := &store.IssueLog{Domain: req.Domain, ClientToken: actor, Action: "apply"}
	start := time.Now()
	defer func() {
		log.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			log.Message = err.Error()
		}
		_ = s.Store.AddLog(context.Background(), log)
	}()

	if !needRenew {
		files := scanCertFiles(outDir)
		log.Success = true
		log.Message = "证书未到期，跳过签发"
		return ApplyResult{
			Success:  true,
			Domain:   req.Domain,
			Renewed:  false,
			NotAfter: notAfter,
			Files:    files,
			TimeLog:  readTimeLog(outDir),
			Message:  log.Message,
		}, nil
	}

	lockFile, err := lock.Acquire(filepath.Join(s.Cfg.Acme.Home, ".certkeeper.issue.lock"))
	if err != nil {
		return result, err
	}
	defer lockFile.Close()

	dnsEnv := map[string]string{}
	if params.ChallengeMode == "dns_api" {
		dnsEnv, err = s.Store.ListSecretsByProvider(ctx, params.DNSProvider, s.Cfg.Storage.EncryptionKey)
		if err != nil {
			return result, fmt.Errorf("读取 DNS Secret 失败: %w", err)
		}
	}

	issue := s.IssueFunc
	if issue == nil {
		runner := &acme.Runner{
			AcmeShPath: s.Cfg.Acme.AcmeShPath,
			Home:       s.Cfg.Acme.Home,
			CertsDir:   s.Cfg.Acme.CertsDir,
			Timeout:    s.Cfg.Acme.IssueTimeout,
		}
		issue = runner.Issue
	}
	res, issueErr := issue(ctx, &acme.IssueParams{
		Domain:        params.Domain,
		SAN:           params.SAN,
		CA:            params.CA,
		ChallengeMode: params.ChallengeMode,
		DNSProvider:   params.DNSProvider,
		WebrootPath:   params.WebrootPath,
		Keylength:     params.Keylength,
		DNSEnv:        dnsEnv,
	})
	if issueErr != nil {
		if res != nil && res.StdoutStderr != "" {
			issueErr = fmt.Errorf("%w\n%s", issueErr, res.StdoutStderr)
		}
		return result, issueErr
	}
	if res != nil {
		notAfter = res.NotAfter
	}

	if req.ChallengeMode != "" && preset == nil {
		if err := s.Store.UpsertCert(ctx, &store.Cert{
			Domain:        params.Domain,
			SAN:           joinSAN(params.SAN),
			CA:            params.CA,
			ChallengeMode: params.ChallengeMode,
			DNSProvider:   nullable(params.DNSProvider),
			WebrootPath:   nullable(params.WebrootPath),
			Keylength:     params.Keylength,
			RenewDays:     params.RenewDays,
			Source:        "pushed",
		}); err != nil {
			return result, fmt.Errorf("保存推送的证书配置失败: %w", err)
		}
	}
	log.Success = true
	return ApplyResult{
		Success:  true,
		Domain:   req.Domain,
		Renewed:  true,
		NotAfter: notAfter,
		Files:    scanCertFiles(outDir),
		TimeLog:  readTimeLog(outDir),
	}, nil
}

// Reissue 强制重新签发指定域名的证书配置。
func (s *Service) Reissue(ctx context.Context, domain, actor string) (ApplyResult, error) {
	if err := validateDomain(domain); err != nil {
		return ApplyResult{}, err
	}
	c, err := s.Store.GetCert(ctx, domain)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("读取证书配置失败: %w", err)
	}
	if c == nil {
		return ApplyResult{}, &ValidationError{Message: "证书配置不存在: " + domain}
	}
	return s.Apply(ctx, ApplyRequest{Domain: domain, Force: true, Actor: actor})
}

// Status 查询指定域名的证书状态。
func (s *Service) Status(_ context.Context, domain string) (CertStatus, error) {
	if err := validateDomain(domain); err != nil {
		return CertStatus{}, err
	}
	outDir := filepath.Join(s.Cfg.Acme.CertsDir, domain)
	notAfter, _ := readCertExpiry(outDir)
	return CertStatus{
		Domain:   domain,
		NotAfter: notAfter,
		TimeLog:  readTimeLog(outDir),
		Files:    scanCertFiles(outDir),
		Exists:   fileExists(filepath.Join(outDir, "fullchain.pem")),
	}, nil
}

// AllStatuses 查询所有已配置证书的有效期总览。
func (s *Service) AllStatuses(ctx context.Context) ([]CertStatusSummary, error) {
	cs, err := s.Store.ListCerts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]CertStatusSummary, 0, len(cs))
	for _, c := range cs {
		status, err := s.Status(ctx, c.Domain)
		if err != nil {
			return nil, err
		}
		out = append(out, CertStatusSummary{
			Domain:        c.Domain,
			NotAfter:      status.NotAfter,
			TimeLog:       status.TimeLog,
			RenewDays:     c.RenewDays,
			ChallengeMode: c.ChallengeMode,
			Exists:        status.Exists,
		})
	}
	return out, nil
}

// ReadFile 读取允许下载的证书文件。
func (s *Service) ReadFile(_ context.Context, domain, name string) ([]byte, error) {
	if err := validateDomain(domain); err != nil {
		return nil, err
	}
	if _, ok := allowedFiles[name]; !ok {
		return nil, &ValidationError{Message: "不允许的文件名"}
	}
	return os.ReadFile(filepath.Join(s.Cfg.Acme.CertsDir, domain, name))
}

func (s *Service) buildIssueParams(req ApplyRequest, preset *store.Cert) (issueParams, error) {
	p := issueParams{
		Domain:        req.Domain,
		SAN:           req.SAN,
		CA:            req.CA,
		ChallengeMode: req.ChallengeMode,
		DNSProvider:   req.DNSProvider,
		WebrootPath:   req.WebrootPath,
		Keylength:     req.Keylength,
		RenewDays:     s.Cfg.Acme.DefaultRenewDays,
	}
	if preset != nil {
		if len(p.SAN) == 0 {
			p.SAN = splitCSV(preset.SAN)
		}
		if p.CA == "" {
			p.CA = preset.CA
		}
		if p.ChallengeMode == "" {
			p.ChallengeMode = preset.ChallengeMode
		}
		if p.DNSProvider == "" && preset.DNSProvider.Valid {
			p.DNSProvider = preset.DNSProvider.String
		}
		if p.WebrootPath == "" && preset.WebrootPath.Valid {
			p.WebrootPath = preset.WebrootPath.String
		}
		if p.Keylength == "" {
			p.Keylength = preset.Keylength
		}
		p.RenewDays = preset.RenewDays
	}
	if p.CA == "" {
		p.CA = s.Cfg.Acme.DefaultCA
	}
	if p.Keylength == "" {
		p.Keylength = s.Cfg.Acme.DefaultKeylength
	}
	if p.ChallengeMode == "" {
		return issueParams{}, &ValidationError{Message: "缺少 challenge_mode：服务端无该域名预置配置且未传参"}
	}
	switch p.ChallengeMode {
	case "dns_api":
		if p.DNSProvider == "" {
			return issueParams{}, &ValidationError{Message: "dns_api 模式需要 dns_provider"}
		}
	case "webroot":
		if p.WebrootPath == "" {
			return issueParams{}, &ValidationError{Message: "webroot 模式需要 webroot_path"}
		}
	case "standalone", "dns_manual":
	default:
		return issueParams{}, &ValidationError{Message: "不支持的 challenge_mode: " + p.ChallengeMode}
	}
	return p, nil
}

type issueParams struct {
	Domain, CA, ChallengeMode, DNSProvider, WebrootPath, Keylength string
	SAN                                                            []string
	RenewDays                                                      int
}

func validateDomain(domain string) error {
	if domain == "" {
		return &ValidationError{Message: "domain 必填"}
	}
	if strings.TrimSpace(domain) != domain || strings.ContainsAny(domain, "/\\") || strings.IndexByte(domain, 0) >= 0 || domain == "." || domain == ".." || strings.Contains(domain, "..") {
		return &ValidationError{Message: "domain 格式不合法"}
	}
	return nil
}

func scanCertFiles(dir string) []FileMeta {
	names := []string{"cert.pem", "key.pem", "fullchain.pem", "ca.pem", "time.log"}
	out := make([]FileMeta, 0, len(names))
	for _, name := range names {
		path := filepath.Join(dir, name)
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		sha, err := acme.FileSHA256(path)
		if err != nil {
			continue
		}
		out = append(out, FileMeta{Name: name, Size: st.Size(), SHA256: sha})
	}
	return out
}

func readTimeLog(dir string) int64 {
	b, err := os.ReadFile(filepath.Join(dir, "time.log"))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func readCertExpiry(dir string) (time.Time, error) {
	b, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return time.Time{}, err
	}
	return acme.ParsePemExpiry(b)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func nullable(s string) store.JSONNullString {
	return store.JSONNullString{String: s, Valid: s != ""}
}

func joinSAN(s []string) string {
	return strings.Join(s, ",")
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// SaveCertConfig 校验并保存证书配置。
func (s *Service) SaveCertConfig(ctx context.Context, c *store.Cert) error {
	if err := validateDomain(c.Domain); err != nil {
		return err
	}
	if c.ChallengeMode == "" {
		return &ValidationError{Message: "domain 和 challenge_mode 必填"}
	}
	if c.ChallengeMode != "dns_api" && c.ChallengeMode != "standalone" && c.ChallengeMode != "webroot" && c.ChallengeMode != "dns_manual" {
		return &ValidationError{Message: "不支持的 challenge_mode: " + c.ChallengeMode}
	}
	if c.CA == "" {
		c.CA = s.Cfg.Acme.DefaultCA
	}
	if c.Keylength == "" {
		c.Keylength = s.Cfg.Acme.DefaultKeylength
	}
	if c.RenewDays == 0 {
		c.RenewDays = s.Cfg.Acme.DefaultRenewDays
	}
	if c.Source == "" {
		c.Source = "preset"
	}
	return s.Store.UpsertCert(ctx, c)
}

// TokenCreateRequest 定义 Token 创建参数。
type TokenCreateRequest struct {
	ID      string
	Secret  string
	Note    string
	Enabled bool
	IsAdmin bool
	AutoGen bool
}

// CreateToken 创建 Token，并返回实际生成的凭据。
func (s *Service) CreateToken(ctx context.Context, req TokenCreateRequest) (*store.Token, error) {
	if req.ID == "" || req.AutoGen {
		id, err := ckauth.GenTokenID()
		if err != nil {
			return nil, err
		}
		req.ID = id
	}
	if req.Secret == "" {
		secret, err := ckauth.GenSecret()
		if err != nil {
			return nil, err
		}
		req.Secret = secret
	}
	t := &store.Token{ID: req.ID, Secret: req.Secret, Note: req.Note, Enabled: req.Enabled, IsAdmin: req.IsAdmin, CreatedAt: time.Now().Unix()}
	if err := s.Store.CreateToken(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// SecretView 是 CLI 使用的 Secret 展示结构。
type SecretView struct {
	ID        int64  `json:"id"`
	Provider  string `json:"provider"`
	EnvKey    string `json:"env_key"`
	EnvValue  string `json:"env_value"`
	CreatedAt int64  `json:"created_at"`
}

// ListSecretViews 列出 Secret，默认只显示脱敏值。
func (s *Service) ListSecretViews(ctx context.Context, showValue bool) ([]SecretView, error) {
	secrets, err := s.Store.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	if showValue {
		providers := map[string]struct{}{}
		for _, secret := range secrets {
			providers[secret.Provider] = struct{}{}
		}
		for provider := range providers {
			params, err := s.Store.ListSecretsByProvider(ctx, provider, s.Cfg.Storage.EncryptionKey)
			if err != nil {
				return nil, err
			}
			for key, value := range params {
				values[provider+"\x00"+key] = value
			}
		}
	}
	out := make([]SecretView, 0, len(secrets))
	for _, secret := range secrets {
		value := "***"
		if showValue {
			value = values[secret.Provider+"\x00"+secret.EnvKey]
		}
		out = append(out, SecretView{ID: secret.ID, Provider: secret.Provider, EnvKey: secret.EnvKey, EnvValue: value, CreatedAt: secret.CreatedAt})
	}
	return out, nil
}

// ProviderItem 表示 DNS provider 及其配置状态。
type ProviderItem struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
}

// ListProviders 返回 acme.sh provider 列表。
func (s *Service) ListProviders(ctx context.Context) ([]ProviderItem, error) {
	providers := acme.ListDNSProviders(s.Cfg.Acme.AcmeShPath, s.Cfg.Acme.Home)
	configured, err := s.Store.ConfiguredProviders(ctx)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, len(configured))
	for _, provider := range configured {
		set[provider] = struct{}{}
	}
	out := make([]ProviderItem, 0, len(providers))
	for _, provider := range providers {
		_, ok := set[provider]
		out = append(out, ProviderItem{Provider: provider, Configured: ok})
	}
	return out, nil
}

// ProviderParameters 返回指定 provider 的脱敏参数。
func (s *Service) ProviderParameters(ctx context.Context, provider string) ([]store.SecretParameter, error) {
	params, err := s.Store.ListSecretParameters(ctx, provider, s.Cfg.Storage.EncryptionKey)
	if err != nil {
		return nil, err
	}
	for i := range params {
		params[i].EnvValue = acme.MaskSecretValue(params[i].EnvValue)
	}
	return params, nil
}
