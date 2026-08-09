// 本文件提供证书相关的 API 处理函数。
package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// applyReq 定义证书申请的请求体。
type applyReq struct {
	Domain        string   `json:"domain"`
	SAN           []string `json:"san"`
	CA            string   `json:"ca"`
	ChallengeMode string   `json:"challenge_mode"`
	DNSProvider   string   `json:"dns_provider"`
	WebrootPath   string   `json:"webroot_path"`
	Keylength     string   `json:"keylength"`
	Force         bool     `json:"force"`
}

// applyResp 定义证书申请的响应体。
type applyResp struct {
	Success  bool       `json:"success"`
	Domain   string     `json:"domain"`
	Renewed  bool       `json:"renewed"`
	NotAfter time.Time  `json:"not_after"`
	Files    []fileMeta `json:"files"`
	TimeLog  int64      `json:"time_log"`
	Message  string     `json:"message,omitempty"`
}

// fileMeta 定义证书文件的元信息。
type fileMeta struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// applyCert 处理证书申请请求。
func (s *Server) applyCert(w http.ResponseWriter, r *http.Request) {
	t := tokenFromCtx(r)
	var req applyReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误: " + err.Error()})
		return
	}
	if req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "domain 必填"})
		return
	}

	// 加载服务端预置配置（若有）
	preset, _ := s.Store.GetCert(r.Context(), req.Domain)
	params := buildIssueParams(req, preset, s.Cfg)

	// 方式2（推参）需要 admin 权限
	if req.ChallengeMode != "" && t != nil && !t.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "推参申请（方式2）需要 admin token"})
		return
	}
	if params.ChallengeMode == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 challenge_mode：服务端无该域名预置配置且未传参"})
		return
	}
	if params.ChallengeMode == "dns_api" && params.DNSProvider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dns_api 模式需要 dns_provider"})
		return
	}
	if params.ChallengeMode == "webroot" && params.WebrootPath == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "webroot 模式需要 webroot_path"})
		return
	}

	start := time.Now()
	outDir := filepath.Join(s.Cfg.Acme.CertsDir, req.Domain)
	// 检查现有证书有效期，决定是否需要重新签发
	notAfter, _ := readCertExpiry(outDir)
	needRenew := req.Force || acme.ShouldRenew(notAfter, params.RenewDays)

	log := &store.IssueLog{
		Domain:      req.Domain,
		ClientToken: t.ID,
		Action:      "apply",
	}
	defer func() {
		log.DurationMs = time.Since(start).Milliseconds()
		_ = s.Store.AddLog(r.Context(), log)
	}()

	if !needRenew {
		files := scanCertFiles(outDir)
		log.Success = true
		log.Message = "证书未到期，跳过签发"
		writeJSON(w, http.StatusOK, applyResp{
			Success:  true,
			Domain:   req.Domain,
			Renewed:  false,
			NotAfter: notAfter,
			Files:    files,
			TimeLog:  readTimeLog(outDir),
		})
		return
	}

	// 取 DNS Secret
	dnsEnv := map[string]string{}
	if params.ChallengeMode == "dns_api" && params.DNSProvider != "" {
		envs, err := s.Store.ListSecretsByProvider(r.Context(), params.DNSProvider, s.Cfg.Storage.EncryptionKey)
		if err != nil {
			log.Message = "读取 DNS Secret 失败: " + err.Error()
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": log.Message})
			return
		}
		dnsEnv = envs
	}

	runner := &acme.Runner{
		AcmeShPath: s.Cfg.Acme.AcmeShPath,
		Home:       s.Cfg.Acme.Home,
		CertsDir:   s.Cfg.Acme.CertsDir,
		Timeout:    s.Cfg.Acme.IssueTimeout,
	}
	res, err := runner.Issue(r.Context(), &acme.IssueParams{
		Domain:        params.Domain,
		SAN:           params.SAN,
		CA:            params.CA,
		ChallengeMode: params.ChallengeMode,
		DNSProvider:   params.DNSProvider,
		WebrootPath:   params.WebrootPath,
		Keylength:     params.Keylength,
		DNSEnv:        dnsEnv,
	})
	if err != nil {
		log.Message = err.Error() + "\n" + res.StdoutStderr
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error(), "detail": res.StdoutStderr})
		return
	}
	log.Success = true
	notAfter = res.NotAfter

	// 若是方式2 推参且服务端无此配置，可选择持久化以便后续续签
	if req.ChallengeMode != "" && preset == nil {
		_ = s.Store.UpsertCert(r.Context(), &store.Cert{
			Domain:        params.Domain,
			SAN:           joinSAN(params.SAN),
			CA:            params.CA,
			ChallengeMode: params.ChallengeMode,
			DNSProvider:   nullable(params.DNSProvider),
			WebrootPath:   nullable(params.WebrootPath),
			Keylength:     params.Keylength,
			RenewDays:     params.RenewDays,
			Source:        "pushed",
		})
	}

	files := scanCertFiles(outDir)
	writeJSON(w, http.StatusOK, applyResp{
		Success:  true,
		Domain:   req.Domain,
		Renewed:  true,
		NotAfter: notAfter,
		Files:    files,
		TimeLog:  readTimeLog(outDir),
	})
}

// certSubtree 处理证书相关的子路径请求，如文件下载和状态查询。
// 路径形如 /api/v1/certs/<domain>/files/<name> 或 /api/v1/certs/<domain>/status
func (s *Server) certSubtree(w http.ResponseWriter, r *http.Request) {
	rest := r.URL.Path
	prefix := "/api/v1/certs/"
	if !startsWith(rest, prefix) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	rest = rest[len(prefix):]
	parts := splitPath(rest)
	if len(parts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少 domain"})
		return
	}
	domain := parts[0]
	if len(parts) >= 2 && parts[1] == "status" {
		s.certStatus(w, r, domain)
		return
	}
	if len(parts) == 3 && parts[1] == "files" {
		s.certFile(w, r, domain, parts[2])
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown path"})
}

func (s *Server) certStatus(w http.ResponseWriter, r *http.Request, domain string) {
	outDir := filepath.Join(s.Cfg.Acme.CertsDir, domain)
	notAfter, _ := readCertExpiry(outDir)
	files := scanCertFiles(outDir)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":     domain,
		"not_after":  notAfter,
		"time_log":   readTimeLog(outDir),
		"files":      files,
		"exists":     fileExists(filepath.Join(outDir, "fullchain.pem")),
	})
}

func (s *Server) certFile(w http.ResponseWriter, r *http.Request, domain, name string) {
	allowed := map[string]bool{"cert.pem": true, "key.pem": true, "fullchain.pem": true, "ca.pem": true, "time.log": true}
	if !allowed[name] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "不允许的文件名"})
		return
	}
	// 鉴权：复用 authed 已经做的；但 subtree 路由未包一层 authed，这里手动校验
	t, err := s.verifyToken(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	_ = t
	path := filepath.Join(s.Cfg.Acme.CertsDir, domain, name)
	http.ServeFile(w, r, path)
}

func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	t := tokenFromCtx(r)
	var req struct {
		Hostname string `json:"hostname"`
		OSInfo   string `json:"os_info"`
	}
	_ = readJSON(r, &req)
	if err := s.Store.UpsertClient(r.Context(), &store.Client{
		TokenID:  t.ID,
		Hostname: nullable(req.Hostname),
		OSInfo:   nullable(req.OSInfo),
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	t := tokenFromCtx(r)
	_ = s.Store.TouchClient(r.Context(), t.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func buildIssueParams(req applyReq, preset *store.Cert, cfg *config.Config) struct {
	Domain, CA, ChallengeMode, DNSProvider, WebrootPath, Keylength string
	SAN                                                []string
	RenewDays                                          int
} {
	type P struct {
		Domain, CA, ChallengeMode, DNSProvider, WebrootPath, Keylength string
		SAN                                                []string
		RenewDays                                          int
	}
	p := P{
		Domain:   req.Domain,
		SAN:      req.SAN,
		CA:       req.CA,
		ChallengeMode: req.ChallengeMode,
		DNSProvider:   req.DNSProvider,
		WebrootPath:   req.WebrootPath,
		Keylength:     req.Keylength,
		RenewDays:     cfg.Acme.DefaultRenewDays,
	}
	if preset != nil {
		if p.Domain == "" {
			p.Domain = preset.Domain
		}
		if p.SAN == nil && preset.SAN != "" {
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
		p.CA = cfg.Acme.DefaultCA
	}
	if p.Keylength == "" {
		p.Keylength = cfg.Acme.DefaultKeylength
	}
	return p
}

func scanCertFiles(dir string) []fileMeta {
	names := []string{"cert.pem", "key.pem", "fullchain.pem", "ca.pem", "time.log"}
	out := []fileMeta{}
	for _, n := range names {
		p := filepath.Join(dir, n)
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		out = append(out, fileMeta{Name: n, Size: st.Size(), SHA256: hex.EncodeToString(h[:])})
	}
	return out
}

func readTimeLog(dir string) int64 {
	data, err := os.ReadFile(filepath.Join(dir, "time.log"))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(string(data), 10, 64)
	return v
}

func readCertExpiry(dir string) (time.Time, error) {
	data, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return time.Time{}, err
	}
	return acme.ParsePemExpiry(data)
}

func nullable(s string) store.JSONNullString {
	return store.JSONNullString{String: s, Valid: s != ""}
}

func joinSAN(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func startsWith(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}

var _ = errors.New
var _ = fmt.Sprintf
var _ = ckauth.Now
