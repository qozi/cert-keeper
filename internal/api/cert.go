// 本文件提供证书相关的 API 处理函数。
package api

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
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
	if err := s.requireLegacyGrant(r, req.Domain, "apply"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	if req.Force {
		if t == nil || !t.IsAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "force 仅管理员可用"})
			return
		}
		if err := s.requireLegacyGrant(r, req.Domain, "force"); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
	}
	if req.ChallengeMode != "" && t != nil && !t.IsAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "推参申请（方式2）需要 admin token"})
		return
	}
	actor := "unknown"
	if t != nil {
		actor = t.ID
	}
	result, err := s.service().Apply(r.Context(), service.ApplyRequest{
		Domain:        req.Domain,
		SAN:           req.SAN,
		CA:            req.CA,
		ChallengeMode: req.ChallengeMode,
		DNSProvider:   req.DNSProvider,
		WebrootPath:   req.WebrootPath,
		Keylength:     req.Keylength,
		Force:         req.Force,
		Actor:         actor,
	})
	if err != nil {
		var validationErr *service.ValidationError
		status := http.StatusInternalServerError
		if errors.As(err, &validationErr) {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
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
	if len(parts) == 2 && parts[1] == "status" {
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
	if err := s.requireLegacyGrant(r, domain, "status"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	status, err := s.service().Status(r.Context(), domain)
	if err != nil {
		var validationErr *service.ValidationError
		code := http.StatusInternalServerError
		if errors.As(err, &validationErr) {
			code = http.StatusBadRequest
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) certFile(w http.ResponseWriter, r *http.Request, domain, name string) {
	permission := "read_cert"
	if name == "key.pem" {
		permission = "read_private_key"
	}
	if err := s.requireLegacyGrant(r, domain, permission); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
		return
	}
	data, err := s.service().ReadFile(r.Context(), domain, name)
	if err != nil {
		var validationErr *service.ValidationError
		code := http.StatusNotFound
		if errors.As(err, &validationErr) {
			code = http.StatusBadRequest
		}
		if !errors.Is(err, os.ErrNotExist) && code == http.StatusNotFound {
			code = http.StatusInternalServerError
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

// requireLegacyGrant 让旧接口也遵循 v2 的域名授权和私钥权限模型。
func (s *Server) requireLegacyGrant(r *http.Request, domain, permission string) error {
	t := tokenFromCtx(r)
	if t == nil {
		return errors.New("缺少认证主体")
	}
	ok, err := s.Store.HasCertificatePermission(r.Context(), t.ID, domain, permission)
	if err != nil {
		return errors.New("检查证书授权失败")
	}
	if !ok {
		return errors.New("token 缺少 " + permission + " 权限")
	}
	return nil
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

func nullable(s string) store.JSONNullString {
	return store.JSONNullString{String: s, Valid: s != ""}
}

func startsWith(s, p string) bool {
	if len(s) < len(p) {
		return false
	}
	return s[:len(p)] == p
}
