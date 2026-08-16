// 本文件提供管理员 API 处理函数，包括 Token、证书、Secret、客户端和日志管理。
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// tokensHandler 处理 Token 相关的 CRUD 请求。
func (s *Server) tokensHandler(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/tokens")
	rest = strings.Trim(rest, "/")
	switch r.Method {
	case http.MethodGet:
		if rest != "" {
			t, err := s.Store.GetToken(r.Context(), rest)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			if t == nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "token 不存在"})
				return
			}
			writeJSON(w, http.StatusOK, t)
			return
		}
		ts, err := s.Store.ListTokens(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ts)
	case http.MethodPost:
		var req struct {
			ID      string `json:"id"`
			Secret  string `json:"secret"`
			Note    string `json:"note"`
			IsAdmin bool   `json:"is_admin"`
			Enabled *bool  `json:"enabled"` // 指针区分"未提供"与显式 false，默认启用
			AutoGen bool   `json:"auto_gen"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.ID == "" || req.AutoGen {
			id, err := ckauth.GenTokenID()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			req.ID = id
		}
		if req.Secret == "" {
			sec, err := ckauth.GenSecret()
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			req.Secret = sec
		}
		// 未提供 enabled 字段时默认启用，避免 Token 创建即禁用
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		t := &store.Token{
			ID:        req.ID,
			Secret:    req.Secret,
			Note:      req.Note,
			Enabled:   enabled,
			IsAdmin:   req.IsAdmin,
			CreatedAt: time.Now().Unix(),
		}
		if err := s.Store.CreateToken(r.Context(), t); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, t)
	case http.MethodPut, http.MethodPatch:
		parts := splitPath(rest)
		if len(parts) != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "PUT 需要 /tokens/{id}"})
			return
		}
		var req struct {
			Note    string `json:"note"`
			Enabled bool   `json:"enabled"`
			IsAdmin bool   `json:"is_admin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误: " + err.Error()})
			return
		}
		if err := s.Store.UpdateToken(r.Context(), parts[0], req.Note, req.Enabled, req.IsAdmin); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodDelete:
		if rest == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "DELETE 需要 /tokens/{id}"})
			return
		}
		if err := s.Store.DeleteToken(r.Context(), rest); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// certsAdminHandler 处理证书管理相关的请求。
func (s *Server) certsAdminHandler(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/certs")
	rest = strings.Trim(rest, "/")
	switch r.Method {
	case http.MethodGet:
		if rest == "status" {
			s.allCertsStatus(w, r)
			return
		}
		cs, err := s.Store.ListCerts(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, cs)
	case http.MethodPost:
		parts := splitPath(rest)
		if len(parts) == 2 && parts[1] == "reissue" {
			actor := "admin"
			if token := tokenFromCtx(r); token != nil {
				actor = token.ID
			}
			result, err := s.service().Reissue(r.Context(), parts[0], actor)
			if err != nil {
				var validationErr *service.ValidationError
				code := http.StatusInternalServerError
				if errors.As(err, &validationErr) {
					code = http.StatusBadRequest
				}
				writeJSON(w, code, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, result)
			return
		}
		var c store.Cert
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := s.service().SaveCertConfig(r.Context(), &c); err != nil {
			var validationErr *service.ValidationError
			code := http.StatusInternalServerError
			if errors.As(err, &validationErr) {
				code = http.StatusBadRequest
			}
			writeJSON(w, code, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, c)
	case http.MethodDelete:
		parts := splitPath(rest)
		if len(parts) < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "DELETE 需要 /certs/{domain}"})
			return
		}
		if err := s.Store.DeleteCert(r.Context(), parts[0]); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (s *Server) allCertsStatus(w http.ResponseWriter, r *http.Request) {
	out, err := s.service().AllStatuses(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// secretsHandler 处理 DNS Secret 相关的请求。
func (s *Server) secretsHandler(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/secrets")
	rest = strings.Trim(rest, "/")
	switch r.Method {
	case http.MethodGet:
		ss, err := s.Store.ListSecrets(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, ss)
	case http.MethodPost:
		var req struct {
			Provider string `json:"provider"`
			EnvKey   string `json:"env_key"`
			EnvValue string `json:"env_value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.Provider == "" || req.EnvKey == "" || req.EnvValue == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider/env_key/env_value 必填"})
			return
		}
		if err := s.Store.UpsertSecret(r.Context(), req.Provider, req.EnvKey, req.EnvValue, s.Cfg.Storage.EncryptionKey); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
	case http.MethodDelete:
		parts := splitPath(rest)
		if len(parts) == 1 {
			id, err := strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 必须为整数"})
				return
			}
			if err := s.Store.DeleteSecret(r.Context(), id); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		if len(parts) == 2 {
			if err := s.Store.DeleteSecretByKV(r.Context(), parts[0], parts[1]); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "DELETE 需要 /secrets/{id} 或 /secrets/{provider}/{env_key}"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

// clientsHandler 处理客户端列表查询请求。
func (s *Server) clientsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	cs, err := s.Store.ListClients(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, cs)
}

// logsHandler 处理日志查询请求。
func (s *Server) logsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	q := r.URL.Query()
	f := store.LogFilter{
		Domain: q.Get("domain"),
		Client: q.Get("client"),
	}
	if v := q.Get("success"); v != "" {
		b := v == "1" || v == "true"
		f.Success = &b
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}
	logs, err := s.Store.ListLogs(r.Context(), f)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, logs)
}
