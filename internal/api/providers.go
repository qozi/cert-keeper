// 本文件提供 DNS provider 支持列表与已配置参数查询的管理 API。
package api

import (
	"net/http"
	"strings"
)

// providersHandler 处理 DNS provider 相关的查询请求。
//
// 路径约定：
//   - GET /api/v1/admin/providers          返回 acme.sh 支持的 provider 列表（含是否已配置标记）
//   - GET /api/v1/admin/providers/{provider}/parameters  返回指定 provider 已配置的参数（脱敏）
func (s *Server) providersHandler(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/providers")
	rest = strings.Trim(rest, "/")
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// 无子路径：返回支持列表
	if rest == "" {
		s.listProviders(w, r)
		return
	}

	parts := splitPath(rest)
	// /api/v1/admin/providers/{provider}/parameters
	if len(parts) == 2 && parts[1] == "parameters" {
		s.listProviderParameters(w, r, parts[0])
		return
	}

	writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown path"})
}

// listProviders 返回 acme.sh 支持的 DNS provider 列表，并标记每个 provider 是否已配置参数。
func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.service().ListProviders(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

// listProviderParameters 返回指定 provider 已配置的参数列表，参数值已脱敏。
func (s *Server) listProviderParameters(w http.ResponseWriter, r *http.Request, provider string) {
	if provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider 不能为空"})
		return
	}

	params, err := s.service().ProviderParameters(r.Context(), provider)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"provider":   provider,
		"parameters": params,
	})
}
