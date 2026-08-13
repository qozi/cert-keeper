// 本文件实现 v2 公共 HTTP API：reconcile、状态查询、generation manifest/文件下载、
// 部署回报与任务查询。所有路由均需 client token 鉴权；写操作不强制 admin，
// 具体授权由 service 层按域名 grant 决定（deny-by-default）。
package api

import (
	"errors"
	"net/http"

	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/pkg/certproto"
)

// v2 路由前缀，与 certproto 协议包的路径段保持一致。
const (
	v2CertsPrefix = certproto.V2APIPath + "/" + certproto.CertificatesPathSegment
	v2JobsPrefix  = certproto.V2APIPath + "/" + certproto.JobsPathSegment
)

// registerV2Routes 注册全部 v2 路由。路径形状与方法检查（404/405）先于鉴权执行，
// 与 v1 admin 路由的顺序保持一致；方法约束复用 routeMethodHandler/methodHandler。
func (s *Server) registerV2Routes(mux *http.ServeMux) {
	certs := routeMethodHandler(v2CertMethods, s.authed(s.v2CertsHandler))
	mux.Handle(v2CertsPrefix, certs)
	mux.Handle(v2CertsPrefix+"/", certs)
	jobs := routeMethodHandler(v2JobMethods, s.authed(s.v2JobsHandler))
	mux.Handle(v2JobsPrefix, jobs)
	mux.Handle(v2JobsPrefix+"/", jobs)
}

// v2CertOp 是 v2 证书子路径解析出的操作。
type v2CertOp struct {
	name       string // 操作名：reconcile/status/deployments/manifest/file
	method     string // 该操作允许的 HTTP 方法
	domain     string // 证书主域名路径段
	generation string // generation 路径段（仅 manifest/file 操作）
	fileName   string // 文件名路径段（仅 file 操作）
}

// parseV2CertPath 解析 /api/v2/certs 之后的路径段，识别操作并做段数与非空校验。
// 域名格式、generation 格式等详细校验由 service 层完成。
func parseV2CertPath(parts []string) (v2CertOp, bool) {
	if len(parts) == 0 || parts[0] == "" {
		return v2CertOp{}, false
	}
	op := v2CertOp{domain: parts[0]}
	switch {
	case len(parts) == 2 && parts[1] == "reconcile":
		op.name, op.method = "reconcile", http.MethodPost
	case len(parts) == 2 && parts[1] == "status":
		op.name, op.method = "status", http.MethodGet
	case len(parts) == 2 && parts[1] == "deployments":
		op.name, op.method = "deployments", http.MethodPost
	case len(parts) == 4 && parts[1] == certproto.GenerationsPathSegment && parts[2] != "" && parts[3] == "manifest":
		op.name, op.method, op.generation = "manifest", http.MethodGet, parts[2]
	case len(parts) == 5 && parts[1] == certproto.GenerationsPathSegment && parts[2] != "" && parts[3] == certproto.FilesPathSegment:
		op.name, op.method, op.generation, op.fileName = "file", http.MethodGet, parts[2], parts[4]
	default:
		return v2CertOp{}, false
	}
	return op, true
}

// v2CertMethods 按 v2 证书子路径形状返回允许的 HTTP 方法；
// 段数不匹配或 domain/generation 段为空时返回 nil，由路由层统一返回 404。
func v2CertMethods(path string) []string {
	op, ok := parseV2CertPath(routeParts(path, v2CertsPrefix))
	if !ok {
		return nil
	}
	return []string{op.method}
}

// v2CertsHandler 分发 /api/v2/certs 子树请求。路径形状与方法已在外层校验，
// 此处按解析结果调用具体 handler；无法解析时兜底返回 404。
func (s *Server) v2CertsHandler(w http.ResponseWriter, r *http.Request) {
	op, ok := parseV2CertPath(routeParts(r.URL.Path, v2CertsPrefix))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	switch op.name {
	case "reconcile":
		s.v2Reconcile(w, r, op.domain)
	case "status":
		s.v2Status(w, r, op.domain)
	case "deployments":
		s.v2Deployments(w, r, op.domain)
	case "manifest":
		s.v2Manifest(w, r, op.domain, op.generation)
	case "file":
		s.v2CertFile(w, r, op.domain, op.generation, op.fileName)
	}
}

// v2JobMethods 只允许 GET /api/v2/jobs/{job_id}；其余段数一律返回 nil（404）。
func v2JobMethods(path string) []string {
	parts := routeParts(path, v2JobsPrefix)
	if len(parts) == 1 && parts[0] != "" {
		return []string{http.MethodGet}
	}
	return nil
}

// v2JobsHandler 分发 /api/v2/jobs 子树请求。
func (s *Server) v2JobsHandler(w http.ResponseWriter, r *http.Request) {
	parts := routeParts(r.URL.Path, v2JobsPrefix)
	if len(parts) != 1 || parts[0] == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	s.v2Job(w, r, parts[0])
}

// v2ReconcileReq 是 v2 reconcile 的请求体。
// 请求体刻意不包含 token_id/is_admin：调用方身份只来自已认证的 token，
// body 中即便携带同名字段也会在反序列化时被忽略。
type v2ReconcileReq struct {
	IdempotencyKey string `json:"idempotency_key"`
	Force          bool   `json:"force"`
	Operation      string `json:"operation"`
	Reason         string `json:"reason"`
}

// v2Reconcile 处理 POST /api/v2/certs/{domain}/reconcile。
// TokenID/IsAdmin 从 ctx 中已认证的 token 注入；force 的权限由 service 层校验。
func (s *Server) v2Reconcile(w http.ResponseWriter, r *http.Request, domain string) {
	var req v2ReconcileReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}
	t := tokenFromCtx(r)
	resp, err := s.service().ReconcileV2(r.Context(), service.V2ReconcileRequest{
		TokenID:        t.ID,
		IsAdmin:        t.IsAdmin,
		Domain:         domain,
		Operation:      req.Operation,
		Reason:         req.Reason,
		IdempotencyKey: req.IdempotencyKey,
		Force:          req.Force,
	})
	if err != nil {
		s.writeV2Error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// v2Status 处理 GET /api/v2/certs/{domain}/status。
func (s *Server) v2Status(w http.ResponseWriter, r *http.Request, domain string) {
	t := tokenFromCtx(r)
	status, err := s.service().StatusV2(r.Context(), t.ID, domain)
	if err != nil {
		s.writeV2Error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// v2Manifest 处理 GET /api/v2/certs/{domain}/generations/{generation}/manifest。
func (s *Server) v2Manifest(w http.ResponseWriter, r *http.Request, domain, generation string) {
	t := tokenFromCtx(r)
	manifest, err := s.service().ManifestV2(r.Context(), t.ID, domain, certproto.GenerationID(generation))
	if err != nil {
		s.writeV2Error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, manifest)
}

// v2CertFile 处理 GET /api/v2/certs/{domain}/generations/{generation}/files/{name}。
// 文件名先按固定集合校验，文件内容以 application/octet-stream 原样返回。
func (s *Server) v2CertFile(w http.ResponseWriter, r *http.Request, domain, generation, name string) {
	if err := certproto.ValidateFileName(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "不允许的证书文件名"})
		return
	}
	t := tokenFromCtx(r)
	data, err := s.service().ReadGenerationFileV2(r.Context(), t.ID, domain, certproto.GenerationID(generation), name)
	if err != nil {
		s.writeV2Error(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// v2Deployments 处理 POST /api/v2/certs/{domain}/deployments。
func (s *Server) v2Deployments(w http.ResponseWriter, r *http.Request, domain string) {
	var report certproto.DeploymentReport
	if err := readJSON(r, &report); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}
	t := tokenFromCtx(r)
	if err := s.service().ReportDeploymentV2(r.Context(), t.ID, domain, report); err != nil {
		s.writeV2Error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// v2Job 处理 GET /api/v2/jobs/{job_id}。
func (s *Server) v2Job(w http.ResponseWriter, r *http.Request, jobID string) {
	t := tokenFromCtx(r)
	status, err := s.service().GetJobV2(r.Context(), t.ID, jobID)
	if err != nil {
		s.writeV2Error(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// writeV2Error 是 v2 统一的错误映射：ValidationError→400、PermissionError→403、其余→500。
// 500 响应只返回通用消息并记录内部日志，不向调用方泄露路径或存储等内部细节。
func (s *Server) writeV2Error(w http.ResponseWriter, err error) {
	var validationErr *service.ValidationError
	var permErr *service.PermissionError
	switch {
	case errors.As(err, &validationErr):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": validationErr.Message})
	case errors.As(err, &permErr):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": permErr.Message})
	default:
		if s.Logger != nil {
			s.Logger.Error("v2 请求处理失败", "err", err.Error())
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "内部处理失败"})
	}
}
