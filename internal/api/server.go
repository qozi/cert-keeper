// Package api 提供 CertKeeper 的 HTTP API 服务器和路由处理功能。
// 包含客户端 API、管理 API 以及认证中间件。
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/observability"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// Server 是 HTTP API 服务器，管理路由和请求处理。
type Server struct {
	Cfg     *config.Config
	Store   *store.Store
	Service *service.Service
	Logger  Logger
	// Metrics 是可选的可观测性注册中心；为 nil 时不暴露 /metrics 与 /readyz。
	Metrics *observability.Registry
	now     func() time.Time
}

func (s *Server) service() *service.Service {
	if s.Service == nil {
		s.Service = service.New(s.Cfg, s.Store)
	}
	return s.Service
}

// Logger 是日志记录器接口，支持 Info/Warn/Error 三个级别。
type Logger interface {
	Info(msg string, fields ...any)
	Warn(msg string, fields ...any)
	Error(msg string, fields ...any)
}

type ctxKey string

const (
	ctxToken ctxKey = "token"

	maxRequestBodySize = 1 << 20
)

var (
	// 鉴权错误统一对外返回，避免泄露 Token、时间戳或签名的具体失败原因。
	errAuthentication = errors.New("认证失败")
	errBodyTooLarge   = errors.New("请求体过大")
	errBodyRead       = errors.New("请求体读取失败")
	errJSONRequired   = errors.New("请求体必须使用 application/json")
)

// Handler 返回配置好的 HTTP 处理器，包含所有路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", methodHandler([]string{http.MethodGet}, http.HandlerFunc(s.healthz)))

	// 客户端 API（需 client token）
	mux.Handle("/api/v1/client/register", methodHandler([]string{http.MethodPost}, s.authed(s.registerClient)))
	mux.Handle("/api/v1/client/heartbeat", methodHandler([]string{http.MethodPost}, s.authed(s.heartbeat)))
	mux.Handle("/api/v1/certs/apply", methodHandler([]string{http.MethodPost}, s.authed(s.applyCert)))
	mux.Handle("/api/v1/certs/", methodHandler([]string{http.MethodGet}, s.authed(s.certSubtree)))
	mux.Handle("/api/v1/ping", methodHandler([]string{http.MethodGet}, s.authed(s.ping)))

	// 管理 API（需 admin token）
	tokens := routeMethodHandler(adminTokenMethods, s.admin(s.tokensHandler))
	mux.Handle("/api/v1/admin/tokens", tokens)
	mux.Handle("/api/v1/admin/tokens/", tokens)
	certs := routeMethodHandler(adminCertMethods, s.admin(s.certsAdminHandler))
	mux.Handle("/api/v1/admin/certs", certs)
	mux.Handle("/api/v1/admin/certs/", certs)
	secrets := routeMethodHandler(adminSecretMethods, s.admin(s.secretsHandler))
	mux.Handle("/api/v1/admin/secrets", secrets)
	mux.Handle("/api/v1/admin/secrets/", secrets)
	providers := routeMethodHandler(adminProviderMethods, s.admin(s.providersHandler))
	mux.Handle("/api/v1/admin/providers", providers)
	mux.Handle("/api/v1/admin/providers/", providers)
	mux.Handle("/api/v1/admin/clients", methodHandler([]string{http.MethodGet}, s.admin(s.clientsHandler)))
	mux.Handle("/api/v1/admin/logs", methodHandler([]string{http.MethodGet}, s.admin(s.logsHandler)))

	// v2 公共 API（需 client token；写操作不强制 admin，由 service 按域名 grant 决定）
	s.registerV2Routes(mux)

	// 可观测性端点无需鉴权，面向内网监控系统，由配置开关控制是否暴露。
	metricsEnabled := s.Metrics != nil && s.Cfg.Observability.MetricsEnabled
	if metricsEnabled {
		mux.Handle("/metrics", methodHandler([]string{http.MethodGet}, http.HandlerFunc(s.metrics)))
	}
	if s.Metrics != nil && s.Cfg.Observability.ReadyEnabled {
		mux.Handle("/readyz", methodHandler([]string{http.MethodGet}, http.HandlerFunc(s.readyz)))
	}

	var handler http.Handler = securityHeaders(mux)
	if metricsEnabled {
		if std, err := s.Metrics.StandardMetrics(); err == nil {
			handler = requestMetricsMiddleware(std.Requests, handler)
		}
	}
	return handler
}

// metrics 以 Prometheus 文本格式暴露全部已注册指标。
func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := s.Metrics.WritePrometheus(w); err != nil && s.Logger != nil {
		s.Logger.Warn("写入 metrics 响应失败", "err", err.Error())
	}
}

// readyz 聚合执行全部就绪检查，任一失败返回 503。
// 响应只包含检查名与通过状态，不泄露内部错误细节。
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	report, err := s.Metrics.CheckReadiness(r.Context())
	s.recordReadiness(report)
	status := http.StatusOK
	if err != nil || !report.Ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, report)
}

// recordReadiness 将就绪检查结果写入 readiness gauge，供 /metrics 展示。
func (s *Server) recordReadiness(report observability.ReadinessReport) {
	std, err := s.Metrics.StandardMetrics()
	if err != nil {
		return
	}
	for _, check := range report.Checks {
		value := 0.0
		if check.Passed {
			value = 1
		}
		_ = std.Readiness.Set(observability.Labels{"check": check.Name}, value)
	}
}

// requestMetricsMiddleware 统计每个请求的方法与响应状态码。
// 标签刻意只包含 method 和 status，不记录域名、token 等高基数或敏感信息。
func requestMetricsMiddleware(requests *observability.Counter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		_ = requests.Inc(observability.Labels{
			"method": r.Method,
			"status": strconv.Itoa(recorder.status),
		})
	})
}

// statusRecorder 包装 ResponseWriter 以捕获响应状态码。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"pong": true, "ts": s.currentTime().Unix()})
}

// authed 校验客户端 token，写入 ctx
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := s.verifyToken(r)
		if err != nil {
			s.logAuthFailure(r, err)
			writeRequestError(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), ctxToken, t)
		h(w, r.WithContext(ctx))
	}
}

// admin 仅 admin token
func (s *Server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := s.verifyToken(r)
		if err != nil {
			s.logAuthFailure(r, err)
			writeRequestError(w, err)
			return
		}
		if !t.IsAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "需要 admin 权限"})
			return
		}
		ctx := context.WithValue(r.Context(), ctxToken, t)
		h(w, r.WithContext(ctx))
	}
}

// verifyToken 读取并校验请求体，然后完成签名认证。成功后恢复请求体供 handler 读取。
func (s *Server) verifyToken(r *http.Request) (*store.Token, error) {
	body, err := readRequestBody(r)
	if err != nil {
		return nil, err
	}
	if isWriteMethod(r.Method) && len(body) > 0 && !isJSONContentType(r) {
		return nil, errJSONRequired
	}

	t, err := s.verifyTokenBody(r, body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return t, nil
}

func (s *Server) verifyTokenBody(r *http.Request, body []byte) (*store.Token, error) {
	id, idOK := singleHeader(r, ckauth.HeaderTokenID)
	tsStr, tsOK := singleHeader(r, ckauth.HeaderTimestamp)
	nonce, nonceOK := singleHeader(r, ckauth.HeaderNonce)
	bodyHash, bodyHashOK := singleHeader(r, ckauth.HeaderBodyHash)
	sig, sigOK := singleHeader(r, ckauth.HeaderSignature)
	if !idOK || !validTokenID(id) || !tsOK || !validTimestampString(tsStr) || !nonceOK || !validHex(nonce, ckauth.NonceHexLen) || !bodyHashOK || !validBodyHash(bodyHash, len(body) > 0) || !sigOK || !validHex(sig, ckauth.HashHexLen) {
		return nil, errAuthentication
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || ts < 0 {
		return nil, errAuthentication
	}
	now := s.currentTime().Unix()
	window := int64(s.Cfg.Auth.TimestampWindowSec)
	if window < 0 {
		return nil, errAuthentication
	}
	diff := now - ts
	if diff < -window || diff > window {
		return nil, errAuthentication
	}

	// 摘要必须来自服务端读取到的原始请求体，不能信任请求头中的声明值。
	expectedBodyHash := ckauth.EmptyBodyHash
	if len(body) > 0 {
		h := sha256.Sum256(body)
		expectedBodyHash = hex.EncodeToString(h[:])
	}
	bodyHash = strings.ToLower(bodyHash)
	if !ckauth.SecureEqual(bodyHash, expectedBodyHash) {
		return nil, errAuthentication
	}

	t, err := s.Store.GetToken(r.Context(), id)
	if err != nil || t == nil || !t.Enabled {
		return nil, errAuthentication
	}

	// query 使用 RawQuery 原样参与签名，确保查询参数不能被替换或重排后复用。
	signedPath := r.URL.Path
	if r.URL.RawQuery != "" {
		signedPath += "?" + r.URL.RawQuery
	}
	want := ckauth.Sign(r.Method, signedPath, ts, nonce, expectedBodyHash, t.Secret)
	if !ckauth.SecureEqual(strings.ToLower(sig), want) {
		return nil, errAuthentication
	}

	// 只有签名完全通过后才消费 nonce，非法请求不会污染防重放记录。
	ok, err := s.Store.ConsumeNonce(r.Context(), nonce, s.Cfg.Auth.NonceTTLSec)
	if err != nil || !ok {
		return nil, errAuthentication
	}
	_ = s.Store.UpdateTokenUsage(r.Context(), id)
	return t, nil
}

func (s *Server) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Server) logAuthFailure(r *http.Request, err error) {
	if s.Logger != nil {
		s.Logger.Warn("鉴权失败", "err", err.Error(), "path", r.URL.Path)
	}
}

func writeRequestError(w http.ResponseWriter, err error) {
	status := http.StatusUnauthorized
	switch {
	case errors.Is(err, errBodyTooLarge):
		status = http.StatusRequestEntityTooLarge
	case errors.Is(err, errBodyRead):
		status = http.StatusBadRequest
	case errors.Is(err, errJSONRequired):
		status = http.StatusUnsupportedMediaType
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func readRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		r.Body = http.NoBody
		return nil, nil
	}
	if r.ContentLength > maxRequestBodySize {
		return nil, errBodyTooLarge
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
	if err != nil {
		return nil, errBodyRead
	}
	if len(body) > maxRequestBodySize {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func isJSONContentType(r *http.Request) bool {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func singleHeader(r *http.Request, name string) (string, bool) {
	values := r.Header.Values(name)
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func validTokenID(id string) bool {
	if len(id) == 0 || len(id) > ckauth.TokenIDMaxLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func validTimestampString(value string) bool {
	if len(value) == 0 || len(value) > ckauth.TimestampMaxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func validBodyHash(value string, hasBody bool) bool {
	if !hasBody {
		return len(value) == len(ckauth.EmptyBodyHash) && value == ckauth.EmptyBodyHash
	}
	return validHex(value, ckauth.HashHexLen)
}

func methodHandler(methods []string, h http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		allowed[method] = struct{}{}
	}
	allow := strings.Join(methods, ", ")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := allowed[r.Method]; !ok {
			w.Header().Set("Allow", allow)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func routeMethodHandler(methodsForPath func(string) []string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods := methodsForPath(r.URL.Path)
		if len(methods) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		methodHandler(methods, h).ServeHTTP(w, r)
	})
}

func adminTokenMethods(path string) []string {
	parts := routeParts(path, "/api/v1/admin/tokens")
	switch len(parts) {
	case 0:
		return []string{http.MethodGet, http.MethodPost}
	case 1:
		return []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete}
	default:
		return nil
	}
}

func adminCertMethods(path string) []string {
	parts := routeParts(path, "/api/v1/admin/certs")
	switch {
	case len(parts) == 0:
		return []string{http.MethodGet, http.MethodPost}
	case len(parts) == 1 && parts[0] == "status":
		return []string{http.MethodGet}
	case len(parts) == 1:
		return []string{http.MethodDelete}
	case len(parts) == 2 && parts[1] == "reissue":
		return []string{http.MethodPost}
	default:
		return nil
	}
}

func adminSecretMethods(path string) []string {
	parts := routeParts(path, "/api/v1/admin/secrets")
	switch len(parts) {
	case 0:
		return []string{http.MethodGet, http.MethodPost}
	case 1, 2:
		return []string{http.MethodDelete}
	default:
		return nil
	}
}

func adminProviderMethods(path string) []string {
	parts := routeParts(path, "/api/v1/admin/providers")
	if len(parts) == 0 || len(parts) == 2 && parts[1] == "parameters" {
		return []string{http.MethodGet}
	}
	return nil
}

func routeParts(path, prefix string) []string {
	if path != prefix && !strings.HasPrefix(path, prefix+"/") {
		return nil
	}
	return splitPath(strings.TrimPrefix(path, prefix))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// writeJSON 将数据序列化为 JSON 并写入 HTTP 响应。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON 从 HTTP 请求体中读取并反序列化 JSON 数据。
func readJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	d, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodySize+1))
	if err != nil {
		return err
	}
	if len(d) > maxRequestBodySize {
		return errBodyTooLarge
	}
	if len(d) == 0 {
		return nil
	}
	return json.Unmarshal(d, v)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func tokenFromCtx(r *http.Request) *store.Token {
	if v, ok := r.Context().Value(ctxToken).(*store.Token); ok {
		return v
	}
	return nil
}
