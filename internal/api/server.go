// Package api 提供 CertKeeper 的 HTTP API 服务器和路由处理功能。
// 包含客户端 API、管理 API 以及认证中间件。
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// Server 是 HTTP API 服务器，管理路由和请求处理。
type Server struct {
	Cfg    *config.Config
	Store  *store.Store
	Logger Logger
	now    func() time.Time
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
)

// Handler 返回配置好的 HTTP 处理器，包含所有路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)

	// 客户端 API（需 client token）
	mux.HandleFunc("/api/v1/client/register", s.authed(s.registerClient))
	mux.HandleFunc("/api/v1/client/heartbeat", s.authed(s.heartbeat))
	mux.HandleFunc("/api/v1/certs/apply", s.authed(s.applyCert))
	mux.HandleFunc("/api/v1/certs/", s.certSubtree)
	mux.HandleFunc("/api/v1/ping", s.authed(s.ping))

	// 管理 API（需 admin token）
	mux.HandleFunc("/api/v1/admin/tokens", s.admin(s.tokensHandler))
	mux.HandleFunc("/api/v1/admin/tokens/", s.tokensHandler)
	mux.HandleFunc("/api/v1/admin/certs", s.admin(s.certsAdminHandler))
	mux.HandleFunc("/api/v1/admin/certs/", s.certsAdminHandler)
	mux.HandleFunc("/api/v1/admin/secrets", s.admin(s.secretsHandler))
	mux.HandleFunc("/api/v1/admin/secrets/", s.secretsHandler)
	mux.HandleFunc("/api/v1/admin/clients", s.admin(s.clientsHandler))
	mux.HandleFunc("/api/v1/admin/logs", s.admin(s.logsHandler))
	return mux
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"pong": true, "ts": time.Now().Unix()})
}

// authed 校验客户端 token，写入 ctx
func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, err := s.verifyToken(r)
		if err != nil {
			s.Logger.Warn("鉴权失败", "err", err.Error(), "path", r.URL.Path)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
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

func (s *Server) verifyToken(r *http.Request) (*store.Token, error) {
	id := r.Header.Get(ckauth.HeaderTokenID)
	sig := r.Header.Get(ckauth.HeaderSignature)
	if id == "" || sig == "" {
		return nil, errors.New("缺少认证头")
	}
	t, err := s.Store.GetToken(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if t == nil || !t.Enabled {
		return nil, errors.New("token 无效或已停用")
	}
	// 时间戳 + nonce 校验
	tsStr := r.Header.Get(ckauth.HeaderTimestamp)
	nonce := r.Header.Get(ckauth.HeaderNonce)
	if tsStr == "" || nonce == "" {
		return nil, errors.New("缺少时间戳或 nonce")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, errors.New("时间戳格式错误")
	}
	diff := time.Now().Unix() - ts
	if diff < -int64(s.Cfg.Auth.TimestampWindowSec) || diff > int64(s.Cfg.Auth.TimestampWindowSec) {
		return nil, errors.New("时间戳超出允许窗口")
	}
	// nonce 唯一性
	ok, err := s.Store.ConsumeNonce(r.Context(), nonce, s.Cfg.Auth.NonceTTLSec)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("nonce 已被使用（疑似重放）")
	}
	// 验证签名
	bodyHash := r.Header.Get("X-CK-BodyHash")
	if bodyHash == "" {
		bodyHash = "0"
	}
	// 签名覆盖 path + ? + rawquery
	signedPath := r.URL.Path
	if r.URL.RawQuery != "" {
		signedPath += "?" + r.URL.RawQuery
	}
	want := ckauth.Sign(r.Method, signedPath, ts, nonce, bodyHash, t.Secret)
	if !ckauth.SecureEqual(sig, want) {
		return nil, errors.New("签名校验失败")
	}
	_ = s.Store.UpdateTokenUsage(r.Context(), id)
	return t, nil
}

// writeJSON 将数据序列化为 JSON 并写入 HTTP 响应。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON 从 HTTP 请求体中读取并反序列化 JSON 数据。
func readJSON(r *http.Request, v any) error {
	d, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
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

var _ = fmt.Sprintf
