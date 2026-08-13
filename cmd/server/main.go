// CertKeeper 服务端入口程序。
// 提供 HTTP API 服务，管理证书签发、续签和客户端认证。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/api"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/observability"
	"github.com/siidoo/certkeeper/internal/scheduler"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/internal/version"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// systemTokenID 是内置系统 token 的 ID，仅供调度器执行协调使用，不用于 HTTP 认证。
const systemTokenID = "system"

// systemTokenGrants 是系统 token 在每个预置证书上需要的权限。
var systemTokenGrants = []string{"apply", "status", "read_cert", "read_private_key"}

func main() {
	var (
		configPath string
		genKey     bool
		showVer    bool
	)
	flag.StringVar(&configPath, "config", "/data/config/config.yaml", "配置文件路径")
	flag.BoolVar(&genKey, "gen-encryption-key", false, "生成并打印一个 32 字节加密密钥后退出")
	flag.BoolVar(&showVer, "version", false, "显示版本")
	flag.Parse()

	if showVer {
		fmt.Println(version.String(version.ServerComponent))
		return
	}
	if genKey {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		fmt.Println(hex.EncodeToString(b))
		return
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	logger := setupLogger(cfg)
	logger.Info("启动 CertKeeper Server", "version", version.Version, "listen", cfg.Server.Listen)

	// 确保 SQLite 目录与日志目录存在
	mustMkdir(filepath.Dir(cfg.Storage.SQLitePath), logger)
	mustMkdir(filepath.Dir(cfg.Log.File), logger)
	mustMkdir(cfg.Acme.Home, logger)
	mustMkdir(cfg.Acme.CertsDir, logger)

	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		logger.Error("打开数据库失败", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	// 引导 admin token
	if err := bootstrapAdminToken(st, cfg, logger); err != nil {
		logger.Error("引导 admin token 失败", "err", err)
		os.Exit(1)
	}

	// 启动时不再自动升级 acme.sh（升级由运维显式执行），仅记录当前版本。
	runner := &acme.Runner{AcmeShPath: cfg.Acme.AcmeShPath, Home: cfg.Acme.Home}
	if res, err := runner.Version(context.Background()); err != nil {
		logger.Warn("查询 acme.sh 版本失败（继续启动）", "err", err)
	} else if res != nil {
		logger.Info("acme.sh 版本", "version", strings.TrimSpace(res.Stdout))
	}
	// 设置默认 CA
	if err := runner.SetDefaultCA(context.Background(), cfg.Acme.DefaultCA); err != nil {
		logger.Warn("设置默认 CA 失败（继续启动）", "err", err)
	}

	// 可观测性注册中心与标准指标
	registry := observability.NewRegistry()
	stdMetrics, err := registry.StandardMetrics()
	if err != nil {
		logger.Error("注册标准指标失败", "err", err)
		os.Exit(1)
	}
	if cfg.Observability.ReadyEnabled {
		if err := registerReadinessChecks(registry, cfg, st); err != nil {
			logger.Error("注册就绪检查失败", "err", err)
			os.Exit(1)
		}
	}

	svc := service.New(cfg, st)

	// 续期调度器：由独立 context 控制生命周期，收到停止信号后先于 HTTP 关闭。
	schedCtx, stopScheduler := context.WithCancel(context.Background())
	defer stopScheduler()
	var schedulerDone chan struct{}
	if cfg.Scheduler.Enabled {
		if err := ensureSystemToken(context.Background(), st, logger); err != nil {
			logger.Error("初始化系统 token 失败", "err", err)
			os.Exit(1)
		}
		sched := scheduler.New(&schedulerWorker{svc: svc, tokenID: systemTokenID}, scheduler.Config{
			Interval: cfg.Scheduler.Interval,
			Jitter:   cfg.Scheduler.Jitter,
			Observer: schedulerObserver(stdMetrics, logger),
		})
		schedulerDone = make(chan struct{})
		go func() {
			defer close(schedulerDone)
			if err := sched.Run(schedCtx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("调度器异常退出", "err", err)
			}
		}()
		logger.Info("续期调度器已启动", "interval", cfg.Scheduler.Interval, "jitter", cfg.Scheduler.Jitter)
	}

	// 启动 nonce 清理 goroutine
	go startNonceCleaner(st, cfg, logger)

	srv := &api.Server{Cfg: cfg, Store: st, Service: svc, Logger: logger, Metrics: registry}
	httpSrv := newHTTPServer(cfg, srv.Handler())

	go func() {
		logger.Info("HTTP 监听", "addr", cfg.Server.Listen, "tls", cfg.Server.TLS)
		var err error
		if cfg.Server.TLS {
			err = httpSrv.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP 服务异常", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Info("收到停止信号，正在关闭")

	// 先停止调度器，避免关闭过程中仍在执行签发。
	stopScheduler()
	if schedulerDone != nil {
		select {
		case <-schedulerDone:
		case <-time.After(5 * time.Second):
			logger.Warn("等待调度器退出超时，继续关闭")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("HTTP 优雅关闭失败", "err", err)
		os.Exit(1)
	}
	logger.Info("已优雅关闭")
}

// newHTTPServer 根据配置构造带超时设置的 HTTP 服务器。
func newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}
}

// schedulerWorker 将 service 的续期能力适配为 scheduler.Worker 接口。
// 协调以系统 token 身份执行，不绕过 service 的域名 grant 检查。
type schedulerWorker struct {
	svc     *service.Service
	tokenID string
}

// ListCandidates 返回全部预置证书的调度候选。
func (w *schedulerWorker) ListCandidates(ctx context.Context) ([]scheduler.Candidate, error) {
	return w.svc.ListRenewalCandidates(ctx)
}

// Reconcile 对单个域名执行 v2 协调。幂等键按调用生成：
// 同一轮内重复调用复用活动任务，跨轮次互不影响。
func (w *schedulerWorker) Reconcile(ctx context.Context, domain string) (scheduler.Result, error) {
	resp, err := w.svc.ReconcileV2(ctx, service.V2ReconcileRequest{
		TokenID:        w.tokenID,
		IsAdmin:        false,
		Domain:         domain,
		Operation:      "reconcile",
		Reason:         "scheduler",
		IdempotencyKey: fmt.Sprintf("scheduler-%d", time.Now().UnixNano()),
	})
	if err != nil {
		return scheduler.Result{}, err
	}
	return scheduler.Result{Changed: resp.Changed, Message: resp.Message}, nil
}

// schedulerObserver 把每轮调度汇总写入 jobs 指标并记录日志，不包含域名等敏感标签。
func schedulerObserver(std *observability.StandardMetrics, logger *slog.Logger) scheduler.Observer {
	return scheduler.ObserverFunc(func(sum scheduler.Summary) {
		if std != nil {
			_ = std.Jobs.Add(observability.Labels{"job": "scheduler_reconcile", "status": "success"}, float64(sum.Succeeded))
			_ = std.Jobs.Add(observability.Labels{"job": "scheduler_reconcile", "status": "failure"}, float64(sum.Failed))
			_ = std.Jobs.Add(observability.Labels{"job": "scheduler_reconcile", "status": "skipped"}, float64(sum.Skipped))
			// 候选项列表获取失败时没有产生任何逐域名结果，单独记一次列表失败。
			if sum.Error != nil && sum.Attempted == 0 && len(sum.Results) == 0 {
				_ = std.Jobs.Inc(observability.Labels{"job": "scheduler_list", "status": "failure"})
			}
		}
		if logger != nil {
			logger.Info("调度轮次完成",
				"candidates", sum.Candidates, "attempted", sum.Attempted,
				"succeeded", sum.Succeeded, "failed", sum.Failed, "skipped", sum.Skipped,
				"duration_ms", sum.CompletedAt.Sub(sum.StartedAt).Milliseconds())
		}
	})
}

// ensureSystemToken 确保内置系统 token 存在且处于启用状态，
// 并对所有预置证书授予调度所需的权限（Grant 幂等，可重复执行）。
// token secret 使用随机值，仅满足存储约束，不用于 HTTP，也不写入日志。
func ensureSystemToken(ctx context.Context, st *store.Store, logger *slog.Logger) error {
	t, err := st.GetToken(ctx, systemTokenID)
	if err != nil {
		return fmt.Errorf("读取系统 token 失败: %w", err)
	}
	switch {
	case t == nil:
		secret, err := ckauth.GenSecret()
		if err != nil {
			return fmt.Errorf("生成系统 token secret 失败: %w", err)
		}
		if err := st.CreateToken(ctx, &store.Token{
			ID:        systemTokenID,
			Secret:    secret,
			Note:      "内置系统 token（调度器使用，不用于 HTTP）",
			Enabled:   true,
			IsAdmin:   false,
			CreatedAt: time.Now().Unix(),
		}); err != nil {
			return fmt.Errorf("创建系统 token 失败: %w", err)
		}
		logger.Info("已创建内置系统 token", "id", systemTokenID)
	case !t.Enabled:
		// 调度依赖系统 token，启动时恢复启用状态。
		if err := st.UpdateToken(ctx, systemTokenID, t.Note, true, t.IsAdmin); err != nil {
			return fmt.Errorf("启用系统 token 失败: %w", err)
		}
		logger.Info("已重新启用内置系统 token", "id", systemTokenID)
	}

	certs, err := st.ListCerts(ctx)
	if err != nil {
		return fmt.Errorf("列出证书配置失败: %w", err)
	}
	for _, c := range certs {
		for _, perm := range systemTokenGrants {
			if err := st.Grant(ctx, systemTokenID, c.Domain, perm); err != nil {
				return fmt.Errorf("授予系统 token 权限失败(%s %s): %w", c.Domain, perm, err)
			}
		}
	}
	return nil
}

// registerReadinessChecks 注册就绪检查：数据库连通性与关键目录可写。
func registerReadinessChecks(registry *observability.Registry, cfg *config.Config, st *store.Store) error {
	if err := registry.RegisterReadiness("store", func(ctx context.Context) error {
		return st.DB.PingContext(ctx)
	}); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("acme_home_writable", dirWritableCheck(cfg.Acme.Home)); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("certs_dir_writable", dirWritableCheck(cfg.Acme.CertsDir)); err != nil {
		return err
	}
	return nil
}

// dirWritableCheck 返回目录可写性检查：写入临时文件成功后立即删除。
func dirWritableCheck(dir string) observability.Check {
	return func(context.Context) error {
		f, err := os.CreateTemp(dir, ".readyz-*")
		if err != nil {
			return err
		}
		name := f.Name()
		if err := f.Close(); err != nil {
			_ = os.Remove(name)
			return err
		}
		return os.Remove(name)
	}
}

func setupLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Log.File != "" {
		if f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			return slog.New(slog.NewJSONHandler(f, opts))
		}
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func mustMkdir(p string, logger *slog.Logger) {
	if p == "" {
		return
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		logger.Error("创建目录失败", "dir", p, "err", err)
		os.Exit(1)
	}
}

func bootstrapAdminToken(st *store.Store, cfg *config.Config, logger *slog.Logger) error {
	ctx := context.Background()
	if cfg.Auth.AdminTokenID == "" {
		return nil
	}
	t, err := st.GetToken(ctx, cfg.Auth.AdminTokenID)
	if err != nil {
		return err
	}
	if t != nil {
		return nil
	}
	secret, err := ckauth.GenSecret()
	if err != nil {
		return err
	}
	// 若配置了 encryption_key，用它派生 admin secret（保持可预测），否则随机
	secret = ckauth.DeriveSecret(cfg.Storage.EncryptionKey, cfg.Auth.AdminTokenID, secret)
	if err := st.CreateToken(ctx, &store.Token{
		ID:        cfg.Auth.AdminTokenID,
		Secret:    secret,
		Note:      "auto-bootstrapped admin",
		Enabled:   true,
		IsAdmin:   true,
		CreatedAt: time.Now().Unix(),
	}); err != nil {
		return err
	}
	logger.Info("已创建 admin token",
		"id", cfg.Auth.AdminTokenID, "secret", secret)
	logger.Info("请妥善保存上述 secret，仅此一次显示")
	return nil
}

func startNonceCleaner(st *store.Store, cfg *config.Config, logger *slog.Logger) {
	ticker := time.NewTicker(time.Duration(cfg.Auth.NonceTTLSec) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if err := st.CleanOldNonces(context.Background(), time.Now().Unix()-int64(cfg.Auth.NonceTTLSec*2)); err != nil {
			logger.Warn("清理过期 nonce 失败", "err", err)
		}
	}
}
