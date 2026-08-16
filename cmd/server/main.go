// CertKeeper 服务端入口程序。
// 提供 HTTP API 服务，管理证书签发、续签和客户端认证。
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	"sync/atomic"
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

var workerHeartbeat atomic.Int64

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
	// 显式 cleanup 函数，避免 os.Exit 绕过 defer 导致 SQLite WAL 未合并
	cleanup := func() { st.Close() }

	// 引导 admin token
	if err := bootstrapAdminToken(st, cfg, logger); err != nil {
		logger.Error("引导 admin token 失败", "err", err)
		cleanup()
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
		cleanup()
		os.Exit(1)
	}
	if cfg.Observability.ReadyEnabled {
		if err := registerReadinessChecks(registry, cfg, st); err != nil {
			logger.Error("注册就绪检查失败", "err", err)
			cleanup()
			os.Exit(1)
		}
	}

	svc := service.New(cfg, st)

	// 续期调度器：由独立 context 控制生命周期，收到停止信号后先于 HTTP 关闭。
	schedCtx, stopScheduler := context.WithCancel(context.Background())
	defer stopScheduler()
	var schedulerDone chan struct{}
	if cfg.Scheduler.Enabled {
		worker := scheduler.NewPersistentWorker(&persistentStoreAdapter{store: st, cfg: cfg}, persistentReconciler{svc: svc}, scheduler.PersistentConfig{
			Interval: cfg.Scheduler.Interval, Jitter: cfg.Scheduler.Jitter,
			Actor:    scheduler.Actor{ID: "certificate-worker", Kind: "system"},
			Observer: persistentObserver(stdMetrics, logger),
		})
		schedulerDone = make(chan struct{})
		go func() {
			defer close(schedulerDone)
			if err := worker.Run(schedCtx); err != nil && !errors.Is(err, context.Canceled) {
				logger.Warn("调度器异常退出", "err", err)
			}
		}()
		logger.Info("续期调度器已启动", "interval", cfg.Scheduler.Interval, "jitter", cfg.Scheduler.Jitter)
	}

	// 启动 nonce 清理 goroutine（使用 schedCtx 控制生命周期，随调度器一同退出）
	nonceDone := make(chan struct{})
	go func() {
		defer close(nonceDone)
		startNonceCleaner(schedCtx, st, cfg, logger)
	}()

	srv := &api.Server{Cfg: cfg, Store: st, Service: svc, Logger: logger, Metrics: registry}
	if cfg.Server.TLSMode == "proxy" {
		logger.Warn("proxy 模式：服务以明文 HTTP 监听，请确保网络层已隔离后端端口，受信代理校验由网络拓扑负责")
	}
	httpSrv, err := newHTTPServer(cfg, srv.Handler())
	if err != nil {
		logger.Error("初始化 HTTP 服务器失败", "err", err)
		cleanup()
		os.Exit(1)
	}

	// fatalErr 用于 goroutine 将致命错误传递给 main，避免 goroutine 内直接 os.Exit 绕过 cleanup
	fatalErr := make(chan error, 1)
	go func() {
		logger.Info("HTTP 监听", "addr", cfg.Server.Listen, "tls_mode", cfg.Server.TLSMode)
		var err error
		if cfg.Server.TLSMode == "direct" {
			err = httpSrv.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP 服务异常", "err", err)
			fatalErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
		logger.Info("收到停止信号，正在关闭")
	case err := <-fatalErr:
		logger.Error("HTTP 服务致命错误，正在关闭", "err", err)
	}

	// 先停止调度器（同时取消 schedCtx，让 nonce 清理协程一并退出），避免关闭过程中仍在执行签发。
	stopScheduler()
	if schedulerDone != nil {
		select {
		case <-schedulerDone:
		case <-time.After(5 * time.Second):
			logger.Warn("等待调度器退出超时，继续关闭")
		}
	}

	// 等待 nonce 清理协程退出，再关闭数据库连接
	select {
	case <-nonceDone:
	case <-time.After(2 * time.Second):
		logger.Warn("等待 nonce 清理协程退出超时，继续关闭")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("HTTP 优雅关闭失败", "err", err)
		cleanup()
		os.Exit(1)
	}
	cleanup()
	logger.Info("已优雅关闭")
}

// newHTTPServer 根据配置构造带超时设置的 HTTP 服务器。
// 当 ClientMTLS=true 时强制要求客户端证书，CA 文件缺失或无效均返回错误。
func newHTTPServer(cfg *config.Config, handler http.Handler) (*http.Server, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.Server.ClientMTLS {
		if cfg.Server.ClientCAFile == "" {
			return nil, errors.New("server.client_mtls=true 但未设置 client_ca_file")
		}
		data, err := os.ReadFile(cfg.Server.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("读取 client_ca_file 失败: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("client_ca_file 不包含有效 CA 证书")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		TLSConfig:         tlsConfig,
	}, nil
}

// persistentReconciler 将持久任务交给 service 的异步执行入口。
type persistentReconciler struct{ svc *service.Service }

func (r persistentReconciler) ReconcileJob(ctx context.Context, actor scheduler.Actor, job scheduler.Job) (scheduler.Result, error) {
	return r.svc.ReconcileJob(ctx, actor, job)
}

// persistentStoreAdapter 把 Store 的证书任务表适配为 scheduler 的 lease 契约。
type persistentStoreAdapter struct {
	store *store.Store
	cfg   *config.Config
}

func (a *persistentStoreAdapter) ListCandidates(ctx context.Context) ([]scheduler.Candidate, error) {
	return service.New(a.cfg, a.store).ListRenewalCandidates(ctx)
}

func (a *persistentStoreAdapter) CreateJob(ctx context.Context, spec scheduler.JobSpec) (scheduler.Job, bool, error) {
	job, err := a.store.CreateJob(ctx, &store.CertificateJob{Domain: spec.Candidate.Domain, Operation: "reconcile", IdempotencyKey: spec.IdempotencyKey, RequestedBy: store.JSONNullString{String: spec.Actor.ID, Valid: spec.Actor.ID != ""}, CreatedAt: spec.CreatedAt.Unix()})
	if err != nil {
		return scheduler.Job{}, false, err
	}
	return adapterJob(*job, spec.Candidate, spec.Actor), job.CreatedAt == spec.CreatedAt.Unix(), nil
}

func (a *persistentStoreAdapter) ClaimJob(ctx context.Context, req scheduler.ClaimRequest) (*scheduler.Job, error) {
	job, err := a.store.ClaimJob(ctx, req.Owner, req.LeaseUntil.Sub(req.Now))
	if err != nil || job == nil {
		return nil, err
	}
	// 查询证书配置以获取真实的 ChallengeMode，避免硬编码 "dns_api"
	challengeMode := "dns_api" // 兜底默认值
	if cert, cerr := a.store.GetCert(ctx, job.Domain); cerr != nil {
		slog.Warn("ClaimJob: 查询证书配置失败，使用默认 ChallengeMode", "domain", job.Domain, "err", cerr)
	} else if cert != nil && cert.ChallengeMode != "" {
		challengeMode = cert.ChallengeMode
	}
	returnJob := adapterJob(*job, scheduler.Candidate{Domain: job.Domain, ChallengeMode: challengeMode}, scheduler.Actor{ID: "certificate-worker", Kind: "system"})
	return &returnJob, nil
}

func (a *persistentStoreAdapter) RenewLease(ctx context.Context, renewal scheduler.LeaseRenewal) (uint64, bool, error) {
	err := a.store.RenewLease(ctx, renewal.ID, renewal.Owner, renewal.LeaseUntil.Sub(renewal.Now))
	if err != nil {
		return renewal.LeaseVersion, false, err
	}
	// SQL store 不追踪乐观锁版本号，合成递增版本以保持接口语义一致
	return renewal.LeaseVersion + 1, true, nil
}
func (a *persistentStoreAdapter) UpdateJob(ctx context.Context, update scheduler.JobUpdate) (bool, error) {
	status := string(update.Status)
	err := a.store.UpdateJobStatus(ctx, update.ID, status, update.LastError)
	return err == nil, err
}
func (a *persistentStoreAdapter) RecordSkippedCandidate(ctx context.Context, record scheduler.SkipRecord) error {
	return nil
}
func adapterJob(job store.CertificateJob, candidate scheduler.Candidate, actor scheduler.Actor) scheduler.Job {
	return scheduler.Job{ID: job.ID, Candidate: candidate, Actor: actor, IdempotencyKey: job.IdempotencyKey, Status: scheduler.JobStatus(job.Status), Attempts: job.Attempts, MaxAttempts: job.MaxAttempts, LeaseOwner: job.LeaseOwner}
}

func persistentObserver(std *observability.StandardMetrics, logger *slog.Logger) scheduler.PersistentObserver {
	return scheduler.PersistentObserverFunc(func(sum scheduler.PersistentSummary) {
		if std != nil {
			_ = std.Jobs.Add(observability.Labels{"job": "persistent_worker", "status": "claimed"}, float64(sum.Claimed))
			_ = std.Jobs.Add(observability.Labels{"job": "persistent_worker", "status": "failed"}, float64(sum.Failed))
		}
		workerHeartbeat.Store(time.Now().Unix())
		if logger != nil {
			logger.Info("持久 worker 轮次完成", "claimed", sum.Claimed, "succeeded", sum.Succeeded, "failed", sum.Failed)
		}
	})
}

// registerReadinessChecks 注册就绪检查：数据库连通性与关键目录可写。
func registerReadinessChecks(registry *observability.Registry, cfg *config.Config, st *store.Store) error {
	if err := registry.RegisterReadiness("store", func(ctx context.Context) error {
		return st.DB.PingContext(ctx)
	}); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("store_encryption", st.CheckEncryptionReadiness); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("acme_home_writable", dirWritableCheck(cfg.Acme.Home)); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("certs_dir_writable", dirWritableCheck(cfg.Acme.CertsDir)); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("acme_config", func(context.Context) error {
		if cfg.Acme.AcmeShPath == "" || cfg.Acme.Home == "" {
			return errors.New("ACME 配置不完整")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("worker_heartbeat", func(context.Context) error {
		if cfg.Scheduler.Enabled && workerHeartbeat.Load() == 0 {
			return errors.New("worker 尚未完成首轮运行")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := registry.RegisterReadiness("renewal_backlog", func(ctx context.Context) error {
		_, err := st.ListRecoverable(ctx, time.Now(), 1)
		return err
	}); err != nil {
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
		if f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
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
	// secret 直接写到 stderr，不经过 slog，避免明文出现在持久化结构化日志中
	fmt.Fprintf(os.Stderr, "[cert-keeper] 已创建 admin token id=%s secret=%s\n", cfg.Auth.AdminTokenID, secret)
	fmt.Fprintf(os.Stderr, "[cert-keeper] 请妥善保存上述 secret，仅此一次显示\n")
	return nil
}

func startNonceCleaner(ctx context.Context, st *store.Store, cfg *config.Config, logger *slog.Logger) {
	ttl := cfg.Auth.NonceTTLSec
	if ttl <= 0 {
		// NonceTTLSec 为 0 会导致 time.NewTicker panic，使用默认值 300 秒
		ttl = 300
	}
	ticker := time.NewTicker(time.Duration(ttl) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := st.CleanOldNonces(ctx, time.Now().Unix()-int64(ttl*2)); err != nil {
				logger.Warn("清理过期 nonce 失败", "err", err)
			}
		}
	}
}
