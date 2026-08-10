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
	"syscall"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/api"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/internal/version"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

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

	// 启动时升级 acme.sh
	if cfg.Acme.AutoUpgrade {
		runner := &acme.Runner{AcmeShPath: cfg.Acme.AcmeShPath, Home: cfg.Acme.Home}
		if err := runner.AutoUpgrade(context.Background()); err != nil {
			logger.Warn("acme.sh 自动升级失败（继续启动）", "err", err)
		}
	}
	// 设置默认 CA
	runner := &acme.Runner{AcmeShPath: cfg.Acme.AcmeShPath, Home: cfg.Acme.Home}
	if err := runner.SetDefaultCA(context.Background(), cfg.Acme.DefaultCA); err != nil {
		logger.Warn("设置默认 CA 失败（继续启动）", "err", err)
	}

	// 启动 nonce 清理 goroutine
	go startNonceCleaner(st, cfg, logger)

	srv := &api.Server{Cfg: cfg, Store: st, Service: service.New(cfg, st), Logger: logger}
	httpSrv := &http.Server{
		Addr:    cfg.Server.Listen,
		Handler: srv.Handler(),
	}

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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
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
