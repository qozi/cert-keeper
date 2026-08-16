// Package config 提供 CertKeeper 的配置管理功能。
// 包含配置结构定义、加载、验证及环境变量覆盖。
package config

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 是 CertKeeper 的主配置结构，包含服务器、认证、存储、ACME 和日志配置。
type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Auth          AuthConfig          `yaml:"auth"`
	Storage       StorageConfig       `yaml:"storage"`
	Acme          AcmeConfig          `yaml:"acme"`
	Log           LogConfig           `yaml:"log"`
	Scheduler     SchedulerConfig     `yaml:"scheduler"`
	Observability ObservabilityConfig `yaml:"observability"`
}

// ServerConfig 定义 HTTP 服务器的配置项。
type ServerConfig struct {
	Listen         string   `yaml:"listen"`
	TLSMode        string   `yaml:"tls_mode"`
	TLS            bool     `yaml:"tls"` // 兼容旧配置；TLSMode 为空时由 TLS 推导
	CertFile       string   `yaml:"cert_file"`
	KeyFile        string   `yaml:"key_file"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	ClientCAFile   string   `yaml:"client_ca_file"`
	ClientMTLS     bool     `yaml:"client_mtls"`
	BaseURL        string   `yaml:"base_url"`
	// 以下超时对应 http.Server 的同名字段，0 表示不限制。
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
}

// SchedulerConfig 定义证书续期调度器的配置项。
type SchedulerConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Jitter   time.Duration `yaml:"jitter"`
}

// ObservabilityConfig 定义可观测性端点（指标与就绪检查）的配置项。
type ObservabilityConfig struct {
	MetricsEnabled bool `yaml:"metrics_enabled"`
	ReadyEnabled   bool `yaml:"ready_enabled"`
}

// AuthConfig 定义认证相关的配置项。
type AuthConfig struct {
	TimestampWindowSec int    `yaml:"timestamp_window_sec"`
	NonceTTLSec        int    `yaml:"nonce_ttl_sec"`
	AdminTokenID       string `yaml:"admin_token_id"`
	LegacyAPIEnabled   bool   `yaml:"legacy_api_enabled"`
}

// StorageConfig 定义数据存储相关的配置项。
type StorageConfig struct {
	SQLitePath    string `yaml:"sqlite_path"`
	EncryptionKey string `yaml:"encryption_key"`
}

// AcmeConfig 定义 ACME 证书签发相关的配置项。
type AcmeConfig struct {
	Home             string        `yaml:"home"`
	CertsDir         string        `yaml:"certs_dir"`
	DefaultCA        string        `yaml:"default_ca"`
	DefaultKeylength string        `yaml:"default_keylength"`
	DefaultRenewDays int           `yaml:"default_renew_days"`
	IssueTimeout     time.Duration `yaml:"issue_timeout"`
	AutoUpgrade      bool          `yaml:"auto_upgrade"`
	AcmeShPath       string        `yaml:"acme_sh_path"`
}

// LogConfig 定义日志相关的配置项。
type LogConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
}

// Default 返回默认配置。
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Listen:            ":8443",
			TLSMode:           "development",
			BaseURL:           "http://localhost:8443",
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
		Auth: AuthConfig{
			TimestampWindowSec: 300,
			NonceTTLSec:        300,
			AdminTokenID:       "admin",
			LegacyAPIEnabled:   false,
		},
		Storage: StorageConfig{
			SQLitePath:    "/data/db/certkeeper.db",
			EncryptionKey: "",
		},
		Acme: AcmeConfig{
			Home:             "/data/acme",
			CertsDir:         "/data/certs",
			DefaultCA:        "letsencrypt",
			DefaultKeylength: "ec-256",
			DefaultRenewDays: 30,
			IssueTimeout:     300 * time.Second,
			AutoUpgrade:      true,
			AcmeShPath:       "/root/.acme.sh/acme.sh",
		},
		Log: LogConfig{
			Level:      "info",
			File:       "/data/logs/certkeeper.log",
			MaxSizeMB:  10,
			MaxBackups: 3,
		},
		Scheduler: SchedulerConfig{
			Enabled:  true,
			Interval: 12 * time.Hour,
			Jitter:   1 * time.Hour,
		},
		Observability: ObservabilityConfig{
			MetricsEnabled: true,
			ReadyEnabled:   true,
		},
	}
}

// Load 从指定路径加载配置文件，若路径为空则使用默认配置。
// 支持环境变量覆盖，加载后自动执行验证。
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		applyEnv(cfg)
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("CK_LISTEN"); v != "" {
		cfg.Server.Listen = v
	}
	if v := os.Getenv("CK_BASE_URL"); v != "" {
		cfg.Server.BaseURL = v
	}
	if v := os.Getenv("CK_SQLITE_PATH"); v != "" {
		cfg.Storage.SQLitePath = v
	}
	if v := os.Getenv("CK_ENCRYPTION_KEY"); v != "" {
		cfg.Storage.EncryptionKey = v
	}
	if v := os.Getenv("CK_ACME_HOME"); v != "" {
		cfg.Acme.Home = v
	}
	if v := os.Getenv("CK_CERTS_DIR"); v != "" {
		cfg.Acme.CertsDir = v
	}
	if v := os.Getenv("CK_LOG_FILE"); v != "" {
		cfg.Log.File = v
	}
	if v := os.Getenv("CK_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("CK_ACME_SH_PATH"); v != "" {
		cfg.Acme.AcmeShPath = v
	}
}

// Validate 验证配置项的有效性。
func (c *Config) Validate() error {
	if c.Server.Listen == "" {
		return fmt.Errorf("server.listen 不能为空")
	}
	if c.Storage.SQLitePath == "" {
		return fmt.Errorf("storage.sqlite_path 不能为空")
	}
	if c.Acme.Home == "" {
		return fmt.Errorf("acme.home 不能为空")
	}
	if c.Acme.CertsDir == "" {
		return fmt.Errorf("acme.certs_dir 不能为空")
	}
	if c.Server.TLSMode == "" {
		if c.Server.TLS {
			c.Server.TLSMode = "direct"
		} else {
			c.Server.TLSMode = "development"
		}
	}
	if c.Server.TLSMode != "direct" && c.Server.TLSMode != "proxy" && c.Server.TLSMode != "development" {
		return fmt.Errorf("server.tls_mode 必须为 direct、proxy 或 development")
	}
	if c.Server.TLSMode == "direct" {
		if c.Server.CertFile == "" || c.Server.KeyFile == "" {
			return fmt.Errorf("direct TLS 模式必须配置 cert_file 和 key_file")
		}
	}
	if c.Server.TLSMode == "proxy" && len(c.Server.TrustedProxies) == 0 {
		host, _, err := net.SplitHostPort(c.Server.Listen)
		if err != nil || !isLoopbackHost(host) {
			return fmt.Errorf("proxy TLS 模式仅允许 loopback 监听，或配置 trusted_proxies")
		}
	}
	for _, proxy := range c.Server.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				return fmt.Errorf("trusted_proxies 包含无效地址: %s", proxy)
			}
		}
	}
	if c.Server.ReadHeaderTimeout < 0 || c.Server.ReadTimeout < 0 || c.Server.WriteTimeout < 0 || c.Server.IdleTimeout < 0 {
		return fmt.Errorf("server 各项超时不能为负数")
	}
	if c.Server.ReadTimeout > 0 && c.Server.ReadHeaderTimeout > c.Server.ReadTimeout {
		return fmt.Errorf("server.read_header_timeout 不能大于 server.read_timeout")
	}
	if c.Scheduler.Interval <= 0 {
		return fmt.Errorf("scheduler.interval 必须大于 0")
	}
	if c.Scheduler.Jitter < 0 {
		return fmt.Errorf("scheduler.jitter 不能为负数")
	}
	if c.Scheduler.Jitter >= c.Scheduler.Interval {
		return fmt.Errorf("scheduler.jitter 必须小于 scheduler.interval")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
