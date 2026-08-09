// Package config 提供 CertKeeper 的配置管理功能。
// 包含配置结构定义、加载、验证及环境变量覆盖。
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 是 CertKeeper 的主配置结构，包含服务器、认证、存储、ACME 和日志配置。
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Auth    AuthConfig    `yaml:"auth"`
	Storage StorageConfig `yaml:"storage"`
	Acme    AcmeConfig    `yaml:"acme"`
	Log     LogConfig     `yaml:"log"`
}

// ServerConfig 定义 HTTP 服务器的配置项。
type ServerConfig struct {
	Listen    string `yaml:"listen"`
	TLS       bool   `yaml:"tls"`
	CertFile  string `yaml:"cert_file"`
	KeyFile   string `yaml:"key_file"`
	BaseURL   string `yaml:"base_url"`
}

// AuthConfig 定义认证相关的配置项。
type AuthConfig struct {
	TimestampWindowSec int    `yaml:"timestamp_window_sec"`
	NonceTTLSec        int    `yaml:"nonce_ttl_sec"`
	AdminTokenID       string `yaml:"admin_token_id"`
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
			Listen:  ":8443",
			TLS:     false,
			BaseURL: "http://localhost:8443",
		},
		Auth: AuthConfig{
			TimestampWindowSec: 300,
			NonceTTLSec:       300,
			AdminTokenID:      "admin",
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
	}
}

// Load 从指定路径加载配置文件，若路径为空则使用默认配置。
// 支持环境变量覆盖，加载后自动执行验证。
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		applyEnv(cfg)
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
	if c.Server.TLS {
		if c.Server.CertFile == "" || c.Server.KeyFile == "" {
			return fmt.Errorf("启用 TLS 时 cert_file 和 key_file 必填")
		}
	}
	return nil
}
