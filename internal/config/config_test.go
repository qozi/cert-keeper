// 本文件验证配置默认值、加载覆盖与 Validate 的合法性检查。
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultValidate 确认默认配置合法，且新增配置段默认值符合预期。
func TestDefaultValidate(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("默认配置应通过验证: %v", err)
	}
	if !cfg.Scheduler.Enabled {
		t.Fatal("scheduler.enabled 默认应为 true")
	}
	if cfg.Scheduler.Interval != 12*time.Hour {
		t.Fatalf("scheduler.interval 默认应为 12h，实际 %v", cfg.Scheduler.Interval)
	}
	if cfg.Scheduler.Jitter != 1*time.Hour {
		t.Fatalf("scheduler.jitter 默认应为 1h，实际 %v", cfg.Scheduler.Jitter)
	}
	wantTimeouts := map[string]time.Duration{
		"read_header_timeout": 10 * time.Second,
		"read_timeout":        30 * time.Second,
		"write_timeout":       120 * time.Second,
		"idle_timeout":        60 * time.Second,
	}
	got := map[string]time.Duration{
		"read_header_timeout": cfg.Server.ReadHeaderTimeout,
		"read_timeout":        cfg.Server.ReadTimeout,
		"write_timeout":       cfg.Server.WriteTimeout,
		"idle_timeout":        cfg.Server.IdleTimeout,
	}
	for name, want := range wantTimeouts {
		if got[name] != want {
			t.Fatalf("server.%s 默认应为 %v，实际 %v", name, want, got[name])
		}
	}
	if !cfg.Observability.MetricsEnabled || !cfg.Observability.ReadyEnabled {
		t.Fatal("observability 的 metrics_enabled/ready_enabled 默认应均为 true")
	}
}

// TestValidateScheduler 确认调度器配置的非法值会被拒绝。
func TestValidateScheduler(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"interval 为零", func(c *Config) { c.Scheduler.Interval = 0 }, "scheduler.interval"},
		{"interval 为负", func(c *Config) { c.Scheduler.Interval = -time.Hour }, "scheduler.interval"},
		{"jitter 为负", func(c *Config) { c.Scheduler.Jitter = -time.Minute }, "scheduler.jitter"},
		{"jitter 不小于 interval", func(c *Config) { c.Scheduler.Jitter = c.Scheduler.Interval }, "scheduler.jitter"},
		{"合法自定义", func(c *Config) {
			c.Scheduler.Interval = 6 * time.Hour
			c.Scheduler.Jitter = 30 * time.Minute
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("期望通过验证，实际报错: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.wantErr, err)
			}
		})
	}
}

// TestValidateServerTimeouts 确认 HTTP 超时配置的非法值会被拒绝。
func TestValidateServerTimeouts(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"read_header_timeout 为负", func(c *Config) { c.Server.ReadHeaderTimeout = -time.Second }, "不能为负数"},
		{"read_timeout 为负", func(c *Config) { c.Server.ReadTimeout = -time.Second }, "不能为负数"},
		{"write_timeout 为负", func(c *Config) { c.Server.WriteTimeout = -time.Second }, "不能为负数"},
		{"idle_timeout 为负", func(c *Config) { c.Server.IdleTimeout = -time.Second }, "不能为负数"},
		{"read_header 超过 read", func(c *Config) {
			c.Server.ReadHeaderTimeout = 60 * time.Second
			c.Server.ReadTimeout = 30 * time.Second
		}, "read_header_timeout"},
		{"零值表示不限制", func(c *Config) {
			c.Server.ReadHeaderTimeout = 0
			c.Server.ReadTimeout = 0
			c.Server.WriteTimeout = 0
			c.Server.IdleTimeout = 0
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("期望通过验证，实际报错: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.wantErr, err)
			}
		})
	}
}

// TestLoadOverrides 确认 yaml 可覆盖新配置段，且未覆盖字段保持默认值。
func TestLoadOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte(`
server:
  listen: ":9443"
  read_header_timeout: 5s
storage:
  sqlite_path: "/tmp/certkeeper-test.db"
acme:
  home: "/tmp/acme-test"
  certs_dir: "/tmp/certs-test"
scheduler:
  enabled: false
  interval: 6h
observability:
  metrics_enabled: false
`)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if cfg.Server.Listen != ":9443" {
		t.Fatalf("listen 应为 :9443，实际 %s", cfg.Server.Listen)
	}
	if cfg.Server.ReadHeaderTimeout != 5*time.Second {
		t.Fatalf("read_header_timeout 应为 5s，实际 %v", cfg.Server.ReadHeaderTimeout)
	}
	// 未在 yaml 中出现的字段保持默认值。
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Fatalf("read_timeout 应保持默认 30s，实际 %v", cfg.Server.ReadTimeout)
	}
	if cfg.Scheduler.Enabled {
		t.Fatal("scheduler.enabled 应被覆盖为 false")
	}
	if cfg.Scheduler.Interval != 6*time.Hour {
		t.Fatalf("scheduler.interval 应为 6h，实际 %v", cfg.Scheduler.Interval)
	}
	if cfg.Scheduler.Jitter != 1*time.Hour {
		t.Fatalf("scheduler.jitter 应保持默认 1h，实际 %v", cfg.Scheduler.Jitter)
	}
	if cfg.Observability.MetricsEnabled {
		t.Fatal("observability.metrics_enabled 应被覆盖为 false")
	}
	if !cfg.Observability.ReadyEnabled {
		t.Fatal("observability.ready_enabled 应保持默认 true")
	}
}
