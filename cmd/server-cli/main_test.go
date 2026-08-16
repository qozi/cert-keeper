package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/siidoo/certkeeper/internal/store"
)

// writeTestConfig 在临时目录生成测试配置，返回配置文件路径和数据库路径。
func writeTestConfig(t *testing.T) (configPath, dbPath string) {
	t.Helper()
	root := t.TempDir()
	configPath = filepath.Join(root, "config.yaml")
	dbPath = filepath.Join(root, "db", "certkeeper.db")
	config := []byte(`
storage:
  sqlite_path: "` + dbPath + `"
  encryption_key: "test-encryption-key"
acme:
  home: "` + filepath.Join(root, "acme") + `"
  certs_dir: "` + filepath.Join(root, "certs") + `"
  auto_upgrade: false
log:
  file: ""
`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, dbPath
}

// runCLI 执行 CLI 并返回标准输出内容。
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, &out, &out, bytes.NewReader(nil))
	return out.String(), err
}

// createTestToken 通过 CLI 创建一个测试 Token 并返回其 ID。
func createTestToken(t *testing.T, configPath string) string {
	t.Helper()
	out, err := runCLI(t, "--config", configPath, "--output", "json", "token", "create", "--auto-gen")
	if err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	if err := json.Unmarshal([]byte(out), &token); err != nil {
		t.Fatal(err)
	}
	id, _ := token["id"].(string)
	if id == "" {
		t.Fatalf("token 创建失败: %s", out)
	}
	return id
}

// createTestCertConfig 通过 CLI 写入指定域名的证书配置，满足外键约束。
func createTestCertConfig(t *testing.T, configPath, domain string) {
	t.Helper()
	if _, err := runCLI(t, "--config", configPath, "cert-config", "set", "-d", domain, "--mode", "dns_api"); err != nil {
		t.Fatal(err)
	}
}

func TestRunTokenCreateJSON(t *testing.T) {
	configPath, _ := writeTestConfig(t)

	var out bytes.Buffer
	if err := run([]string{"--config", configPath, "--output", "json", "token", "create", "--auto-gen"}, &out, &out, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	if err := json.Unmarshal(out.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token["id"] == "" || token["secret"] == "" {
		t.Fatalf("token credentials missing: %s", out.String())
	}
}

// TestGrantLifecycle 覆盖 grant add/list/remove 的完整流程。
func TestGrantLifecycle(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	tokenID := createTestToken(t, configPath)
	createTestCertConfig(t, configPath, "example.com")

	// 授予两项权限。
	for _, permission := range []string{"apply", "read_cert"} {
		out, err := runCLI(t, "--config", configPath, "--output", "json",
			"grant", "add", "--token", tokenID, "--domain", "example.com", "--permission", permission)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if result["ok"] != true {
			t.Fatalf("grant add 结果不符合预期: %s", out)
		}
	}

	// 列出授权，应包含两项权限。
	grants := listGrants(t, configPath, tokenID)
	if len(grants) != 2 {
		t.Fatalf("grant list 数量不符合预期: %v", grants)
	}
	if grants[0]["permission"] != "apply" || grants[1]["permission"] != "read_cert" {
		t.Fatalf("grant list 内容不符合预期: %v", grants)
	}

	// 撤销其中一项权限。
	if _, err := runCLI(t, "--config", configPath,
		"grant", "remove", "--token", tokenID, "--domain", "example.com", "--permission", "apply"); err != nil {
		t.Fatal(err)
	}
	grants = listGrants(t, configPath, tokenID)
	if len(grants) != 1 || grants[0]["permission"] != "read_cert" {
		t.Fatalf("grant remove 后内容不符合预期: %v", grants)
	}
}

// listGrants 通过 CLI 列出指定 Token 的授权。
func listGrants(t *testing.T, configPath, tokenID string) []map[string]any {
	t.Helper()
	out, err := runCLI(t, "--config", configPath, "--output", "json", "grant", "list", "--token", tokenID)
	if err != nil {
		t.Fatal(err)
	}
	var grants []map[string]any
	if err := json.Unmarshal([]byte(out), &grants); err != nil {
		t.Fatal(err)
	}
	return grants
}

// TestGrantInvalidPermission 校验非法权限值时报错并列出合法值。
func TestGrantInvalidPermission(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	tokenID := createTestToken(t, configPath)
	createTestCertConfig(t, configPath, "example.com")

	_, err := runCLI(t, "--config", configPath,
		"grant", "add", "--token", tokenID, "--domain", "example.com", "--permission", "admin")
	if err == nil {
		t.Fatal("非法权限应当报错")
	}
	for _, valid := range certificatePermissions {
		if !strings.Contains(err.Error(), valid) {
			t.Fatalf("错误信息应列出合法权限 %s: %v", valid, err)
		}
	}
}

// TestGrantMissingArgs 校验参数缺失时给出中文用法提示。
func TestGrantMissingArgs(t *testing.T) {
	configPath, _ := writeTestConfig(t)

	if _, err := runCLI(t, "--config", configPath, "grant", "add"); err == nil ||
		!strings.Contains(err.Error(), "grant add 需要 --token ID、--domain DOMAIN 和 --permission PERMISSION") {
		t.Fatalf("grant add 缺参提示不符合预期: %v", err)
	}
	if _, err := runCLI(t, "--config", configPath, "grant", "list"); err == nil ||
		!strings.Contains(err.Error(), "grant list 需要 --token ID") {
		t.Fatalf("grant list 缺参提示不符合预期: %v", err)
	}
}

// TestJobList 校验 job list 的域名与状态过滤。
func TestJobList(t *testing.T) {
	configPath, dbPath := writeTestConfig(t)
	createTestCertConfig(t, configPath, "example.com")
	createTestCertConfig(t, configPath, "other.com")

	// 直接向存储层写入两条任务数据。
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := st.CreateCertificateJob(ctx, &store.CertificateJob{
		Domain: "example.com", Operation: "apply", IdempotencyKey: "key-1", Status: "queued",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateCertificateJob(ctx, &store.CertificateJob{
		Domain: "other.com", Operation: "renew", IdempotencyKey: "key-2", Status: "succeeded",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// 不带过滤条件时应返回全部任务。
	out, err := runCLI(t, "--config", configPath, "--output", "json", "job", "list")
	if err != nil {
		t.Fatal(err)
	}
	var jobs []map[string]any
	if err := json.Unmarshal([]byte(out), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("job list 数量不符合预期: %s", out)
	}

	// 按域名过滤。
	out, err = runCLI(t, "--config", configPath, "--output", "json", "job", "list", "--domain", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	jobs = nil
	if err := json.Unmarshal([]byte(out), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0]["domain"] != "example.com" {
		t.Fatalf("job list 域名过滤结果不符合预期: %s", out)
	}

	// 按状态过滤。
	out, err = runCLI(t, "--config", configPath, "--output", "json", "job", "list", "--status", "succeeded")
	if err != nil {
		t.Fatal(err)
	}
	jobs = nil
	if err := json.Unmarshal([]byte(out), &jobs); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0]["status"] != "succeeded" {
		t.Fatalf("job list 状态过滤结果不符合预期: %s", out)
	}
}

// TestSensitiveArguments 校验 Secret 和私钥的默认保护策略。
func TestSensitiveArguments(t *testing.T) {
	configPath, _ := writeTestConfig(t)
	if _, err := runCLI(t, "--config", configPath, "secret", "set", "--provider", "dns_cf", "--profile", "prod", "--env-key", "CF_Key", "--value", "secret"); err == nil || (!strings.Contains(err.Error(), "禁止使用 --value") && !strings.Contains(err.Error(), "not defined")) {
		t.Fatalf("secret set 应拒绝 --value: %v", err)
	}
	if _, err := runCLI(t, "--config", configPath, "--show-value", "secret", "list", "--provider", "dns_cf", "--profile", "prod"); err == nil || !strings.Contains(err.Error(), "confirm-sensitive") {
		t.Fatalf("show-value 应要求确认: %v", err)
	}
}

// TestHelpAndVersionDoNotOpenDatabase 确保 help/version 不依赖数据库或迁移。
func TestHelpAndVersionDoNotOpenDatabase(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-config.yaml")
	var out bytes.Buffer
	if err := run([]string{"--config", missing, "--version"}, &out, &out, bytes.NewReader(nil)); err != nil {
		t.Fatalf("version 不应读取数据库或配置: %v", err)
	}
	out.Reset()
	if err := run([]string{"--config", missing, "--help"}, &out, &out, bytes.NewReader(nil)); err != nil {
		t.Fatalf("help 不应读取数据库或配置: %v", err)
	}
}
