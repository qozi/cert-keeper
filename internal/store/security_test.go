package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private", "certkeeper.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, path
}

func putTestCert(t *testing.T, st *Store, domain string) {
	t.Helper()
	if err := st.UpsertCert(context.Background(), &Cert{Domain: domain, ChallengeMode: "dns", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
}

func TestV2TokenEncryptionAndAAD(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	first := &Token{ID: "token-one", Secret: "first-secret", Enabled: true}
	second := &Token{ID: "token-two", Secret: "second-secret", Enabled: true}
	if err := st.CreateToken(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateToken(ctx, second); err != nil {
		t.Fatal(err)
	}

	var legacy, ciphertext sql.NullString
	var version int
	if err := st.DB.QueryRowContext(ctx, `SELECT secret, secret_ciphertext, secret_version FROM tokens WHERE id=?`, first.ID).Scan(&legacy, &ciphertext, &version); err != nil {
		t.Fatal(err)
	}
	if legacy.Valid || !ciphertext.Valid || version != tokenSecretVersion {
		t.Fatalf("v2 token 写入不符合预期: legacy=%v ciphertext=%v version=%d", legacy.Valid, ciphertext.Valid, version)
	}

	listed, err := st.ListTokens(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].Secret != "" || listed[1].Secret != "" {
		t.Fatalf("列表泄露 token secret: %+v", listed)
	}
	defaultToken, err := st.GetToken(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(defaultToken)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || string(data) == `{"id":"token-one","secret":"first-secret"}` || containsSecret(data, "first-secret") {
		t.Fatalf("常规 Token JSON 泄露 secret: %s", data)
	}

	got, err := st.GetTokenWithSecret(ctx, first.ID)
	if err != nil || got == nil || got.Secret != "first-secret" {
		t.Fatalf("GetTokenWithSecret 返回异常: token=%+v err=%v", got, err)
	}
	if err := st.DB.QueryRowContext(ctx, `SELECT secret_ciphertext FROM tokens WHERE id=?`, first.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE tokens SET secret_ciphertext=? WHERE id=?`, ciphertext, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetTokenWithSecret(ctx, second.ID); err == nil {
		t.Fatal("复制到不同 token ID 的密文应因 AAD 校验失败")
	}
}

func containsSecret(data []byte, secret string) bool {
	return string(data) != "" && len(secret) > 0 && string(data) != secret && bytes.Contains(data, []byte(secret))
}

func TestLegacyRecordsRemainReadableAfterV2Migration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	initSQL, err := migrationsFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(initSQL)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations(name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO schema_migrations(name, applied_at) VALUES('001_init.sql', 1)`); err != nil {
		t.Fatal(err)
	}
	legacyDNS, err := encryptSecret("legacy-dns-secret", "legacy-key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tokens(id, secret, enabled, is_admin, created_at) VALUES(?, ?, 1, 0, 1)`,
		"legacy-token", "legacy-token-secret"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO clients(token_id, hostname, registered_at, last_seen_at) VALUES(?, ?, 1, 1)`, "legacy-token", "legacy-host"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO dns_secrets(provider, env_key, env_value, created_at) VALUES(?, ?, ?, 1)`,
		"dns_cf", "CF_Token", legacyDNS); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.GetTokenWithSecret(ctx, "legacy-token")
	if err != nil || got == nil || got.Secret != "legacy-token-secret" {
		t.Fatalf("旧 token 兼容读取失败: token=%+v err=%v", got, err)
	}
	values, err := st.ListSecretsByProvider(ctx, "dns_cf", "legacy-key")
	if err != nil || values["CF_Token"] != "legacy-dns-secret" {
		t.Fatalf("旧 DNS secret 兼容读取失败: values=%v err=%v", values, err)
	}
	clients, err := st.ListClients(ctx)
	if err != nil || len(clients) != 1 || clients[0].TokenID != "legacy-token" {
		t.Fatalf("旧 clients 迁移失败: clients=%+v err=%v", clients, err)
	}
	if err := st.RotateTokenSecret(ctx, "legacy-token", "rotated-secret"); err != nil {
		t.Fatal(err)
	}
	var oldSecret sql.NullString
	if err := st.DB.QueryRowContext(ctx, `SELECT secret FROM tokens WHERE id='legacy-token'`).Scan(&oldSecret); err != nil {
		t.Fatal(err)
	}
	if oldSecret.Valid {
		t.Fatal("轮换后不应保留旧 token 明文")
	}
}

func TestDNSProfilesAreIsolatedAndBoundToAAD(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertDNSProfileSecret(ctx, "dns_cf", "account-a", "account-a@example.test", "CF_Token", "secret-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDNSProfileSecret(ctx, "dns_cf", "account-b", "account-b@example.test", "CF_Token", "secret-b"); err != nil {
		t.Fatal(err)
	}
	profiles, err := st.ListDNSProfiles(ctx, "dns_cf")
	if err != nil || len(profiles) != 2 || profiles[0].Account == profiles[1].Account {
		t.Fatalf("DNS profile 账号隔离失败: profiles=%+v err=%v", profiles, err)
	}
	values, err := st.ListDNSProfileSecretsWithValues(ctx, "dns_cf", "account-a")
	if err != nil || values["CF_Token"] != "secret-a" {
		t.Fatalf("profile A 读取异常: values=%v err=%v", values, err)
	}
	metadata, err := st.ListDNSProfileSecrets(ctx, "dns_cf", "account-a")
	if err != nil || len(metadata) != 1 {
		t.Fatalf("profile 元数据读取异常: metadata=%+v err=%v", metadata, err)
	}
	legacyView := DNSSecret{Provider: "dns_cf", EnvKey: "CF_Token", EnvValue: "secret-a"}
	encoded, err := json.Marshal(legacyView)
	if err != nil || containsSecret(encoded, "secret-a") {
		t.Fatalf("DNSSecret JSON 泄露明文: %s err=%v", encoded, err)
	}
	parameter, err := st.ListSecretParameters(ctx, "dns_cf", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if len(parameter) != 0 {
		t.Fatalf("非默认 profile 不应混入旧兼容接口: %+v", parameter)
	}

	var ciphertext string
	if err := st.DB.QueryRowContext(ctx, `
		SELECT dps.secret_ciphertext FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
		WHERE dp.provider='dns_cf' AND dp.profile='account-a' AND dps.env_key='CF_Token'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.ExecContext(ctx, `
		UPDATE dns_profile_secrets SET secret_ciphertext=? WHERE profile_id=(SELECT id FROM dns_profiles WHERE provider='dns_cf' AND profile='account-b') AND env_key='CF_Token'`, ciphertext); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListDNSProfileSecretsWithValues(ctx, "dns_cf", "account-b"); err == nil {
		t.Fatal("复制到不同 profile 的密文应因 AAD 校验失败")
	}
}

func TestCertificateGrantsDenyByDefault(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "example.com")
	if err := st.CreateToken(ctx, &Token{ID: "limited", Secret: "limited-secret", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	allowed, err := st.HasCertificatePermission(ctx, "limited", "example.com", "apply")
	if err != nil || allowed {
		t.Fatalf("未授权 token 必须默认拒绝: allowed=%v err=%v", allowed, err)
	}
	if err := st.Grant(ctx, "limited", "example.com", "apply"); err != nil {
		t.Fatal(err)
	}
	allowed, err = st.HasCertificatePermission(ctx, "limited", "example.com", "apply")
	if err != nil || !allowed {
		t.Fatalf("授予权限失败: allowed=%v err=%v", allowed, err)
	}
	grants, err := st.ListGrants(ctx, "limited")
	if err != nil || len(grants) != 1 || grants[0].Permission != "apply" {
		t.Fatalf("授权列表异常: grants=%+v err=%v", grants, err)
	}
	if err := st.Revoke(ctx, "limited", "example.com", "apply"); err != nil {
		t.Fatal(err)
	}
	allowed, err = st.HasCertificatePermission(ctx, "limited", "example.com", "apply")
	if err != nil || allowed {
		t.Fatalf("撤销授权失败: allowed=%v err=%v", allowed, err)
	}
	for _, domain := range []string{"Example.com", "example.com.", "example.com/path", "127.0.0.1", "*.example.com"} {
		if domain == "*.example.com" {
			if err := st.Grant(ctx, "limited", domain, "status"); err == nil {
				t.Fatalf("通配符域名没有对应证书，不应通过外键写入: %q", domain)
			}
			continue
		}
		if err := st.Grant(ctx, "limited", domain, "apply"); err == nil {
			t.Fatalf("非法域名应被拒绝: %q", domain)
		}
	}
}

func TestJobIdempotencyAndWorkflowCRUD(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "example.com")
	job, err := st.CreateCertificateJob(ctx, &CertificateJob{Domain: "example.com", Operation: "issue", IdempotencyKey: "request-1"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.CreateJob(ctx, &CertificateJob{Domain: "example.com", Operation: "issue", IdempotencyKey: "request-1"})
	if err != nil || again.ID != job.ID {
		t.Fatalf("活动任务幂等失败: first=%+v again=%+v err=%v", job, again, err)
	}
	if err := st.UpdateJobStatus(ctx, job.ID, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	next, err := st.CreateCertificateJob(ctx, &CertificateJob{Domain: "example.com", Operation: "issue", IdempotencyKey: "request-1"})
	if err != nil || next.ID != job.ID || next.Status != "succeeded" {
		t.Fatalf("终态任务必须保持幂等: next=%+v err=%v", next, err)
	}

	generation, err := st.CreateCertificateGeneration(ctx, &CertificateGeneration{JobID: next.ID, Domain: "example.com"})
	if err != nil || generation.Generation != 1 {
		t.Fatalf("创建证书代次失败: generation=%+v err=%v", generation, err)
	}
	if err := st.UpdateCertificateGenerationStatus(ctx, generation.ID, "issued", "cert-ref", "private-key-ref", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	report, err := st.CreateDeploymentReport(ctx, &DeploymentReport{GenerationID: generation.ID, Target: "edge-a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateDeploymentReportStatus(ctx, report.ID, "succeeded", "deployed"); err != nil {
		t.Fatal(err)
	}
	if err := st.AddAuditEvent(ctx, &AuditEvent{Action: "issue", Outcome: "succeeded", Domain: JSONNullString{String: "example.com", Valid: true}}); err != nil {
		t.Fatal(err)
	}
	reports, err := st.ListDeploymentReports(ctx, generation.ID)
	if err != nil || len(reports) != 1 || reports[0].Status != "succeeded" {
		t.Fatalf("部署报告读取失败: reports=%+v err=%v", reports, err)
	}
	events, err := st.ListAuditEvents(ctx, AuditFilter{Domain: "example.com"})
	if err != nil || len(events) != 1 || events[0].Action != "issue" {
		t.Fatalf("审计事件读取失败: events=%+v err=%v", events, err)
	}
	if got, err := st.GetDeploymentReport(ctx, report.ID); err != nil || got == nil || got.Status != "succeeded" {
		t.Fatalf("部署报告单条读取失败: report=%+v err=%v", got, err)
	}
	if got, err := st.GetAuditEvent(ctx, events[0].ID); err != nil || got == nil || got.Outcome != "succeeded" {
		t.Fatalf("审计事件单条读取失败: event=%+v err=%v", got, err)
	}
	if err := st.DeleteDeploymentReport(ctx, report.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAuditEvent(ctx, events[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteCertificateGeneration(ctx, generation.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteJob(ctx, next.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRestrictsDatabasePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不支持 POSIX 权限位")
	}
	st, path := newTestStore(t)
	if _, err := st.DB.Exec(`CREATE TABLE IF NOT EXISTS permission_probe(value TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(path), 0o700},
		{path, 0o600},
		{path + ".kek", 0o600},
	} {
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != item.mode {
			t.Fatalf("%s 权限为 %o，需要 %o", item.path, info.Mode().Perm(), item.mode)
		}
	}
	for _, path := range []string{path + "-wal", path + "-shm"} {
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s 权限为 %o，需要 600", path, info.Mode().Perm())
		}
	}
}
