package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClaimIsAtomicUnderCompetition(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "claim.example.com")
	job, err := st.CreateJob(ctx, &CertificateJob{
		Domain: "claim.example.com", Operation: "issue", IdempotencyKey: "claim-one",
	})
	if err != nil {
		t.Fatal(err)
	}

	const workers = 16
	start := make(chan struct{})
	results := make(chan *CertificateJob, workers)
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			claimed, claimErr := st.Claim(ctx, "worker-"+string(rune('a'+index)), time.Minute)
			results <- claimed
			errorsChannel <- claimErr
		}(index)
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsChannel)

	for claimErr := range errorsChannel {
		if claimErr != nil {
			t.Fatalf("并发 Claim 失败: %v", claimErr)
		}
	}
	claimedCount := 0
	for claimed := range results {
		if claimed != nil {
			claimedCount++
			if claimed.ID != job.ID || claimed.Attempts != 1 || claimed.LeaseOwner == "" {
				t.Fatalf("Claim 结果异常: %+v", claimed)
			}
		}
	}
	if claimedCount != 1 {
		t.Fatalf("同一任务被领取 %d 次，预期 1 次", claimedCount)
	}
}

func TestExpiredLeaseTakeoverAndRetryBackoff(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "lease.example.com")
	created, err := st.CreateJob(ctx, &CertificateJob{
		Domain: "lease.example.com", Operation: "renew", IdempotencyKey: "lease-one", MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Claim(ctx, "worker-a", time.Minute)
	if err != nil || first == nil || first.ID != created.ID {
		t.Fatalf("首次 Claim 失败: job=%+v err=%v", first, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE certificate_jobs SET lease_until=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), created.ID); err != nil {
		t.Fatal(err)
	}
	recoverable, err := st.ListRecoverable(ctx, time.Now(), 10)
	if err != nil || len(recoverable) != 1 || recoverable[0].ID != created.ID {
		t.Fatalf("过期租约未进入恢复列表: jobs=%+v err=%v", recoverable, err)
	}
	second, err := st.Claim(ctx, "worker-b", time.Minute)
	if err != nil || second == nil || second.ID != created.ID || second.Attempts != 2 || second.LeaseOwner != "worker-b" {
		t.Fatalf("租约接管失败: job=%+v err=%v", second, err)
	}
	if err := st.RenewLease(ctx, created.ID, "worker-a", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("旧 owner 不应续租: %v", err)
	}
	if err := st.RenewLease(ctx, created.ID, "worker-b", time.Minute); err != nil {
		t.Fatalf("新 owner 续租失败: %v", err)
	}
	if err := st.Retry(ctx, created.ID, "worker-b", "acme_busy", "稍后重试", time.Hour); err != nil {
		t.Fatal(err)
	}
	final, err := st.GetJob(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Status != "failed" || final.LastErrorCode.String != "acme_busy" || !final.FinishedAt.Valid || final.LeaseOwner != "" {
		t.Fatalf("达到尝试上限后未进入失败终态: %+v", final)
	}
}

func TestRetryHonorsBackoff(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "backoff.example.com")
	created, err := st.CreateJob(ctx, &CertificateJob{
		Domain: "backoff.example.com", Operation: "renew", IdempotencyKey: "backoff-one", MaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := st.Claim(ctx, "worker-a", time.Minute)
	if err != nil || claimed == nil {
		t.Fatalf("Claim 失败: %+v %v", claimed, err)
	}
	if err := st.Retry(ctx, created.ID, "worker-a", "temporary", "暂时失败", time.Hour); err != nil {
		t.Fatal(err)
	}
	recoverable, err := st.ListRecoverable(ctx, time.Now(), 10)
	if err != nil || len(recoverable) != 0 {
		t.Fatalf("backoff 期间不应可恢复: %+v %v", recoverable, err)
	}
	if _, err := st.DB.ExecContext(ctx, `UPDATE certificate_jobs SET next_attempt_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), created.ID); err != nil {
		t.Fatal(err)
	}
	claimed, err = st.Claim(ctx, "worker-b", time.Minute)
	if err != nil || claimed == nil || claimed.Attempts != 2 {
		t.Fatalf("backoff 到期后 Claim 失败: %+v %v", claimed, err)
	}
	if err := st.ReleaseLease(ctx, created.ID, "worker-b"); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalIdempotencyLookup(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "idempotent.example.com")
	created, err := st.CreateJob(ctx, &CertificateJob{
		Domain: "idempotent.example.com", Operation: "issue", IdempotencyKey: "terminal-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateJobStatus(ctx, created.ID, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	again, err := st.CreateJob(ctx, &CertificateJob{
		Domain: "idempotent.example.com", Operation: "issue", IdempotencyKey: "terminal-key",
	})
	if err != nil || again.ID != created.ID || again.Status != "succeeded" {
		t.Fatalf("终态幂等创建失败: %+v %v", again, err)
	}
	got, err := st.GetByIdempotency(ctx, "idempotent.example.com", "issue", "terminal-key")
	if err != nil || got == nil || got.ID != created.ID {
		t.Fatalf("GetByIdempotency 失败: %+v %v", got, err)
	}
}

func TestCertificateDNSProfileBinding(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	if err := st.UpsertDNSProfileSecret(ctx, "dns_cf", "primary", "first", "CF_Token", "secret-one"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertDNSProfileSecret(ctx, "dns_cf", "secondary", "second", "CF_Token", "secret-two"); err != nil {
		t.Fatal(err)
	}
	cert := &Cert{
		Domain: "profile.example.com", ChallengeMode: "dns_api",
		DNSProvider: JSONNullString{String: "dns_cf", Valid: true},
		DNSProfile:  JSONNullString{String: "secondary", Valid: true},
	}
	if err := st.UpsertCert(ctx, cert); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetCert(ctx, cert.Domain)
	if err != nil || got == nil || got.DNSProfile.String != "secondary" {
		t.Fatalf("证书 DNS profile 引用未持久化: %+v %v", got, err)
	}
	first, err := st.ListDNSProfileSecretsWithValues(ctx, "dns_cf", "primary")
	if err != nil || first["CF_Token"] != "secret-one" {
		t.Fatalf("primary profile 串值: %v %v", first, err)
	}
	second, err := st.ListDNSProfileSecretsWithValues(ctx, "dns_cf", got.DNSProfile.String)
	if err != nil || second["CF_Token"] != "secret-two" {
		t.Fatalf("secondary profile 串值: %v %v", second, err)
	}
	if err := st.DeleteDNSProfile(ctx, "dns_cf", "secondary"); err == nil {
		t.Fatal("被证书引用的 DNS profile 不应删除")
	}
}

func TestGenerationRevisionAndDeploymentValidation(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "generation.example.com")
	job, err := st.CreateJob(ctx, &CertificateJob{
		Domain: "generation.example.com", Operation: "issue", IdempotencyKey: "generation-one",
	})
	if err != nil {
		t.Fatal(err)
	}
	generation, err := st.CreateCertificateGeneration(ctx, &CertificateGeneration{JobID: job.ID, Domain: job.Domain})
	if err != nil || generation.Revision != 1 {
		t.Fatalf("创建 generation 失败: %+v %v", generation, err)
	}
	if err := st.UpdateCertificateGenerationStatus(ctx, generation.ID, "issued", "gen-one", "gen-one", "", nil, nil); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	fingerprint := strings.Repeat("b", 64)
	if err := st.UpdateCertificateGenerationArtifact(ctx, generation.ID, GenerationArtifact{
		Revision: 4, ManifestDigest: digest, Serial: "01ab", Fingerprint: fingerprint, Current: true,
	}); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetCurrentCertificateGeneration(ctx, job.Domain)
	if err != nil || current == nil || current.Revision != 4 || !current.Current || current.ManifestDigest.String != digest {
		t.Fatalf("current generation 异常: %+v %v", current, err)
	}
	if _, err := st.CreateDeploymentReport(ctx, &DeploymentReport{
		GenerationID: generation.ID, Generation: "gen-one", Revision: 3,
		ManifestDigest: JSONNullString{String: digest, Valid: true}, Target: "edge-a",
	}); err == nil {
		t.Fatal("revision 不一致的部署报告应被拒绝")
	}
	report, err := st.CreateDeploymentReport(ctx, &DeploymentReport{
		GenerationID: generation.ID, Generation: "gen-one", Revision: 4,
		ManifestDigest: JSONNullString{String: digest, Valid: true}, Target: "edge-a",
	})
	if err != nil || report.Revision != 4 || report.Generation != "gen-one" {
		t.Fatalf("部署报告写入失败: %+v %v", report, err)
	}
}

func TestInjectedRootKeyMigratesLegacyKEK(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "key-recovery", "certkeeper.db")
	t.Setenv("CK_ENCRYPTION_KEY", "")
	legacyStore, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacyStore.CreateToken(ctx, &Token{ID: "recover-token", Secret: "token-secret", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := legacyStore.UpsertDNSProfileSecret(ctx, "dns_cf", "recover", "", "CF_Token", "dns-secret"); err != nil {
		t.Fatal(err)
	}
	if err := legacyStore.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".kek"); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CK_ENCRYPTION_KEY", "new-injected-root-key")
	migrated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info := migrated.KeyInfo()
	if info.Source != keySourceInjected || info.Version != encryptionKeyVersion {
		t.Fatalf("根密钥来源异常: %+v", info)
	}
	token, err := migrated.GetTokenWithSecret(ctx, "recover-token")
	if err != nil || token.Secret != "token-secret" {
		t.Fatalf("token 密钥迁移失败: %+v %v", token, err)
	}
	values, err := migrated.ListDNSProfileSecretsWithValues(ctx, "dns_cf", "recover")
	if err != nil || values["CF_Token"] != "dns-secret" {
		t.Fatalf("DNS 密钥迁移失败: %v %v", values, err)
	}
	ready, err := migrated.EncryptionReady(ctx)
	if err != nil || !ready {
		t.Fatalf("密文 readiness 异常: %t %v", ready, err)
	}
	if err := migrated.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path + ".kek"); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	token, err = recovered.GetTokenWithSecret(ctx, "recover-token")
	if err != nil || token.Secret != "token-secret" {
		t.Fatalf("移除兼容 KEK 后恢复失败: %+v %v", token, err)
	}
}

func TestConsistentBackupValidationAndRestore(t *testing.T) {
	st, _ := newTestStore(t)
	ctx := context.Background()
	putTestCert(t, st, "backup.example.com")
	certificates := filepath.Join(t.TempDir(), "certificates")
	acmeState := filepath.Join(t.TempDir(), "acme")
	if err := os.MkdirAll(certificates, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(acmeState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certificates, "fullchain.pem"), []byte("certificate-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certificates, "manifest.json"), []byte("certificate-manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(acmeState, "account.conf"), []byte("account-state"), 0o600); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(t.TempDir(), "backup")
	manifest, err := st.CreateBackup(ctx, BackupOptions{
		Destination: backupPath, CertificateRepositoryPath: certificates, ACMEStatePath: acmeState,
	})
	if err != nil || len(manifest.Entries) < 4 {
		t.Fatalf("创建备份失败: %+v %v", manifest, err)
	}
	if _, err := ValidateBackup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	restoreRoot := t.TempDir()
	restoredDB := filepath.Join(restoreRoot, "db", "certkeeper.db")
	restoredCerts := filepath.Join(restoreRoot, "certificates")
	restoredACME := filepath.Join(restoreRoot, "acme")
	if err := RestoreBackup(ctx, RestoreOptions{
		BackupPath: backupPath, DatabasePath: restoredDB,
		CertificateRepositoryPath: restoredCerts, ACMEStatePath: restoredACME,
	}); err != nil {
		t.Fatal(err)
	}
	restoredStore, err := Open(restoredDB)
	if err != nil {
		t.Fatal(err)
	}
	restoredCert, err := restoredStore.GetCert(ctx, "backup.example.com")
	_ = restoredStore.Close()
	if err != nil || restoredCert == nil {
		t.Fatalf("恢复后的 SQLite 快照缺少数据: %+v %v", restoredCert, err)
	}
	data, err := os.ReadFile(filepath.Join(restoredCerts, "manifest.json"))
	if err != nil || string(data) != "certificate-manifest" {
		t.Fatalf("证书仓库恢复失败: %q %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(backupPath, "certificates", "fullchain.pem"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBackup(ctx, backupPath); err == nil {
		t.Fatal("被篡改的备份不应通过校验")
	}
}
