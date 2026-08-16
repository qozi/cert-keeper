// 本文件覆盖签发失败场景的安全属性：
// 服务端签发失败时保留旧 current generation，客户端旧证书不受影响。
package e2e

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/siidoo/certkeeper/internal/client"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/certproto"
)

// TestE2EFailureKeepsCurrent 验证：首次签发成功后，fake issuer 转为失败，
// admin force reconcile 返回 500，但服务端与客户端的 current 均保持旧 generation，
// 客户端旧证书与私钥仍可正常读取。
func TestE2EFailureKeepsCurrent(t *testing.T) {
	env := newE2EEnv(t)
	domain := "fail.example.test"
	env.presetDNSAPICert(t, domain)

	// 普通 token 完成首次成功部署。
	const tokenID = "client-fail"
	secret := env.createToken(t, tokenID, false)
	env.grant(t, tokenID, domain, "apply", "status", "read_cert", "read_private_key")
	cli := env.newClient(tokenID, secret)
	outDir := t.TempDir()
	if err := cli.ApplyV2(t.Context(), client.ApplyV2Opts{
		Domain:         domain,
		IdempotencyKey: "fail-key-1",
		OutDir:         outDir,
	}); err != nil {
		t.Fatalf("首次 ApplyV2 失败: %v", err)
	}

	// 记录成功后的基线：客户端/服务端 current 与本地证书内容。
	generation := readLocalCurrent(t, outDir)
	if generation == "" {
		t.Fatal("首次部署后 current 为空")
	}
	if got := env.readServerCurrent(t, domain); got != generation {
		t.Fatalf("服务端 current = %q，期望 %q", got, generation)
	}
	releaseDir := filepath.Join(outDir, "releases", generation)
	baseCert, err := os.ReadFile(filepath.Join(releaseDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	baseKey, err := os.ReadFile(filepath.Join(releaseDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}

	// fake issuer 转为失败。
	env.issuer.fail.Store(true)

	// admin token + apply/force/status grant，发起 force reconcile。
	const adminID = "admin-force"
	adminSecret := env.createToken(t, adminID, true)
	env.grant(t, adminID, domain, "apply", "force", "status")

	reconcilePath, err := certproto.ReconcileURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	code, body := env.signedDo(t, adminID, adminSecret, http.MethodPost, reconcilePath,
		[]byte(`{"idempotency_key":"fail-key-2","force":true,"reason":"故障演练"}`))
	if code != http.StatusAccepted {
		t.Fatalf("签发失败的 force reconcile 状态码 = %d，期望 202: %s", code, body)
	}
	var accepted certproto.JobAcceptedResponse
	if err := json.Unmarshal(body, &accepted); err != nil {
		t.Fatal(err)
	}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	job := env.waitJob(t, adminID, adminSecret, accepted.Location)
	if job.State != certproto.JobStateFailed {
		t.Fatalf("签发失败任务状态 = %q，期望 failed", job.State)
	}
	if got := env.issuer.calls.Load(); got != 2 {
		t.Fatalf("签发次数 = %d，期望 2（首次成功 + force 失败）", got)
	}

	// 服务端任务被标记为 failed。
	jobs, err := env.store.ListCertificateJobs(t.Context(), store.JobFilter{Domain: domain, Status: "failed", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("failed 任务数 = %d，期望 1", len(jobs))
	}

	// 服务端 current 仍是旧 generation，状态仍为 valid。
	if got := env.readServerCurrent(t, domain); got != generation {
		t.Fatalf("失败后服务端 current = %q，期望仍为 %q", got, generation)
	}
	statusPath, err := certproto.CertificateStatusURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	code, body = env.signedDo(t, adminID, adminSecret, http.MethodGet, statusPath, nil)
	if code != http.StatusOK {
		t.Fatalf("失败后查询状态码 = %d，期望 200: %s", code, body)
	}
	var status certproto.CertificateStatus
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if string(status.Generation) != generation || status.State != certproto.CertificateStateValid {
		t.Fatalf("失败后服务端状态 generation=%q state=%q，期望 %q/valid",
			status.Generation, status.State, generation)
	}

	// 客户端 current 仍是旧 generation，旧证书与私钥内容不变且可解析。
	if got := readLocalCurrent(t, outDir); got != generation {
		t.Fatalf("失败后客户端 current = %q，期望仍为 %q", got, generation)
	}
	certData, err := os.ReadFile(filepath.Join(releaseDir, "cert.pem"))
	if err != nil {
		t.Fatalf("失败后旧证书不可读: %v", err)
	}
	if !bytes.Equal(certData, baseCert) {
		t.Fatal("失败后旧证书内容被改变")
	}
	keyData, err := os.ReadFile(filepath.Join(releaseDir, "key.pem"))
	if err != nil {
		t.Fatalf("失败后旧私钥不可读: %v", err)
	}
	if !bytes.Equal(keyData, baseKey) {
		t.Fatal("失败后旧私钥内容被改变")
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("旧证书不是合法 PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		t.Fatalf("旧证书未覆盖 %q: %v", domain, err)
	}
	keyInfo, err := os.Stat(filepath.Join(releaseDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key.pem 权限 = %o，期望 0600", keyInfo.Mode().Perm())
	}
}
