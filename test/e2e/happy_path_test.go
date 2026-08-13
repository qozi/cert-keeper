// 本文件覆盖 v2 全链路 happy path：
// 管理员配置 → 授权 → 客户端 reconcile → 原子部署 → 回报 → 状态/任务可查 → 幂等重放。
package e2e

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/siidoo/certkeeper/internal/client"
	"github.com/siidoo/certkeeper/pkg/certproto"
)

// TestE2EHappyPath 验证 v2 完整链路：管理员预置 dns_api 证书配置并创建 token、
// 普通 token 获得授权后由真实客户端完成 reconcile 与原子部署，服务端记录部署回报，
// 状态与任务均可查询，且相同幂等键重放不会重复签发。
func TestE2EHappyPath(t *testing.T) {
	env := newE2EEnv(t)
	domain := "happy.example.test"
	san := "www.happy.example.test"

	// 管理员 token（仅用于配置预置语义；授权检查中 admin 不绕过 grant）。
	_ = env.createToken(t, "admin-happy", true)
	// 预置 dns_api 证书配置（直接 Store 调用，不走 HTTP admin API）。
	env.presetDNSAPICert(t, domain, san)

	// 普通客户端 token + 域名授权。
	const tokenID = "client-happy"
	secret := env.createToken(t, tokenID, false)
	env.grant(t, tokenID, domain, "apply", "status", "read_cert", "read_private_key")

	// 真实客户端执行 ApplyV2：reconcile → manifest → 下载 → 原子部署 → 回报。
	cli := env.newClient(tokenID, secret)
	outDir := t.TempDir()
	if err := cli.ApplyV2(t.Context(), client.ApplyV2Opts{
		Domain:         domain,
		IdempotencyKey: "happy-key-1",
		OutDir:         outDir,
	}); err != nil {
		t.Fatalf("ApplyV2 失败: %v", err)
	}

	// 本地落盘断言：current 指针与 releases/<generation>/ 完整产物。
	generation := readLocalCurrent(t, outDir)
	if generation == "" {
		t.Fatal("客户端 current 为空")
	}
	releaseDir := filepath.Join(outDir, "releases", generation)
	for _, name := range []string{"cert.pem", "key.pem", "fullchain.pem", "ca.pem", "time.log"} {
		if _, err := os.Stat(filepath.Join(releaseDir, name)); err != nil {
			t.Fatalf("release 缺少文件 %s: %v", name, err)
		}
	}
	// 私钥权限必须为 0600。
	keyInfo, err := os.Stat(filepath.Join(releaseDir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("key.pem 权限 = %o，期望 0600", keyInfo.Mode().Perm())
	}
	// 部署的证书必须覆盖主域名与预置 SAN。
	certData, err := os.ReadFile(filepath.Join(releaseDir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		t.Fatal("cert.pem 不是合法 PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{domain, san} {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Fatalf("叶子证书未覆盖 %q: %v", name, err)
		}
	}
	// 假签发器只被调用一次。
	if got := env.issuer.calls.Load(); got != 1 {
		t.Fatalf("签发次数 = %d，期望 1", got)
	}

	// 服务端断言：generation 记录为 issued，且存在 succeeded 部署回报。
	generations, err := env.store.ListCertificateGenerations(t.Context(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 1 {
		t.Fatalf("服务端 generation 记录数 = %d，期望 1", len(generations))
	}
	genRecord := generations[0]
	if genRecord.Status != "issued" {
		t.Fatalf("generation 状态 = %q，期望 issued", genRecord.Status)
	}
	if genRecord.CertificateRef.String != generation {
		t.Fatalf("服务端 certificate_ref = %q，期望客户端 generation %q", genRecord.CertificateRef.String, generation)
	}
	reports, err := env.store.ListDeploymentReports(t.Context(), genRecord.ID)
	if err != nil {
		t.Fatal(err)
	}
	succeeded := false
	for _, report := range reports {
		if report.Status == "succeeded" {
			succeeded = true
		}
	}
	if !succeeded {
		t.Fatalf("deployment_reports 中没有 succeeded 记录: %+v", reports)
	}

	// 任务可查：HTTP GET /api/v2/jobs/{job_id}（需 status 授权）。
	jobPath, err := certproto.JobURLPath(genRecord.JobID)
	if err != nil {
		t.Fatal(err)
	}
	code, body := env.signedDo(t, tokenID, secret, http.MethodGet, jobPath, nil)
	if code != http.StatusOK {
		t.Fatalf("查询任务状态码 = %d，期望 200: %s", code, body)
	}
	var job certproto.JobStatus
	if err := json.Unmarshal(body, &job); err != nil {
		t.Fatal(err)
	}
	if job.State != certproto.JobStateSucceeded {
		t.Fatalf("任务状态 = %q，期望 succeeded", job.State)
	}

	// 状态可查：StatusV2 显示证书 valid。
	statusPath, err := certproto.CertificateStatusURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	code, body = env.signedDo(t, tokenID, secret, http.MethodGet, statusPath, nil)
	if code != http.StatusOK {
		t.Fatalf("查询证书状态码 = %d，期望 200: %s", code, body)
	}
	var status certproto.CertificateStatus
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	if !status.Exists || status.State != certproto.CertificateStateValid {
		t.Fatalf("证书状态 exists=%t state=%q，期望 exists=true state=valid", status.Exists, status.State)
	}
	if string(status.Generation) != generation {
		t.Fatalf("状态 generation = %q，期望 %q", status.Generation, generation)
	}

	// 幂等重放：相同 idempotency_key 再次 reconcile，
	// 返回同一 job 或 changed=false（不重复签发）。
	reconcilePath, err := certproto.ReconcileURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	code, body = env.signedDo(t, tokenID, secret, http.MethodPost, reconcilePath,
		[]byte(`{"idempotency_key":"happy-key-1","operation":"client","reason":"幂等重放"}`))
	if code != http.StatusOK {
		t.Fatalf("幂等重放状态码 = %d，期望 200: %s", code, body)
	}
	var replay certproto.ReconcileResponse
	if err := json.Unmarshal(body, &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Success {
		t.Fatalf("幂等重放未成功: %+v", replay)
	}
	if replay.Changed && replay.Job.ID != genRecord.JobID {
		t.Fatalf("幂等重放触发了新签发且未复用原任务: changed=%t job=%q", replay.Changed, replay.Job.ID)
	}
	if got := env.issuer.calls.Load(); got != 1 {
		t.Fatalf("幂等重放后签发次数 = %d，期望仍为 1", got)
	}
}
