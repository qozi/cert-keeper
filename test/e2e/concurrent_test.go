// 本文件覆盖同域名并发 reconcile 场景：
// 服务端每域名互斥锁 + 幂等机制保证只发生一次真实签发。
package e2e

import (
	"fmt"
	"sync"
	"testing"

	"github.com/siidoo/certkeeper/internal/client"
	"github.com/siidoo/certkeeper/internal/store"
)

// TestE2EConcurrentReconcile 验证 20 个并发 reconcile（同域名、不同幂等键）：
// 全部成功返回，但假签发器只被调用一次，且所有客户端部署到同一个 generation。
func TestE2EConcurrentReconcile(t *testing.T) {
	env := newE2EEnv(t)
	domain := "conc.example.test"
	env.presetDNSAPICert(t, domain)

	const tokenID = "client-conc"
	secret := env.createToken(t, tokenID, false)
	env.grant(t, tokenID, domain, "apply", "status", "read_cert", "read_private_key")
	cli := env.newClient(tokenID, secret)

	const concurrency = 20
	outDirs := make([]string, concurrency)
	for i := range outDirs {
		outDirs[i] = t.TempDir()
	}

	// 并发执行 20 次 ApplyV2，各自独立的幂等键与部署目录。
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			opts := client.ApplyV2Opts{
				Domain:         domain,
				IdempotencyKey: fmt.Sprintf("conc-key-%d", i),
				OutDir:         outDirs[i],
			}
			for attempt := 0; attempt < 3; attempt++ {
				errs[i] = cli.ApplyV2(t.Context(), opts)
				if errs[i] == nil {
					break
				}
			}
		}(i)
	}
	wg.Wait()

	// 全部请求成功（HTTP 200 且部署完成）。
	for i, err := range errs {
		if err != nil {
			t.Fatalf("第 %d 个并发 ApplyV2 失败: %v", i, err)
		}
	}
	// 仅一次实际签发：首个请求签发并发布，其余在锁内看到证书未到期而跳过。
	if got := env.issuer.calls.Load(); got != 1 {
		t.Fatalf("并发 reconcile 签发次数 = %d，期望 1", got)
	}
	// 所有客户端部署到同一个 generation。
	first := readLocalCurrent(t, outDirs[0])
	if first == "" {
		t.Fatal("首个客户端 current 为空")
	}
	for i := 1; i < concurrency; i++ {
		if got := readLocalCurrent(t, outDirs[i]); got != first {
			t.Fatalf("第 %d 个客户端 generation = %q，期望 %q", i, got, first)
		}
	}
	// 服务端 20 个任务全部成功。
	jobs, err := env.store.ListCertificateJobs(t.Context(), store.JobFilter{Domain: domain, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != concurrency {
		t.Fatalf("任务数 = %d，期望 %d", len(jobs), concurrency)
	}
	for _, job := range jobs {
		if job.Status != "succeeded" {
			t.Fatalf("任务 %s 状态 = %q，期望 succeeded", job.ID, job.Status)
		}
	}
	// 服务端只有一个已签发的 generation 记录。
	generations, err := env.store.ListCertificateGenerations(t.Context(), domain)
	if err != nil {
		t.Fatal(err)
	}
	if len(generations) != 1 || generations[0].Status != "issued" {
		t.Fatalf("generation 记录不符合预期: %+v", generations)
	}
}
