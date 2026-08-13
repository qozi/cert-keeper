package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeExecutor struct {
	commands  []CommandSpec
	results   []CommandResult
	executeFn func(context.Context, CommandSpec) CommandResult
}

func (f *fakeExecutor) Execute(ctx context.Context, spec CommandSpec) CommandResult {
	f.commands = append(f.commands, spec)
	if f.executeFn != nil {
		return f.executeFn(ctx, spec)
	}
	result := f.results[0]
	f.results = f.results[1:]
	return result
}

// splitConfigHome 取出命令参数中的 --config-home 值，返回该值和剩余参数。
func splitConfigHome(t *testing.T, args []string) (string, []string) {
	t.Helper()
	for i, arg := range args {
		if arg == "--config-home" && i+1 < len(args) {
			rest := append([]string(nil), args[:i]...)
			rest = append(rest, args[i+2:]...)
			return args[i+1], rest
		}
	}
	t.Fatalf("命令缺少 --config-home: %v", args)
	return "", nil
}

func assertArgs(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("参数 = %q，期望 %q", got, want)
	}
}

func assertNoFlag(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, arg := range args {
		if arg == flag {
			t.Fatalf("不应出现参数 %q: %v", flag, args)
		}
	}
}

func assertConfigHomeRemoved(t *testing.T, dir string) {
	t.Helper()
	if dir == "" {
		t.Fatal("config home 为空")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("临时 config home 未被删除: %s", dir)
	}
}

// writeTestFullchain 生成一张自签名测试证书并写入指定路径，供 NotAfter 解析使用。
func writeTestFullchain(t *testing.T, path string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// fullchainWriter 返回一个执行回调：在 install-cert 命令执行时写入测试证书。
func fullchainWriter(t *testing.T, notAfter time.Time, results ...CommandResult) func(context.Context, CommandSpec) CommandResult {
	t.Helper()
	index := 0
	return func(_ context.Context, spec CommandSpec) CommandResult {
		result := results[index]
		index++
		for i, arg := range spec.Args {
			if arg == "--fullchain-file" && i+1 < len(spec.Args) {
				writeTestFullchain(t, spec.Args[i+1], notAfter)
			}
		}
		return result
	}
}

func TestIssueECCUsesCallerCertsDirAndInstallECC(t *testing.T) {
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 0}, {ExitCode: 0}}}
	certsDir := t.TempDir()
	runner := &Runner{
		AcmeShPath: "acme.sh",
		Home:       "/acme-home",
		CertsDir:   t.TempDir(),
		Executor:   fake,
	}

	result, err := runner.Issue(context.Background(), &IssueParams{
		Domain:        "example.com",
		ChallengeMode: "dns_api",
		DNSProvider:   "dns_cf",
		Keylength:     "ec-256",
		CertsDir:      certsDir,
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if result.OutDir != filepath.Join(certsDir, "example.com") {
		t.Fatalf("OutDir = %q", result.OutDir)
	}
	if len(fake.commands) != 2 {
		t.Fatalf("调用次数 = %d，期望 2", len(fake.commands))
	}

	// issue 与 install 必须共享同一个临时 config home。
	issueHome, issueArgs := splitConfigHome(t, fake.commands[0].Args)
	installHome, installArgs := splitConfigHome(t, fake.commands[1].Args)
	if issueHome != installHome {
		t.Fatalf("issue/install config home 不一致: %q vs %q", issueHome, installHome)
	}
	assertArgs(t, issueArgs, []string{
		"--issue", "-d", "example.com", "--dns", "dns_cf", "--keylength", "ec-256", "--home", "/acme-home",
	})
	assertArgs(t, installArgs, []string{
		"--install-cert", "-d", "example.com", "--ecc", "--home", "/acme-home",
		"--cert-file", filepath.Join(certsDir, "example.com", "cert.pem"),
		"--key-file", filepath.Join(certsDir, "example.com", "key.pem"),
		"--fullchain-file", filepath.Join(certsDir, "example.com", "fullchain.pem"),
		"--ca-file", filepath.Join(certsDir, "example.com", "ca.pem"),
	})
	// 默认隔离模式下，操作结束后临时 config home 必须被删除。
	assertConfigHomeRemoved(t, issueHome)
	if result.Duration <= 0 {
		t.Fatalf("Duration = %s，期望大于零", result.Duration)
	}
}

func TestRenewAndReissueRSA(t *testing.T) {
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 0}, {ExitCode: 0}}}
	runner := &Runner{AcmeShPath: "acme.sh", Home: "/acme-home", Executor: fake}
	params := &OperationParams{Domain: "example.com", CA: "letsencrypt", Keylength: "4096"}

	if _, err := runner.Renew(context.Background(), params); err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	if _, err := runner.Reissue(context.Background(), params); err != nil {
		t.Fatalf("Reissue() error = %v", err)
	}

	renewHome, renewArgs := splitConfigHome(t, fake.commands[0].Args)
	reissueHome, reissueArgs := splitConfigHome(t, fake.commands[1].Args)
	assertArgs(t, renewArgs, []string{"--renew", "-d", "example.com", "--server", "letsencrypt", "--home", "/acme-home"})
	assertArgs(t, reissueArgs, []string{"--renew", "-d", "example.com", "--force", "--server", "letsencrypt", "--home", "/acme-home"})
	// 每次操作使用独立的临时 config home，且结束后删除。
	if renewHome == reissueHome {
		t.Fatalf("连续操作不应复用同一临时 config home: %q", renewHome)
	}
	assertConfigHomeRemoved(t, renewHome)
	assertConfigHomeRemoved(t, reissueHome)
	for _, args := range [][]string{renewArgs, reissueArgs} {
		assertNoFlag(t, args, "--ecc")
	}
}

func TestExplicitConfigHomeIsReusedAndKept(t *testing.T) {
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 0}}}
	configHome := t.TempDir()
	runner := &Runner{AcmeShPath: "acme.sh", Home: "/acme-home", ConfigHome: configHome, Executor: fake}

	if _, err := runner.Renew(context.Background(), &OperationParams{Domain: "example.com", Keylength: "2048"}); err != nil {
		t.Fatalf("Renew() error = %v", err)
	}
	usedHome, _ := splitConfigHome(t, fake.commands[0].Args)
	if usedHome != configHome {
		t.Fatalf("显式 ConfigHome 未生效: %q", usedHome)
	}
	if _, err := os.Stat(configHome); err != nil {
		t.Fatalf("显式 ConfigHome 不应被删除: %v", err)
	}
}

func TestInvalidParametersDoNotExecute(t *testing.T) {
	cases := []struct {
		name   string
		params *IssueParams
	}{
		{
			name:   "不支持的算法",
			params: &IssueParams{Domain: "example.com", ChallengeMode: "standalone", Keylength: "ec-255"},
		},
		{
			name:   "非法DNS标识符",
			params: &IssueParams{Domain: "example.com", ChallengeMode: "dns_api", DNSProvider: "dns_cf;whoami", Keylength: "2048"},
		},
		{
			name:   "缺少DNS标识符",
			params: &IssueParams{Domain: "example.com", ChallengeMode: "dns_api", Keylength: "2048"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExecutor{}
			runner := &Runner{AcmeShPath: "acme.sh", CertsDir: t.TempDir(), Executor: fake}
			if _, err := runner.Issue(context.Background(), tc.params); err == nil {
				t.Fatal("Issue() 未返回参数错误")
			}
			if len(fake.commands) != 0 {
				t.Fatalf("非法参数不应执行命令: %v", fake.commands)
			}
		})
	}

	runner := &Runner{AcmeShPath: "acme.sh", Executor: &fakeExecutor{}}
	if _, err := runner.Renew(context.Background(), &OperationParams{Domain: "example.com", Keylength: "1024"}); err == nil {
		t.Fatal("Renew() 未拒绝不支持的算法")
	}
}

func TestExitCodeStatusClassification(t *testing.T) {
	fake := &fakeExecutor{results: []CommandResult{
		{ExitCode: 2, Err: errors.New("skipped")},
		{ExitCode: 3, Err: errors.New("manual pending")},
	}}
	runner := &Runner{AcmeShPath: "acme.sh", Executor: fake}
	params := &OperationParams{Domain: "example.com", Keylength: "2048"}

	skipped, err := runner.Renew(context.Background(), params)
	if err != nil || skipped.Status != OperationSkipped || skipped.ExitCode != 2 {
		t.Fatalf("Renew() = %#v, %v", skipped, err)
	}
	pending, err := runner.Reissue(context.Background(), params)
	if err != nil || pending.Status != OperationManualPending || pending.ExitCode != 3 {
		t.Fatalf("Reissue() = %#v, %v", pending, err)
	}
}

func TestIssueSharesTotalTimeout(t *testing.T) {
	var calls int
	fake := &fakeExecutor{executeFn: func(ctx context.Context, _ CommandSpec) CommandResult {
		calls++
		if calls == 1 {
			select {
			case <-time.After(30 * time.Millisecond):
				return CommandResult{ExitCode: 0}
			case <-ctx.Done():
				return CommandResult{ExitCode: -1, Err: ctx.Err()}
			}
		}
		select {
		case <-time.After(40 * time.Millisecond):
			return CommandResult{ExitCode: 0}
		case <-ctx.Done():
			return CommandResult{ExitCode: -1, Err: ctx.Err()}
		}
	}}
	runner := &Runner{
		AcmeShPath: "acme.sh",
		CertsDir:   t.TempDir(),
		Timeout:    50 * time.Millisecond,
		Executor:   fake,
	}

	started := time.Now()
	result, err := runner.Issue(context.Background(), &IssueParams{
		Domain:        "example.com",
		ChallengeMode: "standalone",
		Keylength:     "2048",
	})
	elapsed := time.Since(started)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Issue() error = %v，期望总超时", err)
	}
	if result.Install.Status != OperationTimedOut {
		t.Fatalf("安装状态 = %q，期望 %q", result.Install.Status, OperationTimedOut)
	}
	if elapsed > 75*time.Millisecond {
		t.Fatalf("耗时 = %s，疑似每一步重新计时", elapsed)
	}
}

func TestOutputIsLimitedAndRedacted(t *testing.T) {
	secret := "dns-secret-value"
	fake := &fakeExecutor{results: []CommandResult{{
		Stdout:   "token=" + secret + strings.Repeat("x", 64),
		Stderr:   "failure=" + secret,
		ExitCode: 1,
		Err:      errors.New(secret),
	}}}
	runner := &Runner{AcmeShPath: "acme.sh", OutputLimit: 20, Executor: fake}
	result, err := runner.Renew(context.Background(), &OperationParams{
		Domain:    "example.com",
		Keylength: "2048",
		DNSEnv:    map[string]string{"CF_Token": secret},
	})
	if err == nil {
		t.Fatal("Renew() 未返回失败")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(result.Stdout, secret) || strings.Contains(result.Stderr, secret) {
		t.Fatal("结果或错误泄露了 DNS 环境变量值")
	}
	if len(result.Stdout) > 20 || len(result.Stderr) > 20 || !result.StdoutTruncated {
		t.Fatalf("输出限制未生效: %#v", result)
	}
}

func TestRenewAndInstallECCForce(t *testing.T) {
	certsDir := t.TempDir()
	home := t.TempDir()
	notAfter := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)
	fake := &fakeExecutor{executeFn: fullchainWriter(t, notAfter,
		CommandResult{ExitCode: 0},
		CommandResult{ExitCode: 0},
	)}
	runner := &Runner{AcmeShPath: "acme.sh", Home: home, Executor: fake}

	result, err := runner.RenewAndInstall(context.Background(), &IssueParams{
		Domain:    "example.com",
		CA:        "letsencrypt",
		Keylength: "ec-256",
		CertsDir:  certsDir,
	}, true)
	if err != nil {
		t.Fatalf("RenewAndInstall() error = %v", err)
	}
	if result.Status != OperationSucceeded {
		t.Fatalf("状态 = %q，期望 %q", result.Status, OperationSucceeded)
	}
	if len(fake.commands) != 2 {
		t.Fatalf("调用次数 = %d，期望 2", len(fake.commands))
	}

	outDir := filepath.Join(certsDir, "example.com")
	renewHome, renewArgs := splitConfigHome(t, fake.commands[0].Args)
	installHome, installArgs := splitConfigHome(t, fake.commands[1].Args)
	assertArgs(t, renewArgs, []string{
		"--renew", "-d", "example.com", "--force", "--ecc", "--server", "letsencrypt", "--home", home,
	})
	assertArgs(t, installArgs, []string{
		"--install-cert", "-d", "example.com", "--ecc", "--server", "letsencrypt", "--home", home,
		"--cert-file", filepath.Join(outDir, "cert.pem"),
		"--key-file", filepath.Join(outDir, "key.pem"),
		"--fullchain-file", filepath.Join(outDir, "fullchain.pem"),
		"--ca-file", filepath.Join(outDir, "ca.pem"),
	})
	// renew 与 install 共享同一个临时 config home，且操作后删除。
	if renewHome != installHome {
		t.Fatalf("renew/install config home 不一致: %q vs %q", renewHome, installHome)
	}
	assertConfigHomeRemoved(t, renewHome)

	if _, err := os.Stat(filepath.Join(outDir, "time.log")); err != nil {
		t.Fatalf("成功安装后应写入 time.log: %v", err)
	}
	if !result.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %s，期望 %s", result.NotAfter, notAfter)
	}
}

func TestRenewAndInstallSkippedStillInstalls(t *testing.T) {
	certsDir := t.TempDir()
	fake := &fakeExecutor{executeFn: fullchainWriter(t, time.Now().Add(24*time.Hour),
		CommandResult{ExitCode: 2, Err: errors.New("skipped")},
		CommandResult{ExitCode: 0},
	)}
	runner := &Runner{AcmeShPath: "acme.sh", Home: t.TempDir(), Executor: fake}

	result, err := runner.RenewAndInstall(context.Background(), &IssueParams{
		Domain:    "example.com",
		Keylength: "2048",
		CertsDir:  certsDir,
	}, false)
	if err != nil {
		t.Fatalf("RenewAndInstall() error = %v", err)
	}
	if len(fake.commands) != 2 {
		t.Fatalf("skipped 后仍应执行 install，调用次数 = %d", len(fake.commands))
	}
	if result.Issue.Status != OperationSkipped || result.Status != OperationSkipped {
		t.Fatalf("结果应明确标记 skipped: %#v", result)
	}
	if result.Install.Operation != "install-cert" || result.Install.Status != OperationSucceeded {
		t.Fatalf("install 结果异常: %#v", result.Install)
	}
	renewHome, renewArgs := splitConfigHome(t, fake.commands[0].Args)
	installHome, installArgs := splitConfigHome(t, fake.commands[1].Args)
	if renewHome != installHome {
		t.Fatal("skipped 路径也应共享 config home")
	}
	assertNoFlag(t, renewArgs, "--force")
	assertNoFlag(t, installArgs, "--ecc")
	assertConfigHomeRemoved(t, renewHome)
}

func TestRenewAndInstallManualPendingSkipsInstall(t *testing.T) {
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 3, Err: errors.New("manual pending")}}}
	runner := &Runner{AcmeShPath: "acme.sh", Home: t.TempDir(), Executor: fake}

	result, err := runner.RenewAndInstall(context.Background(), &IssueParams{
		Domain:    "example.com",
		Keylength: "2048",
		CertsDir:  t.TempDir(),
	}, false)
	if err != nil {
		t.Fatalf("manual pending 不应视为错误: %v", err)
	}
	if result.Status != OperationManualPending {
		t.Fatalf("状态 = %q，期望 %q", result.Status, OperationManualPending)
	}
	if len(fake.commands) != 1 {
		t.Fatalf("manual pending 不应执行 install，调用次数 = %d", len(fake.commands))
	}
	if result.Install.Operation != "" {
		t.Fatalf("manual pending 不应产生 install 结果: %#v", result.Install)
	}
}

func TestCanaryInHomeFailsWithoutLeak(t *testing.T) {
	canary := "cf-token-canary-9f27"
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "account.conf"), []byte("SAVED_CF_Token='"+canary+"'"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 0}, {ExitCode: 0}}}
	runner := &Runner{AcmeShPath: "acme.sh", Home: home, CertsDir: t.TempDir(), Executor: fake}

	_, err := runner.Issue(context.Background(), &IssueParams{
		Domain:        "example.com",
		ChallengeMode: "dns_api",
		DNSProvider:   "dns_cf",
		Keylength:     "2048",
		DNSEnv:        map[string]string{"CF_Token": canary},
	})
	if err == nil {
		t.Fatal("扫描到 canary 后 Issue() 应失败")
	}
	if !errors.Is(err, ErrDNSCredentialResidue) {
		t.Fatalf("错误应标记凭据残留: %v", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("错误泄露了 canary: %v", err)
	}
	if len(fake.commands) != 0 {
		t.Fatalf("前置扫描失败不应执行任何命令: %v", fake.commands)
	}
}

func TestCanaryInCertsDirFailsWithoutLeak(t *testing.T) {
	canary := "dp-token-canary-51ab"
	certsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(certsDir, "note.txt"), []byte("export DP_Token="+canary), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 0}}}
	runner := &Runner{AcmeShPath: "acme.sh", Home: t.TempDir(), CertsDir: certsDir, Executor: fake}

	_, err := runner.Renew(context.Background(), &OperationParams{
		Domain:    "example.com",
		Keylength: "2048",
		DNSEnv:    map[string]string{"DP_Token": canary},
	})
	if err == nil || !errors.Is(err, ErrDNSCredentialResidue) {
		t.Fatalf("应返回凭据残留错误: %v", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("错误泄露了 canary: %v", err)
	}
	if len(fake.commands) != 0 {
		t.Fatal("前置扫描失败不应执行命令")
	}
}

func TestCanaryWrittenDuringCommandFailsWithoutLeak(t *testing.T) {
	canary := "ali-token-canary-77cd"
	home := t.TempDir()
	fake := &fakeExecutor{executeFn: func(_ context.Context, _ CommandSpec) CommandResult {
		// 模拟 acme.sh 把 DNS 凭据写入了持久 home。
		_ = os.WriteFile(filepath.Join(home, "leaked.conf"), []byte("token="+canary), 0o600)
		return CommandResult{ExitCode: 0}
	}}
	runner := &Runner{AcmeShPath: "acme.sh", Home: home, CertsDir: t.TempDir(), Executor: fake}

	_, err := runner.Issue(context.Background(), &IssueParams{
		Domain:        "example.com",
		ChallengeMode: "dns_api",
		DNSProvider:   "dns_cf",
		Keylength:     "2048",
		DNSEnv:        map[string]string{"Ali_Token": canary},
	})
	if err == nil || !errors.Is(err, ErrDNSCredentialResidue) {
		t.Fatalf("后置扫描应发现凭据残留: %v", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("错误泄露了 canary: %v", err)
	}
}

func TestSymlinkedCanaryIsNotFollowed(t *testing.T) {
	canary := "ln-token-canary-33ef"
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(home, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	fake := &fakeExecutor{results: []CommandResult{{ExitCode: 0}, {ExitCode: 0}}}
	runner := &Runner{AcmeShPath: "acme.sh", Home: home, CertsDir: t.TempDir(), Executor: fake}

	// 扫描不得跟随符号链接，链接目标中的 canary 不应触发失败。
	if _, err := runner.Issue(context.Background(), &IssueParams{
		Domain:        "example.com",
		ChallengeMode: "dns_api",
		DNSProvider:   "dns_cf",
		Keylength:     "2048",
		DNSEnv:        map[string]string{"LN_Token": canary},
	}); err != nil {
		t.Fatalf("符号链接目标不应被扫描: %v", err)
	}
	if len(fake.commands) != 2 {
		t.Fatalf("调用次数 = %d，期望 2", len(fake.commands))
	}
}

func TestSafeErrorRedactsAndPreservesUnwrap(t *testing.T) {
	secret := "wrap-secret-value"
	base := &OperationError{Operation: "issue", ExitCode: 1, Status: OperationFailed}
	wrapped := safeError(fmt.Errorf("上下文 %s: %w", secret, base), map[string]string{"K": secret})
	if strings.Contains(wrapped.Error(), secret) {
		t.Fatalf("safeError 泄露敏感值: %v", wrapped)
	}
	var opErr *OperationError
	if !errors.As(wrapped, &opErr) {
		t.Fatalf("safeError 应保留错误链: %v", wrapped)
	}
}
