// 本文件实现客户端 v2 流程：reconcile 申请、generation 原子部署、
// 状态查询、单文件下载与部署回报。
package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/pkg/certproto"
	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// ApplyV2Opts 定义 v2 reconcile + generation 原子部署的选项。
type ApplyV2Opts struct {
	// Domain 是申请/续签的主域名。
	Domain string
	// IdempotencyKey 是 reconcile 幂等键；为空时自动生成。
	IdempotencyKey string
	// OutDir 是部署根目录，活动 generation 由其中的 current 文件指向。
	OutDir string
	// VerifyCmd 是 current 切换后执行的校验命令；为空则不校验。
	VerifyCmd string
	// ReloadCmd 是校验成功后执行的 reload 命令；为空则不 reload。
	ReloadCmd string
	// Force 强制重新签发（仅管理员场景）。
	Force bool
}

// ApplyV2 通过 v2 reconcile 申请/续签证书，并以 generation 原子部署到本地。
// 部署完成后向服务端回报 DeploymentReport；回报失败会持久化并在下次运行补发。
func (c *Client) ApplyV2(ctx context.Context, opts ApplyV2Opts) error {
	if opts.Domain == "" {
		return errors.New("域名不能为空")
	}
	if opts.OutDir == "" {
		return errors.New("输出目录不能为空")
	}
	idempotencyKey := strings.TrimSpace(opts.IdempotencyKey)
	if idempotencyKey == "" {
		// 自动生成幂等键，保证重试不会触发重复签发。
		key, err := ckauth.RandomHex(16)
		if err != nil {
			return fmt.Errorf("生成幂等键失败: %w", err)
		}
		idempotencyKey = key
	}

	if err := c.ensureCapabilities(ctx); err != nil {
		return err
	}
	statePath := filepath.Join(opts.OutDir, ".client-state.json")
	state, err := loadClientState(statePath)
	if err != nil {
		return err
	}
	if state != nil && state.Domain == opts.Domain && state.IdempotencyKey != "" {
		idempotencyKey = state.IdempotencyKey
	}
	previousState := state
	state = &clientState{IdempotencyKey: idempotencyKey, Domain: opts.Domain}
	if previousState != nil && previousState.Domain == opts.Domain && previousState.Report != nil && !previousState.ReportSent {
		state.Report = previousState.Report
	}
	if err := saveClientState(statePath, state); err != nil {
		return err
	}
	if state.Report != nil && !state.ReportSent && state.Report.Domain == opts.Domain {
		if err := c.reportDeploymentV2(ctx, opts.Domain, *state.Report); err == nil {
			state.ReportSent = true
			if err := saveClientState(statePath, state); err != nil {
				return err
			}
		}
	}
	reconcile, err := c.reconcileV2(ctx, opts, idempotencyKey)
	if err != nil {
		return err
	}
	generation := reconcile.Generation
	if generation == "" {
		generation = reconcile.Job.Generation
	}
	if generation == "" {
		return errors.New("服务端未返回有效 generation")
	}
	manifest := reconcile.Status.Files
	if len(manifest) == 0 {
		// 响应未携带 manifest 时，按 generation 单独获取。
		manifest, err = c.manifestV2(ctx, opts.Domain, generation)
		if err != nil {
			return err
		}
	}
	c.Log.Info("reconcile 完成",
		"domain", opts.Domain,
		"generation", generation,
		"revision", reconcile.Revision,
		"changed", reconcile.Changed,
		"message", reconcile.Message,
	)

	// 部署 generation 到本地并执行 verify/reload。
	startedAt := time.Now()
	report, deployErr := DeployGeneration(ctx, GenerationDeployOpts{
		Domain:     opts.Domain,
		OutDir:     opts.OutDir,
		Generation: generation,
		Manifest:   manifest,
		Fetch:      c.v2FileFetcher(opts.Domain, generation),
		Verify:     shellDeploymentCommand(opts.VerifyCmd),
		Reload:     shellDeploymentCommand(opts.ReloadCmd),
	})
	finishedAt := time.Now()
	report.Target = deploymentTarget()
	report.Revision = reconcile.Revision
	report.StartedAt = &startedAt
	report.FinishedAt = &finishedAt

	report.Domain = opts.Domain
	report.Generation = generation
	state.Generation = generation
	state.Revision = reconcile.Revision
	state.Report = &report
	_ = saveClientState(statePath, state)
	// 回报失败必须保留状态，供下次运行补发。
	if reportErr := c.reportDeploymentV2(ctx, opts.Domain, report); reportErr != nil {
		c.Log.Warn("部署回报失败，将在下次运行补发", "err", reportErr)
	} else {
		state.ReportSent = true
		_ = saveClientState(statePath, state)
	}

	if deployErr != nil {
		c.Log.Error("v2 部署失败", "domain", opts.Domain, "generation", generation, "err", deployErr)
		return deployErr
	}
	if report.State == certproto.DeploymentStateSkipped {
		c.Log.Info("generation 已是当前版本，跳过部署", "domain", opts.Domain, "generation", generation)
		return nil
	}
	c.Log.Info("v2 证书部署完成", "domain", opts.Domain, "generation", generation)
	return nil
}

// reconcileV2 调用服务端 reconcile 端点并解析响应。
func (c *Client) reconcileV2(ctx context.Context, opts ApplyV2Opts, idempotencyKey string) (*certproto.ReconcileResponse, error) {
	path, err := certproto.ReconcileURLPath(opts.Domain)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"idempotency_key": idempotencyKey,
		"operation":       "client",
		"reason":          "certkeeper-client apply",
	}
	if opts.Force {
		body["force"] = true
	}
	c.Log.Info("开始 v2 reconcile", "domain", opts.Domain, "idempotency_key", idempotencyKey, "force", opts.Force)
	resp, data, err := c.doRequestCtx(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusAccepted {
		var accepted certproto.JobAcceptedResponse
		if err := json.Unmarshal(data, &accepted); err != nil {
			return nil, fmt.Errorf("解析异步任务响应失败: %w", err)
		}
		if err := accepted.Validate(); err != nil {
			return nil, fmt.Errorf("异步任务响应无效: %w", err)
		}
		return c.pollJobV2(ctx, accepted.Location, accepted.Job)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reconcile 失败: 服务端返回 %d: %s", resp.StatusCode, string(data))
	}
	var rr certproto.ReconcileResponse
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("解析 reconcile 响应失败: %w", err)
	}
	if !rr.Success {
		if rr.Error != nil {
			return nil, fmt.Errorf("reconcile 失败: %s", rr.Error.Error())
		}
		return nil, fmt.Errorf("reconcile 失败: %s", rr.Message)
	}
	return &rr, nil
}

// maxPollAttempts 是轮询任务的最大次数（约 10 分钟）。
const maxPollAttempts = 600

func (c *Client) pollJobV2(ctx context.Context, location string, initial certproto.JobStatus) (*certproto.ReconcileResponse, error) {
	job := initial
	delay := 1 * time.Second
	for attempt := 0; ; attempt++ {
		if job.IsTerminal() {
			if job.State != certproto.JobStateSucceeded {
				return nil, fmt.Errorf("异步任务 %s: %s", job.State, job.Message)
			}
			return &certproto.ReconcileResponse{Success: true, Generation: job.Generation, Revision: job.Revision, Job: job}, nil
		}
		if attempt >= maxPollAttempts {
			return nil, errors.New("轮询等待超时：任务未在规定时间内完成")
		}
		if delayErr := sleepContext(ctx, delay); delayErr != nil {
			return nil, delayErr
		}
		resp, data, err := c.doRequestCtx(ctx, http.MethodGet, location, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("轮询任务失败: 服务端返回 %d: %s", resp.StatusCode, string(data))
		}
		if err := json.Unmarshal(data, &job); err != nil {
			return nil, fmt.Errorf("解析任务状态失败: %w", err)
		}
		// 更新下次轮询间隔：优先遵守 Retry-After，否则指数退避，上限 30s。
		if v, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && v > 0 {
			delay = time.Duration(v) * time.Second
		} else {
			delay *= 2
		}
		if delay < 1*time.Second {
			delay = 1 * time.Second
		}
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
}

// manifestV2 按 generation 获取证书 manifest。
func (c *Client) manifestV2(ctx context.Context, domain string, generation certproto.GenerationID) (certproto.CertificateManifest, error) {
	path, err := certproto.ManifestURLPath(domain, string(generation))
	if err != nil {
		return nil, err
	}
	resp, data, err := c.doRequestCtx(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("获取 manifest 失败: 服务端返回 %d: %s", resp.StatusCode, string(data))
	}
	var manifest certproto.CertificateManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("解析 manifest 响应失败: %w", err)
	}
	if len(manifest) == 0 {
		return nil, errors.New("服务端返回空 manifest")
	}
	return manifest, nil
}

// v2FileFetcher 返回按 generation 从服务端下载固定证书文件的 Fetch 函数。
func (c *Client) v2FileFetcher(domain string, generation certproto.GenerationID) FetchCertificateFileFunc {
	return func(ctx context.Context, fileName certproto.FileName) ([]byte, error) {
		path, err := certproto.CertificateFileURLPath(domain, string(generation), string(fileName))
		if err != nil {
			return nil, err
		}
		resp, data, err := c.doRequestCtx(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, string(data))
		}
		return data, nil
	}
}

// reportDeploymentV2 向服务端回报部署结果。
func (c *Client) reportDeploymentV2(ctx context.Context, domain string, report certproto.DeploymentReport) error {
	path, err := certproto.DeploymentsURLPath(domain)
	if err != nil {
		return err
	}
	resp, data, err := c.doRequestCtx(ctx, http.MethodPost, path, report)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

// ensureCapabilities 在所有 v2 操作开始前验证服务端冻结能力。
func (c *Client) ensureCapabilities(ctx context.Context) error {
	resp, data, err := c.doRequestCtx(ctx, http.MethodGet, certproto.CapabilitiesURLPath(), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("获取 capabilities 失败: 服务端返回 %d: %s", resp.StatusCode, string(data))
	}
	var caps certproto.Capabilities
	if err := json.Unmarshal(data, &caps); err != nil {
		return fmt.Errorf("capabilities 无效: %w", err)
	}
	return nil
}

// Heartbeat 向服务端报告客户端仍在线。
func (c *Client) Heartbeat(ctx context.Context) error {
	resp, data, err := c.doRequestCtx(ctx, http.MethodPost, "/api/v1/client/heartbeat", map[string]any{})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat %d: %s", resp.StatusCode, string(data))
	}
	return nil
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// certificateStatusV2 获取并解析 v2 证书状态。
func (c *Client) certificateStatusV2(ctx context.Context, domain string) (*certproto.CertificateStatus, error) {
	path, err := certproto.CertificateStatusURLPath(domain)
	if err != nil {
		return nil, err
	}
	resp, data, err := c.doRequestCtx(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(data))
	}
	var status certproto.CertificateStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("解析状态响应失败: %w", err)
	}
	return &status, nil
}

// StatusV2 通过 v2 API 查询证书状态并打印。
func (c *Client) StatusV2(domain string) error {
	if err := c.ensureCapabilities(context.Background()); err != nil {
		return err
	}
	status, err := c.certificateStatusV2(context.Background(), domain)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// DownloadV2 下载指定 generation 的单个证书文件；generation 为空时使用服务端 current generation。
func (c *Client) DownloadV2(domain, generation, fileName, outPath string) error {
	ctx := context.Background()
	if err := c.ensureCapabilities(ctx); err != nil {
		return err
	}
	if err := certproto.ValidateFileName(fileName); err != nil {
		return fmt.Errorf("不允许下载文件 %q: %w", fileName, err)
	}
	if generation == "" {
		status, err := c.certificateStatusV2(context.Background(), domain)
		if err != nil {
			return err
		}
		generation = string(status.Generation)
		if generation == "" {
			return errors.New("服务端没有可用的 current generation")
		}
	}
	manifest, err := c.manifestV2(ctx, domain, certproto.GenerationID(generation))
	if err != nil {
		return err
	}
	var expected certproto.FileManifest
	for _, item := range manifest {
		if item.Name == fileName {
			expected = item
			break
		}
	}
	if expected.Name == "" {
		return fmt.Errorf("manifest 中不存在文件 %q", fileName)
	}
	path, err := certproto.CertificateFileURLPath(domain, generation, fileName)
	if err != nil {
		return err
	}
	resp, data, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %d: %s", resp.StatusCode, string(data))
	}
	if int64(len(data)) != expected.Size {
		return errors.New("下载大小校验失败")
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected.SHA256 {
		return errors.New("下载 SHA256 校验失败")
	}
	if info, err := os.Lstat(outPath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("输出路径不能是符号链接")
	}
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".download-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("原子替换失败: %w", err)
	}
	fmt.Printf("已下载 %s (generation %s) -> %s (%d 字节)\n", fileName, generation, outPath, len(data))
	return nil
}

// shellDeploymentCommand 把 shell 命令包装为部署命令；cmd 为空时返回 nil。
func shellDeploymentCommand(cmd string) DeploymentCommand {
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	return func(ctx context.Context, workDir string) error {
		return runShellCmdCtx(ctx, cmd, workDir)
	}
}

// deploymentTarget 返回部署目标标识（主机名），用于服务端区分不同部署节点。
func deploymentTarget() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "certkeeper-client"
	}
	// 服务端限制 target 最长 128 字节。
	if len(host) > 128 {
		host = host[:128]
	}
	return host
}
