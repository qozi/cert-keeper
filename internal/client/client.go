// Package client 提供 CertKeeper 客户端的功能。
// 客户端负责与服务端通信，申请证书并下载到本地。
package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/siidoo/certkeeper/pkg/ckauth"
)

// Config 定义客户端的配置。
type Config struct {
	Server     string `yaml:"server"`
	TokenID    string `yaml:"token_id"`
	TokenSecret string `yaml:"token_secret"`
	LogFile    string `yaml:"log_file"`
	LogLevel   string `yaml:"log_level"`
	Defaults   Defaults `yaml:"defaults"`
}

// Defaults 定义客户端的默认配置。
type Defaults struct {
	OutDir        string `yaml:"out_dir"`
	CertFile      string `yaml:"cert_file"`
	KeyFile       string `yaml:"key_file"`
	FullchainFile string `yaml:"fullchain_file"`
	CAFile        string `yaml:"ca_file"`
	VerifyCmd     string `yaml:"verify_cmd"`
	ReloadCmd     string `yaml:"reload_cmd"`
}

// Client 是 CertKeeper 客户端，负责与服务端通信。
type Client struct {
	Cfg  *Config
	HTTP *http.Client
	Log  Logger
}

// Logger 是日志记录器接口。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// ApplyOpts 定义证书申请的选项。
type ApplyOpts struct {
	Domain        string
	SAN           []string
	ChallengeMode string
	DNSProvider   string
	WebrootPath   string
	CA            string
	Keylength     string
	OutDir        string
	CertFile      string
	KeyFile       string
	FullchainFile string
	CAFile        string
	VerifyCmd     string
	ReloadCmd     string
	Force         bool
}

type fileMeta struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type applyResp struct {
	Success  bool       `json:"success"`
	Domain   string     `json:"domain"`
	Renewed  bool       `json:"renewed"`
	NotAfter time.Time  `json:"not_after"`
	Files    []fileMeta `json:"files"`
	TimeLog  int64      `json:"time_log"`
	Message  string     `json:"message"`
}

func (c *Client) doRequest(method, path string, body any) (*http.Response, []byte, error) {
	var bodyBytes []byte
	var bodyHash = "0"
	if body != nil {
		bodyBytes, _ = json.Marshal(body)
		h := sha256.Sum256(bodyBytes)
		bodyHash = hex.EncodeToString(h[:])
	}
	ts := ckauth.Now()
	nonce, err := ckauth.GenNonce()
	if err != nil {
		return nil, nil, err
	}
	sig := ckauth.Sign(method, path, ts, nonce, bodyHash, c.Cfg.TokenSecret)
	req, err := http.NewRequest(method, c.Cfg.Server+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set(ckauth.HeaderTokenID, c.Cfg.TokenID)
	req.Header.Set(ckauth.HeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(ckauth.HeaderNonce, nonce)
	req.Header.Set("X-CK-BodyHash", bodyHash)
	req.Header.Set(ckauth.HeaderSignature, sig)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return resp, data, err
}

// Apply 申请/续签证书并下载到本地。
func (c *Client) Apply(opts ApplyOpts) error {
	c.Log.Info("开始申请证书", "domain", opts.Domain, "mode", opts.ChallengeMode)
	body := map[string]any{"domain": opts.Domain}
	if opts.ChallengeMode != "" {
		body["challenge_mode"] = opts.ChallengeMode
		body["dns_provider"] = opts.DNSProvider
		body["webroot_path"] = opts.WebrootPath
		body["ca"] = opts.CA
		body["keylength"] = opts.Keylength
		body["san"] = opts.SAN
	}
	if opts.Force {
		body["force"] = true
	}

	start := time.Now()
	resp, data, err := c.doRequest(http.MethodPost, "/api/v1/certs/apply", body)
	if err != nil {
		c.Log.Error("请求服务端失败", "err", err)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		c.Log.Error("服务端返回错误", "status", resp.StatusCode, "body", string(data))
		return fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, string(data))
	}
	var ar applyResp
	if err := json.Unmarshal(data, &ar); err != nil {
		c.Log.Error("解析响应失败", "err", err, "body", string(data))
		return err
	}
	if !ar.Success {
		return fmt.Errorf("服务端申请失败: %s", ar.Message)
	}
	c.Log.Info("服务端申请完成", "renewed", ar.Renewed, "not_after", ar.NotAfter, "duration", time.Since(start))

	// 下载文件
	outDir := opts.OutDir
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	nameMap := map[string]string{
		"cert.pem":      opts.CertFile,
		"key.pem":       opts.KeyFile,
		"fullchain.pem": opts.FullchainFile,
		"ca.pem":        opts.CAFile,
		"time.log":      "time.log",
	}
	// 备份旧文件用于回滚
	backups := map[string]string{}
	for _, f := range ar.Files {
		outName := nameMap[f.Name]
		if outName == "" {
			outName = f.Name
		}
		outPath := filepath.Join(outDir, outName)
		// 备份
		if _, err := os.Stat(outPath); err == nil {
			bk := outPath + ".bak"
			if err := os.Rename(outPath, bk); err != nil {
				return fmt.Errorf("备份旧文件 %s 失败: %w", outPath, err)
			}
			backups[outPath] = bk
		}
		// 下载
		path := fmt.Sprintf("/api/v1/certs/%s/files/%s", opts.Domain, f.Name)
		_, data, err := c.doRequest(http.MethodGet, path, nil)
		if err != nil {
			c.restoreBackups(backups)
			return fmt.Errorf("下载 %s 失败: %w", f.Name, err)
		}
		// 校验 SHA256
		h := sha256.Sum256(data)
		got := hex.EncodeToString(h[:])
		if got != f.SHA256 {
			c.restoreBackups(backups)
			return fmt.Errorf("校验失败 %s: 服务端 %s 实际 %s", f.Name, f.SHA256, got)
		}
		if err := os.WriteFile(outPath, data, 0o600); err != nil {
			c.restoreBackups(backups)
			return fmt.Errorf("写入 %s 失败: %w", outPath, err)
		}
		c.Log.Info("下载完成", "file", outPath, "size", f.Size)
	}
	// 清理备份
	for _, bk := range backups {
		_ = os.Remove(bk)
	}

	// 校验命令
	if opts.VerifyCmd != "" {
		c.Log.Info("执行校验命令", "cmd", opts.VerifyCmd)
		if err := runShellCmd(opts.VerifyCmd, outDir); err != nil {
			c.Log.Error("校验失败，回滚证书", "err", err)
			c.restoreBackups(backups)
			return fmt.Errorf("校验失败: %w", err)
		}
	}
	// reload 命令
	if opts.ReloadCmd != "" {
		c.Log.Info("执行 reload 命令", "cmd", opts.ReloadCmd)
		if err := runShellCmd(opts.ReloadCmd, outDir); err != nil {
			c.Log.Error("reload 失败（证书已更新，不回滚）", "err", err)
			return fmt.Errorf("reload 失败: %w", err)
		}
	}
	c.Log.Info("证书更新全部完成", "domain", opts.Domain)
	return nil
}

func (c *Client) restoreBackups(b map[string]string) {
	for dst, src := range b {
		_ = os.Rename(src, dst)
	}
}

// Status 查询某证书状态。
func (c *Client) Status(domain string) error {
	path := fmt.Sprintf("/api/v1/certs/%s/status", domain)
	resp, data, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(data))
	}
	fmt.Println(string(data))
	return nil
}

// Download 下载单个证书文件。
func (c *Client) Download(domain, fileName, outPath string) error {
	path := fmt.Sprintf("/api/v1/certs/%s/files/%s", domain, fileName)
	resp, data, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %d: %s", resp.StatusCode, string(data))
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("写入失败: %w", err)
	}
	fmt.Printf("已下载 %s -> %s (%d 字节)\n", fileName, outPath, len(data))
	return nil
}

// Register 注册客户端。
func (c *Client) Register(hostname, osInfo string) error {
	body := map[string]any{"hostname": hostname, "os_info": osInfo}
	resp, data, err := c.doRequest(http.MethodPost, "/api/v1/client/register", body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register %d: %s", resp.StatusCode, string(data))
	}
	fmt.Println("注册成功")
	return nil
}

// Test 测试与服务端的连接。
func (c *Client) Test() error {
	resp, data, err := c.doRequest(http.MethodGet, "/api/v1/ping", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("test %d: %s", resp.StatusCode, string(data))
	}
	fmt.Println("连接正常:", string(data))
	return nil
}
