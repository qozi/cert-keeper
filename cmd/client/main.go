// CertKeeper 客户端入口程序。
// 提供证书申请、下载、状态查询等功能的命令行工具。
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/internal/client"
	"github.com/siidoo/certkeeper/internal/version"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		command   string
		configPath string
		quiet     bool
	)
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	command = os.Args[1]
	// 顶层 --version / -h
	if command == "--version" || command == "-v" {
		fmt.Println(version.String(version.ClientComponent))
		return
	}
	if command == "-h" || command == "--help" || command == "help" {
		printUsage()
		return
	}

	// 扫描 -c/--config（仅位置，用于加载配置），随后由子命令 fs 统一解析所有 flag
	configPath = scanConfigArg(os.Args[2:])
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}
	logger := setupLogger(cfg, false)
	cli := &client.Client{
		Cfg:  cfg,
		HTTP: &http.Client{Timeout: 5 * time.Minute},
		Log:  logger,
	}

	// 全局 flag 集合（每个子命令 fs 复用）
	makeGlobal := func(fs *flag.FlagSet) {
		fs.StringVar(&server, "s", cfg.Server, "服务端地址")
		fs.StringVar(&tokenID, "i", cfg.TokenID, "认证 token id")
		fs.StringVar(&secret, "k", cfg.TokenSecret, "认证 token secret")
		fs.StringVar(&logFile, "log-file", cfg.LogFile, "日志文件路径")
		fs.StringVar(&logLevel, "log-level", cfg.LogLevel, "日志级别")
		fs.BoolVar(&quiet, "quiet", false, "仅写日志文件")
		// -c/--config 已在加载时扫描，这里仅作占位避免未定义报错
		var discard string
		fs.StringVar(&discard, "c", "", "配置文件路径（加载时已扫描）")
		fs.StringVar(&discard, "config", "", "配置文件路径（加载时已扫描）")
	}

	switch command {
	case "apply":
		runApply(cli, os.Args[2:], logger, makeGlobal)
	case "download":
		runDownload(cli, os.Args[2:], makeGlobal)
	case "status":
		runStatus(cli, os.Args[2:], makeGlobal)
	case "register":
		runRegister(cli, os.Args[2:], makeGlobal)
	case "test":
		runTest(cli, os.Args[2:], makeGlobal)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n", command)
		printUsage()
		os.Exit(1)
	}
	_ = quiet
}

// 包级全局变量（被各子命令 fs 与 applyGlobalOverrides 共用）
var (
	server    string
	tokenID   string
	secret    string
	logFile   string
	logLevel  string
)

func scanConfigArg(args []string) string {
	cfg := "/etc/certkeeper/client.yaml"
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-c" || a == "--config" {
			if i+1 < len(args) {
				return args[i+1]
			}
		} else if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		} else if strings.HasPrefix(a, "-c=") {
			return strings.TrimPrefix(a, "-c=")
		}
	}
	return cfg
}

func applyGlobalOverrides(cli *client.Client, server, tokenID, secret, logFile, logLevel string) {
	if server != "" {
		cli.Cfg.Server = server
	}
	if tokenID != "" {
		cli.Cfg.TokenID = tokenID
	}
	if secret != "" {
		cli.Cfg.TokenSecret = secret
	}
	if logFile != "" {
		cli.Cfg.LogFile = logFile
	}
	if logLevel != "" {
		cli.Cfg.LogLevel = logLevel
	}
}

func loadConfig(path string) (*client.Config, error) {
	cfg := &client.Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func setupLogger(cfg *client.Config, quiet bool) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	var w *os.File = os.Stdout
	if !quiet && cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			w = f
		}
	} else if quiet && cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			w = f
		}
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func printUsage() {
	fmt.Print(`certkeeper-client <command> [flags]

命令:
  apply      申请/续签证书并下载到本地
  download   仅下载已签发证书
  status     查询某证书状态
  register   注册客户端到服务端
  test       测试与服务端连接

全局 flags:
  -s URL          服务端地址
  -i ID           token id
  -k SECRET       token secret
  -c FILE         配置文件路径
  --log-file F    日志文件路径
  --log-level L   日志级别 (debug/info/warn/error)
  --quiet         仅写日志文件
  --version       显示版本

apply flags:
  -d DOMAIN       主域名（必填，可多次指定）
  --mode M        dns_api/standalone/webroot/dns_manual
  --dns-provider P   dns_api 模式
  --webroot P     webroot 模式
  --ca C          letsencrypt/zerossl
  --keylength L   ec-256/rsa-2048
  --out-dir D     证书下载保存目录（默认 /etc/certkeeper/certs）
  --cert-file F   cert 文件名（默认 cert.pem）
  --key-file F    key 文件名（默认 key.pem）
  --fullchain-file F
  --ca-file F
  --reload-cmd C  下载后 reload 命令
  --verify-cmd C  下载后 verify 命令（在 reload 前）
  --force         即使未到期也强制重新下载

示例:
  certkeeper-client apply -d example.com --out-dir /etc/nginx/certs \
    --reload-cmd "nginx -t && systemctl reload nginx"
`)
}

type globalRegFn func(fs *flag.FlagSet)

func runTest(cli *client.Client, args []string, makeGlobal globalRegFn) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	makeGlobal(fs)
	_ = fs.Parse(args)
	applyGlobalOverrides(cli, server, tokenID, secret, logFile, logLevel)
	if err := requireAuth(cli); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := cli.Test(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runApply(cli *client.Client, args []string, logger *slog.Logger, makeGlobal globalRegFn) {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	makeGlobal(fs)
	var (
		domain     stringSlice
		san        stringSlice
		mode       string
		dnsProvider string
		webroot    string
		ca         string
		keylength  string
		outDir     string
		certFile   string
		keyFile    string
		fullchain  string
		caFile     string
		verifyCmd  string
		reloadCmd  string
		force      bool
	)
	fs.Var(&domain, "d", "主域名")
	fs.Var(&san, "san", "附加域名（可多次指定）")
	fs.StringVar(&mode, "mode", "", "challenge 模式")
	fs.StringVar(&dnsProvider, "dns-provider", "", "dns provider")
	fs.StringVar(&webroot, "webroot", "", "webroot 路径")
	fs.StringVar(&ca, "ca", "", "CA")
	fs.StringVar(&keylength, "keylength", "", "密钥长度")
	fs.StringVar(&outDir, "out-dir", "", "输出目录")
	fs.StringVar(&certFile, "cert-file", "", "cert 文件名")
	fs.StringVar(&keyFile, "key-file", "", "key 文件名")
	fs.StringVar(&fullchain, "fullchain-file", "", "fullchain 文件名")
	fs.StringVar(&caFile, "ca-file", "", "ca 文件名")
	fs.StringVar(&verifyCmd, "verify-cmd", "", "校验命令")
	fs.StringVar(&reloadCmd, "reload-cmd", "", "reload 命令")
	fs.BoolVar(&force, "force", false, "强制重新下载")
	_ = fs.Parse(args)

	applyGlobalOverrides(cli, server, tokenID, secret, logFile, logLevel)
	if err := requireAuth(cli); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(domain) == 0 {
		fmt.Fprintln(os.Stderr, "apply 必须指定 -d DOMAIN")
		os.Exit(1)
	}
	cfg := cli.Cfg
	if outDir == "" {
		outDir = cfg.Defaults.OutDir
	}
	if outDir == "" {
		outDir = "/etc/certkeeper/certs"
	}
	if certFile == "" {
		certFile = orDefault(cfg.Defaults.CertFile, "cert.pem")
	}
	if keyFile == "" {
		keyFile = orDefault(cfg.Defaults.KeyFile, "key.pem")
	}
	if fullchain == "" {
		fullchain = orDefault(cfg.Defaults.FullchainFile, "fullchain.pem")
	}
	if caFile == "" {
		caFile = orDefault(cfg.Defaults.CAFile, "ca.pem")
	}
	if verifyCmd == "" {
		verifyCmd = cfg.Defaults.VerifyCmd
	}
	if reloadCmd == "" {
		reloadCmd = cfg.Defaults.ReloadCmd
	}
	opts := client.ApplyOpts{
		Domain:        domain[0],
		SAN:           append(append([]string{}, domain[1:]...), san...),
		ChallengeMode: mode,
		DNSProvider:   dnsProvider,
		WebrootPath:   webroot,
		CA:            ca,
		Keylength:     keylength,
		OutDir:        outDir,
		CertFile:      certFile,
		KeyFile:       keyFile,
		FullchainFile: fullchain,
		CAFile:        caFile,
		VerifyCmd:     verifyCmd,
		ReloadCmd:     reloadCmd,
		Force:         force,
	}
	if err := cli.Apply(opts); err != nil {
		logger.Error("apply 失败", "err", err)
		os.Exit(1)
	}
}

func runDownload(cli *client.Client, args []string, makeGlobal globalRegFn) {
	fs := flag.NewFlagSet("download", flag.ExitOnError)
	makeGlobal(fs)
	var (
		domain string
		file   string
		out    string
	)
	fs.StringVar(&domain, "d", "", "域名")
	fs.StringVar(&file, "f", "", "文件名 (cert/key/fullchain/ca/time.log)")
	fs.StringVar(&out, "o", "", "输出路径")
	_ = fs.Parse(args)
	applyGlobalOverrides(cli, server, tokenID, secret, logFile, logLevel)
	if err := requireAuth(cli); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if domain == "" || file == "" || out == "" {
		fmt.Fprintln(os.Stderr, "download 需要 -d -f -o")
		os.Exit(1)
	}
	if err := cli.Download(domain, file, out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runStatus(cli *client.Client, args []string, makeGlobal globalRegFn) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	makeGlobal(fs)
	var domain string
	fs.StringVar(&domain, "d", "", "域名")
	_ = fs.Parse(args)
	applyGlobalOverrides(cli, server, tokenID, secret, logFile, logLevel)
	if err := requireAuth(cli); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if domain == "" {
		fmt.Fprintln(os.Stderr, "status 需要 -d")
		os.Exit(1)
	}
	if err := cli.Status(domain); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runRegister(cli *client.Client, args []string, makeGlobal globalRegFn) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	makeGlobal(fs)
	var (
		hostname string
		osInfo   string
	)
	fs.StringVar(&hostname, "hostname", "", "主机名")
	fs.StringVar(&osInfo, "os-info", "", "OS 信息")
	_ = fs.Parse(args)
	applyGlobalOverrides(cli, server, tokenID, secret, logFile, logLevel)
	if err := requireAuth(cli); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	if osInfo == "" {
		osInfo = runtime.GOOS + " " + runtime.GOARCH
		if u, err := user.Current(); err == nil {
			osInfo += " user=" + u.Username
		}
	}
	if err := cli.Register(hostname, osInfo); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func requireAuth(cli *client.Client) error {
	if cli.Cfg.Server == "" || cli.Cfg.TokenID == "" || cli.Cfg.TokenSecret == "" {
		return fmt.Errorf("缺少服务端地址或认证参数（server/token_id/token_secret）")
	}
	return nil
}

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
