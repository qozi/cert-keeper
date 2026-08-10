// CertKeeper 服务端本地管理 CLI。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/internal/version"
)

type cli struct {
	out     io.Writer
	errOut  io.Writer
	in      io.Reader
	format  string
	config  string
	showVal bool
	ctx     context.Context
	st      *store.Store
	svc     *service.Service
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer, in io.Reader) error {
	if len(args) == 0 {
		printUsage(out)
		return nil
	}

	global := flag.NewFlagSet("certk-server-cli", flag.ContinueOnError)
	global.SetOutput(errOut)
	global.Usage = func() {}
	configPath := "/data/config/config.yaml"
	format := "table"
	showValue := false
	showVersion := false
	global.StringVar(&configPath, "c", configPath, "服务端配置文件路径")
	global.StringVar(&configPath, "config", configPath, "服务端配置文件路径")
	global.StringVar(&format, "output", format, "输出格式：table 或 json")
	global.BoolVar(&showValue, "show-value", false, "显示 DNS Secret 明文，仅用于 secret list")
	global.BoolVar(&showVersion, "version", false, "显示版本")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(out)
			return nil
		}
		return err
	}
	if showVersion {
		fmt.Fprintln(out, version.String(version.ServerCLIComponent))
		return nil
	}
	if global.NArg() == 0 {
		printUsage(out)
		return nil
	}
	if global.Arg(0) == "help" || global.Arg(0) == "-h" || global.Arg(0) == "--help" {
		printUsage(out)
		return nil
	}
	if format != "table" && format != "json" {
		return fmt.Errorf("不支持的输出格式: %s", format)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}
	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		return fmt.Errorf("打开数据库失败: %w", err)
	}
	defer st.Close()

	c := &cli{
		out:     out,
		errOut:  errOut,
		in:      in,
		format:  format,
		showVal: showValue,
		ctx:     context.Background(),
		st:      st,
		svc:     service.New(cfg, st),
	}
	return c.dispatch(global.Args())
}

func (c *cli) dispatch(args []string) error {
	if len(args) == 0 {
		printUsage(c.out)
		return nil
	}
	switch args[0] {
	case "cert":
		return c.cert(args[1:])
	case "token":
		return c.token(args[1:])
	case "cert-config":
		return c.certConfig(args[1:])
	case "secret":
		return c.secret(args[1:])
	case "provider":
		return c.provider(args[1:])
	case "client":
		return c.client(args[1:])
	case "log":
		return c.log(args[1:])
	case "help", "-h", "--help":
		printUsage(c.out)
		return nil
	default:
		return fmt.Errorf("未知资源: %s", args[0])
	}
}

func (c *cli) cert(args []string) error {
	if len(args) == 0 {
		return errors.New("cert 需要子命令：apply/status/status-all/file/list/reissue")
	}
	switch args[0] {
	case "apply":
		fs := c.flagSet("cert apply")
		domain, san := "", stringList{}
		mode, provider, webroot, ca, keylength := "", "", "", "", ""
		force := false
		fs.StringVar(&domain, "d", "", "主域名")
		fs.Var(&san, "san", "附加域名，可重复")
		fs.StringVar(&mode, "mode", "", "dns_api/standalone/webroot/dns_manual")
		fs.StringVar(&provider, "dns-provider", "", "DNS provider")
		fs.StringVar(&webroot, "webroot", "", "webroot 路径")
		fs.StringVar(&ca, "ca", "", "CA")
		fs.StringVar(&keylength, "keylength", "", "密钥长度")
		fs.BoolVar(&force, "force", false, "强制重新签发")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("cert apply 需要 -d DOMAIN")
		}
		result, err := c.svc.Apply(c.ctx, service.ApplyRequest{
			Domain:        domain,
			SAN:           san,
			ChallengeMode: mode,
			DNSProvider:   provider,
			WebrootPath:   webroot,
			CA:            ca,
			Keylength:     keylength,
			Force:         force,
			Actor:         "server-cli",
		})
		if err != nil {
			return err
		}
		return c.print(result)
	case "status":
		fs := c.flagSet("cert status")
		domain := ""
		fs.StringVar(&domain, "d", "", "域名")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("cert status 需要 -d DOMAIN")
		}
		result, err := c.svc.Status(c.ctx, domain)
		if err != nil {
			return err
		}
		return c.print(result)
	case "status-all":
		fs := c.flagSet("cert status-all")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.svc.AllStatuses(c.ctx)
		if err != nil {
			return err
		}
		return c.print(result)
	case "file":
		fs := c.flagSet("cert file")
		domain, name, output := "", "", ""
		fs.StringVar(&domain, "d", "", "域名")
		fs.StringVar(&name, "f", "", "文件名：cert.pem/key.pem/fullchain.pem/ca.pem/time.log")
		fs.StringVar(&output, "o", "", "输出路径，省略时写入标准输出")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" || name == "" {
			return errors.New("cert file 需要 -d DOMAIN 和 -f FILE")
		}
		data, err := c.svc.ReadFile(c.ctx, domain, name)
		if err != nil {
			return err
		}
		if output == "" {
			_, err = c.out.Write(data)
			return err
		}
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			return fmt.Errorf("创建输出目录失败: %w", err)
		}
		if err := os.WriteFile(output, data, 0o600); err != nil {
			return fmt.Errorf("写入文件失败: %w", err)
		}
		fmt.Fprintf(c.out, "已写入 %s\n", output)
		return nil
	case "list":
		fs := c.flagSet("cert list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.st.ListCerts(c.ctx)
		if err != nil {
			return err
		}
		return c.print(result)
	case "reissue":
		fs := c.flagSet("cert reissue")
		domain := ""
		fs.StringVar(&domain, "d", "", "域名")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("cert reissue 需要 -d DOMAIN")
		}
		result, err := c.svc.Reissue(c.ctx, domain, "server-cli")
		if err != nil {
			return err
		}
		return c.print(result)
	default:
		return fmt.Errorf("未知 cert 子命令: %s", args[0])
	}
}

func (c *cli) token(args []string) error {
	if len(args) == 0 {
		return errors.New("token 需要子命令：list/get/create/update/delete")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("token list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.st.ListTokens(c.ctx)
		if err != nil {
			return err
		}
		return c.print(result)
	case "get":
		fs := c.flagSet("token get")
		id := ""
		fs.StringVar(&id, "i", "", "Token ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id == "" {
			return errors.New("token get 需要 -i ID")
		}
		result, err := c.st.GetToken(c.ctx, id)
		if err != nil {
			return err
		}
		if result == nil {
			return fmt.Errorf("token 不存在: %s", id)
		}
		return c.print(result)
	case "create":
		fs := c.flagSet("token create")
		id, secret, note := "", "", ""
		admin, enabled, autoGen, secretStdin := false, true, false, false
		fs.StringVar(&id, "i", "", "Token ID")
		fs.StringVar(&secret, "k", "", "Token secret")
		fs.StringVar(&note, "note", "", "备注")
		fs.BoolVar(&admin, "admin", false, "创建 admin token")
		fs.BoolVar(&enabled, "enabled", true, "启用 token")
		fs.BoolVar(&autoGen, "auto-gen", false, "自动生成 Token ID")
		fs.BoolVar(&secretStdin, "secret-stdin", false, "从标准输入读取 secret")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if secretStdin {
			value, err := readStdinValue(c.in)
			if err != nil {
				return err
			}
			secret = value
		}
		result, err := c.svc.CreateToken(c.ctx, service.TokenCreateRequest{ID: id, Secret: secret, Note: note, Enabled: enabled, IsAdmin: admin, AutoGen: autoGen})
		if err != nil {
			return err
		}
		return c.print(result)
	case "update":
		fs := c.flagSet("token update")
		id, note := "", ""
		enabled, disabled, admin, notAdmin := false, false, false, false
		fs.StringVar(&id, "i", "", "Token ID")
		fs.StringVar(&note, "note", "", "备注")
		fs.BoolVar(&enabled, "enabled", false, "启用 token")
		fs.BoolVar(&disabled, "disabled", false, "停用 token")
		fs.BoolVar(&admin, "admin", false, "授予 admin 权限")
		fs.BoolVar(&notAdmin, "not-admin", false, "取消 admin 权限")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id == "" {
			return errors.New("token update 需要 -i ID")
		}
		current, err := c.st.GetToken(c.ctx, id)
		if err != nil {
			return err
		}
		if current == nil {
			return fmt.Errorf("token 不存在: %s", id)
		}
		if note == "" {
			note = current.Note
		}
		if enabled && disabled || admin && notAdmin {
			return errors.New("同一项不能同时指定正向和反向参数")
		}
		if enabled {
			current.Enabled = true
		}
		if disabled {
			current.Enabled = false
		}
		if admin {
			current.IsAdmin = true
		}
		if notAdmin {
			current.IsAdmin = false
		}
		if err := c.st.UpdateToken(c.ctx, id, note, current.Enabled, current.IsAdmin); err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true})
	case "delete":
		fs := c.flagSet("token delete")
		id := ""
		fs.StringVar(&id, "i", "", "Token ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id == "" {
			return errors.New("token delete 需要 -i ID")
		}
		if err := c.st.DeleteToken(c.ctx, id); err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 token 子命令: %s", args[0])
	}
}

func (c *cli) certConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("cert-config 需要子命令：list/set/delete")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("cert-config list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.st.ListCerts(c.ctx)
		if err != nil {
			return err
		}
		return c.print(result)
	case "set":
		fs := c.flagSet("cert-config set")
		domain, san := "", stringList{}
		mode, provider, webroot, ca, keylength, reload, source := "", "", "", "", "", "", ""
		renewDays := 0
		fs.StringVar(&domain, "d", "", "主域名")
		fs.Var(&san, "san", "附加域名，可重复")
		fs.StringVar(&mode, "mode", "", "dns_api/standalone/webroot/dns_manual")
		fs.StringVar(&provider, "dns-provider", "", "DNS provider")
		fs.StringVar(&webroot, "webroot", "", "webroot 路径")
		fs.StringVar(&ca, "ca", "", "CA")
		fs.StringVar(&keylength, "keylength", "", "密钥长度")
		fs.IntVar(&renewDays, "renew-days", 0, "提前续签天数")
		fs.StringVar(&reload, "reload-cmd", "", "reload 命令")
		fs.StringVar(&source, "source", "preset", "配置来源")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" || mode == "" {
			return errors.New("cert-config set 需要 -d DOMAIN 和 --mode MODE")
		}
		cert := &store.Cert{
			Domain:        domain,
			SAN:           strings.Join(san, ","),
			CA:            ca,
			ChallengeMode: mode,
			DNSProvider:   nullable(provider),
			WebrootPath:   nullable(webroot),
			Keylength:     keylength,
			RenewDays:     renewDays,
			ReloadCmd:     nullable(reload),
			Source:        source,
		}
		if err := c.svc.SaveCertConfig(c.ctx, cert); err != nil {
			return err
		}
		return c.print(cert)
	case "delete":
		fs := c.flagSet("cert-config delete")
		domain := ""
		fs.StringVar(&domain, "d", "", "域名")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("cert-config delete 需要 -d DOMAIN")
		}
		if err := c.st.DeleteCert(c.ctx, domain); err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 cert-config 子命令: %s", args[0])
	}
}

func (c *cli) secret(args []string) error {
	if len(args) == 0 {
		return errors.New("secret 需要子命令：list/set/delete")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("secret list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.svc.ListSecretViews(c.ctx, c.showVal)
		if err != nil {
			return err
		}
		return c.print(result)
	case "set":
		fs := c.flagSet("secret set")
		provider, envKey, value := "", "", ""
		valueStdin := false
		fs.StringVar(&provider, "provider", "", "provider")
		fs.StringVar(&envKey, "env-key", "", "环境变量名")
		fs.StringVar(&value, "value", "", "Secret 值")
		fs.BoolVar(&valueStdin, "value-stdin", false, "从标准输入读取 Secret 值")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if valueStdin {
			read, err := readStdinValue(c.in)
			if err != nil {
				return err
			}
			value = read
		}
		if provider == "" || envKey == "" || value == "" {
			return errors.New("secret set 需要 --provider、--env-key 和 --value/--value-stdin")
		}
		if err := c.st.UpsertSecret(c.ctx, provider, envKey, value, c.svc.Cfg.Storage.EncryptionKey); err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true})
	case "delete":
		fs := c.flagSet("secret delete")
		id, provider, envKey := int64(0), "", ""
		fs.Int64Var(&id, "id", 0, "Secret ID")
		fs.StringVar(&provider, "provider", "", "provider")
		fs.StringVar(&envKey, "env-key", "", "环境变量名")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		var err error
		if id != 0 {
			err = c.st.DeleteSecret(c.ctx, id)
		} else if provider != "" && envKey != "" {
			err = c.st.DeleteSecretByKV(c.ctx, provider, envKey)
		} else {
			return errors.New("secret delete 需要 --id 或 --provider + --env-key")
		}
		if err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 secret 子命令: %s", args[0])
	}
}

func (c *cli) provider(args []string) error {
	if len(args) == 0 {
		return errors.New("provider 需要子命令：list/parameters")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("provider list")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.svc.ListProviders(c.ctx)
		if err != nil {
			return err
		}
		return c.print(result)
	case "parameters":
		fs := c.flagSet("provider parameters")
		provider := ""
		fs.StringVar(&provider, "provider", "", "provider")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" {
			return errors.New("provider parameters 需要 --provider")
		}
		result, err := c.svc.ProviderParameters(c.ctx, provider)
		if err != nil {
			return err
		}
		return c.print(map[string]any{"provider": provider, "parameters": result})
	default:
		return fmt.Errorf("未知 provider 子命令: %s", args[0])
	}
}

func (c *cli) client(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("client 目前只支持 list")
	}
	fs := c.flagSet("client list")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	result, err := c.st.ListClients(c.ctx)
	if err != nil {
		return err
	}
	return c.print(result)
}

func (c *cli) log(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("log 目前只支持 list")
	}
	fs := c.flagSet("log list")
	domain, clientID, success := "", "", ""
	limit, offset := 100, 0
	fs.StringVar(&domain, "domain", "", "域名过滤")
	fs.StringVar(&clientID, "client", "", "客户端 Token ID 过滤")
	fs.StringVar(&success, "success", "", "true/false")
	fs.IntVar(&limit, "limit", 100, "数量")
	fs.IntVar(&offset, "offset", 0, "偏移量")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	filter := store.LogFilter{Domain: domain, Client: clientID, Limit: limit, Offset: offset}
	if success != "" {
		value, err := strconv.ParseBool(success)
		if err != nil {
			return errors.New("success 必须为 true 或 false")
		}
		filter.Success = &value
	}
	result, err := c.st.ListLogs(c.ctx, filter)
	if err != nil {
		return err
	}
	return c.print(result)
}

func (c *cli) flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.errOut)
	return fs
}

func (c *cli) print(value any) error {
	if c.format == "json" {
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	}
	return printTable(c.out, value)
}

func printTable(out io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	rows := make([]map[string]any, 0)
	switch item := decoded.(type) {
	case []any:
		for _, v := range item {
			if row, ok := v.(map[string]any); ok {
				rows = append(rows, row)
			} else {
				rows = append(rows, map[string]any{"value": v})
			}
		}
	case map[string]any:
		rows = append(rows, item)
	default:
		rows = append(rows, map[string]any{"value": decoded})
	}
	if len(rows) == 0 {
		_, err := fmt.Fprintln(out, "无数据")
		return err
	}
	keys := map[string]struct{}{}
	for _, row := range rows {
		for key := range row {
			keys[key] = struct{}{}
		}
	}
	headers := make([]string, 0, len(keys))
	for key := range keys {
		headers = append(headers, key)
	}
	sort.Strings(headers)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for i, header := range headers {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, header)
	}
	fmt.Fprintln(tw)
	for _, row := range rows {
		for i, header := range headers {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			fmt.Fprint(tw, tableValue(row[header]))
		}
		fmt.Fprintln(tw)
	}
	return tw.Flush()
}

func tableValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(b)
}

func readStdinValue(in io.Reader) (string, error) {
	scanner := bufio.NewScanner(in)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("标准输入为空")
	}
	return strings.TrimRight(scanner.Text(), "\r\n"), nil
}

func nullable(value string) store.JSONNullString {
	return store.JSONNullString{String: value, Valid: value != ""}
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func printUsage(out io.Writer) {
	fmt.Fprint(out, `certk-server-cli [global flags] <resource> <command> [flags]

全局参数:
  -c, --config FILE       服务端配置文件（默认 /data/config/config.yaml）
  --output table|json     输出格式（默认 table）
  --show-value            secret list 显示 Secret 明文
  --version               显示版本

资源:
  cert       apply/status/status-all/file/list/reissue
  token      list/get/create/update/delete
  cert-config list/set/delete
  secret     list/set/delete
  provider   list/parameters
  client     list
  log        list

示例:
  certk-server-cli cert-config set -d example.com --mode dns_api --dns-provider dns_cf
  certk-server-cli secret set --provider dns_cf --env-key CF_Key --value-stdin
  certk-server-cli cert apply -d example.com
  certk-server-cli --output json token create --auto-gen --admin --note web-01
`)
}
