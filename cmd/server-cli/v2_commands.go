package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/certstore"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/service"
	"github.com/siidoo/certkeeper/internal/store"
	"github.com/siidoo/certkeeper/pkg/certproto"
	"github.com/siidoo/certkeeper/pkg/ckauth"
	_ "modernc.org/sqlite"
)

const (
	defaultCLIActor = "server-cli"
	maxSecretBytes  = 1 << 20
)

// hasCLIFlag 判断参数中是否出现了独立的全局控制参数。
func hasCLIFlag(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

// validateCLICommandNames 在打开配置和数据库前拒绝未知资源或子命令。
func validateCLICommandNames(args []string) error {
	if len(args) == 0 {
		return nil
	}
	commands := map[string]map[string]bool{
		"cert":        {"apply": true, "status": true, "status-all": true, "file": true, "list": true, "reissue": true, "revoke": true, "remove": true, "delete": true},
		"token":       {"list": true, "get": true, "create": true, "update": true, "delete": true, "rotate": true},
		"cert-config": {"list": true, "set": true, "delete": true},
		"secret":      {"list": true, "set": true, "delete": true},
		"profile":     {"list": true, "get": true, "show": true, "create": true, "set": true, "update": true, "delete": true},
		"dns-profile": {"list": true, "get": true, "show": true, "create": true, "set": true, "update": true, "delete": true},
		"provider":    {"list": true, "parameters": true},
		"client":      {"list": true},
		"log":         {"list": true},
		"grant":       {"add": true, "remove": true, "list": true},
		"job":         {"list": true, "show": true, "retry": true, "cancel": true},
		"generation":  {"list": true, "show": true, "gc": true, "deployments": true},
		"backup":      {"create": true, "verify": true, "restore": true},
		"migrate":     {"status": true, "verify": true},
		"audit":       {"list": true},
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		return nil
	}
	if args[0] == "dns" {
		if len(args) < 2 || args[1] != "profile" {
			return errors.New("未知 dns 子命令，合法值为 profile")
		}
		return validateCLICommandNames(append([]string{"profile"}, args[2:]...))
	}
	children, ok := commands[args[0]]
	if !ok {
		return fmt.Errorf("未知资源: %s", args[0])
	}
	if len(args) == 1 || strings.HasPrefix(args[1], "-") {
		return nil
	}
	if !children[args[1]] {
		return fmt.Errorf("未知 %s 子命令: %s", args[0], args[1])
	}
	return nil
}

// shouldRunWithoutStore 避免只读校验和恢复过程打开目标数据库。
func shouldRunWithoutStore(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "migrate" {
		return true
	}
	return args[0] == "backup" && len(args) > 1 && (args[1] == "verify" || args[1] == "restore")
}

// cfgOrError 返回已加载的配置；仅 migrate/backup verify/restore 可以没有 Store。
func (c *cli) cfgOrError() (*config.Config, error) {
	if c.cfg == nil {
		return nil, errors.New("配置尚未加载")
	}
	return c.cfg, nil
}

// validateV2Domain 使用 v2 的严格域名规则，拒绝通配符、IP 和路径。
func validateV2Domain(domain string) error {
	if domain == "" || domain != strings.ToLower(domain) || strings.TrimSpace(domain) != domain || len(domain) > 253 || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return errors.New("domain 格式不合法")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("domain 格式不合法")
		}
		for i := 0; i < len(label); i++ {
			if (label[i] < 'a' || label[i] > 'z') && (label[i] < '0' || label[i] > '9') && label[i] != '-' {
				return errors.New("domain 格式不合法")
			}
		}
	}
	return nil
}

// validateTokenID 校验 Token ID 的单段 ASCII 标识，避免把路径或控制字符交给存储层。
func validateTokenID(id string) error {
	if id == "" || len(id) > ckauth.TokenIDMaxLen || strings.TrimSpace(id) != id {
		return errors.New("token ID 格式不合法")
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && !strings.ContainsRune("-._~", rune(ch)) {
			return errors.New("token ID 格式不合法")
		}
	}
	return nil
}

// currentStatus 从 certstore 的 current 指针构造 v2 状态，不回退到旧 certs 目录。
func (c *cli) currentStatus(domain string) (certproto.CertificateStatus, error) {
	if err := validateV2Domain(domain); err != nil {
		return certproto.CertificateStatus{}, err
	}
	cfg, err := c.cfgOrError()
	if err != nil {
		return certproto.CertificateStatus{}, err
	}
	cs, err := certstore.Open(cfg.Acme.CertsDir)
	if err != nil {
		return certproto.CertificateStatus{}, fmt.Errorf("打开证书仓储失败: %w", err)
	}
	generation, err := cs.GetCurrent(domain)
	if errors.Is(err, certstore.ErrNotFound) {
		return certproto.CertificateStatus{Domain: domain, State: certproto.CertificateStateMissing, Message: "没有 current generation"}, nil
	}
	if err != nil {
		return certproto.CertificateStatus{}, err
	}
	manifest, err := cs.LoadManifest(domain, generation)
	if err != nil {
		return certproto.CertificateStatus{}, err
	}
	status := certproto.CertificateStatus{Domain: domain, Generation: generation, Files: manifest, Exists: true}
	if c.st != nil {
		if stored, storeErr := c.st.GetCurrentCertificateGeneration(c.ctx, domain); storeErr == nil && stored != nil {
			status.Revision = certproto.Revision(stored.Revision)
		}
	}
	if fullchain, readErr := cs.ReadFile(domain, generation, certproto.FileFullchain); readErr == nil {
		if expiry, expiryErr := acme.ParsePemExpiry(fullchain); expiryErr == nil {
			status.NotAfter = expiry
			if expiry.Before(time.Now()) {
				status.State = certproto.CertificateStateExpired
			} else {
				status.State = certproto.CertificateStateValid
			}
		}
	}
	if status.State == "" {
		status.State = certproto.CertificateStateUnknown
	}
	if timeLog, readErr := cs.ReadFile(domain, generation, certproto.FileTimeLog); readErr == nil {
		status.TimeLog, _ = strconv.ParseInt(strings.TrimSpace(string(timeLog)), 10, 64)
	}
	return status, nil
}

// certV2 提供本地 v2 证书查询、入队和生命周期操作。
func (c *cli) certV2(args []string) error {
	if len(args) == 0 {
		return errors.New("cert 需要子命令：apply/status/status-all/file/list/reissue/revoke/remove/delete")
	}
	switch args[0] {
	case "apply":
		return c.certApplyV2(args[1:])
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
		result, err := c.currentStatus(domain)
		if err != nil {
			return err
		}
		return c.print(result)
	case "status-all", "list":
		fs := c.flagSet("cert " + args[0])
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		certs, err := c.st.ListCerts(c.ctx)
		if err != nil {
			return err
		}
		statuses := make([]certproto.CertificateStatus, 0, len(certs))
		for _, cert := range certs {
			status, statusErr := c.currentStatus(cert.Domain)
			if statusErr != nil {
				return statusErr
			}
			statuses = append(statuses, status)
		}
		return c.print(statuses)
	case "file":
		return c.certFileV2(args[1:])
	case "reissue":
		return c.certReissueV2(args[1:])
	case "revoke", "remove", "delete":
		return c.certLifecycleV2(args[0], args[1:])
	default:
		return fmt.Errorf("未知 cert 子命令: %s", args[0])
	}
}

// certApplyV2 保留旧 apply 入口；v2 force 入口统一使用 reissue 入队。
func (c *cli) certApplyV2(args []string) error {
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if domain == "" {
		return errors.New("cert apply 需要 -d DOMAIN")
	}
	result, err := c.svc.Apply(c.ctx, service.ApplyRequest{Domain: domain, SAN: san, ChallengeMode: mode, DNSProvider: provider, WebrootPath: webroot, CA: ca, Keylength: keylength, Force: force, Actor: defaultCLIActor})
	if err != nil {
		return err
	}
	_ = c.addAudit("", domain, "cert_apply", "succeeded", "兼容 apply")
	return c.print(result)
}

func (c *cli) certFileV2(args []string) error {
	fs := c.flagSet("cert file")
	domain, name, output, generation := "", "", "", ""
	showPrivate := c.showPrivateKey
	fs.StringVar(&domain, "d", "", "域名")
	fs.StringVar(&name, "f", "", "文件名：cert.pem/key.pem/fullchain.pem/ca.pem/time.log")
	fs.StringVar(&output, "o", "", "输出路径，省略时写入标准输出")
	fs.StringVar(&generation, "generation", "", "generation，省略时读取 current")
	fs.BoolVar(&showPrivate, "show-private-key", showPrivate, "允许将私钥输出到标准输出")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if domain == "" || name == "" {
		return errors.New("cert file 需要 -d DOMAIN 和 -f FILE")
	}
	if name == string(certproto.FileKey) && output == "" && !showPrivate {
		return errors.New("默认禁止将私钥输出到标准输出，请指定 --show-private-key 或 -o 文件")
	}
	if generation != "" {
		if err := certproto.ValidateGenerationID(generation); err != nil {
			return errors.New("generation 格式不合法")
		}
	}
	if err := certproto.ValidateFileName(name); err != nil {
		return err
	}
	cfg, err := c.cfgOrError()
	if err != nil {
		return err
	}
	cs, err := certstore.Open(cfg.Acme.CertsDir)
	if err != nil {
		return err
	}
	data, err := cs.ReadFile(domain, certproto.GenerationID(generation), certproto.FileName(name))
	if err != nil {
		return err
	}
	if output == "" {
		_, err = c.out.Write(data)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	if err := os.WriteFile(output, data, 0o600); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}
	fmt.Fprintf(c.out, "已写入 %s\n", output)
	return nil
}

func (c *cli) certReissueV2(args []string) error {
	fs := c.flagSet("cert reissue")
	domain, tokenID, reason, idempotencyKey := "", "", "", ""
	fs.StringVar(&domain, "d", "", "域名")
	fs.StringVar(&tokenID, "token", "", "管理员 Token ID，默认使用 auth.admin_token_id")
	fs.StringVar(&reason, "reason", "", "重签原因")
	fs.StringVar(&idempotencyKey, "idempotency-key", "", "幂等键")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if domain == "" {
		return errors.New("cert reissue 需要 -d DOMAIN")
	}
	actor, isAdmin, err := c.resolveToken(tokenID)
	if err != nil {
		return err
	}
	if !isAdmin {
		return errors.New("cert reissue 需要 admin Token")
	}
	if idempotencyKey == "" {
		idempotencyKey, err = ckauth.GenNonce()
		if err != nil {
			return fmt.Errorf("生成幂等键失败: %w", err)
		}
	}
	result, err := c.svc.ReconcileV2(c.ctx, service.V2ReconcileRequest{TokenID: actor, IsAdmin: true, Domain: domain, Operation: "reissue", Reason: reason, IdempotencyKey: idempotencyKey, Force: true})
	if err != nil {
		return err
	}
	_ = c.addAudit(actor, domain, "reissue_v2", "succeeded", "force 任务已入队")
	return c.print(result)
}

func (c *cli) certLifecycleV2(action string, args []string) error {
	fs := c.flagSet("cert " + action)
	domain, actor, grant := "", defaultCLIActor, action
	fs.StringVar(&domain, "d", "", "域名")
	fs.StringVar(&actor, "actor", actor, "操作者")
	fs.StringVar(&grant, "grant", grant, "生命周期授权名")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if domain == "" {
		return fmt.Errorf("cert %s 需要 -d DOMAIN", action)
	}
	req := service.LifecycleRequest{Domain: domain, Actor: actor, Grant: grant}
	var err error
	switch action {
	case "revoke":
		err = c.svc.Revoke(c.ctx, req)
	case "remove":
		err = c.svc.Remove(c.ctx, req)
	case "delete":
		err = c.svc.Delete(c.ctx, req)
	}
	if err != nil {
		return err
	}
	_ = c.addAudit(actor, domain, "cert_"+action, "succeeded", "生命周期操作完成")
	return c.print(map[string]any{"ok": true, "action": action, "domain": domain})
}

// addAudit 为 CLI 直接执行的写操作补充审计事件；不存在的本地 actor 不写入外键。
func (c *cli) addAudit(actor, domain, action, outcome, detail string) error {
	if c.st == nil {
		return errors.New("当前命令没有可用数据库，无法写入审计")
	}
	event := &store.AuditEvent{Action: action, Outcome: outcome, Detail: nullable(detail)}
	if domain != "" {
		event.Domain = nullable(domain)
	}
	if actor != "" && actor != defaultCLIActor {
		if token, err := c.st.GetToken(c.ctx, actor); err == nil && token != nil {
			event.ActorTokenID = nullable(actor)
		}
	}
	return c.st.AddAuditEvent(context.Background(), event)
}

// resolveToken 解析管理命令使用的 Token，并拒绝不存在或已停用的 ID。
func (c *cli) resolveToken(id string) (string, bool, error) {
	if id == "" {
		if c.cfg == nil || c.cfg.Auth.AdminTokenID == "" {
			return "", false, errors.New("未指定 Token，且 auth.admin_token_id 为空")
		}
		id = c.cfg.Auth.AdminTokenID
	}
	if err := validateTokenID(id); err != nil {
		return "", false, err
	}
	token, err := c.st.GetToken(c.ctx, id)
	if err != nil {
		return "", false, err
	}
	if token == nil {
		return "", false, fmt.Errorf("token 不存在: %s", id)
	}
	if !token.Enabled {
		return "", false, fmt.Errorf("token 已停用: %s", id)
	}
	return id, token.IsAdmin, nil
}

// adminCount 返回当前管理员数量，用于保护最后一个 admin。
func (c *cli) adminCount() (int, error) {
	tokens, err := c.st.ListTokens(c.ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, token := range tokens {
		if token.IsAdmin {
			count++
		}
	}
	return count, nil
}

func (c *cli) protectLastAdmin(target *store.Token, removeAdmin bool) error {
	if target == nil || !target.IsAdmin || !removeAdmin {
		return nil
	}
	count, err := c.adminCount()
	if err != nil {
		return err
	}
	if count <= 1 {
		return errors.New("拒绝操作：不能移除或停用最后一个 admin Token")
	}
	return nil
}

// tokenV2 提供 Token CRUD 和 secret 轮换，所有标识先经过严格校验。
func (c *cli) tokenV2(args []string) error {
	if len(args) == 0 {
		return errors.New("token 需要子命令：list/get/create/update/delete/rotate")
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
		if err := validateTokenID(id); err != nil {
			return err
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
		return c.tokenCreateV2(args[1:])
	case "update":
		return c.tokenUpdateV2(args[1:])
	case "delete":
		return c.tokenDeleteV2(args[1:])
	case "rotate":
		return c.tokenRotateV2(args[1:])
	default:
		return fmt.Errorf("未知 token 子命令: %s", args[0])
	}
}

func (c *cli) tokenCreateV2(args []string) error {
	fs := c.flagSet("token create")
	id, secret, note, secretFile := "", "", "", ""
	admin, enabled, autoGen, secretStdin := false, true, false, false
	fs.StringVar(&id, "i", "", "Token ID")
	fs.StringVar(&secret, "k", "", "Token secret")
	fs.StringVar(&secretFile, "secret-file", "", "从安全文件读取 Token secret")
	fs.StringVar(&note, "note", "", "备注")
	fs.BoolVar(&admin, "admin", false, "创建 admin token")
	fs.BoolVar(&enabled, "enabled", true, "启用 token")
	fs.BoolVar(&autoGen, "auto-gen", false, "自动生成 Token ID")
	fs.BoolVar(&secretStdin, "secret-stdin", false, "从标准输入读取 secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if id != "" {
		if err := validateTokenID(id); err != nil {
			return err
		}
	}
	if secretStdin && secretFile != "" {
		return errors.New("secret-stdin 与 secret-file 不能同时指定")
	}
	if secretStdin {
		var err error
		secret, err = readSecretInput(c.in, "")
		if err != nil {
			return err
		}
	} else if secretFile != "" {
		var err error
		secret, err = readSecretInput(nil, secretFile)
		if err != nil {
			return err
		}
	}
	result, err := c.svc.CreateToken(c.ctx, service.TokenCreateRequest{ID: id, Secret: secret, Note: note, Enabled: enabled, IsAdmin: admin, AutoGen: autoGen})
	if err != nil {
		return err
	}
	if err := c.addAudit("", "", "token_create", "succeeded", "创建 Token"); err != nil {
		return fmt.Errorf("Token 已创建但写入审计失败: %w", err)
	}
	return c.print(result)
}

func (c *cli) tokenUpdateV2(args []string) error {
	fs := c.flagSet("token update")
	id, note := "", ""
	enabled, disabled, admin, notAdmin, clearNote := false, false, false, false, false
	fs.StringVar(&id, "i", "", "Token ID")
	fs.StringVar(&note, "note", "", "备注")
	fs.BoolVar(&clearNote, "clear-note", false, "清空备注")
	fs.BoolVar(&enabled, "enabled", false, "启用 token")
	fs.BoolVar(&disabled, "disabled", false, "停用 token")
	fs.BoolVar(&admin, "admin", false, "授予 admin 权限")
	fs.BoolVar(&notAdmin, "not-admin", false, "取消 admin 权限")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateTokenID(id); err != nil {
		return err
	}
	if enabled && disabled || admin && notAdmin || clearNote && note != "" {
		return errors.New("同一项不能同时指定正向和反向参数")
	}
	target, err := c.st.GetToken(c.ctx, id)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("token 不存在: %s", id)
	}
	wasAdmin := target.IsAdmin
	if enabled {
		target.Enabled = true
	}
	if disabled {
		target.Enabled = false
	}
	if admin {
		target.IsAdmin = true
	}
	if notAdmin {
		target.IsAdmin = false
	}
	if (disabled || notAdmin) && wasAdmin {
		if err := c.protectLastAdmin(&store.Token{IsAdmin: true}, true); err != nil {
			return err
		}
	}
	if clearNote {
		note = ""
	} else if !flagWasSet(fs, "note") {
		note = target.Note
	}
	if err := c.st.UpdateToken(c.ctx, id, note, target.Enabled, target.IsAdmin); err != nil {
		return err
	}
	if err := c.addAudit("", "", "token_update", "succeeded", "更新 Token"); err != nil {
		return fmt.Errorf("Token 已更新但写入审计失败: %w", err)
	}
	return c.print(map[string]any{"ok": true})
}

func (c *cli) tokenDeleteV2(args []string) error {
	fs := c.flagSet("token delete")
	id := ""
	fs.StringVar(&id, "i", "", "Token ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateTokenID(id); err != nil {
		return err
	}
	target, err := c.st.GetToken(c.ctx, id)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("token 不存在: %s", id)
	}
	if err := c.protectLastAdmin(target, true); err != nil {
		return err
	}
	if err := c.st.DeleteToken(c.ctx, id); err != nil {
		return err
	}
	if err := c.addAudit("", "", "token_delete", "succeeded", "删除 Token"); err != nil {
		return fmt.Errorf("Token 已删除但写入审计失败: %w", err)
	}
	return c.print(map[string]any{"ok": true})
}

func (c *cli) tokenRotateV2(args []string) error {
	fs := c.flagSet("token rotate")
	id, secretFile := "", ""
	secretStdin := false
	fs.StringVar(&id, "i", "", "Token ID")
	fs.StringVar(&secretFile, "secret-file", "", "从安全文件读取新 secret")
	fs.BoolVar(&secretStdin, "secret-stdin", false, "从标准输入读取新 secret")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateTokenID(id); err != nil {
		return err
	}
	if secretStdin && secretFile != "" {
		return errors.New("secret-stdin 与 secret-file 不能同时指定")
	}
	if token, err := c.st.GetToken(c.ctx, id); err != nil {
		return err
	} else if token == nil {
		return fmt.Errorf("token 不存在: %s", id)
	}
	secret := ""
	var err error
	if secretStdin {
		secret, err = readSecretInput(c.in, "")
	} else if secretFile != "" {
		secret, err = readSecretInput(nil, secretFile)
	} else {
		secret, err = ckauth.GenSecret()
	}
	if err != nil {
		return err
	}
	if err := c.st.RotateTokenSecret(c.ctx, id, secret); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("token 不存在: %s", id)
		}
		return err
	}
	if err := c.addAudit("", "", "token_rotate", "succeeded", "轮换 Token secret"); err != nil {
		return fmt.Errorf("Token secret 已轮换但写入审计失败: %w", err)
	}
	return c.print(map[string]any{"id": id, "secret": secret})
}

// flagWasSet 区分 patch 中未提供的字段与显式空值。
func flagWasSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == name {
			set = true
		}
	})
	return set
}

// readSecretInput 只从 stdin 或权限受限的普通文件读取 secret，不接受命令行明文。
func readSecretInput(in io.Reader, path string) (string, error) {
	var data []byte
	var err error
	if path != "" {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return "", statErr
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("secret 文件必须是权限不超过 0600 的普通文件")
		}
		data, err = os.ReadFile(path)
	} else {
		data, err = io.ReadAll(io.LimitReader(in, maxSecretBytes+1))
	}
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data) > maxSecretBytes {
		return "", errors.New("secret 为空或超过大小限制")
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" {
		return "", errors.New("secret 为空")
	}
	return value, nil
}

// profileV2 管理 DNS provider/profile 及其账号元数据。
func (c *cli) profileV2(args []string) error {
	if len(args) == 0 {
		return errors.New("profile 需要子命令：list/get/create/update/delete")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("profile list")
		provider := ""
		fs.StringVar(&provider, "provider", "", "DNS provider")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.st.ListDNSProfiles(c.ctx, provider)
		if err != nil {
			return err
		}
		return c.print(result)
	case "get", "show":
		fs := c.flagSet("profile get")
		provider, profile := "", ""
		fs.StringVar(&provider, "provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "profile")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" || profile == "" {
			return errors.New("profile get 需要 --provider 和 --profile")
		}
		result, err := c.st.GetDNSProfile(c.ctx, provider, profile)
		if err != nil {
			return err
		}
		if result == nil {
			return fmt.Errorf("DNS profile 不存在: %s/%s", provider, profile)
		}
		return c.print(result)
	case "create", "set", "update":
		fs := c.flagSet("profile " + args[0])
		provider, profile, account := "", "", ""
		fs.StringVar(&provider, "provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "profile")
		fs.StringVar(&account, "account", "", "DNS account")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" || profile == "" {
			return errors.New("profile set 需要 --provider 和 --profile")
		}
		item := &store.DNSProfile{Provider: provider, Profile: profile, Account: account}
		if err := c.st.UpsertDNSProfile(c.ctx, item); err != nil {
			return err
		}
		if err := c.addAudit("", "", "dns_profile_set", "succeeded", "更新 DNS profile"); err != nil {
			return fmt.Errorf("DNS profile 已更新但写入审计失败: %w", err)
		}
		return c.print(item)
	case "delete":
		fs := c.flagSet("profile delete")
		provider, profile := "", ""
		fs.StringVar(&provider, "provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "profile")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" || profile == "" {
			return errors.New("profile delete 需要 --provider 和 --profile")
		}
		if item, err := c.st.GetDNSProfile(c.ctx, provider, profile); err != nil {
			return err
		} else if item == nil {
			return fmt.Errorf("DNS profile 不存在: %s/%s", provider, profile)
		}
		if err := c.st.DeleteDNSProfile(c.ctx, provider, profile); err != nil {
			return err
		}
		if err := c.addAudit("", "", "dns_profile_delete", "succeeded", "删除 DNS profile"); err != nil {
			return fmt.Errorf("DNS profile 已删除但写入审计失败: %w", err)
		}
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 profile 子命令: %s", args[0])
	}
}

// secretV2 只操作明确的 provider/profile，防止不同 profile 之间串值。
func (c *cli) secretV2(args []string) error {
	if len(args) == 0 {
		return errors.New("secret 需要子命令：list/set/delete")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("secret list")
		provider, profile := "", ""
		fs.StringVar(&provider, "provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "profile")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" || profile == "" {
			return errors.New("secret list 需要 --provider 和 --profile")
		}
		if c.showVal && !c.confirmSensitive {
			return errors.New("--show-value 必须同时指定 --confirm-sensitive")
		}
		if c.showVal {
			values, err := c.st.ListDNSProfileSecretsWithValues(c.ctx, provider, profile)
			if err != nil {
				return err
			}
			return c.print(values)
		}
		result, err := c.st.ListDNSProfileSecrets(c.ctx, provider, profile)
		if err != nil {
			return err
		}
		return c.print(result)
	case "set":
		fs := c.flagSet("secret set")
		provider, profile, account, envKey, valueFile := "", "", "", "", ""
		valueStdin := false
		fs.StringVar(&provider, "provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "profile")
		fs.StringVar(&account, "account", "", "DNS account")
		fs.StringVar(&envKey, "env-key", "", "环境变量名")
		fs.StringVar(&valueFile, "value-file", "", "从安全文件读取 Secret 值")
		fs.BoolVar(&valueStdin, "value-stdin", false, "从标准输入读取 Secret 值")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" || profile == "" || envKey == "" {
			return errors.New("secret set 需要 --provider、--profile、--env-key 和 --value-stdin/--value-file")
		}
		if !valueStdin && valueFile == "" {
			return errors.New("禁止使用 --value，Secret 只允许 stdin 或安全文件")
		}
		if valueStdin && valueFile != "" {
			return errors.New("value-stdin 与 value-file 不能同时指定")
		}
		value, err := readSecretInput(c.in, valueFile)
		if err != nil {
			return err
		}
		if err := c.st.UpsertDNSProfileSecret(c.ctx, provider, profile, account, envKey, value); err != nil {
			return err
		}
		if err := c.addAudit("", "", "dns_secret_set", "succeeded", "更新 DNS profile secret"); err != nil {
			return fmt.Errorf("Secret 已写入但写入审计失败: %w", err)
		}
		return c.print(map[string]any{"ok": true, "provider": provider, "profile": profile, "env_key": envKey})
	case "delete":
		fs := c.flagSet("secret delete")
		provider, profile, envKey := "", "", ""
		fs.StringVar(&provider, "provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "profile")
		fs.StringVar(&envKey, "env-key", "", "环境变量名")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if provider == "" || profile == "" || envKey == "" {
			return errors.New("secret delete 需要 --provider、--profile 和 --env-key")
		}
		secrets, err := c.st.ListDNSProfileSecrets(c.ctx, provider, profile)
		if err != nil {
			return err
		}
		found := false
		for _, item := range secrets {
			if item.EnvKey == envKey {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("Secret 不存在: %s/%s/%s", provider, profile, envKey)
		}
		if err := c.st.DeleteDNSProfileSecret(c.ctx, provider, profile, envKey); err != nil {
			return err
		}
		if err := c.addAudit("", "", "dns_secret_delete", "succeeded", "删除 DNS profile secret"); err != nil {
			return fmt.Errorf("Secret 已删除但写入审计失败: %w", err)
		}
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 secret 子命令: %s", args[0])
	}
}

// certConfigV2 使用 patch 语义更新证书配置。
func (c *cli) certConfigV2(args []string) error {
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
		domain, san, mode, provider, profile, webroot, ca, keylength, reload, source := "", stringList{}, "", "", "", "", "", "", "", ""
		renewDays := 0
		fs.StringVar(&domain, "d", "", "主域名")
		fs.Var(&san, "san", "附加域名，可重复")
		fs.StringVar(&mode, "mode", "", "挑战模式")
		fs.StringVar(&provider, "dns-provider", "", "DNS provider")
		fs.StringVar(&profile, "profile", "", "DNS profile")
		fs.StringVar(&webroot, "webroot", "", "webroot 路径")
		fs.StringVar(&ca, "ca", "", "CA")
		fs.StringVar(&keylength, "keylength", "", "密钥长度")
		fs.IntVar(&renewDays, "renew-days", 0, "提前续签天数")
		fs.StringVar(&reload, "reload-cmd", "", "reload 命令")
		fs.StringVar(&source, "source", "", "配置来源")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("cert-config set 需要 -d DOMAIN")
		}
		current, err := c.st.GetCert(c.ctx, domain)
		if err != nil {
			return err
		}
		if current == nil {
			current = &store.Cert{Domain: domain}
		}
		if flagWasSet(fs, "san") {
			current.SAN = strings.Join(san, ",")
		}
		if flagWasSet(fs, "mode") {
			current.ChallengeMode = mode
		}
		if flagWasSet(fs, "dns-provider") {
			current.DNSProvider = nullable(provider)
		}
		if flagWasSet(fs, "profile") {
			current.DNSProfile = nullable(profile)
		}
		if flagWasSet(fs, "webroot") {
			current.WebrootPath = nullable(webroot)
		}
		if flagWasSet(fs, "ca") {
			current.CA = ca
		}
		if flagWasSet(fs, "keylength") {
			current.Keylength = keylength
		}
		if flagWasSet(fs, "renew-days") {
			current.RenewDays = renewDays
		}
		if flagWasSet(fs, "reload-cmd") {
			current.ReloadCmd = nullable(reload)
		}
		if flagWasSet(fs, "source") {
			current.Source = source
		}
		if current.ChallengeMode == "" {
			return errors.New("cert-config set 需要 --mode（新建配置）")
		}
		if err := c.svc.SaveCertConfig(c.ctx, current); err != nil {
			return err
		}
		_ = c.addAudit("", domain, "cert_config_set", "succeeded", "更新证书配置")
		return c.print(current)
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
		if current, err := c.st.GetCert(c.ctx, domain); err != nil {
			return err
		} else if current == nil {
			return fmt.Errorf("证书配置不存在: %s", domain)
		}
		if err := c.st.DeleteCert(c.ctx, domain); err != nil {
			return err
		}
		_ = c.addAudit("", domain, "cert_config_delete", "succeeded", "删除证书配置")
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 cert-config 子命令: %s", args[0])
	}
}

// grantV2 保留原有授权命令，并在写入后补审计与 not-found 检查。
func (c *cli) grantV2(args []string) error {
	if len(args) == 0 {
		return errors.New("grant 需要子命令：add/remove/list")
	}
	if args[0] == "list" {
		return c.grant(args)
	}
	fs := c.flagSet("grant " + args[0])
	tokenID, domain, permission := "", "", ""
	fs.StringVar(&tokenID, "token", "", "Token ID")
	fs.StringVar(&domain, "domain", "", "域名")
	fs.StringVar(&permission, "permission", "", "权限")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if tokenID == "" || domain == "" || permission == "" {
		return fmt.Errorf("grant %s 需要 --token ID、--domain DOMAIN 和 --permission PERMISSION", args[0])
	}
	if err := validateTokenID(tokenID); err != nil {
		return err
	}
	if err := validateV2Domain(domain); err != nil {
		return err
	}
	if err := validatePermission(permission); err != nil {
		return err
	}
	if token, err := c.st.GetToken(c.ctx, tokenID); err != nil {
		return err
	} else if token == nil {
		return fmt.Errorf("token 不存在: %s", tokenID)
	}
	var err error
	if args[0] == "add" {
		err = c.st.Grant(c.ctx, tokenID, domain, permission)
	} else if args[0] == "remove" {
		err = c.st.Revoke(c.ctx, tokenID, domain, permission)
	} else {
		return fmt.Errorf("未知 grant 子命令: %s", args[0])
	}
	if err != nil {
		return err
	}
	_ = c.addAudit(tokenID, domain, "grant_"+args[0], "succeeded", "更新证书授权")
	return c.print(map[string]any{"ok": true})
}

// jobV2 提供任务查询和显式状态控制。
func (c *cli) jobV2(args []string) error {
	if len(args) == 0 {
		return errors.New("job 需要子命令：list/show/retry/cancel")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("job list")
		domain, status := "", ""
		limit, offset := 100, 0
		fs.StringVar(&domain, "domain", "", "域名过滤")
		fs.StringVar(&status, "status", "", "状态过滤")
		fs.IntVar(&limit, "limit", 100, "数量")
		fs.IntVar(&offset, "offset", 0, "偏移量")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		result, err := c.st.ListCertificateJobs(c.ctx, store.JobFilter{Domain: domain, Status: status, Limit: limit, Offset: offset})
		if err != nil {
			return err
		}
		return c.print(result)
	case "show":
		fs := c.flagSet("job show")
		id := ""
		fs.StringVar(&id, "id", "", "任务 ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id == "" {
			return errors.New("job show 需要 --id ID")
		}
		result, err := c.st.GetCertificateJob(c.ctx, id)
		if err != nil {
			return err
		}
		if result == nil {
			return fmt.Errorf("任务不存在: %s", id)
		}
		return c.print(result)
	case "retry", "cancel":
		fs := c.flagSet("job " + args[0])
		id, message := "", ""
		fs.StringVar(&id, "id", "", "任务 ID")
		fs.StringVar(&message, "message", "", "原因")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id == "" {
			return errors.New("job 操作需要 --id ID")
		}
		job, err := c.st.GetCertificateJob(c.ctx, id)
		if err != nil {
			return err
		}
		if job == nil {
			return fmt.Errorf("任务不存在: %s", id)
		}
		if args[0] == "retry" && job.Status == "succeeded" {
			return errors.New("succeeded 任务不支持 retry")
		}
		state := "queued"
		if args[0] == "cancel" {
			state = "cancelled"
		}
		if err := c.st.UpdateCertificateJobStatus(c.ctx, id, state, message); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("任务不存在: %s", id)
			}
			return err
		}
		_ = c.addAudit("", job.Domain, "job_"+args[0], "succeeded", "更新任务状态")
		return c.print(map[string]any{"ok": true, "id": id, "status": state})
	default:
		return fmt.Errorf("未知 job 子命令: %s", args[0])
	}
}

// generationV2 查询和清理证书仓储 generation。
func (c *cli) generationV2(args []string) error {
	if len(args) == 0 {
		return errors.New("generation 需要子命令：list/show/gc/deployments")
	}
	switch args[0] {
	case "list":
		fs := c.flagSet("generation list")
		domain := ""
		fs.StringVar(&domain, "domain", "", "域名")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("generation list 需要 --domain DOMAIN")
		}
		result, err := c.st.ListCertificateGenerations(c.ctx, domain)
		if err != nil {
			return err
		}
		for i := range result {
			result[i].PrivateKeyRef = store.JSONNullString{}
		}
		return c.print(result)
	case "show":
		fs := c.flagSet("generation show")
		id := int64(0)
		fs.Int64Var(&id, "id", 0, "generation 数据库 ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id <= 0 {
			return errors.New("generation show 需要 --id N")
		}
		result, err := c.st.GetCertificateGeneration(c.ctx, id)
		if err != nil {
			return err
		}
		if result == nil {
			return fmt.Errorf("generation 不存在: %d", id)
		}
		result.PrivateKeyRef = store.JSONNullString{}
		return c.print(result)
	case "deployments":
		fs := c.flagSet("generation deployments")
		id := int64(0)
		fs.Int64Var(&id, "id", 0, "generation 数据库 ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if id <= 0 {
			return errors.New("generation deployments 需要 --id N")
		}
		result, err := c.st.ListDeploymentReports(c.ctx, id)
		if err != nil {
			return err
		}
		return c.print(result)
	case "gc":
		fs := c.flagSet("generation gc")
		domain, protected := "", stringList{}
		keep := 1
		fs.StringVar(&domain, "domain", "", "域名")
		fs.IntVar(&keep, "keep-recent", 1, "保留最近 generation 数量")
		fs.Var(&protected, "protect", "保护 generation，可重复")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if domain == "" {
			return errors.New("generation gc 需要 --domain DOMAIN")
		}
		if keep < 0 {
			return errors.New("keep-recent 不能为负数")
		}
		cfg, err := c.cfgOrError()
		if err != nil {
			return err
		}
		cs, err := certstore.Open(cfg.Acme.CertsDir)
		if err != nil {
			return err
		}
		result, err := cs.GC(domain, certstore.GCOptions{KeepRecent: keep, ProtectedGenerations: toGenerationIDs(protected)})
		if err != nil {
			return err
		}
		_ = c.addAudit("", domain, "generation_gc", "succeeded", "清理 generation")
		return c.print(result)
	default:
		return fmt.Errorf("未知 generation 子命令: %s", args[0])
	}
}

func toGenerationIDs(values []string) []certproto.GenerationID {
	out := make([]certproto.GenerationID, 0, len(values))
	for _, value := range values {
		out = append(out, certproto.GenerationID(value))
	}
	return out
}

// backupV2 将数据库、兼容密钥、证书仓储和 ACME 状态交给 store 备份底层处理。
func (c *cli) backupV2(args []string) error {
	if len(args) == 0 {
		return errors.New("backup 需要子命令：create/verify/restore")
	}
	cfg, err := c.cfgOrError()
	if err != nil {
		return err
	}
	switch args[0] {
	case "create":
		if c.st == nil {
			return errors.New("backup create 需要数据库")
		}
		fs := c.flagSet("backup create")
		destination := ""
		fs.StringVar(&destination, "destination", "", "备份目录")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if destination == "" {
			return errors.New("backup create 需要 --destination DIR")
		}
		manifest, err := c.st.CreateBackup(c.ctx, store.BackupOptions{Destination: destination, CertificateRepositoryPath: cfg.Acme.CertsDir, ACMEStatePath: cfg.Acme.Home})
		if err != nil {
			return err
		}
		_ = c.addAudit("", "", "backup_create", "succeeded", "创建备份")
		return c.print(manifest)
	case "verify":
		fs := c.flagSet("backup verify")
		path := ""
		fs.StringVar(&path, "path", "", "备份目录")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if path == "" {
			return errors.New("backup verify 需要 --path DIR")
		}
		manifest, err := store.ValidateBackup(c.ctx, path)
		if err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true, "manifest": manifest})
	case "restore":
		fs := c.flagSet("backup restore")
		path, confirm := "", false
		fs.StringVar(&path, "path", "", "备份目录")
		fs.BoolVar(&confirm, "confirm-dangerous-restore", false, "确认危险恢复")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if path == "" {
			return errors.New("backup restore 需要 --path DIR")
		}
		if !confirm {
			return errors.New("backup restore 是危险操作，必须指定 --confirm-dangerous-restore")
		}
		if c.st != nil {
			return errors.New("backup restore 不能在当前进程已打开数据库时执行")
		}
		if err := store.RestoreBackup(c.ctx, store.RestoreOptions{BackupPath: path, DatabasePath: cfg.Storage.SQLitePath, CertificateRepositoryPath: cfg.Acme.CertsDir, ACMEStatePath: cfg.Acme.Home}); err != nil {
			return err
		}
		return c.print(map[string]any{"ok": true})
	default:
		return fmt.Errorf("未知 backup 子命令: %s", args[0])
	}
}

// migrateV2 只读检查 schema_migrations，不调用 store.Open，因此不会隐式迁移。
func (c *cli) migrateV2(args []string) error {
	if len(args) == 0 {
		return errors.New("migrate 需要子命令：status/verify")
	}
	if c.cfg == nil {
		return errors.New("配置尚未加载")
	}
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro", c.cfg.Storage.SQLitePath))
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.QueryContext(c.ctx, "SELECT name, applied_at FROM schema_migrations ORDER BY name")
	if err != nil {
		return errors.New("无法读取迁移状态：数据库可能尚未初始化")
	}
	defer rows.Close()
	type migration struct {
		Name      string `json:"name"`
		AppliedAt int64  `json:"applied_at"`
	}
	var migrations []migration
	for rows.Next() {
		var item migration
		if err := rows.Scan(&item.Name, &item.AppliedAt); err != nil {
			return err
		}
		migrations = append(migrations, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if args[0] == "status" {
		return c.print(migrations)
	}
	if args[0] != "verify" {
		return fmt.Errorf("未知 migrate 子命令: %s", args[0])
	}
	if len(migrations) == 0 {
		return errors.New("迁移未完成：没有已应用迁移")
	}
	return c.print(map[string]any{"ok": true, "migrations": migrations})
}
