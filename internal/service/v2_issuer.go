// 本文件定义 v2 可注入证书签发器及其基于 acme.Runner 的默认实现。
package service

import (
	"context"
	"errors"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/config"
)

// V2IssueParams 定义 v2 签发参数。所有参数仅来自服务端预置证书配置，
// 调用方不能通过请求覆盖 SAN/CA/provider/keylength。
type V2IssueParams struct {
	Domain      string
	SAN         []string
	CA          string
	Keylength   string
	DNSProvider string
	DNSProfile  string
	Force       bool
	// DNSEnv 是已解密的 DNS 环境变量，签发器不得将其写入日志或错误。
	DNSEnv map[string]string
	// StagingDir 是签发产物目录。签发器负责创建该目录，并写入
	// cert.pem、key.pem、fullchain.pem、ca.pem（可选 time.log）。
	StagingDir string
}

// V2Issuer 是可注入的 v2 证书签发器，测试可使用假实现而不依赖 acme。
type V2Issuer interface {
	Issue(ctx context.Context, params V2IssueParams) error
}

// acmeV2Issuer 是基于 acme.Runner.Issue 的默认 v2 签发器，仅支持 dns_api。
type acmeV2Issuer struct {
	cfg *config.Config
}

// Issue 调用 acme.sh 签发并安装到 StagingDir。返回的错误绝不携带 ACME 原始输出。
func (i *acmeV2Issuer) Issue(ctx context.Context, params V2IssueParams) error {
	runner := &acme.Runner{
		AcmeShPath: i.cfg.Acme.AcmeShPath,
		Home:       i.cfg.Acme.Home,
		ConfigHome: i.cfg.Acme.Home,
		CertsDir:   i.cfg.Acme.CertsDir,
		Timeout:    i.cfg.Acme.IssueTimeout,
	}
	res, err := runner.IssueOrRenew(ctx, &acme.IssueParams{
		Domain:        params.Domain,
		SAN:           params.SAN,
		CA:            params.CA,
		ChallengeMode: "dns_api",
		DNSProvider:   params.DNSProvider,
		Keylength:     params.Keylength,
		DNSEnv:        params.DNSEnv,
		Profile:       params.DNSProfile,
		StagingDir:    params.StagingDir,
	}, params.Force)
	if err != nil {
		// 刻意忽略 res.StdoutStderr，避免把 ACME 原始输出传回调用方。
		return err
	}
	// OperationSkipped 表示证书未到期、acme.sh 跳过签发，视为成功。
	if res == nil || (res.Status != acme.OperationSucceeded && res.Status != acme.OperationSkipped) {
		return errors.New("ACME 签发未完成")
	}
	return nil
}
