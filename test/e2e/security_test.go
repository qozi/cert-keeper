// 本文件覆盖 v2 链路的关键安全属性：
// deny-by-default 授权（含 admin 不绕过）与请求体篡改检测。
package e2e

import (
	"net/http"
	"testing"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

// TestE2EDenyByDefault 验证无 grant 的 token 对 reconcile/status/私钥下载等
// 全部 v2 操作均被拒绝（403），且 admin 身份同样不绕过域名授权。
func TestE2EDenyByDefault(t *testing.T) {
	env := newE2EEnv(t)
	domain := "deny.example.test"
	env.presetDNSAPICert(t, domain)

	// 普通 token：没有任何 grant。
	const tokenID = "client-deny"
	secret := env.createToken(t, tokenID, false)
	// admin token：同样没有 grant，用于验证 admin 不绕过授权。
	const adminID = "admin-deny"
	adminSecret := env.createToken(t, adminID, true)

	reconcilePath, err := certproto.ReconcileURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	statusPath, err := certproto.CertificateStatusURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}
	keyPath, err := certproto.CertificateFileURLPath(domain, "g-deny", "key.pem")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := certproto.ManifestURLPath(domain, "g-deny")
	if err != nil {
		t.Fatal(err)
	}
	deployPath, err := certproto.DeploymentsURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		tokenID string
		secret  string
		method  string
		path    string
		body    []byte
	}{
		{"无 grant reconcile", tokenID, secret, http.MethodPost, reconcilePath, []byte(`{"idempotency_key":"deny-key-1"}`)},
		{"无 grant status", tokenID, secret, http.MethodGet, statusPath, nil},
		{"无 grant 下载 key.pem", tokenID, secret, http.MethodGet, keyPath, nil},
		{"无 grant 读取 manifest", tokenID, secret, http.MethodGet, manifestPath, nil},
		{"无 grant 部署回报", tokenID, secret, http.MethodPost, deployPath, []byte(`{"target":"node-1","state":"succeeded","success":true}`)},
		{"admin 无 grant status", adminID, adminSecret, http.MethodGet, statusPath, nil},
		{"admin 无 grant reconcile", adminID, adminSecret, http.MethodPost, reconcilePath, []byte(`{"idempotency_key":"deny-key-2"}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := env.signedDo(t, tc.tokenID, tc.secret, tc.method, tc.path, tc.body)
			if code != http.StatusForbidden {
				t.Fatalf("状态码 = %d，期望 403: %s", code, body)
			}
		})
	}
	// 所有请求都被拒绝，签发器不应被调用。
	if got := env.issuer.calls.Load(); got != 0 {
		t.Fatalf("无授权场景下签发器被调用 %d 次", got)
	}
}

// TestE2EBodyTamper 验证请求体篡改检测：保留合法签名与 X-CK-BodyHash，
// 仅替换请求体时服务端必须拒绝（401）。
func TestE2EBodyTamper(t *testing.T) {
	env := newE2EEnv(t)
	domain := "tamper.example.test"
	env.presetDNSAPICert(t, domain)

	const tokenID = "client-tamper"
	secret := env.createToken(t, tokenID, false)
	env.grant(t, tokenID, domain, "apply")

	reconcilePath, err := certproto.ReconcileURLPath(domain)
	if err != nil {
		t.Fatal(err)
	}

	// 对照组：原始请求体 + 按它计算的签名头，必须通过。
	originalBody := []byte(`{"idempotency_key":"tamper-key-1"}`)
	header := signHeaders(t, tokenID, secret, http.MethodPost, reconcilePath, originalBody)
	code, body := env.doRaw(t, http.MethodPost, reconcilePath, originalBody, header)
	if code != http.StatusOK {
		t.Fatalf("合法签名请求状态码 = %d，期望 200: %s", code, body)
	}

	// 篡改组：保持原 X-CK-BodyHash 与签名不变，仅替换请求体，必须 401。
	tamperedBody := []byte(`{"idempotency_key":"tamper-key-2","force":true}`)
	code, body = env.doRaw(t, http.MethodPost, reconcilePath, tamperedBody, header)
	if code != http.StatusUnauthorized {
		t.Fatalf("篡改请求状态码 = %d，期望 401: %s", code, body)
	}

	// 只有对照组触发了一次真实签发。
	if got := env.issuer.calls.Load(); got != 1 {
		t.Fatalf("签发次数 = %d，期望 1（仅合法请求）", got)
	}
}
