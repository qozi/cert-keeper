// Package ckauth 提供 CertKeeper 的认证与签名工具函数。
// 包含 HMAC 签名、Token 生成、密钥派生等安全相关功能。
package ckauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

const (
	// HeaderTokenID 是用于传递 Token ID 的 HTTP 请求头名称。
	HeaderTokenID = "X-CK-Token-Id"
	// HeaderTimestamp 是用于传递请求时间戳的 HTTP 请求头名称。
	HeaderTimestamp = "X-CK-Timestamp"
	// HeaderNonce 是用于传递防重放随机数的 HTTP 请求头名称。
	HeaderNonce = "X-CK-Nonce"
	// HeaderSignature 是用于传递 HMAC 签名的 HTTP 请求头名称。
	HeaderSignature = "X-CK-Signature"
	// HeaderBodyHash 是用于传递请求体 SHA-256 摘要的 HTTP 请求头名称。
	HeaderBodyHash = "X-CK-BodyHash"
	// HeaderClientToken 是客户端 Token 的标准 Authorization 请求头名称。
	HeaderClientToken = "Authorization"

	// NonceLen 定义随机 nonce 的字节长度。
	NonceLen = 16
	// TokenIDLen 定义 Token ID 的字节长度。
	TokenIDLen = 12
	// SecretLen 定义密钥的字节长度。
	SecretLen = 32
	// TokenIDMaxLen 定义请求头中 Token ID 的最大字节长度。
	TokenIDMaxLen = 64
	// TimestampMaxLen 定义时间戳十进制字符串的最大长度。
	TimestampMaxLen = 20
	// NonceHexLen 定义 nonce 十六进制字符串的固定长度。
	NonceHexLen = NonceLen * 2
	// HashHexLen 定义 SHA-256 十六进制字符串的固定长度。
	HashHexLen = 64
	// EmptyBodyHash 是空请求体使用的协议摘要值。
	EmptyBodyHash = "0"
)

// Now 返回当前时间的 Unix 时间戳（秒）。
func Now() int64 { return time.Now().Unix() }

// RandomHex 生成指定字节数的随机十六进制字符串。
func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenTokenID 生成一个随机的 Token ID。
func GenTokenID() (string, error) { return RandomHex(TokenIDLen / 2) }

// GenSecret 生成一个随机的密钥字符串。
func GenSecret() (string, error) { return RandomHex(SecretLen) }

// GenNonce 生成一个随机的 nonce 字符串。
func GenNonce() (string, error) { return RandomHex(NonceLen) }

// DeriveSecret 若配置了主密钥，则用 ID 作为派生信息生成可预测的 admin secret；
// 否则返回 fallback 随机 secret。便于无文件状态下从加密密钥推导出 admin 凭据。
func DeriveSecret(encKey, id, fallback string) string {
	if encKey == "" {
		return fallback
	}
	// SHA-256 HMAC 输出 32 字节 = 64 十六进制字符，SecretLen*2=64 恰好取完整输出，保留 256 位熵。
	return hmacHex(id+"|"+encKey, encKey)[:SecretLen*2]
}

// 计算 HMAC 风格签名：sha256(method + path + ts + nonce + bodySHA256 + secret)
// 简化版兼容性：直接 sha256(escaped_string, secret) HMAC
func Sign(method, path string, ts int64, nonce, bodyHash, secret string) string {
	payload := fmt.Sprintf("%s\n%s\n%d\n%s\n%s", method, path, ts, nonce, bodyHash)
	return hmacHex(payload, secret)
}
