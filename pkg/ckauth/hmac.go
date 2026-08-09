// 本文件提供 HMAC-SHA256 签名相关的内部工具函数。
package ckauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// hmacHex 使用 HMAC-SHA256 计算签名并返回十六进制字符串。
func hmacHex(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// SecureEqual 使用恒定时间比较两个十六进制签名字符串是否相等，防止时序攻击。
func SecureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}
