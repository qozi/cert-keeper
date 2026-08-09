// 本文件提供密钥派生相关的工具函数。
package store

import (
	"crypto/sha256"
)

// deriveKey 将任意长字符串派生为 32 字节 AES 密钥。
func deriveKey(s string) []byte {
	if len(s) == 32 {
		return []byte(s)
	}
	h := sha256.Sum256([]byte(s))
	return h[:]
}
