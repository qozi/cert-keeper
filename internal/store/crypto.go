// 本文件提供 v2 机密字段的 AES-256-GCM 加密及本地 KEK 管理。
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

const kekSize = 32

// loadOrCreateKEK 为每个数据库创建独立的随机 32 字节 KEK。
// KEK 位于权限为 0600 的同目录文件，使数据库备份不会包含可直接解密的密钥。
func loadOrCreateKEK(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != kekSize {
			return nil, errors.New("数据库密钥长度无效")
		}
		if err := chmodIfSupported(path, 0o600); err != nil {
			return nil, err
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key = make([]byte, kekSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateKEK(path)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Write(key); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptAESGCM(plain string, key, aad []byte) (string, error) {
	if len(key) != kekSize {
		return "", errors.New("AES-256 密钥长度无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), aad)), nil
}

func decryptAESGCM(ciphertext string, key, aad []byte) (string, error) {
	if len(key) != kekSize {
		return "", errors.New("AES-256 密钥长度无效")
	}
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", errors.New("密文编码无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("密文长度不足")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad)
	if err != nil {
		return "", errors.New("无法验证或解密机密")
	}
	return string(plain), nil
}

func tokenSecretAAD(id string) []byte {
	return []byte(fmt.Sprintf("certkeeper/tokens/v2/id=%s", id))
}

func dnsSecretAAD(provider, profile, envKey string) []byte {
	return []byte(fmt.Sprintf("certkeeper/dns-profiles/v2/provider=%s/profile=%s/env_key=%s", provider, profile, envKey))
}
