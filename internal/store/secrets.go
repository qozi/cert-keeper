// 本文件提供 DNS Secret 的加解密存储功能。
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

// DNSSecret 表示 DNS 服务商的密钥信息。
type DNSSecret struct {
	ID        int64  `json:"id"`
	Provider  string `json:"provider"`
	EnvKey    string `json:"env_key"`
	EnvValue  string `json:"env_value"` // 加密前 / 解密后的明文
	CreatedAt int64  `json:"created_at"`
}

// encryptSecret 使用 AES-256-GCM 加密明文。key 长度须为 32 字节，若不足则 sha256 派生。
func encryptSecret(plain, keyStr string) (string, error) {
	key := deriveKey(keyStr)
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
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decryptSecret 使用 AES-256-GCM 解密密文。
func decryptSecret(cipherB64, keyStr string) (string, error) {
	key := deriveKey(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("密文长度不足")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// UpsertSecret 创建或更新 DNS Secret，值会被加密存储。
func (s *Store) UpsertSecret(ctx context.Context, provider, envKey, envValue, keyStr string) error {
	enc, err := encryptSecret(envValue, keyStr)
	if err != nil {
		return fmt.Errorf("加密 Secret 失败: %w", err)
	}
	now := time.Now().Unix()
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO dns_secrets(provider, env_key, env_value, created_at) VALUES(?, ?, ?, ?)
		 ON CONFLICT(provider, env_key) DO UPDATE SET env_value=excluded.env_value, created_at=excluded.created_at`,
		provider, envKey, enc, now)
	return err
}

// ListSecrets 列出所有 DNS Secret（值为加密后的密文）。
func (s *Store) ListSecrets(ctx context.Context) ([]DNSSecret, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, provider, env_key, env_value, created_at FROM dns_secrets ORDER BY provider, env_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSSecret
	for rows.Next() {
		var d DNSSecret
		var enc string
		if err := rows.Scan(&d.ID, &d.Provider, &d.EnvKey, &enc, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.EnvValue = enc // 列表不返回明文
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListSecretsByProvider 列出指定服务商的所有 Secret，并解密返回明文。
func (s *Store) ListSecretsByProvider(ctx context.Context, provider, keyStr string) (map[string]string, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT env_key, env_value FROM dns_secrets WHERE provider=?`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var envKey, enc string
		if err := rows.Scan(&envKey, &enc); err != nil {
			return nil, err
		}
		pt, err := decryptSecret(enc, keyStr)
		if err != nil {
			return nil, fmt.Errorf("解密 %s/%s 失败: %w", provider, envKey, err)
		}
		out[envKey] = pt
	}
	return out, rows.Err()
}

// DeleteSecret 根据 ID 删除 DNS Secret。
func (s *Store) DeleteSecret(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM dns_secrets WHERE id=?`, id)
	return err
}

// DeleteSecretByKV 根据服务商和环境变量键删除 DNS Secret。
func (s *Store) DeleteSecretByKV(ctx context.Context, provider, envKey string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM dns_secrets WHERE provider=? AND env_key=?`, provider, envKey)
	return err
}

var _ = sql.ErrNoRows
