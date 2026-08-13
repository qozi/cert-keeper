// 本文件提供旧 DNS Secret 的兼容读取和默认 profile 适配。
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// DNSSecret 表示 DNS 服务商的机密元数据。列表不填充 EnvValue。
type DNSSecret struct {
	ID        int64  `json:"id"`
	Provider  string `json:"provider"`
	Profile   string `json:"profile,omitempty"`
	Account   string `json:"account,omitempty"`
	EnvKey    string `json:"env_key"`
	EnvValue  string `json:"env_value,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

// MarshalJSON 默认不输出 DNS Secret 明文。
func (s DNSSecret) MarshalJSON() ([]byte, error) {
	type dnsSecretJSON struct {
		ID        int64  `json:"id"`
		Provider  string `json:"provider"`
		Profile   string `json:"profile,omitempty"`
		Account   string `json:"account,omitempty"`
		EnvKey    string `json:"env_key"`
		CreatedAt int64  `json:"created_at"`
	}
	return json.Marshal(dnsSecretJSON{ID: s.ID, Provider: s.Provider, Profile: s.Profile, Account: s.Account, EnvKey: s.EnvKey, CreatedAt: s.CreatedAt})
}

// String 避免日志格式化 DNSSecret 时泄露其机密。
func (s DNSSecret) String() string {
	return fmt.Sprintf("DNSSecret{ID:%d Provider:%q Profile:%q EnvKey:%q}", s.ID, s.Provider, s.Profile, s.EnvKey)
}

// encryptSecret 使用 v1 密钥格式加密，仅用于测试和模拟旧记录。
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
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plain), nil)), nil
}

// decryptSecret 使用 v1 密钥格式解密，仅用于读取升级前记录。
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
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// UpsertSecret 创建或更新默认 profile 的 DNS Secret，兼容 v1 调用。
// keyStr 只用于读取升级前记录，新写入使用数据库随机 KEK。
func (s *Store) UpsertSecret(ctx context.Context, provider, envKey, envValue, keyStr string) error {
	return s.UpsertDNSProfileSecret(ctx, provider, "default", "", envKey, envValue)
}

// ListSecrets 列出 DNS Secret 元数据。负数 ID 表示 v2 profile 记录。
func (s *Store) ListSecrets(ctx context.Context) ([]DNSSecret, error) {
	v2, err := s.listV2DNSSecrets(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, provider, env_key, created_at FROM dns_secrets ORDER BY provider, env_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := v2
	v2DefaultKeys := make(map[string]struct{}, len(v2))
	for _, item := range v2 {
		if item.Profile == "default" {
			v2DefaultKeys[item.Provider+"\x00"+item.EnvKey] = struct{}{}
		}
	}
	for rows.Next() {
		var item DNSSecret
		if err := rows.Scan(&item.ID, &item.Provider, &item.EnvKey, &item.CreatedAt); err != nil {
			return nil, err
		}
		if _, shadowed := v2DefaultKeys[item.Provider+"\x00"+item.EnvKey]; shadowed {
			continue
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ListSecretsByProvider 读取默认 profile 的明文参数，并兼容补充旧记录。
func (s *Store) ListSecretsByProvider(ctx context.Context, provider, keyStr string) (map[string]string, error) {
	out, err := s.ListDNSProfileSecretsWithValues(ctx, provider, "default")
	if err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT env_key, env_value FROM dns_secrets WHERE provider=?`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var envKey, ciphertext string
		if err := rows.Scan(&envKey, &ciphertext); err != nil {
			return nil, err
		}
		plain, err := decryptSecret(ciphertext, keyStr)
		if err != nil {
			return nil, fmt.Errorf("解密旧 DNS secret 失败: %w", err)
		}
		if _, exists := out[envKey]; !exists {
			out[envKey] = plain
		}
	}
	return out, rows.Err()
}

// SecretParameter 表示 provider 已配置参数项，受控调用才会填充 EnvValue 明文。
type SecretParameter struct {
	EnvKey    string `json:"env_key"`
	EnvValue  string `json:"env_value"`
	CreatedAt int64  `json:"created_at"`
}

// MarshalJSON 默认对受控读取的明文参数进行脱敏。
func (p SecretParameter) MarshalJSON() ([]byte, error) {
	type parameterJSON struct {
		EnvKey    string `json:"env_key"`
		EnvValue  string `json:"env_value,omitempty"`
		CreatedAt int64  `json:"created_at"`
	}
	value := ""
	if p.EnvValue != "" {
		value = "***"
	}
	return json.Marshal(parameterJSON{EnvKey: p.EnvKey, EnvValue: value, CreatedAt: p.CreatedAt})
}

// String 避免日志格式化 SecretParameter 时泄露其机密。
func (p SecretParameter) String() string {
	return fmt.Sprintf("SecretParameter{EnvKey:%q}", p.EnvKey)
}

// ListSecretParameters 列出默认 profile 的参数，兼容读取旧记录。
func (s *Store) ListSecretParameters(ctx context.Context, provider, keyStr string) ([]SecretParameter, error) {
	values, err := s.ListSecretsByProvider(ctx, provider, keyStr)
	if err != nil {
		return nil, err
	}
	createdAt, err := s.defaultSecretTimes(ctx, provider)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]SecretParameter, 0, len(keys))
	for _, key := range keys {
		out = append(out, SecretParameter{EnvKey: key, EnvValue: values[key], CreatedAt: createdAt[key]})
	}
	return out, nil
}

func (s *Store) defaultSecretTimes(ctx context.Context, provider string) (map[string]int64, error) {
	times := map[string]int64{}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT dps.env_key, dps.updated_at FROM dns_profile_secrets dps
		JOIN dns_profiles dp ON dp.id=dps.profile_id
		WHERE dp.provider=? AND dp.profile='default'`, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var at int64
		if err := rows.Scan(&key, &at); err != nil {
			return nil, err
		}
		times[key] = at
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	legacyRows, err := s.DB.QueryContext(ctx, `SELECT env_key, created_at FROM dns_secrets WHERE provider=?`, provider)
	if err != nil {
		return nil, err
	}
	defer legacyRows.Close()
	for legacyRows.Next() {
		var key string
		var at int64
		if err := legacyRows.Scan(&key, &at); err != nil {
			return nil, err
		}
		if _, exists := times[key]; !exists {
			times[key] = at
		}
	}
	return times, legacyRows.Err()
}

// ConfiguredProviders 返回旧记录和 v2 profile 中的 provider 名称。
func (s *Store) ConfiguredProviders(ctx context.Context) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT DISTINCT provider FROM (
			SELECT provider FROM dns_secrets
			UNION
			SELECT provider FROM dns_profiles
		) ORDER BY provider`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var providers []string
	for rows.Next() {
		var provider string
		if err := rows.Scan(&provider); err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	return providers, rows.Err()
}

// DeleteSecret 根据 ID 删除 DNS Secret。负数 ID 表示 v2 profile 记录。
func (s *Store) DeleteSecret(ctx context.Context, id int64) error {
	if id < 0 {
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var provider, profile, envKey string
		err = tx.QueryRowContext(ctx, `
			SELECT dp.provider, dp.profile, dps.env_key FROM dns_profile_secrets dps
			JOIN dns_profiles dp ON dp.id=dps.profile_id WHERE dps.id=?`, -id).
			Scan(&provider, &profile, &envKey)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM dns_profile_secrets WHERE id=?`, -id); err != nil {
			return err
		}
		if profile == "default" {
			if _, err := tx.ExecContext(ctx, `DELETE FROM dns_secrets WHERE provider=? AND env_key=?`, provider, envKey); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM dns_secrets WHERE id=?`, id)
	return err
}

// DeleteSecretByKV 删除默认 profile 的机密和同名旧记录。
func (s *Store) DeleteSecretByKV(ctx context.Context, provider, envKey string) error {
	if err := s.DeleteDNSProfileSecret(ctx, provider, "default", envKey); err != nil {
		return err
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM dns_secrets WHERE provider=? AND env_key=?`, provider, envKey)
	return err
}

var _ = sql.ErrNoRows
