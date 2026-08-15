// 本文件提供 DNS provider profile 的账号隔离和机密存储。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DNSProfile 表示同一 DNS 服务商下独立的账号或用途配置。
type DNSProfile struct {
	ID        string `json:"id"`
	Provider  string `json:"provider"`
	Profile   string `json:"profile"`
	Account   string `json:"account"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// DNSProfileSecret 是 profile 中机密项的元数据，默认不包含机密值。
type DNSProfileSecret struct {
	ID        int64  `json:"id"`
	ProfileID string `json:"profile_id"`
	EnvKey    string `json:"env_key"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// UpsertDNSProfile 创建或更新 DNS provider profile。
func (s *Store) UpsertDNSProfile(ctx context.Context, profile *DNSProfile) error {
	if profile == nil {
		return errors.New("DNS profile 不能为空")
	}
	if err := validateDNSProfile(profile.Provider, profile.Profile); err != nil {
		return err
	}
	if strings.Contains(profile.Account, "\x00") {
		return errors.New("DNS account 格式无效")
	}
	profile.ID = dnsProfileID(profile.Provider, profile.Profile)
	now := time.Now().Unix()
	if profile.CreatedAt == 0 {
		profile.CreatedAt = now
	}
	profile.UpdatedAt = now
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO dns_profiles(id, provider, profile, account, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, profile) DO UPDATE SET account=excluded.account, updated_at=excluded.updated_at`,
		profile.ID, profile.Provider, profile.Profile, profile.Account, profile.CreatedAt, profile.UpdatedAt)
	return err
}

// GetDNSProfile 按 provider/profile 获取账号隔离配置，不存在时返回 nil。
func (s *Store) GetDNSProfile(ctx context.Context, provider, profile string) (*DNSProfile, error) {
	var item DNSProfile
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, provider, profile, account, created_at, updated_at FROM dns_profiles WHERE provider=? AND profile=?`, provider, profile).
		Scan(&item.ID, &item.Provider, &item.Profile, &item.Account, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// ListDNSProfiles 列出全部 DNS provider profile，不包含机密值。
func (s *Store) ListDNSProfiles(ctx context.Context, provider string) ([]DNSProfile, error) {
	q := `SELECT id, provider, profile, account, created_at, updated_at FROM dns_profiles`
	args := []any{}
	if provider != "" {
		q += ` WHERE provider=?`
		args = append(args, provider)
	}
	q += ` ORDER BY provider, profile`
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var profiles []DNSProfile
	for rows.Next() {
		var item DNSProfile
		if err := rows.Scan(&item.ID, &item.Provider, &item.Profile, &item.Account, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		profiles = append(profiles, item)
	}
	return profiles, rows.Err()
}

// DeleteDNSProfile 删除指定 profile 及其全部机密。
func (s *Store) DeleteDNSProfile(ctx context.Context, provider, profile string) error {
	var references int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs WHERE dns_provider=? AND dns_profile=?`, provider, profile).Scan(&references); err != nil {
		return err
	}
	if references > 0 {
		return errors.New("DNS profile 仍被证书配置引用")
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM dns_profiles WHERE provider=? AND profile=?`, provider, profile)
	return err
}

// UpsertDNSProfileSecret 创建或更新 profile 机密。provider/profile/env_key 全部纳入 AAD。
func (s *Store) UpsertDNSProfileSecret(ctx context.Context, provider, profile, account, envKey, value string) error {
	if err := validateDNSProfile(provider, profile); err != nil {
		return err
	}
	if err := validateEnvKey(envKey); err != nil {
		return err
	}
	if value == "" {
		return errors.New("DNS secret 不能为空")
	}
	item := &DNSProfile{Provider: provider, Profile: profile, Account: account}
	if err := s.UpsertDNSProfile(ctx, item); err != nil {
		return err
	}
	ciphertext, err := encryptAESGCM(value, s.kek, dnsSecretAAD(provider, profile, envKey))
	if err != nil {
		return fmt.Errorf("加密 DNS secret 失败: %w", err)
	}
	now := time.Now().Unix()
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO dns_profile_secrets(profile_id, env_key, secret_ciphertext, created_at, updated_at) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(profile_id, env_key) DO UPDATE SET secret_ciphertext=excluded.secret_ciphertext, updated_at=excluded.updated_at`,
		item.ID, envKey, ciphertext, now, now)
	return err
}

// ListDNSProfileSecrets 列出 profile 机密元数据，绝不返回明文或密文。
func (s *Store) ListDNSProfileSecrets(ctx context.Context, provider, profile string) ([]DNSProfileSecret, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT dps.id, dps.profile_id, dps.env_key, dps.created_at, dps.updated_at
		FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
		WHERE dp.provider=? AND dp.profile=? ORDER BY dps.env_key`, provider, profile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var secrets []DNSProfileSecret
	for rows.Next() {
		var item DNSProfileSecret
		if err := rows.Scan(&item.ID, &item.ProfileID, &item.EnvKey, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, item)
	}
	return secrets, rows.Err()
}

// ListDNSProfileSecretsWithValues 是受控明文读取入口，供签发流程注入环境变量。
func (s *Store) ListDNSProfileSecretsWithValues(ctx context.Context, provider, profile string) (map[string]string, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT dps.env_key, dps.secret_ciphertext
		FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
		WHERE dp.provider=? AND dp.profile=?`, provider, profile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var envKey, ciphertext string
		if err := rows.Scan(&envKey, &ciphertext); err != nil {
			return nil, err
		}
		value, err := s.decryptStoredSecret(ciphertext, dnsSecretAAD(provider, profile, envKey))
		if err != nil {
			return nil, fmt.Errorf("解密 DNS secret 失败: %w", err)
		}
		values[envKey] = value
	}
	return values, rows.Err()
}

// DeleteDNSProfileSecret 删除 profile 中的一项机密。
func (s *Store) DeleteDNSProfileSecret(ctx context.Context, provider, profile, envKey string) error {
	_, err := s.DB.ExecContext(ctx, `
		DELETE FROM dns_profile_secrets WHERE id IN (
			SELECT dps.id FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
			WHERE dp.provider=? AND dp.profile=? AND dps.env_key=?
		)`, provider, profile, envKey)
	return err
}

func (s *Store) listV2DNSSecrets(ctx context.Context) ([]DNSSecret, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT dps.id, dp.provider, dp.profile, dp.account, dps.env_key, dps.created_at
		FROM dns_profile_secrets dps JOIN dns_profiles dp ON dp.id=dps.profile_id
		ORDER BY dp.provider, dp.profile, dps.env_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var secrets []DNSSecret
	for rows.Next() {
		var item DNSSecret
		if err := rows.Scan(&item.ID, &item.Provider, &item.Profile, &item.Account, &item.EnvKey, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.ID = -item.ID
		secrets = append(secrets, item)
	}
	return secrets, rows.Err()
}

func dnsProfileID(provider, profile string) string { return provider + "\x00" + profile }

func validateDNSProfile(provider, profile string) error {
	if provider == "" || profile == "" || strings.TrimSpace(provider) != provider || strings.TrimSpace(profile) != profile ||
		strings.Contains(provider, "\x00") || strings.Contains(profile, "\x00") {
		return errors.New("DNS provider/profile 格式无效")
	}
	return nil
}

func validateEnvKey(key string) error {
	if key == "" || len(key) > 255 || strings.TrimSpace(key) != key || strings.ContainsAny(key, "\x00=\n\r") {
		return errors.New("DNS env_key 格式无效")
	}
	return nil
}
