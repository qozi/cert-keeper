// 本文件提供 Token 的安全存储和 v2 域名授权操作。
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const tokenSecretVersion = 2

// Token 表示认证令牌。常规读取为兼容认证会填充 Secret，但默认 JSON 和 String 输出会隐藏它。
type Token struct {
	ID         string        `json:"id"`
	Secret     string        `json:"secret,omitempty"`
	Note       string        `json:"note"`
	Enabled    bool          `json:"enabled"`
	IsAdmin    bool          `json:"is_admin"`
	CreatedAt  int64         `json:"created_at"`
	LastUsedAt sql.NullInt64 `json:"last_used_at"`

	exposeSecret bool
}

// MarshalJSON 默认隐藏 Token secret；只有创建或显式取密接口返回的对象才会包含它。
func (t Token) MarshalJSON() ([]byte, error) {
	type tokenJSON struct {
		ID         string        `json:"id"`
		Secret     string        `json:"secret,omitempty"`
		Note       string        `json:"note"`
		Enabled    bool          `json:"enabled"`
		IsAdmin    bool          `json:"is_admin"`
		CreatedAt  int64         `json:"created_at"`
		LastUsedAt sql.NullInt64 `json:"last_used_at"`
	}
	secret := ""
	if t.exposeSecret {
		secret = t.Secret
	}
	return json.Marshal(tokenJSON{
		ID: t.ID, Secret: secret, Note: t.Note, Enabled: t.Enabled, IsAdmin: t.IsAdmin,
		CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt,
	})
}

// String 避免日志格式化 Token 时泄露其机密。
func (t Token) String() string {
	return fmt.Sprintf("Token{ID:%q Note:%q Enabled:%t IsAdmin:%t}", t.ID, t.Note, t.Enabled, t.IsAdmin)
}

// TokenGrant 是 Token 在特定证书上的单项权限。
type TokenGrant struct {
	TokenID    string `json:"token_id"`
	Domain     string `json:"domain"`
	Permission string `json:"permission"`
	CreatedAt  int64  `json:"created_at"`
}

var validCertificatePermissions = map[string]struct{}{
	"apply":            {},
	"status":           {},
	"read_cert":        {},
	"read_private_key": {},
	"force":            {},
}

// CreateToken 创建 v2 Token。明文仅由调用方持有，不写入旧的 tokens.secret 列。
func (s *Store) CreateToken(ctx context.Context, t *Token) error {
	if t == nil {
		return errors.New("token 不能为空")
	}
	return s.CreateTokenWithSecret(ctx, t, t.Secret)
}

// CreateTokenWithSecret 创建 v2 Token，并将提供的机密加密保存。
func (s *Store) CreateTokenWithSecret(ctx context.Context, t *Token, secret string) error {
	if t == nil {
		return errors.New("token 不能为空")
	}
	if strings.TrimSpace(t.ID) == "" {
		return errors.New("token ID 不能为空")
	}
	if secret == "" {
		return errors.New("token secret 不能为空")
	}
	if t.CreatedAt == 0 {
		t.CreatedAt = time.Now().Unix()
	}
	ciphertext, err := encryptAESGCM(secret, s.kek, tokenSecretAAD(t.ID))
	if err != nil {
		return fmt.Errorf("加密 token secret 失败: %w", err)
	}
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO tokens(id, secret_ciphertext, secret_version, secret_rotated_at, note, enabled, is_admin, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, ciphertext, tokenSecretVersion, t.CreatedAt, t.Note, boolToInt(t.Enabled), boolToInt(t.IsAdmin), t.CreatedAt)
	if err == nil {
		t.Secret = secret
		t.exposeSecret = true
	}
	return err
}

// GetToken 根据 ID 获取 Token。为保持现有签名认证调用可用，会解密填充 Secret，
// 但默认 JSON 序列化不会泄露它；新代码应优先使用明确命名的 GetTokenWithSecret。
func (s *Store) GetToken(ctx context.Context, id string) (*Token, error) {
	t, err := s.getTokenWithSecret(ctx, id)
	if t != nil {
		t.exposeSecret = false
	}
	return t, err
}

// GetTokenWithSecret 根据 ID 获取 Token 及明文机密。
// 对 v1 记录仅在 secret_ciphertext 缺失时读取旧 secret 列以兼容升级前数据。
func (s *Store) GetTokenWithSecret(ctx context.Context, id string) (*Token, error) {
	t, err := s.getTokenWithSecret(ctx, id)
	if t != nil {
		t.exposeSecret = true
	}
	return t, err
}

func (s *Store) getTokenWithSecret(ctx context.Context, id string) (*Token, error) {
	t, ciphertext, version, err := s.getToken(ctx, id)
	if err != nil || t == nil {
		return t, err
	}
	if ciphertext == "" {
		var legacy string
		err := s.DB.QueryRowContext(ctx, `SELECT secret FROM tokens WHERE id=?`, id).Scan(&legacy)
		if err != nil {
			return nil, err
		}
		t.Secret = legacy
		return t, nil
	}
	if version != tokenSecretVersion {
		return nil, fmt.Errorf("不支持的 token secret 版本: %d", version)
	}
	secret, err := s.decryptStoredSecret(ciphertext, tokenSecretAAD(id))
	if err != nil {
		return nil, fmt.Errorf("解密 token secret 失败: %w", err)
	}
	t.Secret = secret
	return t, nil
}

func (s *Store) getToken(ctx context.Context, id string) (*Token, string, int, error) {
	var t Token
	var ciphertext sql.NullString
	var en, ad, version int
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, secret_ciphertext, secret_version, COALESCE(note, ''), enabled, is_admin, created_at, last_used_at FROM tokens WHERE id=?`, id).
		Scan(&t.ID, &ciphertext, &version, &t.Note, &en, &ad, &t.CreatedAt, &t.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", 0, nil
	}
	if err != nil {
		return nil, "", 0, err
	}
	t.Enabled = en == 1
	t.IsAdmin = ad == 1
	return &t, ciphertext.String, version, nil
}

// ListTokens 列出所有 Token 元数据，不返回机密。
func (s *Store) ListTokens(ctx context.Context) ([]*Token, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, COALESCE(note, ''), enabled, is_admin, created_at, last_used_at FROM tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		var t Token
		var en, ad int
		if err := rows.Scan(&t.ID, &t.Note, &en, &ad, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		t.Enabled = en == 1
		t.IsAdmin = ad == 1
		out = append(out, &t)
	}
	return out, rows.Err()
}

// RotateTokenSecret 轮换 Token 机密，旧明文列保持为空。
func (s *Store) RotateTokenSecret(ctx context.Context, id, secret string) error {
	if strings.TrimSpace(id) == "" || secret == "" {
		return errors.New("token ID 和 secret 不能为空")
	}
	ciphertext, err := encryptAESGCM(secret, s.kek, tokenSecretAAD(id))
	if err != nil {
		return fmt.Errorf("加密 token secret 失败: %w", err)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE tokens SET secret_ciphertext=?, secret_version=?, secret_rotated_at=?, secret=NULL WHERE id=?`,
		ciphertext, tokenSecretVersion, time.Now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// UpdateTokenUsage 更新 Token 的最后使用时间。
func (s *Store) UpdateTokenUsage(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE tokens SET last_used_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// UpdateToken 更新 Token 的备注、启用状态和管理员权限。
func (s *Store) UpdateToken(ctx context.Context, id string, note string, enabled bool, isAdmin bool) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE tokens SET note=?, enabled=?, is_admin=? WHERE id=?`,
		note, boolToInt(enabled), boolToInt(isAdmin), id)
	return err
}

// DeleteToken 根据 ID 删除 Token。
func (s *Store) DeleteToken(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM tokens WHERE id=?`, id)
	return err
}

// Grant 授予 Token 对指定证书的一项权限。域名和权限均严格校验。
func (s *Store) Grant(ctx context.Context, tokenID, domain, permission string) error {
	if err := validateCertificateDomain(domain); err != nil {
		return err
	}
	if _, ok := validCertificatePermissions[permission]; !ok {
		return errors.New("无效的证书权限")
	}
	if strings.TrimSpace(tokenID) == "" {
		return errors.New("token ID 不能为空")
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO token_certificate_grants(token_id, domain, permission, created_at) VALUES(?, ?, ?, ?)
		 ON CONFLICT(token_id, domain, permission) DO NOTHING`,
		tokenID, domain, permission, time.Now().Unix())
	return err
}

// Revoke 撤销 Token 对指定证书的一项权限。
func (s *Store) Revoke(ctx context.Context, tokenID, domain, permission string) error {
	if err := validateCertificateDomain(domain); err != nil {
		return err
	}
	if _, ok := validCertificatePermissions[permission]; !ok {
		return errors.New("无效的证书权限")
	}
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM token_certificate_grants WHERE token_id=? AND domain=? AND permission=?`, tokenID, domain, permission)
	return err
}

// ListGrants 列出 Token 的域名授权，不返回任何机密。
func (s *Store) ListGrants(ctx context.Context, tokenID string) ([]TokenGrant, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT token_id, domain, permission, created_at FROM token_certificate_grants WHERE token_id=? ORDER BY domain, permission`, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var grants []TokenGrant
	for rows.Next() {
		var grant TokenGrant
		if err := rows.Scan(&grant.TokenID, &grant.Domain, &grant.Permission, &grant.CreatedAt); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

// HasCertificatePermission 按拒绝优先检查域名权限。管理员不绕过显式授权，普通 Token 无 grant 默认拒绝。
func (s *Store) HasCertificatePermission(ctx context.Context, tokenID, domain, permission string) (bool, error) {
	if err := validateCertificateDomain(domain); err != nil {
		return false, err
	}
	if _, ok := validCertificatePermissions[permission]; !ok {
		return false, errors.New("无效的证书权限")
	}
	if strings.TrimSpace(tokenID) == "" {
		return false, nil
	}
	var found int
	err := s.DB.QueryRowContext(ctx,
		`SELECT 1 FROM token_certificate_grants WHERE token_id=? AND domain=? AND permission=?`, tokenID, domain, permission).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// validateCertificateDomain 接受规范化的 DNS 主机名或通配符域名，拒绝路径、端口、IP 与非规范形式。
func validateCertificateDomain(domain string) error {
	if domain == "" || domain != strings.ToLower(domain) || strings.TrimSpace(domain) != domain || len(domain) > 253 {
		return errors.New("域名格式无效")
	}
	base := domain
	if strings.HasPrefix(base, "*.") {
		base = strings.TrimPrefix(base, "*.")
	}
	if base == "" || strings.Contains(domain, "*") || net.ParseIP(base) != nil || !strings.Contains(base, ".") {
		return errors.New("域名格式无效")
	}
	for _, label := range strings.Split(base, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("域名格式无效")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errors.New("域名格式无效")
			}
		}
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
