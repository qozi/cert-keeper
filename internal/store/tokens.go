// 本文件提供 Token 的 CRUD 操作。
package store

import (
	"context"
	"database/sql"
	"time"
)

// Token 表示认证令牌。
type Token struct {
	ID         string        `json:"id"`
	Secret     string        `json:"secret"`
	Note       string        `json:"note"`
	Enabled    bool          `json:"enabled"`
	IsAdmin    bool          `json:"is_admin"`
	CreatedAt  int64         `json:"created_at"`
	LastUsedAt sql.NullInt64 `json:"last_used_at"`
}

// CreateToken 创建新的 Token。
func (s *Store) CreateToken(ctx context.Context, t *Token) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO tokens(id, secret, note, enabled, is_admin, created_at) VALUES(?, ?, ?, ?, ?, ?)`,
		t.ID, t.Secret, t.Note, boolToInt(t.Enabled), boolToInt(t.IsAdmin), t.CreatedAt)
	return err
}

// GetToken 根据 ID 获取 Token，不存在返回 nil。
func (s *Store) GetToken(ctx context.Context, id string) (*Token, error) {
	var t Token
	var en, ad int
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, secret, note, enabled, is_admin, created_at, last_used_at FROM tokens WHERE id=?`, id).
		Scan(&t.ID, &t.Secret, &t.Note, &en, &ad, &t.CreatedAt, &t.LastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Enabled = en == 1
	t.IsAdmin = ad == 1
	return &t, nil
}

// ListTokens 列出所有 Token。
func (s *Store) ListTokens(ctx context.Context) ([]*Token, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, secret, note, enabled, is_admin, created_at, last_used_at FROM tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Token
	for rows.Next() {
		var t Token
		var en, ad int
		if err := rows.Scan(&t.ID, &t.Secret, &t.Note, &en, &ad, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		t.Enabled = en == 1
		t.IsAdmin = ad == 1
		out = append(out, &t)
	}
	return out, rows.Err()
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

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
