// 本文件提供客户端信息的 CRUD 操作。
package store

import (
	"context"
	"time"
)

// Client 表示注册的客户端信息。
type Client struct {
	TokenID      string         `json:"token_id"`
	Hostname     JSONNullString `json:"hostname"`
	OSInfo       JSONNullString `json:"os_info"`
	RegisteredAt int64          `json:"registered_at"`
	LastSeenAt   int64          `json:"last_seen_at"`
}

// UpsertClient 创建或更新客户端信息。
func (s *Store) UpsertClient(ctx context.Context, c *Client) error {
	now := time.Now().Unix()
	c.LastSeenAt = now
	if c.RegisteredAt == 0 {
		c.RegisteredAt = now
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO clients(token_id, hostname, os_info, registered_at, last_seen_at)
		 VALUES(?, ?, ?, ?, ?)
		 ON CONFLICT(token_id) DO UPDATE SET
		   hostname=excluded.hostname, os_info=excluded.os_info, last_seen_at=excluded.last_seen_at`,
		c.TokenID, c.Hostname, c.OSInfo, c.RegisteredAt, c.LastSeenAt)
	return err
}

// TouchClient 更新客户端的最后在线时间。
func (s *Store) TouchClient(ctx context.Context, tokenID string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE clients SET last_seen_at=? WHERE token_id=?`, time.Now().Unix(), tokenID)
	return err
}

// ListClients 列出所有已注册的客户端。
func (s *Store) ListClients(ctx context.Context) ([]*Client, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT token_id, hostname, os_info, registered_at, last_seen_at FROM clients ORDER BY last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.TokenID, &c.Hostname, &c.OSInfo, &c.RegisteredAt, &c.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}
