// 本文件提供操作日志和 nonce 管理功能。
package store

import (
	"context"
	"time"
)

// IssueLog 表示证书签发操作的日志记录。
type IssueLog struct {
	ID          int64  `json:"id"`
	Domain      string `json:"domain"`
	ClientToken string `json:"client_token"`
	Action      string `json:"action"`
	Success     bool   `json:"success"`
	DurationMs  int64  `json:"duration_ms"`
	Message     string `json:"message"`
	CreatedAt   int64  `json:"created_at"`
}

// AddLog 添加一条操作日志。
func (s *Store) AddLog(ctx context.Context, l *IssueLog) error {
	l.CreatedAt = time.Now().Unix()
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO issue_logs(domain, client_token, action, success, duration_ms, message, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?)`,
		l.Domain, l.ClientToken, l.Action, boolToInt(l.Success), l.DurationMs, l.Message, l.CreatedAt)
	return err
}

// LogFilter 定义日志查询的过滤条件。
type LogFilter struct {
	Domain  string
	Client  string
	Success *bool
	Limit   int
	Offset  int
}

// ListLogs 根据过滤条件查询日志列表。
func (s *Store) ListLogs(ctx context.Context, f LogFilter) ([]*IssueLog, error) {
	q := `SELECT id, domain, client_token, action, success, duration_ms, message, created_at
	      FROM issue_logs WHERE 1=1`
	args := []interface{}{}
	if f.Domain != "" {
		q += " AND domain=?"
		args = append(args, f.Domain)
	}
	if f.Client != "" {
		q += " AND client_token=?"
		args = append(args, f.Client)
	}
	if f.Success != nil {
		q += " AND success=?"
		args = append(args, boolToInt(*f.Success))
	}
	q += " ORDER BY created_at DESC"
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	q += " LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*IssueLog
	for rows.Next() {
		var l IssueLog
		var succ int
		if err := rows.Scan(&l.ID, &l.Domain, &l.ClientToken, &l.Action, &succ, &l.DurationMs, &l.Message, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.Success = succ == 1
		out = append(out, &l)
	}
	return out, rows.Err()
}

// CleanOldNonces 清理指定时间之前的 nonce 记录。
func (s *Store) CleanOldNonces(ctx context.Context, before int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM nonces WHERE created_at < ?`, before)
	return err
}

// ConsumeNonce 消费 nonce，成功返回 true；若 nonce 已存在则返回 false（防重放）。
func (s *Store) ConsumeNonce(ctx context.Context, nonce string, ttlSec int) (bool, error) {
	// 简单幂等：插入失败说明已存在
	now := time.Now().Unix()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM nonces WHERE created_at < ?`, now-int64(ttlSec)); err != nil {
		return false, err
	}
	res, err := tx.Exec(`INSERT OR IGNORE INTO nonces(nonce, created_at) VALUES(?, ?)`, nonce, now)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
