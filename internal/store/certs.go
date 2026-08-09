// 本文件提供证书配置的 CRUD 操作。
package store

import (
	"context"
	"database/sql"
	"time"
)

// Cert 表示证书的配置信息。
type Cert struct {
	Domain        string         `json:"domain"`
	SAN           string         `json:"san"`
	CA            string         `json:"ca"`
	ChallengeMode string         `json:"challenge_mode"`
	DNSProvider   JSONNullString `json:"dns_provider"`
	WebrootPath   JSONNullString `json:"webroot_path"`
	Keylength     string         `json:"keylength"`
	RenewDays     int            `json:"renew_days"`
	ReloadCmd     JSONNullString `json:"reload_cmd"`
	CreatedAt     int64          `json:"created_at"`
	UpdatedAt     int64          `json:"updated_at"`
	Source        string         `json:"source"`
}

// UpsertCert 创建或更新证书配置。
func (s *Store) UpsertCert(ctx context.Context, c *Cert) error {
	now := time.Now().Unix()
	c.CreatedAt = now
	c.UpdatedAt = now
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO certs(domain, san, ca, challenge_mode, dns_provider, webroot_path, keylength, renew_days, reload_cmd, created_at, updated_at, source)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(domain) DO UPDATE SET
		   san=excluded.san, ca=excluded.ca, challenge_mode=excluded.challenge_mode,
		   dns_provider=excluded.dns_provider, webroot_path=excluded.webroot_path,
		   keylength=excluded.keylength, renew_days=excluded.renew_days,
		   reload_cmd=excluded.reload_cmd, updated_at=excluded.updated_at, source=excluded.source`,
		c.Domain, c.SAN, c.CA, c.ChallengeMode, c.DNSProvider, c.WebrootPath,
		c.Keylength, c.RenewDays, c.ReloadCmd, c.CreatedAt, c.UpdatedAt, c.Source)
	return err
}

// GetCert 根据域名获取证书配置，不存在返回 nil。
func (s *Store) GetCert(ctx context.Context, domain string) (*Cert, error) {
	var c Cert
	err := s.DB.QueryRowContext(ctx,
		`SELECT domain, san, ca, challenge_mode, dns_provider, webroot_path, keylength, renew_days, reload_cmd, created_at, updated_at, source
		 FROM certs WHERE domain=?`, domain).
		Scan(&c.Domain, &c.SAN, &c.CA, &c.ChallengeMode, &c.DNSProvider, &c.WebrootPath,
			&c.Keylength, &c.RenewDays, &c.ReloadCmd, &c.CreatedAt, &c.UpdatedAt, &c.Source)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListCerts 列出所有证书配置。
func (s *Store) ListCerts(ctx context.Context) ([]*Cert, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT domain, san, ca, challenge_mode, dns_provider, webroot_path, keylength, renew_days, reload_cmd, created_at, updated_at, source
		 FROM certs ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cert
	for rows.Next() {
		var c Cert
		if err := rows.Scan(&c.Domain, &c.SAN, &c.CA, &c.ChallengeMode, &c.DNSProvider, &c.WebrootPath,
			&c.Keylength, &c.RenewDays, &c.ReloadCmd, &c.CreatedAt, &c.UpdatedAt, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// DeleteCert 根据域名删除证书配置。
func (s *Store) DeleteCert(ctx context.Context, domain string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM certs WHERE domain=?`, domain)
	return err
}
