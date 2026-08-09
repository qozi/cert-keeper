// Package store 提供 CertKeeper 的数据存储功能。
// 基于 SQLite 实现，包含证书、客户端、Token、日志等数据的持久化管理。
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store 是数据存储的核心结构，封装 SQLite 数据库连接。
type Store struct {
	DB *sql.DB
}

// Open 打开或创建指定路径的 SQLite 数据库，并执行必要的迁移。
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 失败: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite 写并发友好
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping SQLite 失败: %w", err)
	}
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库连接。
func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) migrate() error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("读取迁移目录失败: %w", err)
	}
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("创建迁移记录表失败: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		var exists int
		if err := s.DB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE name=?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("读取迁移文件 %s 失败: %w", name, err)
		}
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("执行迁移 %s 失败: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`, name, time.Now().Unix()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
