// Package store 提供 CertKeeper 的数据存储功能。
// 基于 SQLite 实现，包含证书、客户端、Token、日志等数据的持久化管理。
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Store 是数据存储的核心结构，封装 SQLite 数据库连接。
type Store struct {
	DB         *sql.DB
	path       string
	kek        []byte
	legacyKEK  []byte
	keySource  string
	keyVersion int
}

// Open 打开或创建指定路径的 SQLite 数据库，并执行必要的迁移。
func Open(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}
	if err := chmodIfSupported(dir, 0o700); err != nil {
		return nil, fmt.Errorf("收紧数据库目录权限失败: %w", err)
	}
	kek, keySource, keyVersion, legacyKEK, err := loadEncryptionKey(path)
	if err != nil {
		return nil, fmt.Errorf("加载数据库密钥失败: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 SQLite 失败: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite 写并发友好
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping SQLite 失败: %w", err)
	}
	s := &Store{
		DB:         db,
		path:       path,
		kek:        kek,
		legacyKEK:  legacyKEK,
		keySource:  keySource,
		keyVersion: keyVersion,
	}
	if err := s.migrate(); err != nil {
		s.clearKeys()
		_ = db.Close()
		return nil, err
	}
	if err := s.migrateLegacyCiphertexts(context.Background()); err != nil {
		s.clearKeys()
		_ = db.Close()
		return nil, fmt.Errorf("迁移数据库密文失败: %w", err)
	}
	if err := s.CheckEncryptionReadiness(context.Background()); err != nil {
		s.clearKeys()
		_ = db.Close()
		return nil, err
	}
	if err := s.saveKeyMetadata(context.Background()); err != nil {
		s.clearKeys()
		_ = db.Close()
		return nil, fmt.Errorf("保存数据库密钥元数据失败: %w", err)
	}
	if err := secureDatabaseFiles(path); err != nil {
		s.clearKeys()
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close 关闭数据库连接。
func (s *Store) Close() error {
	s.clearKeys()
	return s.DB.Close()
}

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
		if _, err := tx.Exec(`PRAGMA defer_foreign_keys = ON`); err != nil {
			_ = tx.Rollback()
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

// secureDatabaseFiles 收紧 SQLite 主文件及其 WAL/SHM 辅助文件的访问权限。
func secureDatabaseFiles(path string) error {
	for _, file := range []string{path, path + "-wal", path + "-shm"} {
		if err := chmodIfSupported(file, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("收紧数据库文件权限失败: %w", err)
		}
	}
	return nil
}

func chmodIfSupported(path string, mode os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return os.Chmod(path, mode)
}
