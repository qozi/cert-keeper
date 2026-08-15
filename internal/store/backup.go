// 本文件提供 SQLite 一致性备份、文件摘要校验和恢复底层。
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const backupFormatVersion = 1

const backupManifestName = "manifest.json"

// BackupOptions 定义备份目标及由调用方提供的外部状态路径。
type BackupOptions struct {
	Destination               string
	CertificateRepositoryPath string
	ACMEStatePath             string
}

// RestoreOptions 定义恢复来源和各类数据的目标路径。
type RestoreOptions struct {
	BackupPath                string
	DatabasePath              string
	CertificateRepositoryPath string
	ACMEStatePath             string
}

// BackupEntry 是备份中一个普通文件的校验元数据。
type BackupEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// BackupManifest 描述一个可独立校验的完整备份。
type BackupManifest struct {
	Version    int           `json:"version"`
	CreatedAt  int64         `json:"created_at"`
	KeySource  string        `json:"key_source"`
	KeyVersion int           `json:"key_version"`
	Entries    []BackupEntry `json:"entries"`
}

// CreateBackup 创建 SQLite 一致性快照，并复制调用方指定的证书仓库和 ACME 状态。
func (s *Store) CreateBackup(ctx context.Context, options BackupOptions) (*BackupManifest, error) {
	if strings.TrimSpace(options.Destination) == "" {
		return nil, errors.New("备份目标不能为空")
	}
	parent := filepath.Dir(options.Destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("创建备份父目录失败: %w", err)
	}
	if _, err := os.Stat(options.Destination); err == nil {
		return nil, errors.New("备份目标已存在")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	temporary, err := os.MkdirTemp(parent, ".certkeeper-backup-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temporary)
	if err := chmodIfSupported(temporary, 0o700); err != nil {
		return nil, err
	}

	databaseTarget := filepath.Join(temporary, "database", "certkeeper.db")
	if err := os.MkdirAll(filepath.Dir(databaseTarget), 0o700); err != nil {
		return nil, err
	}
	if _, err := s.DB.ExecContext(ctx, `VACUUM main INTO ?`, databaseTarget); err != nil {
		return nil, fmt.Errorf("创建 SQLite 一致性快照失败: %w", err)
	}
	if err := chmodIfSupported(databaseTarget, 0o600); err != nil {
		return nil, err
	}

	legacyKeyPath := s.path + ".kek"
	if _, err := os.Stat(legacyKeyPath); err == nil {
		if err := copyRegularFile(legacyKeyPath, filepath.Join(temporary, "database", "certkeeper.db.kek"), 0o600); err != nil {
			return nil, fmt.Errorf("备份数据库兼容密钥失败: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := copyOptionalTree(options.CertificateRepositoryPath, filepath.Join(temporary, "certificates")); err != nil {
		return nil, fmt.Errorf("备份证书仓库失败: %w", err)
	}
	if err := copyOptionalTree(options.ACMEStatePath, filepath.Join(temporary, "acme")); err != nil {
		return nil, fmt.Errorf("备份 ACME 状态失败: %w", err)
	}

	entries, err := collectBackupEntries(temporary)
	if err != nil {
		return nil, err
	}
	manifest := &BackupManifest{
		Version: backupFormatVersion, CreatedAt: time.Now().Unix(), KeySource: s.keySource,
		KeyVersion: s.keyVersion, Entries: entries,
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(temporary, backupManifestName), data, 0o600); err != nil {
		return nil, err
	}
	if err := syncTree(temporary); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, options.Destination); err != nil {
		return nil, fmt.Errorf("发布备份失败: %w", err)
	}
	return manifest, nil
}

// Backup 是 CreateBackup 的简短别名。
func (s *Store) Backup(ctx context.Context, options BackupOptions) (*BackupManifest, error) {
	return s.CreateBackup(ctx, options)
}

// ValidateBackup 在恢复前校验 manifest、所有文件摘要和 SQLite 完整性。
func ValidateBackup(ctx context.Context, backupPath string) (*BackupManifest, error) {
	manifestPath := filepath.Join(backupPath, backupManifestName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("读取备份 manifest 失败: %w", err)
	}
	var manifest BackupManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("解析备份 manifest 失败: %w", err)
	}
	if manifest.Version != backupFormatVersion || manifest.KeyVersion < 1 || manifest.KeySource == "" {
		return nil, errors.New("备份 manifest 版本或密钥元数据无效")
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	databaseFound := false
	for _, entry := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		clean, err := safeBackupPath(entry.Path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[clean]; exists {
			return nil, errors.New("备份 manifest 包含重复路径")
		}
		seen[clean] = struct{}{}
		if clean == "database/certkeeper.db" {
			databaseFound = true
		}
		path := filepath.Join(backupPath, filepath.FromSlash(clean))
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("备份文件缺失 %s: %w", clean, err)
		}
		if !info.Mode().IsRegular() || info.Size() != entry.Size || !validSHA256Digest(entry.SHA256) {
			return nil, fmt.Errorf("备份文件元数据无效: %s", clean)
		}
		digest, _, err := hashFile(path)
		if err != nil {
			return nil, err
		}
		if digest != entry.SHA256 {
			return nil, fmt.Errorf("备份文件摘要不匹配: %s", clean)
		}
	}
	if !databaseFound {
		return nil, errors.New("备份缺少 SQLite 数据库")
	}
	actualEntries, err := collectBackupEntries(backupPath)
	if err != nil {
		return nil, err
	}
	if len(actualEntries) != len(manifest.Entries) {
		return nil, errors.New("备份包含未登记文件或缺少文件")
	}
	if err := validateSQLiteBackup(ctx, filepath.Join(backupPath, "database", "certkeeper.db")); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// ValidateBackup 校验当前 Store 创建的备份。
func (s *Store) ValidateBackup(ctx context.Context, backupPath string) (*BackupManifest, error) {
	return ValidateBackup(ctx, backupPath)
}

// RestoreBackup 先完整校验备份，再将各类数据恢复到调用方指定路径。
func RestoreBackup(ctx context.Context, options RestoreOptions) error {
	if strings.TrimSpace(options.BackupPath) == "" || strings.TrimSpace(options.DatabasePath) == "" {
		return errors.New("备份路径和数据库恢复路径不能为空")
	}
	manifest, err := ValidateBackup(ctx, options.BackupPath)
	if err != nil {
		return err
	}
	_ = manifest
	if err := stageAndReplaceFile(filepath.Join(options.BackupPath, "database", "certkeeper.db"), options.DatabasePath, 0o600); err != nil {
		return fmt.Errorf("恢复 SQLite 数据库失败: %w", err)
	}
	keySource := filepath.Join(options.BackupPath, "database", "certkeeper.db.kek")
	if _, err := os.Stat(keySource); err == nil {
		if err := stageAndReplaceFile(keySource, options.DatabasePath+".kek", 0o600); err != nil {
			return fmt.Errorf("恢复数据库兼容密钥失败: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if options.CertificateRepositoryPath != "" {
		if err := stageAndReplaceTree(filepath.Join(options.BackupPath, "certificates"), options.CertificateRepositoryPath); err != nil {
			return fmt.Errorf("恢复证书仓库失败: %w", err)
		}
	}
	if options.ACMEStatePath != "" {
		if err := stageAndReplaceTree(filepath.Join(options.BackupPath, "acme"), options.ACMEStatePath); err != nil {
			return fmt.Errorf("恢复 ACME 状态失败: %w", err)
		}
	}
	return nil
}

func collectBackupEntries(root string) ([]BackupEntry, error) {
	var entries []BackupEntry
	err := filepath.WalkDir(root, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || item.IsDir() || path == filepath.Join(root, backupManifestName) {
			return nil
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("备份不支持非普通文件: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		digest, size, err := hashFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, BackupEntry{
			Path: filepath.ToSlash(relative), Size: size, SHA256: digest,
			Mode: uint32(info.Mode().Perm()),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

func copyOptionalTree(source, destination string) error {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("外部状态路径必须是目录")
	}
	return copyTree(source, destination)
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := item.Info()
		if err != nil {
			return err
		}
		if item.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm()&0o700)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("不支持备份非普通文件: %s", path)
		}
		return copyRegularFile(path, target, info.Mode().Perm())
	})
}

func copyRegularFile(source, destination string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode&0o700)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = output.Close()
		if remove {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func safeBackupPath(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") {
		return "", errors.New("备份 manifest 包含不安全路径")
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != path {
		return "", errors.New("备份 manifest 包含不安全路径")
	}
	return clean, nil
}

func validateSQLiteBackup(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)", path))
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("检查备份数据库完整性失败: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("备份数据库完整性检查失败: %s", result)
	}
	return nil
}

func stageAndReplaceFile(source, destination string, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".certkeeper-restore-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	_ = os.Remove(temporaryPath)
	defer os.Remove(temporaryPath)
	if err := copyRegularFile(source, temporaryPath, mode); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func stageAndReplaceTree(source, destination string) error {
	if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(parent, ".certkeeper-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := copyTree(source, temporary); err != nil {
		return err
	}
	old := destination + fmt.Sprintf(".restore-old-%d", time.Now().UnixNano())
	if _, err := os.Stat(destination); err == nil {
		if err := os.Rename(destination, old); err != nil {
			return err
		}
		defer os.RemoveAll(old)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		if _, statErr := os.Stat(old); statErr == nil {
			_ = os.Rename(old, destination)
		}
		return err
	}
	return nil
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		return file.Sync()
	})
}
