package acme

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const maxCanaryScanFileSize = 1 << 20

// ErrDNSCredentialResidue 表示在可持久目录中发现了本次操作的 DNS 凭据。
// 错误不携带凭据值，避免在日志或 API 响应中泄露敏感信息。
var ErrDNSCredentialResidue = errors.New("检测到 DNS 凭据残留")

// withIsolatedConfig 为一次操作提供独立的 config-home，并在命令前后检查凭据是否被写入持久目录。
func (r *Runner) withIsolatedConfig(ctx context.Context, operation string, dnsEnv map[string]string, certsDirs []string, run func(string) error) (err error) {
	configHome, temporary, err := r.prepareConfigHome()
	if err != nil {
		return err
	}
	if temporary {
		defer func() {
			if removeErr := os.RemoveAll(configHome); removeErr != nil && err == nil {
				err = errors.New("清理临时 ACME 配置目录失败")
			}
		}()
	}

	persistentDirs := []string{r.Home}
	persistentDirs = append(persistentDirs, certsDirs...)
	if !temporary {
		persistentDirs = append(persistentDirs, configHome)
	}
	if scanErr := scanPersistentDirs(ctx, persistentDirs, dnsEnv); scanErr != nil {
		return isolationOperationError(operation, scanErr)
	}

	runErr := run(configHome)
	if scanErr := scanPersistentDirs(ctx, persistentDirs, dnsEnv); scanErr != nil {
		if runErr != nil {
			return runErr
		}
		return isolationOperationError(operation, scanErr)
	}
	return runErr
}

// prepareConfigHome 返回本次操作使用的 config-home 及其是否应在结束时删除。
// 未设置 ConfigHome 时默认创建临时目录；EphemeralConfigHome 可在设置了 ConfigHome 时强制使用临时目录。
func (r *Runner) prepareConfigHome() (string, bool, error) {
	if r.ConfigHome == "" || r.EphemeralConfigHome {
		dir, err := os.MkdirTemp("", "certkeeper-acme-config-")
		if err != nil {
			return "", false, errors.New("创建临时 ACME 配置目录失败")
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return "", false, errors.New("设置临时 ACME 配置目录权限失败")
		}
		return dir, true, nil
	}

	if err := os.MkdirAll(r.ConfigHome, 0o700); err != nil {
		return "", false, errors.New("创建 ACME 配置目录失败")
	}
	return r.ConfigHome, false, nil
}

func isolationOperationError(operation string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return contextOperationError(operation, err)
	}
	return err
}

// scanPersistentDirs 在不跟随符号链接的前提下检查指定目录中的文件内容。
// 不存在或无权访问的路径无法安全读取，按约定跳过。
func scanPersistentDirs(ctx context.Context, dirs []string, dnsEnv map[string]string) error {
	canaries := dnsCanaries(dnsEnv)
	if len(canaries) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(dirs))
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		cleanDir := filepath.Clean(dir)
		if _, ok := seen[cleanDir]; ok {
			continue
		}
		seen[cleanDir] = struct{}{}
		if err := scanPersistentPath(ctx, cleanDir, canaries); err != nil {
			return err
		}
	}
	return nil
}

func dnsCanaries(dnsEnv map[string]string) []string {
	seen := make(map[string]struct{}, len(dnsEnv))
	values := make([]string, 0, len(dnsEnv))
	for _, value := range dnsEnv {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func scanPersistentPath(ctx context.Context, path string, canaries []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if isIgnorableScanError(err) {
			return nil
		}
		return errors.New("检查持久目录失败")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			if isIgnorableScanError(err) {
				return nil
			}
			return errors.New("检查持久目录失败")
		}
		for _, entry := range entries {
			if err := scanPersistentPath(ctx, filepath.Join(path, entry.Name()), canaries); err != nil {
				return err
			}
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		if isIgnorableScanError(err) {
			return nil
		}
		return errors.New("检查持久目录失败")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCanaryScanFileSize))
	if err != nil {
		if isIgnorableScanError(err) {
			return nil
		}
		return errors.New("检查持久目录失败")
	}
	contents := string(data)
	for _, canary := range canaries {
		if strings.Contains(contents, canary) {
			return ErrDNSCredentialResidue
		}
	}
	return nil
}

func isIgnorableScanError(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}
