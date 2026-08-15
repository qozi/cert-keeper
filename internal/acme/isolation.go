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

// ErrDNSCredentialResidue 表示在可持久目录中发现了本次操作的 DNS 凭据。
// 错误不携带凭据值，避免在日志或 API 响应中泄露敏感信息。
var ErrDNSCredentialResidue = errors.New("检测到 DNS 凭据残留")

// withIsolatedConfig 复用持久 config-home，并用独立 accountconf 隔离 DNS 插件写入的 SAVED_*。
func (r *Runner) withIsolatedConfig(ctx context.Context, operation string, dnsEnv map[string]string, certsDirs []string, run func(string, string) error) (err error) {
	configHome, temporaryConfig, err := r.prepareConfigHome()
	if err != nil {
		return err
	}
	var accountConf, credentialDir string
	if isolatesDNSCredentials(operation) {
		accountConf, credentialDir, err = prepareAccountConf()
		if err != nil {
			if temporaryConfig {
				_ = os.RemoveAll(configHome)
			}
			return err
		}
	}
	defer func() {
		if credentialDir != "" {
			if cleanupErr := os.RemoveAll(credentialDir); cleanupErr != nil {
				err = joinCleanupError(err, "清理临时 ACME accountconf 失败")
			}
		}
		if temporaryConfig {
			if cleanupErr := os.RemoveAll(configHome); cleanupErr != nil {
				err = joinCleanupError(err, "清理临时 ACME config-home 失败")
			}
		}
	}()

	persistentDirs := []string{r.stateHome(), configHome}
	persistentDirs = append(persistentDirs, certsDirs...)
	if scanErr := scanPersistentDirs(ctx, persistentDirs, dnsEnv); scanErr != nil {
		return isolationOperationError(operation, scanErr)
	}

	runErr := run(configHome, accountConf)
	// 操作已经结束后仍需完成持久目录扫描，不能因命令超时而跳过安全检查。
	scanCtx := context.WithoutCancel(ctx)
	if scanErr := scanPersistentDirs(scanCtx, persistentDirs, dnsEnv); scanErr != nil {
		return isolationOperationError(operation, scanErr)
	}
	return runErr
}

func isolatesDNSCredentials(operation string) bool {
	switch operation {
	case "issue", "renew", "reissue", "install-cert":
		return true
	default:
		return false
	}
}

func joinCleanupError(err error, message string) error {
	cleanupErr := errors.New(message)
	if err == nil {
		return cleanupErr
	}
	return errors.Join(err, cleanupErr)
}

// prepareConfigHome 返回持久 config-home；只有调用方明确要求临时模式或无法确定持久路径时才创建临时目录。
func (r *Runner) prepareConfigHome() (string, bool, error) {
	if !r.EphemeralConfigHome {
		if configHome := r.persistentConfigHome(); configHome != "" {
			if r.ConfigHome != "" {
				if err := os.MkdirAll(configHome, 0o700); err != nil {
					return "", false, errors.New("创建 ACME 配置目录失败")
				}
				if err := os.Chmod(configHome, 0o700); err != nil {
					return "", false, errors.New("设置 ACME 配置目录权限失败")
				}
			}
			return configHome, false, nil
		}
	}

	dir, err := os.MkdirTemp("", "certkeeper-acme-state-")
	if err != nil {
		return "", false, errors.New("创建临时 ACME 配置目录失败")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", false, errors.New("设置临时 ACME 配置目录权限失败")
	}
	return dir, true, nil
}

func prepareAccountConf() (string, string, error) {
	dir, err := os.MkdirTemp("", "certkeeper-acme-credentials-")
	if err != nil {
		return "", "", errors.New("创建临时 ACME 凭据目录失败")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", errors.New("设置临时 ACME 凭据目录权限失败")
	}
	accountConf := filepath.Join(dir, "account.conf")
	if err := os.WriteFile(accountConf, nil, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", errors.New("创建临时 ACME accountconf 失败")
	}
	return accountConf, dir, nil
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
	return scanFileCanaries(file, canaries)
}

func scanFileCanaries(file *os.File, canaries []string) error {
	buffer := make([]byte, 64*1024)
	var carry string
	for {
		n, err := file.Read(buffer)
		if n > 0 {
			contents := carry + string(buffer[:n])
			for _, canary := range canaries {
				if strings.Contains(contents, canary) {
					return ErrDNSCredentialResidue
				}
			}
			maxCarry := maxCanaryLength(canaries) - 1
			if maxCarry > 0 && len(contents) > maxCarry {
				carry = contents[len(contents)-maxCarry:]
			} else {
				carry = contents
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if isIgnorableScanError(err) {
				return nil
			}
			return errors.New("检查持久目录失败")
		}
	}
}

func maxCanaryLength(canaries []string) int {
	max := 0
	for _, canary := range canaries {
		if len(canary) > max {
			max = len(canary)
		}
	}
	return max
}

func isIgnorableScanError(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission)
}
