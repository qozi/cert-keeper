// Package acme 提供 ACME 证书签发相关的功能。
// 本文件封装对 acme.sh DNS provider 脚本的扫描能力。
package acme

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ProviderInfo 表示一个 DNS provider 的基础信息。
type ProviderInfo struct {
	Provider string `json:"provider"`
}

// ListDNSProviders 扫描 acme.sh 安装目录下的 dnsapi/dns_*.sh 脚本，
// 返回去重并按字母序排序的 provider 名称列表（形如 dns_cf）。
//
// 扫描位置优先取 acme.sh 主目录（Home）下的 dnsapi；
// 若不存在则回退到 acme.sh 可执行文件所在目录的 dnsapi 子目录。
// 任一目录不存在或为空均返回空列表，不视为错误。
func ListDNSProviders(acmeShPath, home string) []string {
	dirs := candidateDNSAPIDirs(acmeShPath, home)
	seen := map[string]struct{}{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, "dns_") || !strings.HasSuffix(name, ".sh") {
				continue
			}
			if e.IsDir() {
				continue
			}
			provider := strings.TrimSuffix(name, ".sh")
			seen[provider] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// candidateDNSAPIDirs 返回可能存放 dnsapi 脚本的目录列表（按优先级）。
func candidateDNSAPIDirs(acmeShPath, home string) []string {
	var dirs []string
	if home != "" {
		dirs = append(dirs, filepath.Join(home, "dnsapi"))
	}
	if acmeShPath != "" {
		dirs = append(dirs, filepath.Join(filepath.Dir(acmeShPath), "dnsapi"))
		// acme.sh 可执行文件本身常位于 .acme.sh 根目录
		dirs = append(dirs, filepath.Join(filepath.Dir(acmeShPath), ".acme.sh", "dnsapi"))
	}
	return dirs
}

// MaskSecretValue 对明文参数值进行脱敏，保留首尾各 2 个字符，中间以 **** 代替。
// 长度不足 5 时统一返回 ***，避免泄露长度信息过多。
func MaskSecretValue(s string) string {
	if s == "" {
		return ""
	}
	n := len(s)
	if n < 5 {
		return "***"
	}
	return s[:2] + "****" + s[n-2:]
}
