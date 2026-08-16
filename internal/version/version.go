// Package version 提供 CertKeeper 的版本信息。
package version

import "fmt"

// 以下变量在构建时通过 -ldflags -X 注入，默认值用于本地开发。
var (
	// Version 是 CertKeeper 的版本号。
	Version = "dev"
	// GitCommit 是构建时的 Git 短提交哈希。
	GitCommit = "unknown"
	// BuildDate 是构建时的 UTC 时间（ISO 8601）。
	BuildDate = "unknown"
)

const (
	// ServerComponent 是服务端组件名称。
	ServerComponent = "certk-server"
	// ClientComponent 是客户端组件名称。
	ClientComponent = "certk-client"
	// ServerCLIComponent 是服务端 CLI 组件名称。
	ServerCLIComponent = "certk-server-cli"
)

// String 返回组件的完整版本字符串。
func String(component string) string {
	return fmt.Sprintf("%s/%s", component, Version)
}
