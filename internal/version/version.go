// Package version 提供 CertKeeper 的版本信息。
package version

import "fmt"

// Version 是 CertKeeper 的版本号。
const Version = "0.1.0"

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
