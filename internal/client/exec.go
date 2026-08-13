// 本文件提供 Shell 命令执行的工具函数。
package client

import (
	"context"
	"os"
	"os/exec"
)

// runShellCmd 通过 sh -c 执行命令，工作目录设为 workdir。
func runShellCmd(cmd, workdir string) error {
	return runShellCmdCtx(context.Background(), cmd, workdir)
}

// runShellCmdCtx 通过 sh -c 执行命令，工作目录设为 workdir；ctx 取消时会终止子进程。
func runShellCmdCtx(ctx context.Context, cmd, workdir string) error {
	c := exec.CommandContext(ctx, "sh", "-c", cmd)
	c.Dir = workdir
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
