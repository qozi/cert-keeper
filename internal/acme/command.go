package acme

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
)

// CommandSpec 描述一次不经过 shell 的命令执行。
type CommandSpec struct {
	Path        string
	Args        []string
	Env         []string
	OutputLimit int
}

// CommandResult 是命令执行器返回的原始结果。
type CommandResult struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	Err             error
}

// CommandExecutor 允许调用方替换命令执行方式，便于测试或受控运行环境集成。
type CommandExecutor interface {
	Execute(context.Context, CommandSpec) CommandResult
}

// OSCommandExecutor 通过 os/exec 执行本地命令。
type OSCommandExecutor struct{}

// Execute 直接调用可执行文件，不拼接或执行 shell 字符串。
// 命令使用独立进程组，取消时同时终止 acme.sh 派生的插件进程。
func (OSCommandExecutor) Execute(ctx context.Context, spec CommandSpec) CommandResult {
	stdout := &limitedBuffer{limit: spec.OutputLimit}
	stderr := &limitedBuffer{limit: spec.OutputLimit}
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1, Err: err}
	}
	cmd := exec.Command(spec.Path, spec.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = spec.Env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return CommandResult{
			Stdout:          stdout.String(),
			Stderr:          stderr.String(),
			StdoutTruncated: stdout.Truncated(),
			StderrTruncated: stderr.Truncated(),
			ExitCode:        -1,
			Err:             err,
		}
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		// 负 PID 表示进程组；忽略进程已经自行退出时的 ESRCH。
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		err = ctx.Err()
	}

	result := CommandResult{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
		ExitCode:        0,
		Err:             err,
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}
	return result
}

// limitedBuffer 在命令持续输出时限制内存占用。
type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if b.limit <= 0 {
		return len(data), nil
	}
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		_, _ = b.buffer.Write(data[:remaining])
	}
	if len(data) > remaining {
		b.truncated = true
	}
	return len(data), nil
}

func (b *limitedBuffer) String() string {
	return b.buffer.String()
}

// Truncated 返回写入内容是否因长度限制而被截断。
func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}
