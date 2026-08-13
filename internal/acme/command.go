package acme

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
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
func (OSCommandExecutor) Execute(ctx context.Context, spec CommandSpec) CommandResult {
	stdout := &limitedBuffer{limit: spec.OutputLimit}
	stderr := &limitedBuffer{limit: spec.OutputLimit}
	cmd := exec.CommandContext(ctx, spec.Path, spec.Args...)
	cmd.Env = spec.Env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()

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
