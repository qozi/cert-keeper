//go:build darwin || linux

// Package lock 提供跨进程文件锁。
package lock

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// File 表示一个持有中的文件锁。
type File struct {
	f *os.File
}

// Acquire 获取独占文件锁。调用方必须关闭返回的锁。
func Acquire(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建锁目录失败: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开锁文件失败: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("获取文件锁失败: %w", err)
	}
	return &File{f: f}, nil
}

// Close 释放文件锁并关闭锁文件。
func (f *File) Close() error {
	if f == nil || f.f == nil {
		return nil
	}
	err := unix.Flock(int(f.f.Fd()), unix.LOCK_UN)
	closeErr := f.f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
