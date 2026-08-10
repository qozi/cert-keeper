//go:build !darwin && !linux

// Package lock 提供跨进程文件锁。
package lock

import (
	"os"
	"path/filepath"
)

// File 是非 Unix 平台上的兼容实现。
type File struct {
	f *os.File
}

// Acquire 在不支持系统文件锁的平台上仅创建锁文件。
func Acquire(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &File{f: f}, nil
}

// Close 关闭锁文件。
func (f *File) Close() error {
	if f == nil || f.f == nil {
		return nil
	}
	return f.f.Close()
}
