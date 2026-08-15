package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/siidoo/certkeeper/pkg/certproto"
)

// clientState 保存异步任务和部署回报，允许进程重启后继续执行。
type clientState struct {
	IdempotencyKey string                      `json:"idempotency_key"`
	JobID          string                      `json:"job_id,omitempty"`
	Domain         string                      `json:"domain"`
	Generation     certproto.GenerationID      `json:"generation,omitempty"`
	Revision       certproto.Revision          `json:"revision,omitempty"`
	Report         *certproto.DeploymentReport `json:"report,omitempty"`
	ReportSent     bool                        `json:"report_sent"`
}

func loadClientState(path string) (*clientState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取客户端状态失败: %w", err)
	}
	var state clientState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("解析客户端状态失败: %w", err)
	}
	return &state, nil
}

func saveClientState(path string, state *clientState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".state-")
	if err != nil {
		return err
	}
	tmp := temporary.Name()
	defer os.Remove(tmp)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
