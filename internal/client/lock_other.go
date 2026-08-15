//go:build !linux && !darwin

package client

import (
	"context"
	"os"
	"path/filepath"
)

func lockDeployment(ctx context.Context, outDir string) (*os.File, error) {
	_ = ctx
	return os.OpenFile(filepath.Join(outDir, ".deploy.lock"), os.O_CREATE|os.O_RDWR, 0o600)
}
