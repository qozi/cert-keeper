package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunTokenCreateJSON(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "config.yaml")
	config := []byte(`
storage:
  sqlite_path: "` + filepath.Join(root, "db", "certkeeper.db") + `"
  encryption_key: "test-encryption-key"
acme:
  home: "` + filepath.Join(root, "acme") + `"
  certs_dir: "` + filepath.Join(root, "certs") + `"
  auto_upgrade: false
log:
  file: ""
`)
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := run([]string{"--config", configPath, "--output", "json", "token", "create", "--auto-gen"}, &out, &out, bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	var token map[string]any
	if err := json.Unmarshal(out.Bytes(), &token); err != nil {
		t.Fatal(err)
	}
	if token["id"] == "" || token["secret"] == "" {
		t.Fatalf("token credentials missing: %s", out.String())
	}
}
