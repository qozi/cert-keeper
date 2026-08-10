package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/siidoo/certkeeper/internal/acme"
	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/store"
)

func newTestService(t *testing.T) (*Service, *config.Config, func()) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(root, "db", "certkeeper.db")
	cfg.Storage.EncryptionKey = "test-encryption-key"
	cfg.Acme.Home = filepath.Join(root, "acme")
	cfg.Acme.CertsDir = filepath.Join(root, "certs")
	cfg.Acme.AutoUpgrade = false
	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, st), cfg, func() { _ = st.Close() }
}

func TestApplyUsesPresetAndRecordsSuccess(t *testing.T) {
	svc, cfg, cleanup := newTestService(t)
	defer cleanup()

	if err := svc.SaveCertConfig(context.Background(), &store.Cert{
		Domain:        "example.com",
		ChallengeMode: "standalone",
	}); err != nil {
		t.Fatal(err)
	}
	svc.IssueFunc = func(_ context.Context, params *acme.IssueParams) (*acme.IssueResult, error) {
		dir := filepath.Join(cfg.Acme.CertsDir, params.Domain)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		for _, name := range []string{"cert.pem", "key.pem", "fullchain.pem", "ca.pem"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
				return nil, err
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "time.log"), []byte("123"), 0o644); err != nil {
			return nil, err
		}
		return &acme.IssueResult{Domain: params.Domain, NotAfter: time.Now().Add(90 * 24 * time.Hour)}, nil
	}

	result, err := svc.Apply(context.Background(), ApplyRequest{Domain: "example.com", Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || !result.Renewed || len(result.Files) != 5 {
		t.Fatalf("unexpected apply result: %+v", result)
	}
	logs, err := svc.Store.ListLogs(context.Background(), store.LogFilter{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || !logs[0].Success || logs[0].ClientToken != "test" {
		t.Fatalf("unexpected issue log: %+v", logs)
	}
}

func TestApplyRejectsUnsafeDomain(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()

	_, err := svc.Status(context.Background(), "../outside")
	if err == nil {
		t.Fatal("expected unsafe domain error")
	}
	if _, ok := err.(*ValidationError); !ok {
		t.Fatalf("expected ValidationError, got %T", err)
	}
}

func TestSecretViewsMaskByDefault(t *testing.T) {
	svc, _, cleanup := newTestService(t)
	defer cleanup()

	if err := svc.Store.UpsertSecret(context.Background(), "dns_cf", "CF_Key", "secret-value", svc.Cfg.Storage.EncryptionKey); err != nil {
		t.Fatal(err)
	}
	masked, err := svc.ListSecretViews(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(masked) != 1 || masked[0].EnvValue != "***" {
		t.Fatalf("unexpected masked secret: %+v", masked)
	}
	plain, err := svc.ListSecretViews(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != 1 || plain[0].EnvValue != "secret-value" {
		t.Fatalf("unexpected plain secret: %+v", plain)
	}
}
