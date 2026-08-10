package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/siidoo/certkeeper/internal/config"
	"github.com/siidoo/certkeeper/internal/store"
)

type testLogger struct{}

func (testLogger) Info(string, ...any)  {}
func (testLogger) Warn(string, ...any)  {}
func (testLogger) Error(string, ...any) {}

func TestCertStatusRequiresAuthentication(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(root, "db", "certkeeper.db")
	st, err := store.Open(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srv := &Server{Cfg: cfg, Store: st, Logger: testLogger{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/example.com/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		body, _ := io.ReadAll(rec.Result().Body)
		t.Fatalf("expected 401, got %d: %s", rec.Code, body)
	}
}
