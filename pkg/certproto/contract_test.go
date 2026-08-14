package certproto

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReconcileRequestStrictJSONAndForceKeySemantics(t *testing.T) {
	request := ReconcileRequest{
		IdempotencyKey: "request-1",
		Force:          true,
		Operation:      "client",
		Reason:         "manual retry",
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ReconcileRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != request {
		t.Fatalf("请求 round-trip 不一致：%#v != %#v", decoded, request)
	}
	if err := request.ValidateForNewAttempt("request-1"); err == nil {
		t.Fatal("force 复用旧幂等键应被拒绝")
	} else if code := errorCode(err); code != ErrorCodeConflict {
		t.Fatalf("错误码 = %q，期望 %q", code, ErrorCodeConflict)
	}
	if err := request.ValidateForNewAttempt("request-0"); err != nil {
		t.Fatal(err)
	}

	for _, input := range []string{
		`{"idempotency_key":""}`,
		`{"idempotency_key":"key with space"}`,
		`{"idempotency_key":"key","unknown":true}`,
		`{"idempotency_key":"key\nvalue"}`,
	} {
		var invalid ReconcileRequest
		if err := json.Unmarshal([]byte(input), &invalid); err == nil {
			t.Fatalf("请求 %s 应被拒绝", input)
		}
	}
}

func TestCapabilitiesJSONAndEndpointTemplates(t *testing.T) {
	capabilities := DefaultCapabilities()
	if err := capabilities.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(capabilities)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Capabilities
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.APIVersion != APIVersion || decoded.URLs != DefaultCapabilitiesURLs() {
		t.Fatalf("能力声明 round-trip 不一致：%#v", decoded)
	}
	if CapabilitiesURLPath() != "/api/v2/capabilities" || JobsURLPath() != "/api/v2/jobs" {
		t.Fatalf("能力/任务路径不符合协议")
	}
	if _, err := json.Marshal(Capabilities{APIVersion: APIVersion}); err == nil {
		t.Fatal("不完整 capabilities 应被拒绝")
	}

	paths := map[string]string{
		"reconcile": "/api/v2/certs/example.com/reconcile",
		"status":    "/api/v2/certs/example.com/status",
		"manifest":  "/api/v2/certs/example.com/generations/g-1/manifest",
		"files":     "/api/v2/certs/example.com/generations/g-1/files/key.pem",
		"deploy":    "/api/v2/certs/example.com/deployments",
		"job":       "/api/v2/jobs/job-1",
	}
	assertPath := func(name, got string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s 路径错误: %v", name, err)
		}
		if got != paths[name] {
			t.Fatalf("%s 路径 = %q，期望 %q", name, got, paths[name])
		}
	}
	path, err := ReconcileURLPath("example.com")
	assertPath("reconcile", path, err)
	path, err = CertificateStatusURLPath("example.com")
	assertPath("status", path, err)
	path, err = ManifestURLPath("example.com", "g-1")
	assertPath("manifest", path, err)
	path, err = CertificateFileURLPath("example.com", "g-1", "key.pem")
	assertPath("files", path, err)
	path, err = DeploymentsURLPath("example.com")
	assertPath("deploy", path, err)
	path, err = JobURLPath("job-1")
	assertPath("job", path, err)
	if _, err := ReconcileURLPath("Example.com"); err == nil {
		t.Fatal("非规范 domain 应被路径构造拒绝")
	}
}

func TestJobStatusRetryFieldsAndTerminalReuse(t *testing.T) {
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	next := now.Add(time.Minute)
	queued := JobStatus{
		ID:            "job-1",
		State:         JobStateQueued,
		Retryable:     true,
		NextAttemptAt: &next,
		CreatedAt:     now,
	}
	data, err := json.Marshal(queued)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"retryable":true`) || !strings.Contains(string(data), `"next_attempt_at"`) {
		t.Fatalf("JSON 未包含重试字段: %s", data)
	}
	var decoded JobStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NextAttemptAt == nil || !decoded.Retryable || decoded.IsTerminal() {
		t.Fatalf("任务状态不正确: %#v", decoded)
	}

	terminal := JobStatus{ID: "job-2", State: JobStateSucceeded, CreatedAt: now}
	if err := terminal.Validate(); err != nil {
		t.Fatal(err)
	}
	if !terminal.IsTerminal() || JobStateRunning.IsTerminal() {
		t.Fatal("终态判断错误")
	}
	accepted := JobAcceptedResponse{Job: terminal, Location: "/api/v2/jobs/job-2", Reused: true}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := JobURLPath("../job"); err == nil {
		t.Fatal("不安全 job id 应被拒绝")
	}

	failed := JobStatus{
		ID:        "job-3",
		State:     JobStateFailed,
		ErrorCode: ErrorCodeJobFailed,
		CreatedAt: now,
	}
	if err := failed.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(JobStatus{ID: "job-4", State: JobStateFailed, CreatedAt: now}); err == nil {
		t.Fatal("缺少失败 error_code 的任务应被拒绝")
	}
}

func TestDeploymentReportRequiresCallerVersionAndDomain(t *testing.T) {
	report := validDeploymentReport()
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := report.ValidateForDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeploymentReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Domain != "example.com" || decoded.Generation != report.Generation || decoded.Revision != report.Revision {
		t.Fatalf("部署回报 round-trip 丢失绑定字段: %#v", decoded)
	}

	for name, invalid := range map[string]DeploymentReport{
		"missing domain":     func() DeploymentReport { r := report; r.Domain = ""; return r }(),
		"missing generation": func() DeploymentReport { r := report; r.Generation = ""; return r }(),
		"zero revision":      func() DeploymentReport { r := report; r.Revision = 0; return r }(),
		"wrong state":        func() DeploymentReport { r := report; r.State = "unknown"; return r }(),
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("%s 应被拒绝", name)
		}
	}
	if err := report.ValidateForDomain("other.example.com"); err == nil {
		t.Fatal("部署回报 domain 不匹配请求路径时应被拒绝")
	}
	if _, err := json.Marshal(DeploymentReport{Target: "web-1", State: DeploymentStateSucceeded, Success: true}); err == nil {
		t.Fatal("缺少 domain/generation/revision 的部署回报应被拒绝")
	}
}

func TestHTTPStatusForErrorCode(t *testing.T) {
	tests := map[ErrorCode]int{
		ErrorCodeInvalidRequest:        http.StatusBadRequest,
		ErrorCodeUnauthorized:          http.StatusUnauthorized,
		ErrorCodeForbidden:             http.StatusForbidden,
		ErrorCodeNotFound:              http.StatusNotFound,
		ErrorCodeConflict:              http.StatusConflict,
		ErrorCodeJobFailed:             http.StatusInternalServerError,
		ErrorCodeDeploymentFailed:      http.StatusInternalServerError,
		ErrorCodeInternal:              http.StatusInternalServerError,
		ErrorCode("future_error_code"): http.StatusInternalServerError,
	}
	for code, expected := range tests {
		if got := HTTPStatusForErrorCode(code); got != expected {
			t.Fatalf("%s 映射为 %d，期望 %d", code, got, expected)
		}
	}
	if got := HTTPStatusForError(ErrorResponse{Code: ErrorCodeForbidden}); got != http.StatusForbidden {
		t.Fatalf("结构化错误映射为 %d", got)
	}
	if got := HTTPStatusForError(&ErrorResponse{Code: ErrorCodeNotFound}); got != http.StatusNotFound {
		t.Fatalf("指针结构化错误映射为 %d", got)
	}
	if got := HTTPStatusForError(errors.New("internal")); got != http.StatusInternalServerError {
		t.Fatalf("普通错误映射为 %d", got)
	}
}

func TestStrictIdentifierValidation(t *testing.T) {
	for _, domain := range []string{"", "Example.com", "example.com/other", "127.0.0.1", "-bad.example.com", "bad..example.com"} {
		if err := ValidateDomain(domain); err == nil {
			t.Fatalf("domain %q 应被拒绝", domain)
		}
	}
	if err := ValidateDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateIdempotencyKey(strings.Repeat("a", MaxIdempotencyKeyLength+1)); err == nil {
		t.Fatal("过长幂等键应被拒绝")
	}
	if err := ValidateJobID("job/id"); err == nil {
		t.Fatal("包含路径分隔符的 job id 应被拒绝")
	}
}

func validDeploymentReport() DeploymentReport {
	return DeploymentReport{
		Domain:     "example.com",
		Target:     "web-1",
		State:      DeploymentStateSucceeded,
		Success:    true,
		Generation: "g-1",
		Revision:   1,
	}
}

func errorCode(err error) ErrorCode {
	var response ErrorResponse
	if errors.As(err, &response) {
		return response.Code
	}
	return ""
}
