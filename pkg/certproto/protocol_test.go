package certproto

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValidateFileNameRejectsUnsafeNames(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
	}{
		{name: "", code: ErrorCodeInvalidFileName},
		{name: "../key.pem", code: ErrorCodePathTraversal},
		{name: `dir\\key.pem`, code: ErrorCodePathTraversal},
		{name: "unknown.pem", code: ErrorCodeUnknownFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFileName(tt.name)
			if err == nil {
				t.Fatal("期望文件名校验失败")
			}
			var response ErrorResponse
			if !errors.As(err, &response) {
				t.Fatalf("期望结构化错误，得到 %T", err)
			}
			if response.Code != tt.code {
				t.Fatalf("错误码 = %q，期望 %q", response.Code, tt.code)
			}
		})
	}
}

func TestCertificateManifestRejectsDuplicateFileNames(t *testing.T) {
	manifest := CertificateManifest{
		validFileManifest(FileCert),
		validFileManifest(FileCert),
	}
	err := manifest.Validate()
	if err == nil {
		t.Fatal("期望重复文件名校验失败")
	}
	var response ErrorResponse
	if !errors.As(err, &response) || response.Code != ErrorCodeDuplicateFile {
		t.Fatalf("错误 = %#v，期望错误码 %q", err, ErrorCodeDuplicateFile)
	}

	_, err = json.Marshal(manifest)
	if err == nil {
		t.Fatal("期望重复 manifest 无法编码")
	}
}

func TestGenerationAndURLPathRejectTraversal(t *testing.T) {
	for _, id := range []string{".", "..", "../other", `one\\two`} {
		err := ValidateGenerationID(id)
		if err == nil {
			t.Fatalf("generation %q 应被拒绝", id)
		}
		var response ErrorResponse
		if !errors.As(err, &response) || response.Code != ErrorCodePathTraversal {
			t.Fatalf("generation %q 错误 = %#v，期望错误码 %q", id, err, ErrorCodePathTraversal)
		}
	}
	for _, id := range []string{"", "with space"} {
		if err := ValidateGenerationID(id); err == nil {
			t.Fatalf("generation %q 应被拒绝", id)
		}
	}
	if _, err := CertificateFileURLPath("example.com", "gen-1", "../key.pem"); err == nil {
		t.Fatal("路径穿越文件名应被拒绝")
	}
	if _, err := CertificateFileURLPath("example.com", "../gen", string(FileKey)); err == nil {
		t.Fatal("路径穿越 generation 应被拒绝")
	}

	path, err := CertificateFileURLPath("example.com", "gen-1", string(FileKey))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/v2/certs/example.com/generations/gen-1/files/key.pem" {
		t.Fatalf("路径 = %q", path)
	}

	escaped, err := EscapePathSegment("name with spaces")
	if err != nil {
		t.Fatal(err)
	}
	if escaped != "name%20with%20spaces" || strings.Contains(escaped, "/") {
		t.Fatalf("转义路径段 = %q", escaped)
	}
}

func TestProtocolJSONRoundTrip(t *testing.T) {
	now := time.Date(2026, time.August, 12, 9, 30, 0, 0, time.UTC)
	manifest := CertificateManifest{
		validFileManifest(FileCert),
		validFileManifest(FileKey),
	}
	response := ApplyResponse{
		Success:    true,
		Domain:     "example.com",
		Generation: GenerationID("gen-2026"),
		Revision:   Revision(3),
		Renewed:    true,
		Job: JobStatus{
			ID:         "job-1",
			State:      JobStateSucceeded,
			Generation: GenerationID("gen-2026"),
			Revision:   Revision(3),
			CreatedAt:  now,
		},
		Status: CertificateStatus{
			Domain:     "example.com",
			Generation: GenerationID("gen-2026"),
			Revision:   Revision(3),
			State:      CertificateStateValid,
			NotAfter:   now.Add(90 * 24 * time.Hour),
			Files:      manifest,
			Exists:     true,
		},
		Deployment: &DeploymentReport{
			Target:     "web-1",
			State:      DeploymentStateSucceeded,
			Success:    true,
			Generation: GenerationID("gen-2026"),
			Revision:   Revision(3),
			Verified:   true,
			Reloaded:   true,
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ApplyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(response, decoded) {
		t.Fatalf("JSON round-trip 不一致：\n原值: %#v\n解码: %#v", response, decoded)
	}
}

func TestManifestJSONRejectsUnknownAndDuplicateFiles(t *testing.T) {
	validSHA := strings.Repeat("a", 64)
	for _, input := range []string{
		`[{"name":"unknown.pem","size":1,"sha256":"` + validSHA + `"}]`,
		`[{"name":"../key.pem","size":1,"sha256":"` + validSHA + `"}]`,
		`[{"name":"cert.pem","size":1,"sha256":"` + validSHA + `"},{"name":"cert.pem","size":1,"sha256":"` + validSHA + `"}]`,
	} {
		var manifest CertificateManifest
		if err := json.Unmarshal([]byte(input), &manifest); err == nil {
			t.Fatalf("JSON %s 应被拒绝", input)
		}
	}
}

func validFileManifest(name FileName) FileManifest {
	return FileManifest{Name: string(name), Size: 12, SHA256: strings.Repeat("a", 64)}
}
