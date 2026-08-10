package acme

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestListDNSProviders(t *testing.T) {
	tmp := t.TempDir()
	dnsapi := filepath.Join(tmp, "dnsapi")
	if err := os.MkdirAll(dnsapi, 0o755); err != nil {
		t.Fatal(err)
	}
	files := []string{
		"dns_cf.sh",
		"dns_dp.sh",
		"dns_cf.sh.bak", // 非 .sh 结尾的命名变体，不会被匹配
		"dns_api.sh",
		"helper.sh", // 非 dns_ 前缀
		"README.md",
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dnsapi, f), []byte("#!/bin/bash"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 创建一个子目录名为 dns_sub.sh 形式，确认目录不会被当作 provider
	if err := os.MkdirAll(filepath.Join(dnsapi, "dns_dir.sh"), 0o755); err != nil {
		t.Fatal(err)
	}

	got := ListDNSProviders("/nonexistent/acme.sh", tmp)
	want := []string{"dns_api", "dns_cf", "dns_dp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestListDNSProvidersEmptyAndMissing(t *testing.T) {
	// 目录不存在时返回空列表且不报错
	got := ListDNSProviders("", "/nonexistent/path")
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestListDNSProvidersFallbackToAcmeShDir(t *testing.T) {
	tmp := t.TempDir()
	// 模拟 acme.sh 可执行文件所在目录下存在 dnsapi
	acmeBin := filepath.Join(tmp, "acme.sh")
	if err := os.WriteFile(acmeBin, []byte("#!/bin/bash"), 0o755); err != nil {
		t.Fatal(err)
	}
	dnsapi := filepath.Join(tmp, "dnsapi")
	if err := os.MkdirAll(dnsapi, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dnsapi, "dns_cf.sh"), []byte("#!/bin/bash"), 0o644); err != nil {
		t.Fatal(err)
	}
	// home 不存在，应回退到 acme.sh 所在目录
	got := ListDNSProviders(acmeBin, "/nonexistent/home")
	if !reflect.DeepEqual(got, []string{"dns_cf"}) {
		t.Fatalf("expected fallback to acme.sh dir, got %v", got)
	}
}

func TestMaskSecretValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"a", "***"},
		{"ab", "***"},
		{"abc", "***"},
		{"abcd", "***"},
		{"abcde", "ab****de"},
		{"1234567890", "12****90"},
		{"verylongsecretvalue", "ve****ue"},
	}
	for _, c := range cases {
		if got := MaskSecretValue(c.in); got != c.want {
			t.Errorf("MaskSecretValue(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
