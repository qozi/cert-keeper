package observability

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestCounterAndGaugeAreConcurrentSafe(t *testing.T) {
	registry := NewRegistry()
	counter, err := registry.Counter("requests_total", "请求数", "method")
	if err != nil {
		t.Fatal(err)
	}
	gauge, err := registry.Gauge("workers", "工作线程数")
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	const increments = 100
	var group sync.WaitGroup
	for range goroutines {
		group.Add(1)
		go func() {
			defer group.Done()
			for range increments {
				if err := counter.Inc(Labels{"method": "GET"}); err != nil {
					t.Error(err)
					return
				}
				if err := gauge.Add(nil, 1); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	group.Wait()

	snapshot := registry.Snapshot()
	if len(snapshot.Metrics) != 2 {
		t.Fatalf("指标数量 = %d，期望 2", len(snapshot.Metrics))
	}
	for _, metric := range snapshot.Metrics {
		if len(metric.Samples) != 1 || metric.Samples[0].Value != goroutines*increments {
			t.Fatalf("并发更新结果不正确: %+v", metric)
		}
	}
}

func TestPrometheusTextEscapesAndSortsLabels(t *testing.T) {
	registry := NewRegistry()
	counter, err := registry.Counter("requests_total", "HTTP\\n请求", "status", "method")
	if err != nil {
		t.Fatal(err)
	}
	if err := counter.Add(Labels{"method": "GET", "status": "200"}, 2); err != nil {
		t.Fatal(err)
	}
	gauge, err := registry.Gauge("temperature", "温度", "zone")
	if err != nil {
		t.Fatal(err)
	}
	if err := gauge.Set(Labels{"zone": "east\"\\\n"}, -2.5); err != nil {
		t.Fatal(err)
	}

	text := registry.PrometheusText()
	want := "# HELP requests_total HTTP\\\\n请求\n" +
		"# TYPE requests_total counter\n" +
		"requests_total{method=\"GET\",status=\"200\"} 2\n" +
		"# HELP temperature 温度\n" +
		"# TYPE temperature gauge\n" +
		"temperature{zone=\"east\\\"\\\\\\n\"} -2.5\n"
	if text != want {
		t.Fatalf("PrometheusText() = %q，期望 %q", text, want)
	}
}

func TestSensitiveAndInvalidLabelsAreRejected(t *testing.T) {
	registry := NewRegistry()
	if _, err := registry.Counter("requests_total", "请求", "domain"); !errors.Is(err, ErrSensitiveLabel) {
		t.Fatalf("domain 标签错误 = %v，期望 ErrSensitiveLabel", err)
	}
	counter, err := registry.Counter("requests_total", "请求", "method")
	if err != nil {
		t.Fatal(err)
	}
	if err := counter.Inc(Labels{"token": "value"}); !errors.Is(err, ErrSensitiveLabel) {
		t.Fatalf("token 标签错误 = %v，期望 ErrSensitiveLabel", err)
	}
	if _, err := registry.Gauge("bad-name", "无效"); !errors.Is(err, ErrInvalidMetricName) {
		t.Fatalf("非法指标名错误 = %v，期望 ErrInvalidMetricName", err)
	}
	if err := ValidateLabels(Labels{"authorization": "Bearer x"}); !errors.Is(err, ErrSensitiveLabel) {
		t.Fatalf("authorization 标签错误 = %v，期望 ErrSensitiveLabel", err)
	}
}

func TestReadinessRunsAllChecksAndAggregatesSafeFailures(t *testing.T) {
	registry := NewRegistry()
	secret := "database-secret-value"
	var secondRan bool
	if err := registry.RegisterReadiness("acme", func(context.Context) error {
		return errors.New(secret)
	}); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterReadiness("storage", func(context.Context) error {
		secondRan = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	report, err := registry.CheckReadiness(context.Background())
	if err == nil || !strings.Contains(err.Error(), "acme") || strings.Contains(err.Error(), secret) {
		t.Fatalf("聚合错误 = %v，不应泄露检查原始错误", err)
	}
	if report.Ready || !secondRan || len(report.Checks) != 2 || !report.Checks[1].Passed {
		t.Fatalf("就绪报告不正确: %+v", report)
	}
	if err := registry.RegisterReadiness("domain", func(context.Context) error { return nil }); !errors.Is(err, ErrSensitiveLabel) {
		t.Fatalf("敏感检查名错误 = %v，期望 ErrSensitiveLabel", err)
	}
}
