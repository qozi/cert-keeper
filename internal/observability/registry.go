// Package observability 提供不依赖外部库的轻量指标和就绪检查能力。
package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	// ErrInvalidMetricName 表示指标名称不符合 Prometheus 标识符规则。
	ErrInvalidMetricName = errors.New("指标名称无效")
	// ErrInvalidLabel 表示标签名称、标签集合或标签值无效。
	ErrInvalidLabel = errors.New("指标标签无效")
	// ErrSensitiveLabel 表示标签名称可能承载敏感数据。
	ErrSensitiveLabel = errors.New("不允许使用敏感标签")
	// ErrMetricConflict 表示同名指标的类型、说明或标签定义不一致。
	ErrMetricConflict = errors.New("指标定义冲突")
)

// Labels 是一个指标样本的标签集合。
type Labels map[string]string

// MetricType 表示指标的类型。
type MetricType string

const (
	// CounterType 表示只增不减的计数器。
	CounterType MetricType = "counter"
	// GaugeType 表示可增可减的瞬时值。
	GaugeType MetricType = "gauge"
)

// Registry 是并发安全的指标和就绪检查注册中心。
type Registry struct {
	mu      sync.RWMutex
	metrics map[string]*metric
	checks  map[string]Check
}

type metric struct {
	name       string
	help       string
	typ        MetricType
	labelNames []string
	series     map[string]series
}

type series struct {
	labels Labels
	value  float64
}

// Counter 是注册中心中的计数器句柄。
type Counter struct {
	registry *Registry
	name     string
}

// Gauge 是注册中心中的 gauge 句柄。
type Gauge struct {
	registry *Registry
	name     string
}

// MetricSnapshot 是一个指标及其所有样本的只读副本。
type MetricSnapshot struct {
	Name    string
	Help    string
	Type    MetricType
	Samples []Sample
}

// Sample 是一个标签组合对应的数值。
type Sample struct {
	Labels Labels
	Value  float64
}

// Snapshot 是注册中心在某一时刻的稳定副本。
type Snapshot struct {
	Metrics []MetricSnapshot
}

// StandardMetrics 是常用服务指标的句柄集合。
type StandardMetrics struct {
	Requests    *Counter
	ACME        *Counter
	Jobs        *Counter
	Deployments *Counter
	Readiness   *Gauge
}

// NewRegistry 创建一个空的注册中心。
func NewRegistry() *Registry {
	return &Registry{
		metrics: make(map[string]*metric),
		checks:  make(map[string]Check),
	}
}

// Counter 注册或获取一个计数器。同名计数器必须使用完全相同的定义。
func (r *Registry) Counter(name, help string, labelNames ...string) (*Counter, error) {
	if err := r.register(name, help, CounterType, labelNames); err != nil {
		return nil, err
	}
	return &Counter{registry: r, name: name}, nil
}

// Gauge 注册或获取一个 gauge。同名 gauge 必须使用完全相同的定义。
func (r *Registry) Gauge(name, help string, labelNames ...string) (*Gauge, error) {
	if err := r.register(name, help, GaugeType, labelNames); err != nil {
		return nil, err
	}
	return &Gauge{registry: r, name: name}, nil
}

// Inc 将指定标签组合的计数器增加一。
func (c *Counter) Inc(labels Labels) error {
	return c.Add(labels, 1)
}

// Add 将指定标签组合的计数器增加 value。计数器不允许负数或非有限值。
func (c *Counter) Add(labels Labels, value float64) error {
	if value < 0 || !isFinite(value) {
		return fmt.Errorf("%w: 计数器增量必须是非负有限数", ErrInvalidLabel)
	}
	return c.registry.add(c.name, CounterType, labels, value)
}

// Set 将指定标签组合的 gauge 设为 value。
func (g *Gauge) Set(labels Labels, value float64) error {
	if !isFinite(value) {
		return fmt.Errorf("%w: gauge 值必须是有限数", ErrInvalidLabel)
	}
	return g.registry.set(g.name, GaugeType, labels, value)
}

// Add 将指定标签组合的 gauge 增加 value。
func (g *Gauge) Add(labels Labels, value float64) error {
	if !isFinite(value) {
		return fmt.Errorf("%w: gauge 增量必须是有限数", ErrInvalidLabel)
	}
	return g.registry.add(g.name, GaugeType, labels, value)
}

// Snapshot 返回指标的独立副本，调用方可以安全修改其内容。
func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.metrics))
	for name := range r.metrics {
		names = append(names, name)
	}
	sort.Strings(names)

	snapshot := Snapshot{Metrics: make([]MetricSnapshot, 0, len(names))}
	for _, name := range names {
		metric := r.metrics[name]
		keys := make([]string, 0, len(metric.series))
		for key := range metric.series {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		item := MetricSnapshot{
			Name:    name,
			Help:    metric.help,
			Type:    metric.typ,
			Samples: make([]Sample, 0, len(keys)),
		}
		for _, key := range keys {
			value := metric.series[key]
			item.Samples = append(item.Samples, Sample{Labels: copyLabels(value.labels), Value: value.value})
		}
		snapshot.Metrics = append(snapshot.Metrics, item)
	}
	return snapshot
}

// PrometheusText 以 Prometheus 文本格式返回当前快照。
func (r *Registry) PrometheusText() string {
	var output strings.Builder
	for _, metric := range r.Snapshot().Metrics {
		fmt.Fprintf(&output, "# HELP %s %s\n", metric.Name, escapeHelp(metric.Help))
		fmt.Fprintf(&output, "# TYPE %s %s\n", metric.Name, metric.Type)
		for _, sample := range metric.Samples {
			output.WriteString(metric.Name)
			output.WriteString(formatLabels(sample.Labels))
			output.WriteByte(' ')
			output.WriteString(strconv.FormatFloat(sample.Value, 'g', -1, 64))
			output.WriteByte('\n')
		}
	}
	return output.String()
}

// WritePrometheus 将 Prometheus 文本写入 HTTP 或其他 io.Writer。
func (r *Registry) WritePrometheus(writer io.Writer) error {
	_, err := io.WriteString(writer, r.PrometheusText())
	return err
}

// StandardMetrics 注册并返回 request、ACME、job、deployment 和 readiness 指标。
// 预定义指标不包含 token、secret 或原始域名等高基数敏感标签。
func (r *Registry) StandardMetrics() (*StandardMetrics, error) {
	requests, err := r.Counter("certkeeper_requests_total", "处理的 HTTP 请求总数", "method", "status")
	if err != nil {
		return nil, err
	}
	acme, err := r.Counter("certkeeper_acme_operations_total", "执行的 ACME 操作总数", "operation", "status")
	if err != nil {
		return nil, err
	}
	jobs, err := r.Counter("certkeeper_jobs_total", "执行的后台任务总数", "job", "status")
	if err != nil {
		return nil, err
	}
	deployments, err := r.Counter("certkeeper_deployments_total", "执行的部署总数", "status")
	if err != nil {
		return nil, err
	}
	readiness, err := r.Gauge("certkeeper_readiness", "就绪检查状态，成功为 1", "check")
	if err != nil {
		return nil, err
	}
	return &StandardMetrics{
		Requests: requests, ACME: acme, Jobs: jobs, Deployments: deployments, Readiness: readiness,
	}, nil
}

// ValidateLabels 校验标签名称和值，拒绝可能包含敏感信息的标签键。
func ValidateLabels(labels Labels) error {
	for name, value := range labels {
		if err := validateLabelName(name); err != nil {
			return err
		}
		if strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%w: 标签值不能包含 NUL", ErrInvalidLabel)
		}
	}
	return nil
}

func (r *Registry) register(name, help string, typ MetricType, labelNames []string) error {
	if !validIdentifier(name, true) {
		return fmt.Errorf("%w: %q", ErrInvalidMetricName, name)
	}
	labels, err := normalizedLabelNames(labelNames)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.metrics[name]; ok {
		if existing.typ != typ || existing.help != help || !sameStrings(existing.labelNames, labels) {
			return fmt.Errorf("%w: %s", ErrMetricConflict, name)
		}
		return nil
	}
	r.metrics[name] = &metric{name: name, help: help, typ: typ, labelNames: labels, series: make(map[string]series)}
	return nil
}

func (r *Registry) add(name string, typ MetricType, labels Labels, value float64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	metric, err := r.metricFor(name, typ, labels)
	if err != nil {
		return err
	}
	key := labelsKey(metric.labelNames, labels)
	item := metric.series[key]
	item.labels = copyLabels(labels)
	item.value += value
	metric.series[key] = item
	return nil
}

func (r *Registry) set(name string, typ MetricType, labels Labels, value float64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	metric, err := r.metricFor(name, typ, labels)
	if err != nil {
		return err
	}
	key := labelsKey(metric.labelNames, labels)
	metric.series[key] = series{labels: copyLabels(labels), value: value}
	return nil
}

func (r *Registry) metricFor(name string, typ MetricType, labels Labels) (*metric, error) {
	metric, ok := r.metrics[name]
	if !ok || metric.typ != typ {
		return nil, fmt.Errorf("%w: 指标不存在", ErrMetricConflict)
	}
	if err := ValidateLabels(labels); err != nil {
		return nil, err
	}
	if len(labels) != len(metric.labelNames) {
		return nil, fmt.Errorf("%w: 标签数量不匹配", ErrInvalidLabel)
	}
	for _, name := range metric.labelNames {
		if _, ok := labels[name]; !ok {
			return nil, fmt.Errorf("%w: 缺少标签 %s", ErrInvalidLabel, name)
		}
	}
	return metric, nil
}

func normalizedLabelNames(labelNames []string) ([]string, error) {
	labels := append([]string(nil), labelNames...)
	sort.Strings(labels)
	for index, name := range labels {
		if err := validateLabelName(name); err != nil {
			return nil, err
		}
		if index > 0 && labels[index-1] == name {
			return nil, fmt.Errorf("%w: 标签重复 %s", ErrInvalidLabel, name)
		}
	}
	return labels, nil
}

func validateLabelName(name string) error {
	if isSensitiveName(name) {
		return fmt.Errorf("%w: %s", ErrSensitiveLabel, name)
	}
	if !validIdentifier(name, false) {
		return fmt.Errorf("%w: %q", ErrInvalidLabel, name)
	}
	return nil
}

func validIdentifier(name string, allowColon bool) bool {
	if name == "" || strings.HasPrefix(name, "__") {
		return false
	}
	for index, char := range name {
		if char == ':' && allowColon {
			continue
		}
		if char == '_' || isASCIILetter(char) || (index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}

func isASCIILetter(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}

func isSensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, sensitive := range []string{"token", "secret", "authorization", "domain", "password", "credential", "api_key", "apikey"} {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}

func labelsKey(names []string, labels Labels) string {
	var key strings.Builder
	for _, name := range names {
		key.WriteString(name)
		key.WriteByte('=')
		key.WriteString(strconv.Quote(labels[name]))
		key.WriteByte(';')
	}
	return key.String()
}

func formatLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	var output strings.Builder
	output.WriteByte('{')
	for index, name := range names {
		if index > 0 {
			output.WriteByte(',')
		}
		output.WriteString(name)
		output.WriteString("=\"")
		output.WriteString(escapeLabelValue(labels[name]))
		output.WriteByte('"')
	}
	output.WriteByte('}')
	return output.String()
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\n", "\\n")
	return strings.ReplaceAll(value, "\"", "\\\"")
}

func escapeHelp(help string) string {
	return strings.ReplaceAll(strings.ReplaceAll(help, "\\", "\\\\"), "\n", "\\n")
}

func copyLabels(labels Labels) Labels {
	if len(labels) == 0 {
		return nil
	}
	copy := make(Labels, len(labels))
	for name, value := range labels {
		copy[name] = value
	}
	return copy
}

func sameStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

// Check 是一个具名的就绪检查函数。
type Check func(ctx context.Context) error

// CheckResult 是一个就绪检查的安全结果，不包含原始错误文本。
type CheckResult struct {
	Name   string
	Passed bool
}

// ReadinessReport 汇总所有已注册就绪检查的结果。
type ReadinessReport struct {
	Ready  bool
	Checks []CheckResult
}

// RegisterReadiness 注册一个具名就绪检查。名称同时受标签安全规则约束。
func (r *Registry) RegisterReadiness(name string, check Check) error {
	if check == nil {
		return errors.New("就绪检查不能为空")
	}
	if err := validateLabelName(name); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.checks[name]; exists {
		return fmt.Errorf("就绪检查已存在: %s", name)
	}
	r.checks[name] = check
	return nil
}

// CheckReadiness 执行全部已注册检查，并以安全的具名错误聚合失败项。
func (r *Registry) CheckReadiness(ctx context.Context) (ReadinessReport, error) {
	r.mu.RLock()
	names := make([]string, 0, len(r.checks))
	checks := make(map[string]Check, len(r.checks))
	for name, check := range r.checks {
		names = append(names, name)
		checks[name] = check
	}
	r.mu.RUnlock()
	sort.Strings(names)

	report := ReadinessReport{Ready: true, Checks: make([]CheckResult, 0, len(names))}
	var failures []error
	for _, name := range names {
		err := checks[name](ctx)
		passed := err == nil
		report.Checks = append(report.Checks, CheckResult{Name: name, Passed: passed})
		if !passed {
			report.Ready = false
			failures = append(failures, fmt.Errorf("就绪检查失败: %s", name))
		}
	}
	return report, errors.Join(failures...)
}
