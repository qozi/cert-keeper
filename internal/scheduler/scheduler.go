// Package scheduler 提供与具体业务实现解耦的证书协调调度器。
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"
)

const defaultInterval = 12 * time.Hour

// ErrRunInProgress 表示已有一次协调正在执行。
var ErrRunInProgress = errors.New("调度任务正在执行")

// Candidate 是可参与自动协调的证书候选项。
type Candidate struct {
	Domain        string
	ChallengeMode string
}

// Result 是单个域名协调操作返回的业务结果。
// 调度器只负责汇总该结果，不解释其具体字段。
type Result struct {
	Changed bool
	Message string
}

// Worker 是调度器依赖的最小业务接口。
// 实现方可以来自存储层、远程 API 或任意业务组件。
type Worker interface {
	ListCandidates(ctx context.Context) ([]Candidate, error)
	Reconcile(ctx context.Context, domain string) (Result, error)
}

// Ticker 是可停止的时钟 tick 来源。
type Ticker interface {
	Chan() <-chan time.Time
	Stop()
}

// Clock 允许测试替换当前时间和 ticker，避免依赖真实时间。
type Clock interface {
	Now() time.Time
	NewTicker(interval time.Duration) Ticker
}

// Random 提供 jitter 所需的随机数。Float64 的返回范围应为 [0, 1)。
type Random interface {
	Float64() float64
}

// Observer 在一次实际运行结束后接收汇总结果。
type Observer interface {
	Observe(summary Summary)
}

// ObserverFunc 允许使用函数作为 Observer。
type ObserverFunc func(summary Summary)

// Observe 调用函数自身。
func (f ObserverFunc) Observe(summary Summary) {
	f(summary)
}

// Config 定义调度运行参数。
type Config struct {
	Interval time.Duration
	Jitter   time.Duration
	Clock    Clock
	Rand     Random
	Observer Observer
}

// DomainResult 是一个候选域名在本轮的结果。
type DomainResult struct {
	Candidate  Candidate
	Result     Result
	Skipped    bool
	SkipReason string
	Error      error
}

// Summary 汇总一次运行中每个候选项的处理结果。
type Summary struct {
	StartedAt   time.Time
	CompletedAt time.Time
	Candidates  int
	Attempted   int
	Succeeded   int
	Failed      int
	Skipped     int
	Results     []DomainResult
	Error       error
}

// Scheduler 按固定间隔协调候选证书。
type Scheduler struct {
	worker  Worker
	config  Config
	running atomic.Bool
}

// New 创建一个独立于具体 service 实现的调度器。
func New(worker Worker, config Config) *Scheduler {
	if config.Interval <= 0 {
		config.Interval = defaultInterval
	}
	if config.Jitter < 0 {
		config.Jitter = 0
	}
	if config.Clock == nil {
		config.Clock = systemClock{}
	}
	if config.Rand == nil {
		config.Rand = randomSource{}
	}
	return &Scheduler{worker: worker, config: config}
}

// RunOnce 立即执行一轮协调。单个域名失败不会阻止后续候选项。
func (s *Scheduler) RunOnce(ctx context.Context) (summary Summary, err error) {
	if !s.running.CompareAndSwap(false, true) {
		return Summary{}, ErrRunInProgress
	}
	defer s.running.Store(false)

	summary.StartedAt = s.config.Clock.Now()
	defer func() {
		summary.CompletedAt = s.config.Clock.Now()
		summary.Error = err
		if s.config.Observer != nil {
			s.config.Observer.Observe(summary)
		}
	}()

	if s.worker == nil {
		return summary, errors.New("调度 worker 不能为空")
	}
	candidates, listErr := s.worker.ListCandidates(ctx)
	if listErr != nil {
		return summary, fmt.Errorf("列出协调候选项失败: %w", listErr)
	}

	summary.Candidates = len(candidates)
	var failures []error
	for _, candidate := range candidates {
		if candidate.ChallengeMode == "dns_manual" {
			reason := "dns_manual 不支持自动调度"
			summary.Skipped++
			summary.Results = append(summary.Results, DomainResult{
				Candidate:  candidate,
				Skipped:    true,
				SkipReason: reason,
			})
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			failures = append(failures, ctxErr)
			break
		}

		summary.Attempted++
		result, reconcileErr := s.worker.Reconcile(ctx, candidate.Domain)
		domainResult := DomainResult{Candidate: candidate, Result: result, Error: reconcileErr}
		summary.Results = append(summary.Results, domainResult)
		if reconcileErr != nil {
			summary.Failed++
			failures = append(failures, fmt.Errorf("协调 %s 失败: %w", candidate.Domain, reconcileErr))
			continue
		}
		summary.Succeeded++
	}
	return summary, errors.Join(failures...)
}

// Run 先立即执行一轮，随后根据 interval 和 jitter 周期运行，直到 context 被取消。
// 单轮业务错误由 Summary 和 Observer 报告，不会终止后续周期。
func (s *Scheduler) Run(ctx context.Context) error {
	if _, err := s.RunOnce(ctx); err != nil {
		if errors.Is(err, ErrRunInProgress) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	for {
		ticker := s.config.Clock.NewTicker(s.nextInterval())
		select {
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		case <-ticker.Chan():
			ticker.Stop()
			_, _ = s.RunOnce(ctx)
		}
	}
}

func (s *Scheduler) nextInterval() time.Duration {
	if s.config.Jitter == 0 {
		return s.config.Interval
	}
	offset := time.Duration((s.config.Rand.Float64()*2 - 1) * float64(s.config.Jitter))
	interval := s.config.Interval + offset
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

func (systemClock) NewTicker(interval time.Duration) Ticker {
	return systemTicker{ticker: time.NewTicker(interval)}
}

type systemTicker struct {
	ticker *time.Ticker
}

func (t systemTicker) Chan() <-chan time.Time {
	return t.ticker.C
}

func (t systemTicker) Stop() {
	t.ticker.Stop()
}

type randomSource struct{}

func (randomSource) Float64() float64 {
	return rand.Float64()
}
