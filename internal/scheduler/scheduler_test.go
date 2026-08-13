package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeWorker struct {
	mu          sync.Mutex
	candidates  []Candidate
	listErr     error
	calls       []string
	reconcileFn func(context.Context, string) (Result, error)
}

func (w *fakeWorker) ListCandidates(context.Context) ([]Candidate, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]Candidate(nil), w.candidates...), w.listErr
}

func (w *fakeWorker) Reconcile(ctx context.Context, domain string) (Result, error) {
	w.mu.Lock()
	w.calls = append(w.calls, domain)
	fn := w.reconcileFn
	w.mu.Unlock()
	if fn != nil {
		return fn(ctx, domain)
	}
	return Result{}, nil
}

func (w *fakeWorker) Calls() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.calls...)
}

type fakeTicker struct {
	ch      chan time.Time
	mu      sync.Mutex
	stopped bool
}

func (t *fakeTicker) Chan() <-chan time.Time {
	return t.ch
}

func (t *fakeTicker) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
}

func (t *fakeTicker) Stopped() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stopped
}

type fakeClock struct {
	now       time.Time
	ticker    *fakeTicker
	mu        sync.Mutex
	intervals []time.Duration
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) NewTicker(interval time.Duration) Ticker {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.intervals = append(c.intervals, interval)
	return c.ticker
}

func (c *fakeClock) Intervals() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.intervals...)
}

type fixedRandom float64

func (r fixedRandom) Float64() float64 {
	return float64(r)
}

func TestRunOnceContinuesInOrderAndSkipsManualDNS(t *testing.T) {
	failed := errors.New("协调失败")
	worker := &fakeWorker{
		candidates: []Candidate{
			{Domain: "first.example", ChallengeMode: "dns_api"},
			{Domain: "manual.example", ChallengeMode: "dns_manual"},
			{Domain: "third.example", ChallengeMode: "webroot"},
		},
		reconcileFn: func(_ context.Context, domain string) (Result, error) {
			if domain == "first.example" {
				return Result{}, failed
			}
			return Result{Changed: true}, nil
		},
	}
	var observed Summary
	s := New(worker, Config{
		Clock: systemClock{},
		Observer: ObserverFunc(func(summary Summary) {
			observed = summary
		}),
	})

	summary, err := s.RunOnce(context.Background())
	if !errors.Is(err, failed) {
		t.Fatalf("RunOnce() error = %v，期望包含 %v", err, failed)
	}
	if got, want := worker.Calls(), []string{"first.example", "third.example"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("协调顺序 = %v，期望 %v", got, want)
	}
	if summary.Candidates != 3 || summary.Attempted != 2 || summary.Succeeded != 1 || summary.Failed != 1 || summary.Skipped != 1 {
		t.Fatalf("汇总结果不正确: %+v", summary)
	}
	if len(summary.Results) != 3 || !summary.Results[1].Skipped || observed.Failed != 1 {
		t.Fatalf("observer 或结果记录不正确: summary=%+v observed=%+v", summary, observed)
	}
}

func TestRunImmediatelyUsesJitterAndStopsOnCancellation(t *testing.T) {
	ticker := &fakeTicker{ch: make(chan time.Time)}
	clock := &fakeClock{now: time.Unix(100, 0), ticker: ticker}
	called := make(chan struct{}, 1)
	worker := &fakeWorker{
		candidates: []Candidate{{Domain: "example.com", ChallengeMode: "standalone"}},
		reconcileFn: func(context.Context, string) (Result, error) {
			called <- struct{}{}
			return Result{}, nil
		},
	}
	s := New(worker, Config{
		Interval: time.Second,
		Jitter:   200 * time.Millisecond,
		Clock:    clock,
		Rand:     fixedRandom(0),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("Run() 未立即执行首轮")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v，期望 context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() 未响应取消")
	}
	if got := clock.Intervals(); len(got) != 1 || got[0] != 800*time.Millisecond {
		t.Fatalf("ticker interval = %v，期望 800ms", got)
	}
	if !ticker.Stopped() {
		t.Fatal("取消时未停止 ticker")
	}
}

func TestRunTickerDoesNotOverlapReconciliation(t *testing.T) {
	ticker := &fakeTicker{ch: make(chan time.Time, 1)}
	clock := &fakeClock{ticker: ticker}
	started := make(chan struct{})
	release := make(chan struct{})
	secondStarted := make(chan struct{})
	var calls int
	var callsMu sync.Mutex
	worker := &fakeWorker{
		candidates: []Candidate{{Domain: "example.com", ChallengeMode: "standalone"}},
		reconcileFn: func(context.Context, string) (Result, error) {
			callsMu.Lock()
			calls++
			call := calls
			callsMu.Unlock()
			if call == 1 {
				close(started)
				<-release
			} else {
				close(secondStarted)
			}
			return Result{}, nil
		},
	}
	s := New(worker, Config{Interval: time.Second, Clock: clock})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	<-started
	ticker.ch <- time.Now()
	time.Sleep(25 * time.Millisecond)
	if got := len(worker.Calls()); got != 1 {
		t.Fatalf("首轮阻塞时发生重入，调用次数 = %d", got)
	}
	close(release)
	select {
	case <-secondStarted:
	case <-time.After(time.Second):
		t.Fatal("tick 未在首轮完成后执行")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run() 未结束")
	}
}

func TestRunOnceRejectsConcurrentInvocation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	worker := &fakeWorker{
		candidates: []Candidate{{Domain: "example.com", ChallengeMode: "standalone"}},
		reconcileFn: func(context.Context, string) (Result, error) {
			close(started)
			<-release
			return Result{}, nil
		},
	}
	s := New(worker, Config{})
	done := make(chan struct{})
	go func() {
		_, _ = s.RunOnce(context.Background())
		close(done)
	}()
	<-started
	if _, err := s.RunOnce(context.Background()); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("并发 RunOnce() error = %v，期望 ErrRunInProgress", err)
	}
	close(release)
	<-done
}
