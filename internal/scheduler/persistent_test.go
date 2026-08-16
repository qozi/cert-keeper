package scheduler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type persistentMemoryStore struct {
	mu           sync.Mutex
	candidates   []Candidate
	jobs         map[string]Job
	jobOrder     []string
	keys         map[string]string
	skips        []SkipRecord
	nextID       int
	claimCalls   chan struct{}
	renewedCalls chan struct{}
}

func newPersistentMemoryStore(candidates ...Candidate) *persistentMemoryStore {
	return &persistentMemoryStore{
		candidates: append([]Candidate(nil), candidates...),
		jobs:       make(map[string]Job),
		keys:       make(map[string]string),
	}
}

func (s *persistentMemoryStore) ListCandidates(ctx context.Context) ([]Candidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Candidate(nil), s.candidates...), nil
}

func (s *persistentMemoryStore) CreateJob(ctx context.Context, spec JobSpec) (Job, bool, error) {
	if err := ctx.Err(); err != nil {
		return Job{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := spec.Candidate.Domain + "\x00" + spec.IdempotencyKey
	if id, ok := s.keys[key]; ok {
		return s.jobs[id], false, nil
	}
	s.nextID++
	job := Job{
		ID:             fmt.Sprintf("job-%d", s.nextID),
		Candidate:      spec.Candidate,
		Actor:          spec.Actor,
		IdempotencyKey: spec.IdempotencyKey,
		Status:         JobQueued,
		MaxAttempts:    spec.MaxAttempts,
		AvailableAt:    spec.CreatedAt,
	}
	s.jobs[job.ID] = job
	s.jobOrder = append(s.jobOrder, job.ID)
	s.keys[key] = job.ID
	return job, true, nil
}

func (s *persistentMemoryStore) ClaimJob(ctx context.Context, request ClaimRequest) (*Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimCalls != nil {
		select {
		case s.claimCalls <- struct{}{}:
		default:
		}
	}
	for _, id := range s.jobOrder {
		job := s.jobs[id]
		if !s.eligible(job, request.Now) || s.domainLeased(job, request.Now) {
			continue
		}
		job.Status = JobRunning
		job.LeaseOwner = request.Owner
		job.LeaseVersion++
		job.LeaseExpiresAt = request.LeaseUntil
		job.Attempts++
		s.jobs[id] = job
		claimed := job
		return &claimed, nil
	}
	return nil, nil
}

func (s *persistentMemoryStore) RenewLease(ctx context.Context, renewal LeaseRenewal) (uint64, bool, error) {
	if err := ctx.Err(); err != nil {
		return renewal.LeaseVersion, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[renewal.ID]
	if !ok || job.Status != JobRunning || job.LeaseOwner != renewal.Owner || job.LeaseVersion != renewal.LeaseVersion || !job.LeaseExpiresAt.After(renewal.Now) {
		return renewal.LeaseVersion, false, nil
	}
	// 续租成功，递增版本号以模拟乐观锁语义
	job.LeaseVersion++
	job.LeaseExpiresAt = renewal.LeaseUntil
	s.jobs[job.ID] = job
	if s.renewedCalls != nil {
		select {
		case s.renewedCalls <- struct{}{}:
		default:
		}
	}
	return job.LeaseVersion, true, nil
}

func (s *persistentMemoryStore) UpdateJob(ctx context.Context, update JobUpdate) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[update.ID]
	if !ok || job.Status != JobRunning || job.LeaseOwner != update.Owner || job.LeaseVersion != update.LeaseVersion || !job.LeaseExpiresAt.After(update.Now) {
		return false, nil
	}
	job.Status = update.Status
	job.AvailableAt = update.AvailableAt
	job.LastError = update.LastError
	job.Result = update.Result
	job.LeaseOwner = ""
	job.LeaseExpiresAt = time.Time{}
	s.jobs[job.ID] = job
	return true, nil
}

func (s *persistentMemoryStore) RecordSkippedCandidate(ctx context.Context, record SkipRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.skips = append(s.skips, record)
	return nil
}

func (s *persistentMemoryStore) seed(job Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.ID == "" {
		s.nextID++
		job.ID = fmt.Sprintf("job-%d", s.nextID)
	}
	if job.MaxAttempts == 0 {
		job.MaxAttempts = 3
	}
	s.jobs[job.ID] = job
	s.jobOrder = append(s.jobOrder, job.ID)
	s.keys[job.Candidate.Domain+"\x00"+job.IdempotencyKey] = job.ID
}

func (s *persistentMemoryStore) addCandidate(candidate Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.candidates = append(s.candidates, candidate)
}

func (s *persistentMemoryStore) job(id string) Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[id]
}

func (s *persistentMemoryStore) jobsForDomain(domain string) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	var jobs []Job
	for _, id := range s.jobOrder {
		if s.jobs[id].Candidate.Domain == domain {
			jobs = append(jobs, s.jobs[id])
		}
	}
	return jobs
}

func (s *persistentMemoryStore) eligible(job Job, now time.Time) bool {
	switch job.Status {
	case JobQueued, JobRetrying:
		return job.AvailableAt.IsZero() || !job.AvailableAt.After(now)
	case JobRunning:
		return !job.LeaseExpiresAt.After(now)
	default:
		return false
	}
}

func (s *persistentMemoryStore) domainLeased(candidate Job, now time.Time) bool {
	for _, other := range s.jobs {
		if other.ID == candidate.ID || other.Candidate.Domain != candidate.Candidate.Domain {
			continue
		}
		if other.Status == JobRunning && other.LeaseExpiresAt.After(now) {
			return true
		}
	}
	return false
}

type persistentTestClock struct {
	mu          sync.Mutex
	now         time.Time
	ticker      []*persistentTestTicker
	tickerReady chan struct{}
}

func newPersistentTestClock(now time.Time) *persistentTestClock {
	return &persistentTestClock{now: now, tickerReady: make(chan struct{}, 8)}
}

func (c *persistentTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *persistentTestClock) NewTicker(time.Duration) Ticker {
	t := &persistentTestTicker{ch: make(chan time.Time, 1)}
	c.mu.Lock()
	c.ticker = append(c.ticker, t)
	c.mu.Unlock()
	select {
	case c.tickerReady <- struct{}{}:
	default:
	}
	return t
}

func (c *persistentTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	now := c.now
	tickers := append([]*persistentTestTicker(nil), c.ticker...)
	c.mu.Unlock()
	for _, ticker := range tickers {
		select {
		case ticker.ch <- now:
		default:
		}
	}
}

type persistentTestTicker struct {
	ch chan time.Time
}

func (t *persistentTestTicker) Chan() <-chan time.Time { return t.ch }
func (t *persistentTestTicker) Stop()                  {}

func persistentWorkerForTest(store PersistentStore, reconciler PersistentReconciler, clock Clock, owner string) *PersistentWorker {
	return NewPersistentWorker(store, reconciler, PersistentConfig{
		Interval:       time.Hour,
		PollInterval:   time.Hour,
		LeaseDuration:  time.Minute,
		RenewInterval:  10 * time.Millisecond,
		BackoffInitial: time.Minute,
		BackoffMax:     4 * time.Minute,
		MaxAttempts:    3,
		Owner:          owner,
		Actor:          Actor{ID: "internal-scheduler", Kind: "worker"},
		Clock:          clock,
	})
}

func TestPersistentWorkersSameDomainClaimOnlyOnce(t *testing.T) {
	clock := newPersistentTestClock(time.Unix(100, 0))
	store := newPersistentMemoryStore(Candidate{Domain: "example.com", ChallengeMode: "dns_api"})
	store.claimCalls = make(chan struct{}, 20)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	reconciler := PersistentReconcilerFunc(func(context.Context, Actor, Job) (Result, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return Result{}, nil
	})

	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		worker := persistentWorkerForTest(store, reconciler, clock, fmt.Sprintf("worker-%d", i))
		go func() {
			_, err := worker.RunOnce(context.Background())
			results <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("没有 worker 成功 claim 任务")
	}
	for i := 0; i < 20; i++ {
		select {
		case <-store.claimCalls:
		case <-time.After(time.Second):
			t.Fatalf("第 %d 个 worker 未完成 claim", i+1)
		}
	}
	close(release)
	for i := 0; i < 20; i++ {
		if err := <-results; err != nil {
			t.Fatalf("RunOnce() error = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("同域 reconcile 次数 = %d，期望 1", got)
	}
	if got := len(store.jobsForDomain("example.com")); got != 1 {
		t.Fatalf("同轮任务数 = %d，期望 1", got)
	}
}

func TestPersistentWorkerTakesOverExpiredLeaseAndRecoversAfterRestart(t *testing.T) {
	now := time.Unix(200, 0)
	clock := newPersistentTestClock(now)
	store := newPersistentMemoryStore()
	store.seed(Job{
		ID: "stale", Candidate: Candidate{Domain: "stale.example", ChallengeMode: "dns_api"},
		Status: JobRunning, Attempts: 1, MaxAttempts: 3,
		LeaseOwner: "dead-worker", LeaseExpiresAt: now.Add(-time.Second), AvailableAt: now,
		IdempotencyKey: "old-round",
	})
	var claimed Job
	worker := persistentWorkerForTest(store, PersistentReconcilerFunc(func(_ context.Context, _ Actor, job Job) (Result, error) {
		claimed = job
		return Result{Changed: true}, nil
	}), clock, "restarted-worker")
	if _, err := worker.runCycle(context.Background(), false); err != nil {
		t.Fatalf("接管过期任务失败: %v", err)
	}
	if claimed.ID != "stale" || claimed.Attempts != 2 || claimed.LeaseOwner != "restarted-worker" {
		t.Fatalf("接管任务信息不正确: %+v", claimed)
	}
	if got := store.job("stale"); got.Status != JobSucceeded {
		t.Fatalf("接管后状态 = %s，期望 succeeded", got.Status)
	}

	queuedStore := newPersistentMemoryStore()
	queuedStore.seed(Job{
		ID: "queued", Candidate: Candidate{Domain: "queued.example", ChallengeMode: "dns_api"},
		Status: JobQueued, MaxAttempts: 3, AvailableAt: now,
		IdempotencyKey: "queued-round",
	})
	queuedWorker := persistentWorkerForTest(queuedStore, PersistentReconcilerFunc(func(_ context.Context, _ Actor, job Job) (Result, error) {
		if job.ID != "queued" {
			t.Fatalf("重启恢复 claim 了错误任务: %+v", job)
		}
		return Result{}, nil
	}), clock, "new-process")
	if _, err := queuedWorker.runCycle(context.Background(), false); err != nil {
		t.Fatalf("重启恢复失败: %v", err)
	}
	if got := queuedStore.job("queued"); got.Status != JobSucceeded {
		t.Fatalf("重启恢复状态 = %s，期望 succeeded", got.Status)
	}
}

func TestPersistentWorkerUsesExponentialBackoff(t *testing.T) {
	now := time.Unix(300, 0)
	clock := newPersistentTestClock(now)
	store := newPersistentMemoryStore(Candidate{Domain: "retry.example", ChallengeMode: "dns_api"})
	var calls atomic.Int32
	temporaryErr := errors.New("上游暂时不可用")
	worker := persistentWorkerForTest(store, PersistentReconcilerFunc(func(_ context.Context, _ Actor, job Job) (Result, error) {
		if calls.Add(1) < 3 {
			return Result{}, &TemporaryError{Err: temporaryErr}
		}
		return Result{Changed: true}, nil
	}), clock, "retry-worker")

	if _, err := worker.RunOnce(context.Background()); !errors.Is(err, temporaryErr) {
		t.Fatalf("临时错误未向调用方报告: %v", err)
	}
	job := store.jobsForDomain("retry.example")[0]
	if job.Status != JobRetrying || !job.AvailableAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("第一次退避不正确: %+v", job)
	}
	if _, err := worker.runCycle(context.Background(), false); err != nil {
		t.Fatalf("退避期间不应 claim 任务: %v", err)
	}
	clock.Advance(time.Minute)
	if _, err := worker.runCycle(context.Background(), false); err == nil {
		t.Fatal("第二次临时错误应继续返回错误")
	}
	job = store.jobsForDomain("retry.example")[0]
	if job.Status != JobRetrying || !job.AvailableAt.Equal(now.Add(3*time.Minute)) {
		t.Fatalf("第二次退避不正确: %+v", job)
	}
	clock.Advance(2 * time.Minute)
	if _, err := worker.runCycle(context.Background(), false); err != nil {
		t.Fatalf("退避后成功执行失败: %v", err)
	}
	if job = store.jobsForDomain("retry.example")[0]; job.Status != JobSucceeded || calls.Load() != 3 {
		t.Fatalf("重试最终状态不正确: job=%+v calls=%d", job, calls.Load())
	}
}

func TestPersistentWorkerStopsPermanentChallengeAtMaxAttempts(t *testing.T) {
	now := time.Unix(400, 0)
	clock := newPersistentTestClock(now)
	store := newPersistentMemoryStore(Candidate{Domain: "permanent.example", ChallengeMode: "dns_api"})
	var calls atomic.Int32
	worker := persistentWorkerForTest(store, PersistentReconcilerFunc(func(context.Context, Actor, Job) (Result, error) {
		calls.Add(1)
		return Result{}, &PermanentChallengeError{Err: errors.New("challenge 配置永久错误")}
	}), clock, "permanent-worker")
	for attempt := 1; attempt <= 3; attempt++ {
		if _, err := worker.runCycle(context.Background(), attempt == 1); err == nil {
			t.Fatalf("第 %d 次永久错误未报告", attempt)
		}
		if attempt < 3 {
			clock.Advance(time.Duration(1<<(attempt-1)) * time.Minute)
		}
	}
	job := store.jobsForDomain("permanent.example")[0]
	if job.Status != JobFailed || job.Attempts != 3 || calls.Load() != 3 {
		t.Fatalf("永久错误未在 max attempts 停止: job=%+v calls=%d", job, calls.Load())
	}
}

func TestPersistentWorkerCancellationRequeuesJob(t *testing.T) {
	clock := newPersistentTestClock(time.Unix(500, 0))
	store := newPersistentMemoryStore(Candidate{Domain: "cancel.example", ChallengeMode: "dns_api"})
	started := make(chan struct{})
	worker := persistentWorkerForTest(store, PersistentReconcilerFunc(func(ctx context.Context, _ Actor, _ Job) (Result, error) {
		close(started)
		<-ctx.Done()
		return Result{}, ctx.Err()
	}), clock, "cancel-worker")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := worker.RunOnce(ctx)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("任务未开始执行")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("取消返回错误 = %v，期望 context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("取消后 worker 未退出")
	}
	job := store.jobsForDomain("cancel.example")[0]
	if job.Status != JobQueued || !job.LeaseExpiresAt.IsZero() || job.LeaseOwner != "" {
		t.Fatalf("取消后任务未重新入队: %+v", job)
	}
}

func TestPersistentWorkerRenewalPreventsPrematureTakeover(t *testing.T) {
	now := time.Unix(600, 0)
	clock := newPersistentTestClock(now)
	store := newPersistentMemoryStore(Candidate{Domain: "renew.example", ChallengeMode: "dns_api"})
	store.renewedCalls = make(chan struct{}, 1)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	worker := NewPersistentWorker(store, PersistentReconcilerFunc(func(context.Context, Actor, Job) (Result, error) {
		calls.Add(1)
		close(started)
		<-release
		return Result{}, nil
	}), PersistentConfig{
		Interval: time.Hour, PollInterval: time.Hour, LeaseDuration: 100 * time.Millisecond,
		RenewInterval: 10 * time.Millisecond, MaxAttempts: 2, Owner: "renew-worker", Clock: clock,
	})
	result := make(chan error, 1)
	go func() {
		_, err := worker.RunOnce(context.Background())
		result <- err
	}()
	<-started
	select {
	case <-clock.tickerReady:
	case <-time.After(time.Second):
		t.Fatal("续租 ticker 未启动")
	}
	clock.Advance(50 * time.Millisecond)
	select {
	case <-store.renewedCalls:
	case <-time.After(time.Second):
		t.Fatal("lease 未续租")
	}
	clock.Advance(70 * time.Millisecond)
	other := persistentWorkerForTest(store, PersistentReconcilerFunc(func(context.Context, Actor, Job) (Result, error) {
		t.Fatal("续租有效期间不应被其他 worker 接管")
		return Result{}, nil
	}), clock, "other-worker")
	if _, err := other.runCycle(context.Background(), false); err != nil {
		t.Fatalf("竞争 worker 处理失败: %v", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("原 worker 执行失败: %v", err)
	}
	if calls.Load() != 1 || store.job("job-1").Status != JobSucceeded {
		t.Fatalf("续租后任务状态不正确: calls=%d job=%+v", calls.Load(), store.job("job-1"))
	}
}

func TestPersistentWorkerSkipsModesAndFindsNewCandidateNextRound(t *testing.T) {
	now := time.Unix(700, 0)
	clock := newPersistentTestClock(now)
	store := newPersistentMemoryStore(
		Candidate{Domain: "dns.example", ChallengeMode: "dns_api"},
		Candidate{Domain: "manual.example", ChallengeMode: "dns_manual"},
	)
	var domainsMu sync.Mutex
	var domains []string
	worker := persistentWorkerForTest(store, PersistentReconcilerFunc(func(_ context.Context, _ Actor, job Job) (Result, error) {
		domainsMu.Lock()
		domains = append(domains, job.Candidate.Domain)
		domainsMu.Unlock()
		return Result{}, nil
	}), clock, "scan-worker")
	if summary, err := worker.RunOnce(context.Background()); err != nil || summary.Skipped != 1 {
		t.Fatalf("首次扫描结果不正确: summary=%+v err=%v", summary, err)
	}
	if len(store.skips) != 1 || store.skips[0].Reason == "" {
		t.Fatalf("跳过原因未记录: %+v", store.skips)
	}
	store.addCandidate(Candidate{Domain: "new.example", ChallengeMode: "dns_api"})
	clock.Advance(time.Hour)
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("下一轮发现新候选失败: %v", err)
	}
	domainsMu.Lock()
	defer domainsMu.Unlock()
	if !containsString(domains, "new.example") {
		t.Fatalf("下一轮未执行新候选: %v", domains)
	}
}

func TestPersistentWorkerHonorsConcurrencyLimit(t *testing.T) {
	clock := newPersistentTestClock(time.Unix(800, 0))
	store := newPersistentMemoryStore(
		Candidate{Domain: "one.example", ChallengeMode: "dns_api"},
		Candidate{Domain: "two.example", ChallengeMode: "dns_api"},
		Candidate{Domain: "three.example", ChallengeMode: "dns_api"},
		Candidate{Domain: "four.example", ChallengeMode: "dns_api"},
		Candidate{Domain: "five.example", ChallengeMode: "dns_api"},
	)
	var active, maximum atomic.Int32
	worker := NewPersistentWorker(store, PersistentReconcilerFunc(func(_ context.Context, _ Actor, _ Job) (Result, error) {
		current := active.Add(1)
		for {
			old := maximum.Load()
			if current <= old || maximum.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		return Result{}, nil
	}), PersistentConfig{
		Interval: time.Hour, PollInterval: time.Hour, LeaseDuration: time.Second,
		RenewInterval: 100 * time.Millisecond, MaxAttempts: 2, Concurrency: 2,
		Owner: "limited-worker", Clock: clock,
	})
	if _, err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("并发处理失败: %v", err)
	}
	if maximum.Load() > 2 {
		t.Fatalf("最大并发 = %d，超过配置值 2", maximum.Load())
	}
}

func TestClassifyError(t *testing.T) {
	timeout := &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	tests := []struct {
		name  string
		err   error
		class ErrorClass
	}{
		{name: "429", err: &HTTPError{Code: 429}, class: ErrorTemporary},
		{name: "5xx", err: &HTTPError{Code: 503}, class: ErrorTemporary},
		{name: "dns timeout", err: timeout, class: ErrorTemporary},
		{name: "permanent challenge", err: &PermanentChallengeError{Err: errors.New("invalid challenge")}, class: ErrorPermanentChallenge},
		{name: "bad request", err: &HTTPError{Code: 400}, class: ErrorPermanent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyError(test.err); got != test.class {
				t.Fatalf("ClassifyError() = %s，期望 %s", got, test.class)
			}
		})
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
