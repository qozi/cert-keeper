package scheduler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultPollInterval   = 5 * time.Second
	defaultLeaseDuration  = time.Minute
	defaultBackoffInitial = 30 * time.Second
	defaultBackoffMax     = 30 * time.Minute
	defaultMaxAttempts    = 5
	cleanupTimeout        = 5 * time.Second
)

// JobStatus 是持久任务的状态。
type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobRetrying  JobStatus = "retrying"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
)

// Actor 标识发起内部协调的主体，不包含 HTTP token 或外部凭据。
type Actor struct {
	ID   string
	Kind string
}

// JobSpec 是扫描候选后创建持久任务所需的字段。
type JobSpec struct {
	Candidate      Candidate
	Actor          Actor
	IdempotencyKey string
	MaxAttempts    int
	CreatedAt      time.Time
}

// Job 是由 PersistentStore 持久化的协调任务。
type Job struct {
	ID             string
	Candidate      Candidate
	Actor          Actor
	IdempotencyKey string
	Status         JobStatus
	Attempts       int
	MaxAttempts    int
	AvailableAt    time.Time
	LeaseOwner     string
	LeaseVersion   uint64
	LeaseExpiresAt time.Time
	LastError      string
	Result         Result
}

// ClaimRequest 定义一次原子 claim 的时间和 lease 所有者。
type ClaimRequest struct {
	Owner      string
	Now        time.Time
	LeaseUntil time.Time
}

// LeaseRenewal 使用 owner 和当前时间原子续租仍有效的 lease。
type LeaseRenewal struct {
	ID           string
	Owner        string
	Now          time.Time
	LeaseVersion uint64
	LeaseUntil   time.Time
}

// JobUpdate 使用 lease owner 比较并交换更新任务状态。
type JobUpdate struct {
	ID           string
	Owner        string
	Now          time.Time
	LeaseVersion uint64
	Status       JobStatus
	AvailableAt  time.Time
	LastError    string
	Result       Result
}

// SkipRecord 记录没有进入持久任务队列的候选及原因。
type SkipRecord struct {
	Candidate Candidate
	Actor     Actor
	Reason    string
	CreatedAt time.Time
}

// PersistentStore 定义持久 worker 所需的原子存储契约。
// CreateJob 必须按 domain 和 idempotency key 永久幂等；ClaimJob 必须原子选择到期任务、
// 接管过期 running，并保证同一域名最多存在一个未过期 lease。
type PersistentStore interface {
	ListCandidates(ctx context.Context) ([]Candidate, error)
	CreateJob(ctx context.Context, spec JobSpec) (job Job, created bool, err error)
	ClaimJob(ctx context.Context, request ClaimRequest) (*Job, error)
	RenewLease(ctx context.Context, renewal LeaseRenewal) (bool, error)
	UpdateJob(ctx context.Context, update JobUpdate) (bool, error)
	RecordSkippedCandidate(ctx context.Context, record SkipRecord) error
}

// PersistentReconciler 使用内部 actor 执行一个已 claim 的持久任务。
type PersistentReconciler interface {
	ReconcileJob(ctx context.Context, actor Actor, job Job) (Result, error)
}

// PersistentReconcilerFunc 允许函数直接作为 PersistentReconciler。
type PersistentReconcilerFunc func(context.Context, Actor, Job) (Result, error)

func (f PersistentReconcilerFunc) ReconcileJob(ctx context.Context, actor Actor, job Job) (Result, error) {
	return f(ctx, actor, job)
}

// PersistentObserver 接收持久 worker 单轮扫描或轮询结果。
type PersistentObserver interface {
	ObservePersistent(summary PersistentSummary)
}

// PersistentObserverFunc 允许函数直接作为 PersistentObserver。
type PersistentObserverFunc func(PersistentSummary)

func (f PersistentObserverFunc) ObservePersistent(summary PersistentSummary) {
	f(summary)
}

// PersistentConfig 定义扫描、claim、续租和重试策略。
type PersistentConfig struct {
	Interval       time.Duration
	Jitter         time.Duration
	PollInterval   time.Duration
	LeaseDuration  time.Duration
	RenewInterval  time.Duration
	BackoffInitial time.Duration
	BackoffMax     time.Duration
	MaxAttempts    int
	Concurrency    int
	Owner          string
	Actor          Actor
	Clock          Clock
	Rand           Random
	Observer       PersistentObserver
}

// PersistentSummary 汇总一轮候选扫描和到期任务处理结果。
type PersistentSummary struct {
	StartedAt   time.Time
	CompletedAt time.Time
	Scanned     int
	Created     int
	Skipped     int
	Claimed     int
	Succeeded   int
	Retried     int
	Failed      int
	Released    int
	Error       error
}

// PersistentWorker 扫描候选并执行具备 lease 的持久协调任务。
type PersistentWorker struct {
	store      PersistentStore
	reconciler PersistentReconciler
	config     PersistentConfig
	cycle      atomic.Bool
	loop       atomic.Bool
}

var ownerSequence atomic.Uint64

// NewPersistentWorker 创建持久任务 worker。持久化实现由后续 service/store 适配器注入。
func NewPersistentWorker(store PersistentStore, reconciler PersistentReconciler, config PersistentConfig) *PersistentWorker {
	if config.Interval <= 0 {
		config.Interval = defaultInterval
	}
	if config.Jitter < 0 {
		config.Jitter = 0
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = defaultLeaseDuration
	}
	if config.RenewInterval <= 0 || config.RenewInterval >= config.LeaseDuration {
		config.RenewInterval = config.LeaseDuration / 3
		if config.RenewInterval <= 0 {
			config.RenewInterval = time.Nanosecond
		}
	}
	if config.BackoffInitial <= 0 {
		config.BackoffInitial = defaultBackoffInitial
	}
	if config.BackoffMax <= 0 {
		config.BackoffMax = defaultBackoffMax
	}
	if config.BackoffMax < config.BackoffInitial {
		config.BackoffMax = config.BackoffInitial
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}
	if config.Owner == "" {
		config.Owner = defaultLeaseOwner()
	}
	if config.Actor.ID == "" {
		config.Actor = Actor{ID: "certificate-scheduler", Kind: "system"}
	}
	if config.Clock == nil {
		config.Clock = systemClock{}
	}
	if config.Rand == nil {
		config.Rand = randomSource{}
	}
	return &PersistentWorker{store: store, reconciler: reconciler, config: config}
}

// RunOnce 立即扫描候选并处理当前可 claim 的任务。
func (w *PersistentWorker) RunOnce(ctx context.Context) (PersistentSummary, error) {
	return w.runCycle(ctx, true)
}

// Run 立即执行首轮，随后周期扫描候选，并短周期轮询退避到期的任务。
func (w *PersistentWorker) Run(ctx context.Context) error {
	if !w.loop.CompareAndSwap(false, true) {
		return ErrRunInProgress
	}
	defer w.loop.Store(false)

	if _, err := w.runCycle(ctx, true); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	scanTicker := w.config.Clock.NewTicker(w.nextInterval())
	pollTicker := w.config.Clock.NewTicker(w.config.PollInterval)
	defer func() { scanTicker.Stop() }()
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTicker.Chan():
			_, _ = w.runCycle(ctx, false)
		case <-scanTicker.Chan():
			scanTicker.Stop()
			_, _ = w.runCycle(ctx, true)
			scanTicker = w.config.Clock.NewTicker(w.nextInterval())
		}
	}
}

func (w *PersistentWorker) runCycle(ctx context.Context, scan bool) (summary PersistentSummary, err error) {
	if !w.cycle.CompareAndSwap(false, true) {
		return PersistentSummary{}, ErrRunInProgress
	}
	defer w.cycle.Store(false)

	if w.store == nil {
		return summary, errors.New("持久任务存储不能为空")
	}
	if w.reconciler == nil {
		return summary, errors.New("持久任务 reconciler 不能为空")
	}
	summary.StartedAt = w.config.Clock.Now()
	recorder := persistentRecorder{summary: &summary}
	defer func() {
		summary.CompletedAt = w.config.Clock.Now()
		summary.Error = errors.Join(recorder.errors...)
		err = summary.Error
		if w.config.Observer != nil {
			w.config.Observer.ObservePersistent(summary)
		}
	}()

	if scan {
		w.scanCandidates(ctx, &recorder)
	}
	if ctx.Err() == nil {
		w.processDueJobs(ctx, &recorder)
	}
	return summary, nil
}

func (w *PersistentWorker) scanCandidates(ctx context.Context, recorder *persistentRecorder) {
	candidates, err := w.store.ListCandidates(ctx)
	if err != nil {
		recorder.addError(fmt.Errorf("扫描协调候选项失败: %w", err))
		return
	}
	recorder.addScanned(len(candidates))
	scanTime := w.config.Clock.Now()
	idempotencyKey := w.scanIdempotencyKey(scanTime)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			recorder.addError(ctx.Err())
			return
		}
		if candidate.ChallengeMode != "dns_api" {
			reason := fmt.Sprintf("仅调度 dns_api，已跳过 challenge_mode=%s", candidate.ChallengeMode)
			record := SkipRecord{Candidate: candidate, Actor: w.config.Actor, Reason: reason, CreatedAt: w.config.Clock.Now()}
			if err := w.store.RecordSkippedCandidate(ctx, record); err != nil {
				recorder.addError(fmt.Errorf("记录跳过候选项 %s 失败: %w", candidate.Domain, err))
			}
			recorder.addSkipped()
			continue
		}
		_, created, err := w.store.CreateJob(ctx, JobSpec{
			Candidate:      candidate,
			Actor:          w.config.Actor,
			IdempotencyKey: idempotencyKey,
			MaxAttempts:    w.config.MaxAttempts,
			CreatedAt:      scanTime,
		})
		if err != nil {
			recorder.addError(fmt.Errorf("创建持久任务 %s 失败: %w", candidate.Domain, err))
			continue
		}
		if created {
			recorder.addCreated()
		}
	}
}

func (w *PersistentWorker) processDueJobs(ctx context.Context, recorder *persistentRecorder) {
	var workers sync.WaitGroup
	workers.Add(w.config.Concurrency)
	for range w.config.Concurrency {
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				now := w.config.Clock.Now()
				job, err := w.store.ClaimJob(ctx, ClaimRequest{
					Owner:      w.config.Owner,
					Now:        now,
					LeaseUntil: now.Add(w.config.LeaseDuration),
				})
				if err != nil {
					recorder.addError(fmt.Errorf("claim 持久任务失败: %w", err))
					return
				}
				if job == nil {
					return
				}
				recorder.addClaimed()
				w.executeJob(ctx, *job, recorder)
			}
		}()
	}
	workers.Wait()
}

func (w *PersistentWorker) executeJob(ctx context.Context, job Job, recorder *persistentRecorder) {
	jobCtx, cancelJob := context.WithCancel(ctx)
	stopRenewal := make(chan struct{})
	renewalDone := make(chan error, 1)
	go func() {
		renewalDone <- w.renewLease(jobCtx, job.ID, job.LeaseVersion, stopRenewal, cancelJob)
	}()

	actor := job.Actor
	if actor.ID == "" {
		actor = w.config.Actor
	}
	result, reconcileErr := w.reconciler.ReconcileJob(jobCtx, actor, job)
	close(stopRenewal)
	renewalErr := <-renewalDone
	cancelJob()

	if ctx.Err() != nil {
		w.releaseCanceledJob(job, ctx.Err(), recorder)
		recorder.addError(ctx.Err())
		return
	}
	if renewalErr != nil {
		recorder.addError(fmt.Errorf("任务 %s 续租失败: %w", job.ID, renewalErr))
		return
	}
	if reconcileErr == nil {
		w.updateClaimedJob(ctx, JobUpdate{
			ID: job.ID, Owner: w.config.Owner, Now: w.config.Clock.Now(), LeaseVersion: job.LeaseVersion,
			Status: JobSucceeded, Result: result,
		}, recorder, func() { recorder.addSucceeded() })
		return
	}

	class := ClassifyError(reconcileErr)
	maxAttempts := job.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = w.config.MaxAttempts
	}
	if job.Attempts < maxAttempts && (class == ErrorTemporary || class == ErrorPermanentChallenge) {
		w.updateClaimedJob(ctx, JobUpdate{
			ID:           job.ID,
			Owner:        w.config.Owner,
			Now:          w.config.Clock.Now(),
			LeaseVersion: job.LeaseVersion,
			Status:       JobRetrying,
			AvailableAt:  w.config.Clock.Now().Add(w.backoff(job.Attempts)),
			LastError:    reconcileErr.Error(),
		}, recorder, func() { recorder.addRetried() })
		recorder.addError(fmt.Errorf("协调 %s 将重试: %w", job.Candidate.Domain, reconcileErr))
		return
	}
	w.updateClaimedJob(ctx, JobUpdate{
		ID: job.ID, Owner: w.config.Owner, Now: w.config.Clock.Now(), LeaseVersion: job.LeaseVersion,
		Status: JobFailed, LastError: reconcileErr.Error(),
	}, recorder, func() { recorder.addFailed() })
	recorder.addError(fmt.Errorf("协调 %s 已停止: %w", job.Candidate.Domain, reconcileErr))
}

func (w *PersistentWorker) renewLease(ctx context.Context, id string, leaseVersion uint64, stop <-chan struct{}, cancel context.CancelFunc) error {
	ticker := w.config.Clock.NewTicker(w.config.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.Chan():
			now := w.config.Clock.Now()
			ok, err := w.store.RenewLease(ctx, LeaseRenewal{
				ID: id, Owner: w.config.Owner, Now: now, LeaseVersion: leaseVersion,
				LeaseUntil: now.Add(w.config.LeaseDuration),
			})
			if err != nil {
				cancel()
				return err
			}
			if !ok {
				cancel()
				return errors.New("lease 已丢失")
			}
		}
	}
}

func (w *PersistentWorker) releaseCanceledJob(job Job, cause error, recorder *persistentRecorder) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	ok, err := w.store.UpdateJob(cleanupCtx, JobUpdate{
		ID: job.ID, Owner: w.config.Owner, Now: w.config.Clock.Now(), LeaseVersion: job.LeaseVersion,
		Status: JobQueued, AvailableAt: w.config.Clock.Now(), LastError: cause.Error(),
	})
	if err != nil {
		recorder.addError(fmt.Errorf("释放已取消任务 %s 失败: %w", job.ID, err))
		return
	}
	if !ok {
		recorder.addError(fmt.Errorf("释放已取消任务 %s 失败: lease 已丢失", job.ID))
		return
	}
	recorder.addReleased()
}

func (w *PersistentWorker) updateClaimedJob(ctx context.Context, update JobUpdate, recorder *persistentRecorder, applied func()) {
	ok, err := w.store.UpdateJob(ctx, update)
	if err != nil {
		recorder.addError(fmt.Errorf("更新任务 %s 状态失败: %w", update.ID, err))
		return
	}
	if !ok {
		recorder.addError(fmt.Errorf("更新任务 %s 状态失败: lease 已丢失", update.ID))
		return
	}
	applied()
}

func (w *PersistentWorker) backoff(attempt int) time.Duration {
	if attempt <= 1 {
		return w.config.BackoffInitial
	}
	delay := w.config.BackoffInitial
	for i := 1; i < attempt; i++ {
		if delay >= w.config.BackoffMax/2 {
			return w.config.BackoffMax
		}
		delay *= 2
	}
	if delay > w.config.BackoffMax {
		return w.config.BackoffMax
	}
	return delay
}

func (w *PersistentWorker) nextInterval() time.Duration {
	if w.config.Jitter == 0 {
		return w.config.Interval
	}
	offset := time.Duration((w.config.Rand.Float64()*2 - 1) * float64(w.config.Jitter))
	interval := w.config.Interval + offset
	if interval <= 0 {
		return time.Nanosecond
	}
	return interval
}

func (w *PersistentWorker) scanIdempotencyKey(now time.Time) string {
	window := now.UnixNano() / int64(w.config.Interval)
	return fmt.Sprintf("scheduler:%d:%d", int64(w.config.Interval), window)
}

func defaultLeaseOwner() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown-host"
	}
	return fmt.Sprintf("%s:%d:%d", hostname, os.Getpid(), ownerSequence.Add(1))
}

type persistentRecorder struct {
	mu      sync.Mutex
	summary *PersistentSummary
	errors  []error
}

func (r *persistentRecorder) addError(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errors = append(r.errors, err)
}

func (r *persistentRecorder) addScanned(count int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.summary.Scanned += count
}

func (r *persistentRecorder) addCreated()   { r.increment(&r.summary.Created) }
func (r *persistentRecorder) addSkipped()   { r.increment(&r.summary.Skipped) }
func (r *persistentRecorder) addClaimed()   { r.increment(&r.summary.Claimed) }
func (r *persistentRecorder) addSucceeded() { r.increment(&r.summary.Succeeded) }
func (r *persistentRecorder) addRetried()   { r.increment(&r.summary.Retried) }
func (r *persistentRecorder) addFailed()    { r.increment(&r.summary.Failed) }
func (r *persistentRecorder) addReleased()  { r.increment(&r.summary.Released) }

func (r *persistentRecorder) increment(value *int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	(*value)++
}
