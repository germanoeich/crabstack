package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"crabstack.local/projects/crab-sdk/types"
)

var ErrJobNotFound = errors.New("job not found")

type Job struct {
	ID        string
	Name      string
	Schedule  string
	EventType types.EventType
	TenantID  string
	AgentID   string
	SessionID string
	Input     map[string]any
	Enabled   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

type JobStore interface {
	List(ctx context.Context) ([]Job, error)
	Get(ctx context.Context, jobID string) (Job, error)
	Create(ctx context.Context, job Job) (Job, error)
	Delete(ctx context.Context, jobID string) error
}

type MemoryJobStore struct {
	mu   sync.RWMutex
	jobs map[string]Job
}

func NewMemoryJobStore() *MemoryJobStore {
	return &MemoryJobStore{
		jobs: make(map[string]Job),
	}
}

func (s *MemoryJobStore) List(ctx context.Context) ([]Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, cloneJob(job))
	}
	sort.Slice(jobs, func(i, j int) bool {
		if jobs[i].CreatedAt.Equal(jobs[j].CreatedAt) {
			return jobs[i].ID < jobs[j].ID
		}
		return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
	})
	return jobs, nil
}

func (s *MemoryJobStore) Get(ctx context.Context, jobID string) (Job, error) {
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}

	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return Job{}, ErrJobNotFound
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.jobs[jobID]
	if !ok {
		return Job{}, ErrJobNotFound
	}
	return cloneJob(job), nil
}

func (s *MemoryJobStore) Create(ctx context.Context, job Job) (Job, error) {
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}

	now := time.Now().UTC()
	job.ID = strings.TrimSpace(job.ID)
	if job.ID == "" {
		job.ID = newID()
	}
	job.Name = strings.TrimSpace(job.Name)
	job.Schedule = strings.TrimSpace(job.Schedule)
	if job.EventType == "" {
		job.EventType = types.EventTypeCronTriggered
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	job.Input = cloneMap(job.Input)

	s.mu.Lock()
	s.jobs[job.ID] = cloneJob(job)
	s.mu.Unlock()

	return cloneJob(job), nil
}

func (s *MemoryJobStore) Delete(ctx context.Context, jobID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	jobID = strings.TrimSpace(jobID)
	if jobID == "" {
		return ErrJobNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.jobs[jobID]; !ok {
		return ErrJobNotFound
	}
	delete(s.jobs, jobID)
	return nil
}

func cloneJob(job Job) Job {
	job.Input = cloneMap(job.Input)
	return job
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func newID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}
