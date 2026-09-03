package memory

import (
	"context"
	"encoding/json"
	"sort"
	"sync"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

type Store struct {
	mu        sync.RWMutex
	runs      map[string]*domain.Run
	byRequest map[string]string
}

func New() *Store {
	return &Store{runs: map[string]*domain.Run{}, byRequest: map[string]string{}}
}

func requestKey(tenantID, requestID string) string { return tenantID + "\x00" + requestID }

func (s *Store) Create(ctx context.Context, run *domain.Run) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.runs[run.ID]; exists {
		return domain.ErrAlreadyExists
	}
	key := requestKey(run.Scope.TenantID, run.RequestID)
	if _, exists := s.byRequest[key]; exists {
		return domain.ErrAlreadyExists
	}
	copyRun, err := clone(run)
	if err != nil {
		return err
	}
	s.runs[run.ID] = copyRun
	s.byRequest[key] = run.ID
	return nil
}

func (s *Store) Get(ctx context.Context, id string) (*domain.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	run, ok := s.runs[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return clone(run)
}

func (s *Store) FindByRequestID(ctx context.Context, tenantID, requestID string) (*domain.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byRequest[requestKey(tenantID, requestID)]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return clone(s.runs[id])
}

func (s *Store) Update(ctx context.Context, id string, mutate func(*domain.Run) error) (*domain.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.runs[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	working, err := clone(current)
	if err != nil {
		return nil, err
	}
	if err := mutate(working); err != nil {
		return nil, err
	}
	s.runs[id] = working
	return clone(working)
}

func (s *Store) List(ctx context.Context, filter store.ListFilter) ([]domain.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]domain.Run, 0, len(s.runs))
	for _, run := range s.runs {
		if filter.TenantID != "" && run.Scope.TenantID != filter.TenantID {
			continue
		}
		if filter.AgentID != "" && run.AgentID != filter.AgentID {
			continue
		}
		if filter.Status != "" && run.Status != filter.Status {
			continue
		}
		copyRun, err := clone(run)
		if err != nil {
			return nil, err
		}
		result = append(result, *copyRun)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	if filter.Limit > 0 && len(result) > filter.Limit {
		result = result[:filter.Limit]
	}
	return result, nil
}

func clone(run *domain.Run) (*domain.Run, error) {
	data, err := json.Marshal(run)
	if err != nil {
		return nil, err
	}
	var copyRun domain.Run
	if err := json.Unmarshal(data, &copyRun); err != nil {
		return nil, err
	}
	return &copyRun, nil
}
