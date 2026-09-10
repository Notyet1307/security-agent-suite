package file

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

type Store struct {
	mu        sync.RWMutex
	syncDir   func(string) error
	root      string
	runsDir   string
	auditPath string
	runs      map[string]*domain.Run
	byRequest map[string]string
}

func New(root string) (*Store, error) {
	runsDir := filepath.Join(root, "runs")
	if err := os.MkdirAll(runsDir, 0o750); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := store.SyncDirectory(root); err != nil {
		return nil, err
	}
	if err := store.SyncDirectory(filepath.Dir(root)); err != nil {
		return nil, err
	}
	s := &Store{
		root:      root,
		syncDir:   store.SyncDirectory,
		runsDir:   runsDir,
		auditPath: filepath.Join(root, "audit.jsonl"),
		runs:      map[string]*domain.Run{},
		byRequest: map[string]string{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func requestKey(tenantID, requestID string) string { return tenantID + "\x00" + requestID }

func (s *Store) load() error {
	entries, err := os.ReadDir(s.runsDir)
	if err != nil {
		return fmt.Errorf("read state directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.runsDir, entry.Name()))
		if err != nil {
			return fmt.Errorf("read run state %s: %w", entry.Name(), err)
		}
		var run domain.Run
		if err := json.Unmarshal(data, &run); err != nil {
			return fmt.Errorf("decode run state %s: %w", entry.Name(), err)
		}
		if run.ID == "" || run.RequestID == "" || run.Scope.TenantID == "" {
			return fmt.Errorf("invalid run state %s", entry.Name())
		}
		copyRun, err := clone(&run)
		if err != nil {
			return err
		}
		s.runs[run.ID] = copyRun
		key := requestKey(run.Scope.TenantID, run.RequestID)
		if previous, ok := s.byRequest[key]; ok && previous != run.ID {
			return fmt.Errorf("duplicate persisted request id")
		}
		s.byRequest[key] = run.ID
	}
	return nil
}

func (s *Store) Create(ctx context.Context, run *domain.Run) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.runs[run.ID]; ok {
		return domain.ErrAlreadyExists
	}
	key := requestKey(run.Scope.TenantID, run.RequestID)
	if _, ok := s.byRequest[key]; ok {
		return domain.ErrAlreadyExists
	}
	copyRun, err := clone(run)
	if err != nil {
		return err
	}
	published, err := s.persistLocked(copyRun)
	if published {
		s.runs[run.ID] = copyRun
		s.byRequest[key] = run.ID
	}
	if err != nil {
		return err
	}
	return s.appendAuditLocked(copyRun.Events[len(copyRun.Events)-1], copyRun)
}

func (s *Store) Get(ctx context.Context, id string) (*domain.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.syncDir(s.runsDir); err != nil {
		return nil, err
	}
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
	if err := s.syncDir(s.runsDir); err != nil {
		return nil, err
	}
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
	beforeEvents := len(working.Events)
	if err := mutate(working); err != nil {
		return nil, err
	}
	published, err := s.persistLocked(working)
	if published {
		s.runs[id] = working
	}
	if err != nil {
		return nil, err
	}
	for _, event := range working.Events[beforeEvents:] {
		if err := s.appendAuditLocked(event, working); err != nil {
			return nil, err
		}
	}
	return clone(working)
}

func (s *Store) List(ctx context.Context, filter store.ListFilter) ([]domain.Run, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.syncDir(s.runsDir); err != nil {
		return nil, err
	}
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

// persistLocked reports publication even when the final sync fails: callers
// retain the in-memory reservation, and reads must reconfirm durability.
func (s *Store) persistLocked(run *domain.Run) (bool, error) {
	data, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode run state: %w", err)
	}
	path := filepath.Join(s.runsDir, run.ID+".json")
	tmp, err := os.CreateTemp(s.runsDir, run.ID+"-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create state temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return false, err
	}
	writer := bufio.NewWriter(tmp)
	if _, err := writer.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("write run state: %w", err)
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("flush run state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("sync run state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("close run state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, fmt.Errorf("replace run state: %w", err)
	}
	return true, s.syncDir(s.runsDir)
}

func (s *Store) appendAuditLocked(event domain.RunEvent, run *domain.Run) error {
	record := struct {
		RunID     string          `json:"run_id"`
		RequestID string          `json:"request_id"`
		TenantID  string          `json:"tenant_id"`
		AgentID   string          `json:"agent_id"`
		Event     domain.RunEvent `json:"event"`
	}{run.ID, run.RequestID, run.Scope.TenantID, run.AgentID, event}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(s.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
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

var _ store.RunStore = (*Store)(nil)
