package memory

import (
	"context"
	"encoding/json"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

func (s *Store) GetInputJournal(ctx context.Context, runID string) (store.InputJournal, error) {
	var j store.InputJournal
	if err := ctx.Err(); err != nil {
		return j, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.journals[runID]
	if !ok {
		return j, domain.ErrNotFound
	}
	err := json.Unmarshal(data, &j)
	return j, err
}
func (s *Store) CreateInputJournal(ctx context.Context, j store.InputJournal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.journals[j.RunID]; ok {
		return domain.ErrAlreadyExists
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	s.journals[j.RunID] = data
	return nil
}
