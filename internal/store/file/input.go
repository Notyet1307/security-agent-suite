package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/store"
)

func (s *Store) GetInputJournal(ctx context.Context, runID string) (store.InputJournal, error) {
	var j store.InputJournal
	if err := ctx.Err(); err != nil {
		return j, err
	}
	if !store.ValidIdentifier(runID) {
		return j, domain.ErrInvalidRequest
	}
	path := filepath.Join(s.root, "input-journals", runID+".json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return j, domain.ErrNotFound
	}
	if err != nil {
		return j, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return j, fmt.Errorf("invalid input journal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return j, err
	}
	if err = json.Unmarshal(data, &j); err != nil {
		return j, err
	}
	if err := s.syncDir(filepath.Dir(path)); err != nil {
		return j, err
	}
	return j, nil
}
func (s *Store) CreateInputJournal(ctx context.Context, j store.InputJournal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !store.ValidIdentifier(j.RunID) {
		return domain.ErrInvalidRequest
	}
	dir := filepath.Join(s.root, "input-journals")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := s.syncDir(s.root); err != nil {
		return err
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".input-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), filepath.Join(dir, j.RunID+".json")); err != nil {
		if os.IsExist(err) {
			return domain.ErrAlreadyExists
		}
		return err
	}
	return s.syncDir(dir)
}
