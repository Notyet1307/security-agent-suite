package store

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

// InputJournal is private persistence, never decoded from a public request.
type InputJournal struct {
	Version    string             `json:"version"`
	TenantID   string             `json:"tenant_id"`
	RunID      string             `json:"run_id"`
	Artifact   domain.ArtifactRef `json:"artifact"`
	Evidence   domain.EvidenceRef `json:"evidence"`
	Submission domain.Submission  `json:"submission"`
}
type InputJournalStore interface {
	GetInputJournal(context.Context, string) (InputJournal, error)
	CreateInputJournal(context.Context, InputJournal) error
}
type InputArtifacts interface {
	Get(context.Context, string, string) (domain.ArtifactRef, error)
	ReadInput(context.Context, string, domain.ArtifactRef, int64) ([]byte, error)
	PutInputReader(context.Context, string, string, io.Reader, domain.InputManifest, int64, time.Time) (domain.ArtifactRef, error)
}

// SyncDirectory makes a published filename durable before publishing dependents.
func SyncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
