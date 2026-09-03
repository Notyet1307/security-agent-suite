package store

import (
	"context"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type ListFilter struct {
	TenantID string
	AgentID  string
	Status   domain.RunStatus
	Limit    int
}

type RunStore interface {
	Create(ctx context.Context, run *domain.Run) error
	Get(ctx context.Context, id string) (*domain.Run, error)
	FindByRequestID(ctx context.Context, tenantID, requestID string) (*domain.Run, error)
	Update(ctx context.Context, id string, mutate func(*domain.Run) error) (*domain.Run, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Run, error)
}
