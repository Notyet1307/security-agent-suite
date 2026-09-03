package executor

import (
	"context"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type Executor interface {
	Name() string
	Execute(ctx context.Context, request domain.ExecutionRequest) (domain.ExecutionResult, error)
}
