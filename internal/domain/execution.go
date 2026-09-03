package domain

import "time"

// ExecutionRequest is the runtime-neutral request passed to an executor.
type ExecutionRequest struct {
	Run     Run
	Agent   AgentDefinition
	Prompt  string
	Timeout time.Duration
}

// ExecutionResult is returned by the runtime adapter. The application service
// owns the final Run status transition and persistence.
type ExecutionResult struct {
	Status RunStatus
	Result RunResult
}
