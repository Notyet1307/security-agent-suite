package domain

import "time"

// AgentRisk describes the operational risk of invoking an agent.
type AgentRisk string

const (
	AgentRiskLow    AgentRisk = "low"
	AgentRiskMedium AgentRisk = "medium"
	AgentRiskHigh   AgentRisk = "high"
)

// AgentDefinition is the stable business catalog entry exposed by the API.
// Runtime-specific details remain in agent-compose.yml and the executor adapter.
type AgentDefinition struct {
	ID                    string        `json:"id"`
	DisplayName           string        `json:"display_name"`
	Description           string        `json:"description"`
	Risk                  AgentRisk     `json:"risk"`
	ExecutorAgent         string        `json:"executor_agent"`
	AllowedModes          []string      `json:"allowed_modes"`
	InputTypes            []string      `json:"input_types"`
	OutputFormats         []string      `json:"output_formats"`
	CapsetIDs             []string      `json:"capset_ids"`
	ApprovalRequiredModes []string      `json:"approval_required_modes,omitempty"`
	DefaultTimeout        time.Duration `json:"-"`
	DefaultTimeoutText    string        `json:"default_timeout"`
}

func (a AgentDefinition) AllowsMode(mode string) bool {
	for _, candidate := range a.AllowedModes {
		if candidate == mode {
			return true
		}
	}
	return false
}

func (a AgentDefinition) RequiresApproval(mode string) bool {
	for _, candidate := range a.ApprovalRequiredModes {
		if candidate == mode {
			return true
		}
	}
	return false
}
