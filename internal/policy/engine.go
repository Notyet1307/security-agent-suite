package policy

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type Decision struct {
	InitialStatus domain.RunStatus
	Reason        string
}

type Engine struct {
	MaxInputs         int
	MaxActiveRequests int
	AllowUnrestricted bool
}

func New() *Engine {
	return &Engine{MaxInputs: 64, MaxActiveRequests: 1000}
}

func (e *Engine) NormalizeAndEvaluate(agent domain.AgentDefinition, req *domain.CreateRunRequest) (Decision, error) {
	trimRequest(req)
	if req.RequestID == "" || len(req.RequestID) > 128 {
		return Decision{}, fmt.Errorf("%w: request_id is required and must not exceed 128 characters", domain.ErrInvalidRequest)
	}
	if req.Scope.TenantID == "" || len(req.Scope.TenantID) > 128 {
		return Decision{}, fmt.Errorf("%w: scope.tenant_id is required and must not exceed 128 characters", domain.ErrInvalidRequest)
	}
	if !agent.AllowsMode(req.Mode) {
		return Decision{}, fmt.Errorf("%w: mode %q is not allowed for agent %q", domain.ErrInvalidRequest, req.Mode, agent.ID)
	}
	if len(req.Inputs) > e.MaxInputs {
		return Decision{}, fmt.Errorf("%w: no more than %d inputs are allowed", domain.ErrInvalidRequest, e.MaxInputs)
	}
	for i, input := range req.Inputs {
		if err := validateInput(agent, input); err != nil {
			return Decision{}, fmt.Errorf("%w: inputs[%d]: %v", domain.ErrInvalidRequest, i, err)
		}
	}
	if req.Scope.TimeRange != nil && !req.Scope.TimeRange.Start.Before(req.Scope.TimeRange.End) {
		return Decision{}, fmt.Errorf("%w: scope.time_range.start must be before end", domain.ErrInvalidRequest)
	}
	if req.Output.Language == "" {
		req.Output.Language = "zh-CN"
	}
	if len(req.Output.Formats) == 0 {
		req.Output.Formats = []string{"json"}
	}
	for _, format := range req.Output.Formats {
		if !slices.Contains(agent.OutputFormats, format) {
			return Decision{}, fmt.Errorf("%w: output format %q is not supported by agent %q", domain.ErrInvalidRequest, format, agent.ID)
		}
	}
	if req.Policy.ApprovalID != "" {
		return Decision{}, fmt.Errorf("%w: policy.approval_id is server-managed and must not be supplied", domain.ErrInvalidRequest)
	}
	if req.Policy.NetworkAccess == "" {
		req.Policy.NetworkAccess = "deny"
	}
	switch req.Policy.NetworkAccess {
	case "deny", "restricted":
	case "allow":
		if !e.AllowUnrestricted {
			return Decision{}, fmt.Errorf("%w: unrestricted network access is disabled", domain.ErrForbidden)
		}
	default:
		return Decision{}, fmt.Errorf("%w: policy.network_access must be deny, restricted, or allow", domain.ErrInvalidRequest)
	}
	if req.Policy.MaxRequests < 0 || req.Policy.MaxRequests > e.MaxActiveRequests {
		return Decision{}, fmt.Errorf("%w: policy.max_requests must be between 0 and %d", domain.ErrInvalidRequest, e.MaxActiveRequests)
	}
	if req.Policy.MaxDuration != "" {
		duration, err := time.ParseDuration(req.Policy.MaxDuration)
		if err != nil || duration <= 0 || duration > 24*time.Hour {
			return Decision{}, fmt.Errorf("%w: policy.max_duration must be a positive duration no greater than 24h", domain.ErrInvalidRequest)
		}
	}

	if req.Policy.ActiveValidation && agent.ID != "attack-path-validation" {
		return Decision{}, fmt.Errorf("%w: active validation is only permitted for attack-path-validation", domain.ErrForbidden)
	}
	if req.Mode == "active_validate" && !req.Policy.ActiveValidation {
		return Decision{}, fmt.Errorf("%w: active_validate mode requires policy.active_validation=true", domain.ErrInvalidRequest)
	}
	if req.Policy.ActiveValidation {
		if req.Scope.AuthorizationRef == "" {
			return Decision{}, fmt.Errorf("%w: active validation requires scope.authorization_ref", domain.ErrForbidden)
		}
		if len(req.Scope.Assets)+len(req.Scope.Networks)+len(req.Scope.Domains) == 0 {
			return Decision{}, fmt.Errorf("%w: active validation requires an explicit asset, network, or domain scope", domain.ErrForbidden)
		}
		if req.Policy.NetworkAccess != "restricted" {
			return Decision{}, fmt.Errorf("%w: active validation requires restricted network access", domain.ErrForbidden)
		}
		if req.Policy.MaxRequests == 0 {
			req.Policy.MaxRequests = 100
		}
		return Decision{InitialStatus: domain.RunStatusWaitingApproval, Reason: "active validation requires explicit approval"}, nil
	}
	if agent.RequiresApproval(req.Mode) {
		return Decision{InitialStatus: domain.RunStatusWaitingApproval, Reason: "agent mode requires explicit approval"}, nil
	}
	return Decision{InitialStatus: domain.RunStatusQueued, Reason: "request passed deterministic preflight"}, nil
}

func (e *Engine) ValidateExecution(agent domain.AgentDefinition, run domain.Run) error {
	if run.Status == domain.RunStatusCancelled {
		return domain.ErrConflict
	}
	if agent.RequiresApproval(run.Mode) || run.Policy.ActiveValidation {
		if run.Approval == nil || strings.TrimSpace(run.Approval.ID) == "" || strings.TrimSpace(run.Approval.Actor) == "" {
			return fmt.Errorf("%w: run requires approval before execution", domain.ErrForbidden)
		}
		if run.Scope.AuthorizationRef == "" {
			return fmt.Errorf("%w: authorization reference is missing", domain.ErrForbidden)
		}
	}
	return nil
}

func trimRequest(req *domain.CreateRunRequest) {
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.CaseID = strings.TrimSpace(req.CaseID)
	req.Mode = strings.TrimSpace(req.Mode)
	req.Scope.TenantID = strings.TrimSpace(req.Scope.TenantID)
	req.Scope.AuthorizationRef = strings.TrimSpace(req.Scope.AuthorizationRef)
	req.Policy.NetworkAccess = strings.TrimSpace(req.Policy.NetworkAccess)
	req.Policy.ApprovalID = strings.TrimSpace(req.Policy.ApprovalID)
	req.Policy.MaxDuration = strings.TrimSpace(req.Policy.MaxDuration)
	req.Output.Language = strings.TrimSpace(req.Output.Language)
	for i := range req.Inputs {
		req.Inputs[i].Type = strings.TrimSpace(req.Inputs[i].Type)
		req.Inputs[i].URI = strings.TrimSpace(req.Inputs[i].URI)
		req.Inputs[i].SHA256 = strings.ToLower(strings.TrimSpace(req.Inputs[i].SHA256))
	}
	for i := range req.Output.Formats {
		req.Output.Formats[i] = strings.ToLower(strings.TrimSpace(req.Output.Formats[i]))
	}
}

func validateInput(agent domain.AgentDefinition, input domain.InputRef) error {
	if input.Type == "" || !slices.Contains(agent.InputTypes, input.Type) {
		return fmt.Errorf("input type %q is not accepted", input.Type)
	}
	if input.URI == "" || len(input.URI) > 2048 {
		return fmt.Errorf("uri is required and must not exceed 2048 characters")
	}
	parsed, err := url.Parse(input.URI)
	if err != nil || parsed.Scheme == "" {
		return fmt.Errorf("uri must be absolute and include a scheme")
	}
	switch parsed.Scheme {
	case "artifact", "file", "s3", "https", "http", "case", "evidence":
	default:
		return fmt.Errorf("uri scheme %q is not allowed", parsed.Scheme)
	}
	if input.SHA256 != "" {
		decoded, err := hex.DecodeString(input.SHA256)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("sha256 must contain 64 hexadecimal characters")
		}
	}
	if input.SizeBytes < 0 {
		return fmt.Errorf("size_bytes cannot be negative")
	}
	return nil
}
