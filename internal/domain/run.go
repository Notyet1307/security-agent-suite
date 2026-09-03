package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type RunStatus string

const (
	RunStatusQueued          RunStatus = "queued"
	RunStatusValidating      RunStatus = "validating"
	RunStatusWaitingApproval RunStatus = "waiting_approval"
	RunStatusRunning         RunStatus = "running"
	RunStatusSucceeded       RunStatus = "succeeded"
	RunStatusPartial         RunStatus = "partial"
	RunStatusFailed          RunStatus = "failed"
	RunStatusCancelled       RunStatus = "cancelled"
)

var ErrInvalidTransition = errors.New("invalid run status transition")

var allowedTransitions = map[RunStatus]map[RunStatus]struct{}{
	RunStatusQueued: {
		RunStatusValidating: {},
		RunStatusCancelled:  {},
		RunStatusFailed:     {},
	},
	RunStatusValidating: {
		RunStatusWaitingApproval: {},
		RunStatusRunning:         {},
		RunStatusFailed:          {},
		RunStatusCancelled:       {},
	},
	RunStatusWaitingApproval: {
		RunStatusQueued:    {},
		RunStatusCancelled: {},
		RunStatusFailed:    {},
	},
	RunStatusRunning: {
		RunStatusSucceeded: {},
		RunStatusPartial:   {},
		RunStatusFailed:    {},
		RunStatusCancelled: {},
	},
}

func (s RunStatus) Terminal() bool {
	switch s {
	case RunStatusSucceeded, RunStatusPartial, RunStatusFailed, RunStatusCancelled:
		return true
	default:
		return false
	}
}

type InputRef struct {
	Type      string            `json:"type"`
	URI       string            `json:"uri"`
	SHA256    string            `json:"sha256,omitempty"`
	MediaType string            `json:"media_type,omitempty"`
	SizeBytes int64             `json:"size_bytes,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type Scope struct {
	TenantID         string     `json:"tenant_id"`
	AuthorizationRef string     `json:"authorization_ref,omitempty"`
	Assets           []string   `json:"assets,omitempty"`
	Networks         []string   `json:"networks,omitempty"`
	Domains          []string   `json:"domains,omitempty"`
	TimeRange        *TimeRange `json:"time_range,omitempty"`
}

type PolicyRequest struct {
	NetworkAccess    string `json:"network_access,omitempty"`
	ActiveValidation bool   `json:"active_validation,omitempty"`
	ApprovalID       string `json:"approval_id,omitempty"`
	MaxRequests      int    `json:"max_requests,omitempty"`
	MaxDuration      string `json:"max_duration,omitempty"`
}

type OutputRequest struct {
	Language string   `json:"language,omitempty"`
	Formats  []string `json:"formats,omitempty"`
}

type CreateRunRequest struct {
	RequestID string            `json:"request_id"`
	CaseID    string            `json:"case_id,omitempty"`
	Mode      string            `json:"mode"`
	Inputs    []InputRef        `json:"inputs,omitempty"`
	Scope     Scope             `json:"scope"`
	Policy    PolicyRequest     `json:"policy,omitempty"`
	Output    OutputRequest     `json:"output,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Approval struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type ApprovalRequest struct {
	ApprovalID string `json:"approval_id"`
	Actor      string `json:"actor"`
	Reason     string `json:"reason"`
}

type EvidenceRef struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	SourceURI   string            `json:"source_uri,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	Excerpt     string            `json:"excerpt,omitempty"`
	Tool        string            `json:"tool,omitempty"`
	CollectedAt time.Time         `json:"collected_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type Finding struct {
	ID               string            `json:"id"`
	Type             string            `json:"type"`
	Title            string            `json:"title"`
	Severity         string            `json:"severity"`
	Confidence       float64           `json:"confidence"`
	Status           string            `json:"status"`
	EvidenceRefs     []string          `json:"evidence_refs"`
	AssetRefs        []string          `json:"asset_refs,omitempty"`
	AttackTechniques []string          `json:"attack_techniques,omitempty"`
	Description      string            `json:"description,omitempty"`
	Recommendations  []Recommendation  `json:"recommendations,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type Recommendation struct {
	Action    string `json:"action"`
	Priority  string `json:"priority"`
	Rationale string `json:"rationale,omitempty"`
}

type ArtifactRef struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URI       string    `json:"uri"`
	MediaType string    `json:"media_type"`
	SHA256    string    `json:"sha256,omitempty"`
	SizeBytes int64     `json:"size_bytes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type RunResult struct {
	Executor     string          `json:"executor"`
	Summary      string          `json:"summary"`
	Evidence     []EvidenceRef   `json:"evidence,omitempty"`
	Findings     []Finding       `json:"findings,omitempty"`
	Artifacts    []ArtifactRef   `json:"artifacts,omitempty"`
	Limitations  []string        `json:"limitations,omitempty"`
	RawOutput    json.RawMessage `json:"raw_output,omitempty"`
	ErrorCode    string          `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

type RunEvent struct {
	Sequence int64             `json:"sequence"`
	Type     string            `json:"type"`
	From     RunStatus         `json:"from,omitempty"`
	To       RunStatus         `json:"to,omitempty"`
	Message  string            `json:"message"`
	Actor    string            `json:"actor,omitempty"`
	At       time.Time         `json:"at"`
	Details  map[string]string `json:"details,omitempty"`
}

type Run struct {
	ID          string            `json:"id"`
	RequestID   string            `json:"request_id"`
	CaseID      string            `json:"case_id,omitempty"`
	AgentID     string            `json:"agent_id"`
	AgentName   string            `json:"agent_name"`
	Mode        string            `json:"mode"`
	Inputs      []InputRef        `json:"inputs,omitempty"`
	Scope       Scope             `json:"scope"`
	Policy      PolicyRequest     `json:"policy,omitempty"`
	Output      OutputRequest     `json:"output,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Status      RunStatus         `json:"status"`
	Approval    *Approval         `json:"approval,omitempty"`
	Result      *RunResult        `json:"result,omitempty"`
	Events      []RunEvent        `json:"events,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Version     int64             `json:"version"`
}

func NewRun(id, agentID, agentName string, req CreateRunRequest, initial RunStatus, now time.Time) *Run {
	r := &Run{
		ID:        id,
		RequestID: req.RequestID,
		CaseID:    req.CaseID,
		AgentID:   agentID,
		AgentName: agentName,
		Mode:      req.Mode,
		Inputs:    req.Inputs,
		Scope:     req.Scope,
		Policy:    req.Policy,
		Output:    req.Output,
		Metadata:  req.Metadata,
		Status:    initial,
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
		Version:   1,
	}
	r.appendEvent(RunEvent{Type: "run.created", To: initial, Message: "run created", Actor: "system", At: now.UTC()})
	return r
}

func (r *Run) Transition(to RunStatus, message, actor string, now time.Time) error {
	if r.Status == to {
		return nil
	}
	if _, ok := allowedTransitions[r.Status][to]; !ok {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, r.Status, to)
	}
	from := r.Status
	r.Status = to
	now = now.UTC()
	r.UpdatedAt = now
	r.Version++
	if to == RunStatusRunning && r.StartedAt == nil {
		r.StartedAt = &now
	}
	if to.Terminal() {
		r.CompletedAt = &now
	}
	r.appendEvent(RunEvent{Type: "run.status_changed", From: from, To: to, Message: message, Actor: actor, At: now})
	return nil
}

func (r *Run) RecordEvent(eventType, message, actor string, details map[string]string, now time.Time) {
	r.UpdatedAt = now.UTC()
	r.Version++
	r.appendEvent(RunEvent{Type: eventType, Message: message, Actor: actor, At: now.UTC(), Details: details})
}

func (r *Run) SetApproval(approval Approval, now time.Time) {
	r.Approval = &approval
	r.Policy.ApprovalID = approval.ID
	r.RecordEvent("run.approved", "run approved", approval.Actor, map[string]string{"approval_id": approval.ID}, now)
}

func (r *Run) SetResult(result RunResult, now time.Time) {
	r.Result = &result
	r.UpdatedAt = now.UTC()
	r.Version++
}

func (r *Run) appendEvent(event RunEvent) {
	event.Sequence = int64(len(r.Events) + 1)
	r.Events = append(r.Events, event)
}
