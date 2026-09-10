package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

// NormalizeManual supplements the existing policy without changing automatic runs.
func NormalizeManual(agent domain.AgentDefinition, req *domain.CreateRunRequest, limit int64) error {
	if agent.ID != "event-triage" || req.Mode != "triage" || req.InputManifest == nil || len(req.Inputs) != 0 {
		return domain.ErrInvalidRequest
	}
	if req.Policy.NetworkAccess != "deny" || req.Policy.ActiveValidation {
		return domain.ErrForbidden
	}
	if len(req.CaseID) > 128 || strings.ContainsRune(req.RequestID, 0) || strings.ContainsRune(req.Scope.TenantID, 0) {
		return domain.ErrInvalidRequest
	}
	m := req.InputManifest
	m.SHA256 = strings.ToLower(strings.TrimSpace(m.SHA256))
	hash, err := hex.DecodeString(m.SHA256)
	if err != nil || len(hash) != 32 || m.Schema != domain.InputSchema || m.MediaType != "application/json" || m.SizeBytes <= 0 {
		return domain.ErrInvalidRequest
	}
	if limit <= 0 || limit > domain.MaxInputBytes {
		limit = domain.MaxInputBytes
	}
	if m.SizeBytes > limit {
		return domain.ErrInputTooLarge
	}
	seen := map[string]bool{}
	for _, f := range req.Output.Formats {
		if seen[f] {
			return domain.ErrInvalidRequest
		}
		seen[f] = true
	}
	if req.Policy.MaxDuration == "" {
		req.Policy.MaxDuration = "20m"
	}
	duration, err := time.ParseDuration(req.Policy.MaxDuration)
	if err != nil {
		return domain.ErrInvalidRequest
	}
	req.Policy.MaxDuration = duration.String()
	if req.Scope.TimeRange != nil {
		req.Scope.TimeRange.Start = req.Scope.TimeRange.Start.UTC()
		req.Scope.TimeRange.End = req.Scope.TimeRange.End.UTC()
	}
	if len(req.Metadata) > 128 {
		return domain.ErrInvalidRequest
	}
	for k, v := range req.Metadata {
		if strings.TrimSpace(k) == "" || len(k) > 128 || len(v) > 4096 {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func Fingerprint(version string, value map[string]any) string {
	raw, _ := json.Marshal(value)
	return fmt.Sprintf("%s:%x", version, sha256.Sum256(raw))
}
func CreationFingerprint(agent string, req domain.CreateRunRequest) string {
	list := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	var tr any
	if req.Scope.TimeRange != nil {
		tr = map[string]any{"start": req.Scope.TimeRange.Start.UTC().Format(time.RFC3339Nano), "end": req.Scope.TimeRange.End.UTC().Format(time.RFC3339Nano)}
	}
	metadata := req.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	m := req.InputManifest
	return Fingerprint("sas.manual-create/v1", map[string]any{
		"agent_id": agent, "mode": req.Mode, "execution_mode": "manual", "case_id": req.CaseID,
		"input_manifest": map[string]any{"schema": m.Schema, "sha256": m.SHA256, "size_bytes": m.SizeBytes, "media_type": m.MediaType},
		"scope":          map[string]any{"tenant_id": req.Scope.TenantID, "authorization_ref": req.Scope.AuthorizationRef, "assets": list(req.Scope.Assets), "networks": list(req.Scope.Networks), "domains": list(req.Scope.Domains), "time_range": tr},
		"policy":         map[string]any{"network_access": req.Policy.NetworkAccess, "active_validation": req.Policy.ActiveValidation, "max_requests": req.Policy.MaxRequests, "max_duration": req.Policy.MaxDuration},
		"output":         map[string]any{"language": req.Output.Language, "formats": list(req.Output.Formats)}, "metadata": metadata,
	})
}
