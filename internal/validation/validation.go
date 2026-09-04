package validation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

const (
	CodeEmpty           = "agent_output_empty"
	CodeMalformed       = "agent_output_malformed"
	CodeContractInvalid = "agent_output_contract_invalid"
	CodeEvidenceInvalid = "agent_output_evidence_invalid"
	CodeUntrustedClaims = "agent_output_untrusted_claims"
)

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func Code(err error) string {
	var validationErr *Error
	if errors.As(err, &validationErr) {
		return validationErr.Code
	}
	return ""
}

// Parse validates the supported portion of an agent's final JSON output.
// Supported contracts are the five versioned agent output schemas in agents/*/output.schema.json:
// root object closure, required fields, primitive/array/object types, enums, string bounds,
// protocol constants, and evidence reference integrity. It does not claim full JSON Schema
// draft-2020-12 validation (formats beyond RFC3339 and schema keywords are intentionally omitted).
func Parse(agentID string, raw []byte) (domain.RunResult, error) {
	result, _, err := parse(agentID, raw, false)
	return result, err
}

func parse(agentID string, raw []byte, allowEnvelope bool) (domain.RunResult, domain.RunStatus, error) {
	return parseWithTrusted(agentID, raw, allowEnvelope, nil)
}

func parseWithTrusted(agentID string, raw []byte, allowEnvelope bool, trustedIDs map[string]struct{}) (domain.RunResult, domain.RunStatus, error) {
	result := domain.RunResult{RawOutput: append(json.RawMessage(nil), raw...)}
	if len(bytes.TrimSpace(raw)) == 0 {
		return result, "", &Error{Code: CodeEmpty, Message: "agent output is empty"}
	}
	if allowEnvelope {
		candidate, err := unwrapOutput(raw)
		if err != nil {
			return result, "", err
		}
		raw = candidate
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&value); err != nil {
		return result, "", &Error{Code: CodeMalformed, Message: fmt.Sprintf("agent output is not valid JSON: %v", err)}
	}
	if err := ensureEOF(decoder); err != nil {
		return result, "", &Error{Code: CodeMalformed, Message: "agent output contains trailing JSON"}
	}
	root, ok := value.(map[string]any)
	if !ok {
		return result, "", &Error{Code: CodeContractInvalid, Message: "agent output must be a JSON object"}
	}
	spec, ok := contracts[agentID]
	if !ok {
		return result, "", &Error{Code: CodeContractInvalid, Message: "no output contract is registered for agent " + agentID}
	}
	if err := spec.validate(root, "$", false); err != nil {
		return result, "", err
	}
	if trustedIDs != nil {
		if err := validateTrustedClaims(root, trustedIDs); err != nil {
			return result, "", err
		}
	}
	if err := validateEvidenceIntegrityWithTrusted(root, trustedIDs); err != nil {
		return result, "", err
	}
	result.Summary = summary(root)
	result.Evidence = evidence(root)
	result.Findings = findings(root)
	status, _ := root["status"].(string)
	return result, statusFor(status), nil
}

func unwrapOutput(raw []byte) ([]byte, error) {
	var document json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&document); err != nil {
		return nil, &Error{Code: CodeMalformed, Message: fmt.Sprintf("agent output is not valid JSON: %v", err)}
	}
	if err := ensureEOF(decoder); err != nil {
		return nil, &Error{Code: CodeMalformed, Message: "agent output contains trailing JSON"}
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(document, &envelope); err != nil {
		return nil, &Error{Code: CodeContractInvalid, Message: "agent output must be a JSON object"}
	}
	if envelope == nil {
		return nil, &Error{Code: CodeContractInvalid, Message: "agent output must be a JSON object"}
	}
	if _, direct := envelope["protocol"]; direct {
		return raw, nil
	}
	result, hasResult := envelope["result"]
	output, hasOutput := envelope["output"]
	if hasResult == hasOutput {
		if !hasResult && isEmptyCapture(envelope) {
			return nil, &Error{Code: CodeEmpty, Message: "agent output is empty"}
		}
		if !hasResult && isMalformedCapture(envelope) {
			return nil, &Error{Code: CodeMalformed, Message: "agent output is not valid JSON"}
		}
		return nil, &Error{Code: CodeContractInvalid, Message: "agent output must contain exactly one result or output envelope"}
	}
	candidate := result
	if hasOutput {
		candidate = output
	}
	candidate = bytes.TrimSpace(candidate)
	if len(candidate) == 0 {
		return nil, &Error{Code: CodeContractInvalid, Message: "result or output envelope is empty"}
	}
	if candidate[0] == '"' {
		var text string
		if err := json.Unmarshal(candidate, &text); err != nil {
			return nil, &Error{Code: CodeContractInvalid, Message: "result or output envelope must contain a JSON object or string"}
		}
		return []byte(text), nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(candidate, &object); err != nil || object == nil {
		return nil, &Error{Code: CodeContractInvalid, Message: "result or output envelope must contain a JSON object or string"}
	}
	return candidate, nil
}

func isEmptyCapture(envelope map[string]json.RawMessage) bool {
	var empty bool
	var stdout string
	return json.Unmarshal(envelope["stdout_empty"], &empty) == nil && empty &&
		json.Unmarshal(envelope["stdout"], &stdout) == nil && stdout == ""
}

func isMalformedCapture(envelope map[string]json.RawMessage) bool {
	var valid, empty bool
	var stdout string
	return json.Unmarshal(envelope["stdout_valid_json"], &valid) == nil && !valid &&
		json.Unmarshal(envelope["stdout_empty"], &empty) == nil && !empty &&
		json.Unmarshal(envelope["stdout"], &stdout) == nil && stdout != ""
}

// SupportedAgents lists the only output contracts accepted by Parse.
func SupportedAgents() []string {
	return []string{"traffic-analysis", "security-report", "compliance-query", "event-triage", "attack-path-validation"}
}

// Gate prevents any non-synthetic executor from treating an unvalidated successful
// result as a security conclusion. Mock is deliberately marked by its own protocol.
func Gate(agentID string, execution domain.ExecutionResult, executorName string) domain.ExecutionResult {
	if executorName == "mock" && isSyntheticMock(execution.Result.RawOutput) {
		return execution
	}
	if execution.Status != domain.RunStatusSucceeded && execution.Status != domain.RunStatusPartial {
		return execution
	}
	trustedIDs := trustedEvidenceIDs(execution.Result.Evidence)
	parsed, status, err := parseWithTrusted(agentID, execution.Result.RawOutput, true, trustedIDs)
	parsed.Executor = execution.Result.Executor
	parsed.Artifacts = execution.Result.Artifacts
	parsed.Evidence = trustedEvidence(execution.Result.Evidence)
	if err == nil {
		return domain.ExecutionResult{Status: status, Result: parsed}
	}
	parsed.Summary = "agent output failed validation"
	parsed.ErrorCode = Code(err)
	parsed.ErrorMessage = err.Error()
	return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: parsed}

}

func validateTrustedClaims(root map[string]any, trustedIDs map[string]struct{}) error {
	if items, ok := root["evidence"].([]any); ok {
		for _, item := range items {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			id, _ := obj["id"].(string)
			if _, ok := trustedIDs[id]; !ok {
				return &Error{Code: CodeUntrustedClaims, Message: fmt.Sprintf("model evidence %q is not backed by trusted executor evidence", id)}
			}
		}
	}
	var walk func(any, string) error
	walk = func(value any, path string) error {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if isEvidenceReferenceKey(key) {
					if refs, ok := child.([]any); ok {
						for i, ref := range refs {
							id, ok := ref.(string)
							if !ok {
								return &Error{Code: CodeUntrustedClaims, Message: fmt.Sprintf("%s.%s[%d] is not trusted", path, key, i)}
							}
							if _, ok := trustedIDs[id]; !ok {
								return &Error{Code: CodeUntrustedClaims, Message: fmt.Sprintf("%s.%s[%d] references untrusted evidence %q", path, key, i, id)}
							}
						}
					}
				}
				if err := walk(child, path+"."+key); err != nil {
					return err
				}
			}
		case []any:
			for i, child := range value {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(root, "$"); err != nil {
		return err
	}
	for _, key := range []string{"metrics", "citations"} {
		if values, ok := root[key].([]any); ok && len(values) > 0 {
			return &Error{Code: CodeUntrustedClaims, Message: key + " are not backed by trusted executor evidence"}
		}
	}
	return nil
}

func isEvidenceReferenceKey(key string) bool {
	switch key {
	case "evidence_refs", "supporting_evidence", "contradicting_evidence", "source_refs", "customer_evidence_refs":
		return true
	default:
		return false
	}
}

func trustedEvidence(evidence []domain.EvidenceRef) []domain.EvidenceRef {
	if evidence == nil {
		return nil
	}
	return append([]domain.EvidenceRef(nil), evidence...)
}

func trustedEvidenceIDs(evidence []domain.EvidenceRef) map[string]struct{} {
	ids := make(map[string]struct{}, len(evidence))
	for _, ref := range evidence {
		if ref.ID != "" {
			ids[ref.ID] = struct{}{}
		}
	}
	return ids
}

func isSyntheticMock(raw []byte) bool {
	var payload struct {
		Protocol string `json:"protocol"`
	}
	return json.Unmarshal(raw, &payload) == nil && payload.Protocol == "security-agent-suite.mock-result.v1"
}

func statusFor(status string) domain.RunStatus {
	if status == "completed" {
		return domain.RunStatusSucceeded
	}
	if status == "blocked_by_policy" {
		return domain.RunStatusFailed
	}
	return domain.RunStatusPartial
}

func summary(root map[string]any) string {
	for _, key := range []string{"summary", "executive_summary", "answer"} {
		if value, ok := root[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "agent output validated"
}

func evidence(root map[string]any) []domain.EvidenceRef {
	items, _ := root["evidence"].([]any)
	out := make([]domain.EvidenceRef, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ref := domain.EvidenceRef{}
		if v, ok := obj["id"].(string); ok {
			ref.ID = v
		}
		if v, ok := obj["type"].(string); ok {
			ref.Type = v
		}
		if v, ok := obj["source_uri"].(string); ok {
			ref.SourceURI = v
		}
		if v, ok := obj["sha256"].(string); ok {
			ref.SHA256 = v
		}
		if v, ok := obj["excerpt"].(string); ok {
			ref.Excerpt = v
		}
		if v, ok := obj["tool"].(string); ok {
			ref.Tool = v
		}
		if v, ok := obj["collected_at"].(string); ok {
			ref.CollectedAt, _ = time.Parse(time.RFC3339, v)
		}
		if v, ok := obj["metadata"].(map[string]any); ok {
			ref.Metadata = map[string]string{}
			for key, value := range v {
				if text, ok := value.(string); ok {
					ref.Metadata[key] = text
				}
			}
		}
		out = append(out, ref)
	}
	return out
}

func findings(root map[string]any) []domain.Finding {
	items, _ := root["findings"].([]any)
	out := make([]domain.Finding, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		finding := domain.Finding{}
		if v, ok := obj["id"].(string); ok {
			finding.ID = v
		}
		if v, ok := obj["type"].(string); ok {
			finding.Type = v
		}
		if v, ok := obj["title"].(string); ok {
			finding.Title = v
		}
		if v, ok := obj["severity"].(string); ok {
			finding.Severity = v
		}
		if v, ok := obj["confidence"].(float64); ok {
			finding.Confidence = v
		}
		if v, ok := obj["status"].(string); ok {
			finding.Status = v
		}
		if refs, ok := obj["evidence_refs"].([]any); ok {
			for _, ref := range refs {
				if text, ok := ref.(string); ok {
					finding.EvidenceRefs = append(finding.EvidenceRefs, text)
				}
			}
		}
		if refs, ok := obj["asset_refs"].([]any); ok {
			for _, ref := range refs {
				if text, ok := ref.(string); ok {
					finding.AssetRefs = append(finding.AssetRefs, text)
				}
			}
		}
		if refs, ok := obj["attack_techniques"].([]any); ok {
			for _, ref := range refs {
				if text, ok := ref.(string); ok {
					finding.AttackTechniques = append(finding.AttackTechniques, text)
				}
			}
		}
		if v, ok := obj["description"].(string); ok {
			finding.Description = v
		}
		out = append(out, finding)
	}
	return out
}

func validateEvidenceIntegrity(root map[string]any) error {
	return validateEvidenceIntegrityWithTrusted(root, nil)
}

func validateEvidenceIntegrityWithTrusted(root map[string]any, trustedIDs map[string]struct{}) error {
	ids := map[string]bool{}
	if items, ok := root["evidence"].([]any); ok {
		for i, item := range items {
			obj, ok := item.(map[string]any)
			if !ok {
				return typeErr(fmt.Sprintf("$.evidence[%d]", i), "object")
			}
			id, ok := obj["id"].(string)
			if !ok {
				return typeErr(fmt.Sprintf("$.evidence[%d].id", i), "string")
			}
			if ids[id] {
				return &Error{Code: CodeEvidenceInvalid, Message: fmt.Sprintf("duplicate evidence id at $.evidence[%d]: %s", i, id)}
			}
			ids[id] = true
		}
	}
	for id := range trustedIDs {
		ids[id] = true
	}
	var walk func(any, string) error
	walk = func(value any, path string) error {
		if obj, ok := value.(map[string]any); ok {
			for key, child := range obj {
				if isEvidenceReferenceKey(key) {
					if refs, ok := child.([]any); ok {
						for i, ref := range refs {
							id, ok := ref.(string)
							if !ok || id == "" || !ids[id] {
								return &Error{Code: CodeEvidenceInvalid, Message: fmt.Sprintf("%s.%s[%d] references missing evidence %q", path, key, i, id)}
							}
						}
					}
				}
				if err := walk(child, path+"."+key); err != nil {
					return err
				}
			}
			return nil
		}
		if items, ok := value.([]any); ok {
			for i, child := range items {
				if err := walk(child, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(root, "$"); err != nil {
		return err
	}
	if items, ok := root["findings"].([]any); ok {
		for i, item := range items {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			severity, _ := obj["severity"].(string)
			refs, _ := obj["evidence_refs"].([]any)
			if (severity == "high" || severity == "critical") && len(refs) == 0 {
				return &Error{Code: CodeEvidenceInvalid, Message: fmt.Sprintf("$.findings[%d] %s finding requires evidence_refs", i, severity)}
			}
		}
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return errors.New("trailing JSON value")
	}
	return err
}

type fieldSpec struct {
	kind               string
	required           bool
	enum               []string
	object             *objectSpec
	item               *fieldSpec
	min                int
	minNum, maxNum     *float64
	constValue, format string
}

type objectSpec struct {
	fields         map[string]fieldSpec
	required       []string
	additional     bool
	additionalKind string
}

func str(required bool) fieldSpec      { return fieldSpec{kind: "string", required: required} }
func nonEmpty(required bool) fieldSpec { return fieldSpec{kind: "string", required: required, min: 1} }
func enum(required bool, values ...string) fieldSpec {
	return fieldSpec{kind: "string", required: required, enum: values}
}
func scalar(required bool) fieldSpec { return fieldSpec{kind: "scalar", required: required} }
func bounded(required bool, min, max float64) fieldSpec {
	return fieldSpec{kind: "number", required: required, minNum: &min, maxNum: &max}
}
func boolean(required bool) fieldSpec { return fieldSpec{kind: "boolean", required: required} }
func array(required bool, item fieldSpec) fieldSpec {
	return fieldSpec{kind: "array", required: required, item: &item}
}
func object(required bool, spec objectSpec) fieldSpec {
	return fieldSpec{kind: "object", required: required, object: &spec}
}
func root(required []string, fields map[string]fieldSpec) objectSpec {
	return objectSpec{required: required, fields: fields}
}

func (s objectSpec) validate(value map[string]any, path string, _ bool) error {
	for _, key := range s.required {
		if _, ok := value[key]; !ok {
			return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s is missing required field %q", path, key)}
		}
	}
	for key, child := range value {
		spec, ok := s.fields[key]
		if !ok {
			if !s.additional {
				return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s contains unknown field %q", path, key)}
			}
			if s.additionalKind != "" {
				if err := (fieldSpec{kind: s.additionalKind}).validate(child, path+"."+key); err != nil {
					return err
				}
			}
			continue
		}
		if err := spec.validate(child, path+"."+key); err != nil {
			return err
		}
	}
	return nil
}

func (s fieldSpec) validate(value any, path string) error {
	switch s.kind {
	case "string":
		v, ok := value.(string)
		if !ok {
			return typeErr(path, "string")
		}
		if len(v) < s.min {
			return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s must not be empty", path)}
		}
		if len(s.enum) > 0 && !contains(s.enum, v) {
			return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s has unsupported value %q", path, v)}
		}
		if s.constValue != "" && v != s.constValue {
			return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s must equal %q", path, s.constValue)}
		}
		if s.format == "date-time" {
			if _, err := time.Parse(time.RFC3339, v); err != nil {
				return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s must be RFC3339 date-time", path)}
			}
		}
		if s.format == "sha256" {
			if len(v) != 64 {
				return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s must be a SHA-256 hex string", path)}
			}
			if _, err := hex.DecodeString(v); err != nil {
				return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s must be a SHA-256 hex string", path)}
			}
		}
	case "scalar":
		switch value.(type) {
		case string, float64:
		default:
			return typeErr(path, "number or string")
		}
	case "number":
		v, ok := value.(float64)
		if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
			return typeErr(path, "number")
		}
		if (s.minNum != nil && v < *s.minNum) || (s.maxNum != nil && v > *s.maxNum) {
			return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s is out of range", path)}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return typeErr(path, "boolean")
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return typeErr(path, "array")
		}
		for i, item := range items {
			if err := s.item.validate(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return typeErr(path, "object")
		}
		return s.object.validate(obj, path, false)
	default:
		return &Error{Code: CodeContractInvalid, Message: "validator has unsupported field kind"}
	}
	return nil
}

func typeErr(path, want string) error {
	return &Error{Code: CodeContractInvalid, Message: fmt.Sprintf("%s must be %s", path, want)}
}
func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
func withFormat(spec fieldSpec, format string) fieldSpec { spec.format = format; return spec }
func withConst(spec fieldSpec, value string) fieldSpec   { spec.constValue = value; return spec }
func withMin(spec fieldSpec, min int) fieldSpec          { spec.min = min; return spec }

var (
	evidenceSpec = object(false, root([]string{"id", "type"}, map[string]fieldSpec{
		"id": withMin(nonEmpty(true), 1), "type": withMin(nonEmpty(true), 1),
		"source_uri": str(false), "sha256": withFormat(str(false), "sha256"), "excerpt": str(false), "tool": str(false),
		"collected_at": withFormat(str(false), "date-time"),
		"metadata":     object(false, objectSpec{additional: true, additionalKind: "string"}),
	}))
	recommendationSpec = object(false, root([]string{"action", "priority"}, map[string]fieldSpec{
		"action": withMin(nonEmpty(true), 1), "priority": enum(true, "immediate", "high", "medium", "low", "long_term"), "rationale": str(false),
	}))
	findingSpec = object(false, root([]string{"id", "type", "title", "severity", "confidence", "status", "evidence_refs"}, map[string]fieldSpec{
		"id": str(true), "type": str(true), "title": str(true), "severity": enum(true, "critical", "high", "medium", "low", "informational"),
		"confidence": bounded(true, 0, 1), "status": str(true), "evidence_refs": array(true, str(true)), "asset_refs": array(false, str(true)),
		"attack_techniques": array(false, str(true)), "description": str(false), "recommendations": array(false, recommendationSpec),
	}))
	limitationSpec = withMin(str(true), 1)
)

func contract(proto string, required []string, fields map[string]fieldSpec) objectSpec {
	fields["protocol"] = withConst(str(true), proto)
	return root(required, fields)
}

var contracts = map[string]objectSpec{
	"traffic-analysis": contract("security-agent-suite.traffic-analysis.v1",
		[]string{"protocol", "status", "summary", "evidence", "timeline", "findings", "limitations"},
		map[string]fieldSpec{
			"status": enum(true, "completed", "partial", "insufficient_evidence"), "summary": str(true),
			"input_assessment": object(false, root([]string{"processable", "notes"}, map[string]fieldSpec{
				"processable": boolean(true), "notes": array(true, str(true)),
			})),
			"entities": array(false, object(false, root([]string{"id", "type", "value"}, map[string]fieldSpec{
				"id": str(true), "type": str(true), "value": str(true), "asset_ref": str(false),
			}))),
			"evidence": array(true, evidenceSpec),
			"timeline": array(true, object(false, root([]string{"time", "event_type", "subject", "description", "evidence_refs", "confidence"}, map[string]fieldSpec{
				"time": withFormat(str(true), "date-time"), "event_type": str(true), "subject": str(true), "object": str(false), "description": str(true),
				"classification": enum(false, "observed", "inferred", "reported"), "evidence_refs": array(true, str(true)), "confidence": bounded(true, 0, 1),
			}))),
			"attack_path": array(false, object(false, root([]string{"from", "to", "relation", "verification", "evidence_refs"}, map[string]fieldSpec{
				"from": str(true), "to": str(true), "relation": str(true), "verification": enum(true, "observed", "inferred", "unverified"), "evidence_refs": array(true, str(true)),
			}))),
			"affected_assets": array(false, str(true)), "findings": array(true, findingSpec), "limitations": array(true, limitationSpec),
		}),
	"security-report": contract("security-agent-suite.security-report.v1",
		[]string{"protocol", "status", "report_type", "period", "executive_summary", "metrics", "key_events", "recommendations", "artifacts", "validation", "limitations"},
		map[string]fieldSpec{
			"status": enum(true, "completed", "partial", "insufficient_data"), "report_type": enum(true, "daily", "weekly", "monthly", "incident", "traffic", "compliance"),
			"period":            object(true, root([]string{"start", "end", "timezone"}, map[string]fieldSpec{"start": withFormat(str(true), "date-time"), "end": withFormat(str(true), "date-time"), "timezone": str(true)})),
			"executive_summary": str(true), "metrics": array(true, object(false, root([]string{"name", "value", "unit", "formula", "source_refs", "validated"}, map[string]fieldSpec{
				"name": str(true), "value": scalar(true), "unit": str(true), "formula": str(true), "source_refs": array(true, str(true)), "validated": boolean(true),
			}))),
			"trends":          array(false, object(false, root([]string{"metric", "direction", "explanation", "source_refs"}, map[string]fieldSpec{"metric": str(true), "direction": enum(true, "up", "down", "flat", "not_comparable"), "explanation": str(true), "source_refs": array(true, str(true))}))),
			"key_events":      array(true, object(false, root([]string{"title", "severity", "summary", "source_refs"}, map[string]fieldSpec{"title": str(true), "severity": str(true), "summary": str(true), "source_refs": array(true, str(true))}))),
			"recommendations": array(true, recommendationSpec),
			"artifacts":       array(true, object(false, root([]string{"name", "uri", "media_type"}, map[string]fieldSpec{"name": str(true), "uri": str(true), "media_type": str(true), "sha256": str(false)}))),
			"validation":      object(true, root([]string{"numbers", "citations", "template", "sensitive_data"}, map[string]fieldSpec{"numbers": enum(true, "passed", "failed", "not_applicable"), "citations": enum(true, "passed", "failed", "not_applicable"), "template": enum(true, "passed", "failed", "not_applicable"), "sensitive_data": enum(true, "passed", "failed", "not_applicable")})),
			"limitations":     array(true, limitationSpec),
		}),
	"compliance-query": contract("security-agent-suite.compliance-query.v1",
		[]string{"protocol", "status", "answer", "applicability", "citations", "control_gaps", "evidence_requirements", "recommendations", "uncertainty"},
		map[string]fieldSpec{
			"status": enum(true, "completed", "partial", "insufficient_basis"), "answer": str(true),
			"applicability":         object(true, root([]string{"applies", "assumptions", "reason"}, map[string]fieldSpec{"applies": enum(true, "yes", "no", "conditional", "unknown"), "assumptions": array(true, str(true)), "reason": str(true)})),
			"citations":             array(true, object(false, root([]string{"document", "issuer", "version", "effective_date", "location", "source_uri", "summary"}, map[string]fieldSpec{"document": str(true), "issuer": str(true), "version": str(true), "effective_date": str(true), "location": str(true), "source_uri": str(true), "summary": str(true), "validation_status": enum(false, "validated", "needs_review")}))),
			"control_gaps":          array(true, object(false, root([]string{"control", "status", "requirement_citation", "customer_evidence_refs", "reason"}, map[string]fieldSpec{"control": str(true), "status": enum(true, "satisfied", "partially_satisfied", "not_satisfied", "not_assessed"), "requirement_citation": str(true), "customer_evidence_refs": array(true, str(true)), "reason": str(true)}))),
			"evidence_requirements": array(true, str(true)), "recommendations": array(true, recommendationSpec), "uncertainty": array(true, str(true)),
		}),
	"event-triage": contract("security-agent-suite.event-triage.v1",
		[]string{"protocol", "status", "summary", "classification", "severity", "confidence", "hypotheses", "evidence", "findings", "recommended_actions", "limitations"},
		map[string]fieldSpec{
			"status": enum(true, "completed", "partial", "insufficient_evidence"), "summary": str(true), "classification": enum(true, "true_positive", "false_positive", "benign", "suspicious", "insufficient_evidence"), "severity": enum(true, "critical", "high", "medium", "low", "informational", "undetermined"), "confidence": bounded(true, 0, 1),
			"attack_stage": array(false, str(true)), "affected_assets": array(false, str(true)),
			"hypotheses": array(true, object(false, root([]string{"hypothesis", "status", "supporting_evidence", "contradicting_evidence", "gaps"}, map[string]fieldSpec{"hypothesis": str(true), "status": enum(true, "supported", "rejected", "possible", "unknown"), "supporting_evidence": array(true, str(true)), "contradicting_evidence": array(true, str(true)), "gaps": array(true, str(true))}))),
			"evidence":   array(true, evidenceSpec), "findings": array(true, findingSpec), "recommended_actions": array(true, recommendationSpec), "limitations": array(true, limitationSpec),
		}),
	"attack-path-validation": contract("security-agent-suite.attack-path-validation.v1",
		[]string{"protocol", "status", "summary", "scope_check", "validations", "evidence", "findings", "attack_paths", "stop_reason", "limitations"},
		map[string]fieldSpec{
			"status": enum(true, "completed", "partial", "blocked_by_policy", "insufficient_evidence"), "summary": str(true),
			"scope_check": object(true, root([]string{"authorized", "authorization_ref", "approval_id", "targets", "checks"}, map[string]fieldSpec{
				"authorized": boolean(true), "authorization_ref": str(true), "approval_id": str(true), "targets": array(true, str(true)),
				"checks": array(true, object(false, root([]string{"name", "passed", "detail"}, map[string]fieldSpec{
					"name": str(true), "passed": boolean(true), "detail": str(true),
				}))),
			})),
			"validations": array(true, object(false, root([]string{"target", "candidate", "method", "status", "evidence_refs", "side_effects_observed"}, map[string]fieldSpec{
				"target": str(true), "candidate": str(true), "method": str(true),
				"status":        enum(true, "verified", "likely_exploitable", "not_reproduced", "false_positive", "blocked_by_policy", "insufficient_evidence"),
				"evidence_refs": array(true, str(true)), "side_effects_observed": boolean(true), "notes": str(false),
			}))),
			"evidence": array(true, evidenceSpec), "findings": array(true, findingSpec),
			"attack_paths": array(true, object(false, root([]string{"id", "status", "nodes", "edges", "cut_points"}, map[string]fieldSpec{
				"id": str(true), "status": enum(true, "verified", "candidate", "rejected"), "nodes": array(true, str(true)),
				"edges": array(true, object(false, root([]string{"from", "to", "relation", "evidence_refs"}, map[string]fieldSpec{
					"from": str(true), "to": str(true), "relation": str(true), "evidence_refs": array(true, str(true)),
				}))),
				"cut_points": array(true, str(true)),
			}))),
			"stop_reason": str(true), "limitations": array(true, limitationSpec),
		}),
}
