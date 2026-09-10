package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

func manualRequest(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return false
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return false
		}
		if field, ok := key.(string); ok && strings.EqualFold(field, "execution_mode") {
			var mode string
			if json.Unmarshal(value, &mode) == nil && strings.TrimSpace(mode) == "manual" {
				return true
			}
		}
	}
	return false
}
func (s *Server) decodeCreate(r *http.Request, req *domain.CreateRunRequest) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
	if err != nil {
		return err
	}
	manual := manualRequest(raw)
	if int64(len(raw)) > s.cfg.MaxBodyBytes {
		if manual {
			return domain.ErrRequestTooLarge
		}
		return domain.ErrInvalidRequest
	}
	if manual {
		var syntax map[string]json.RawMessage
		if err := validation.StrictDecode(raw, &syntax); err != nil {
			return err
		}
		if err := manifestSizeLimit(raw, min(s.cfg.MaxBodyBytes, domain.MaxInputBytes)); err != nil {
			return err
		}
		if err = validation.StrictDecode(raw, req); err != nil {
			return err
		}
		if strings.TrimSpace(req.ExecutionMode) != "manual" || strings.TrimSpace(req.Scope.TenantID) == "" {
			return domain.ErrInvalidRequest
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		var p map[string]json.RawMessage
		_ = json.Unmarshal(fields["policy"], &p)
		if _, ok := p["approval_id"]; ok {
			return domain.ErrInvalidRequest
		}
		var scope map[string]json.RawMessage
		_ = json.Unmarshal(fields["scope"], &scope)
		if tr, ok := scope["time_range"]; ok {
			var f map[string]json.RawMessage
			_ = json.Unmarshal(tr, &f)
			if f["start"] == nil || f["end"] == nil {
				return domain.ErrInvalidRequest
			}
		}
	} else {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err = d.Decode(req); err != nil {
			return fmt.Errorf("%w: invalid JSON body", domain.ErrInvalidRequest)
		}
		var extra any
		if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
			return domain.ErrInvalidRequest
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		for key := range fields {
			if strings.EqualFold(key, "input_manifest") {
				return domain.ErrInvalidRequest
			}
		}
	}
	if req.InputManifest != nil && req.InputManifest.SizeBytes > min(s.cfg.MaxBodyBytes, domain.MaxInputBytes) {
		return domain.ErrInputTooLarge
	}
	return nil
}
func (s *Server) submitRun(w http.ResponseWriter, r *http.Request) {
	tenant, runID := tenantIDFromContext(r.Context()), r.PathValue("runID")
	if _, err := s.service.GetRun(r.Context(), tenant, runID); err != nil {
		writeError(w, r, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBytes+1))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if int64(len(raw)) > s.cfg.MaxBodyBytes {
		writeError(w, r, domain.ErrRequestTooLarge)
		return
	}
	var req struct {
		ArtifactID string `json:"artifact_id"`
	}
	if err = validation.StrictDecode(raw, &req); err != nil {
		writeError(w, r, err)
		return
	}
	run, created, err := s.service.SubmitRun(r.Context(), tenant, runID, req.ArtifactID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusAccepted
	}
	w.Header().Set("Location", "/v1/runs/"+run.ID)
	writeJSON(w, status, run)
}

// Compare positive integer literals before int64 decoding, so an arbitrarily
// large (but body-bounded) JSON integer reports the input limit, not overflow.
func manifestSizeLimit(raw []byte, limit int64) error {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(fields["input_manifest"], &manifest) != nil {
		return nil
	}
	value := strings.TrimSpace(string(manifest["size_bytes"]))
	if value == "" {
		return nil
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return nil
		}
	}
	bound := strconv.FormatInt(limit, 10)
	if len(value) > len(bound) || (len(value) == len(bound) && value > bound) {
		return domain.ErrInputTooLarge
	}
	return nil
}
