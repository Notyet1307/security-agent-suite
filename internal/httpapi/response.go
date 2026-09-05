package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Notyet1307/security-agent-suite/internal/domain"
)

type errorResponse struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id,omitempty"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	code := "internal_error"
	switch {
	case errors.Is(err, domain.ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, domain.ErrAlreadyExists), errors.Is(err, domain.ErrConflict), errors.Is(err, domain.ErrInvalidTransition):
		status, code = http.StatusConflict, "conflict"
	case errors.Is(err, domain.ErrInvalidRequest):
		status, code = http.StatusBadRequest, "invalid_request"
	case errors.Is(err, domain.ErrUnauthorized):
		status, code = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, domain.ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	}
	writeStatusError(w, r, status, code, err.Error())
}

func writeStatusError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	payload := errorResponse{}
	payload.Error.Code = code
	payload.Error.Message = message
	payload.Error.RequestID = requestIDFromContext(r.Context())
	writeJSON(w, status, payload)
}
