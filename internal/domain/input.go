package domain

import "time"

const InputSchema = "sas.synthetic-alert/v1"
const MaxInputBytes int64 = 1 << 20

type InputManifest struct {
	Schema    string `json:"schema"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
}
type Submission struct {
	RunID       string    `json:"run_id"`
	ArtifactID  string    `json:"artifact_id"`
	Schema      string    `json:"schema"`
	SHA256      string    `json:"sha256"`
	SizeBytes   int64     `json:"size_bytes"`
	MediaType   string    `json:"media_type"`
	EvidenceID  string    `json:"evidence_id"`
	SubmittedAt time.Time `json:"submitted_at"`
	Fingerprint string    `json:"fingerprint"`
}

func (r Run) Manual() bool { return r.ExecutionMode == "manual" }
