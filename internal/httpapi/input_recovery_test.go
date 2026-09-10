package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/app"
	"github.com/Notyet1307/security-agent-suite/internal/artifacts"
	"github.com/Notyet1307/security-agent-suite/internal/catalog"
	"github.com/Notyet1307/security-agent-suite/internal/domain"
	"github.com/Notyet1307/security-agent-suite/internal/executor"
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	"github.com/Notyet1307/security-agent-suite/internal/store"
	filestore "github.com/Notyet1307/security-agent-suite/internal/store/file"
	memorystore "github.com/Notyet1307/security-agent-suite/internal/store/memory"
)

var interruptedInput = errors.New("injected persistence interruption")

type inputFaults struct{ stage atomic.Int32 }

func (f *inputFaults) fail(stage int32) bool { return f.stage.CompareAndSwap(stage, 0) }

type interruptedRuns struct {
	store.RunStore
	store.InputJournalStore
	faults *inputFaults
}

func (r *interruptedRuns) CreateInputJournal(ctx context.Context, j store.InputJournal) error {
	if r.faults.fail(1) {
		return interruptedInput
	}
	err := r.InputJournalStore.CreateInputJournal(ctx, j)
	if err == nil && r.faults.fail(2) {
		return interruptedInput
	}
	return err
}
func (r *interruptedRuns) Update(ctx context.Context, id string, fn func(*domain.Run) error) (*domain.Run, error) {
	if r.faults.fail(5) {
		return nil, interruptedInput
	}
	run, err := r.RunStore.Update(ctx, id, fn)
	if err == nil && r.faults.fail(6) {
		return nil, interruptedInput
	}
	return run, err
}

type interruptedEvidence struct {
	store.EvidenceStore
	faults *inputFaults
}

func (e *interruptedEvidence) Append(ctx context.Context, tenant, run string, ref domain.EvidenceRef) (domain.EvidenceRef, error) {
	if e.faults.fail(3) {
		return domain.EvidenceRef{}, interruptedInput
	}
	stored, err := e.EvidenceStore.Append(ctx, tenant, run, ref)
	if err == nil && e.faults.fail(4) {
		return domain.EvidenceRef{}, interruptedInput
	}
	return stored, err
}

type inputEnv struct {
	h        http.Handler
	svc      *app.Service
	runs     *interruptedRuns
	arts     *artifacts.Store
	evidence store.EvidenceStore
	faults   *inputFaults
}

func newInputEnv(t *testing.T, root string, memory bool, runtime executor.Executor, existing *inputEnv) *inputEnv {
	t.Helper()
	var runs store.RunStore
	var journals store.InputJournalStore
	var evidence store.EvidenceStore
	arts, err := artifacts.New(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if memory {
		if existing != nil {
			runs = existing.runs.RunStore
			journals = existing.runs.InputJournalStore
			evidence = existing.evidence
		} else {
			r := memorystore.New()
			runs = r
			journals = r
			evidence, err = memorystore.NewEvidenceStore(r, arts)
		}
	} else {
		r, e := filestore.New(filepath.Join(root, "state"))
		if e != nil {
			t.Fatal(e)
		}
		runs = r
		journals = r
		evidence, err = filestore.NewEvidenceStore(filepath.Join(root, "state"), r, arts)
	}
	if err != nil {
		t.Fatal(err)
	}
	faults := &inputFaults{}
	wrapped := &interruptedRuns{runs, journals, faults}
	cat, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := app.New(app.Config{Workers: 1, QueueSize: 1, InputArtifacts: arts}, wrapped, cat, policy.New(), runtime, prompt.New(), metrics, logger, &interruptedEvidence{evidence, faults})
	t.Cleanup(svc.Close)
	h := New(Config{APIKey: "key", RateLimitPerMinute: 10000}, svc, arts, metrics, logger, evidence).Handler()
	return &inputEnv{h, svc, wrapped, arts, evidence, faults}
}
func prepareInput(t *testing.T, h http.Handler, id string, raw []byte) (domain.Run, domain.ArtifactRef) {
	t.Helper()
	w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest(id, raw), nil)
	requireStatus(t, w, 201)
	var run domain.Run
	json.Unmarshal(w.Body.Bytes(), &run)
	w = inputCall(h, "POST", "/v1/runs/"+run.ID+"/artifacts?name=a", "t", raw, map[string]string{"X-Artifact-SHA256": fmt.Sprintf("%x", sha256.Sum256(raw))})
	requireStatus(t, w, 201)
	var art domain.ArtifactRef
	json.Unmarshal(w.Body.Bytes(), &art)
	return run, art
}
func submitInput(t *testing.T, h http.Handler, run domain.Run, art domain.ArtifactRef, status int) {
	t.Helper()
	w := inputCall(h, "POST", "/v1/runs/"+run.ID+"/submit", "t", []byte(fmt.Sprintf(`{"artifact_id":%q}`, art.ID)), nil)
	requireStatus(t, w, status)
}
func awaitCalls(t *testing.T, counter *inputCounter, n int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for counter.calls.Load() < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if counter.calls.Load() != n {
		t.Fatalf("calls=%d want %d", counter.calls.Load(), n)
	}
}

func TestManualPersistenceInterruptions(t *testing.T) {
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	for _, memory := range []bool{false, true} {
		for stage := int32(1); stage <= 6; stage++ {
			for _, restart := range []bool{false, true} {
				t.Run(fmt.Sprintf("memory=%v/stage=%d/restart=%v", memory, stage, restart), func(t *testing.T) {
					root := t.TempDir()
					counter := &inputCounter{}
					env := newInputEnv(t, root, memory, counter, nil)
					run, art := prepareInput(t, env.h, "fault", raw)
					env.faults.stage.Store(stage)
					submitInput(t, env.h, run, art, 500)
					if counter.calls.Load() != 0 {
						t.Fatal("unstarted service executed")
					}
					if restart {
						env.svc.Close()
						env = newInputEnv(t, root, memory, counter, env)
					}
					if stage < 6 {
						if err := env.svc.Start(); err != nil {
							t.Fatal(err)
						}
						time.Sleep(10 * time.Millisecond)
						if counter.calls.Load() != 0 {
							t.Fatal("partial preparation resumed execution")
						}
						submitInput(t, env.h, run, art, 202)
					} else {
						if err := env.svc.Start(); err != nil {
							t.Fatal(err)
						}
						submitInput(t, env.h, run, art, 200)
					}
					awaitCalls(t, counter, 1)
					submitInput(t, env.h, run, art, 200)
					w := inputCall(env.h, "GET", "/v1/runs/"+run.ID+"/evidence", "t", nil, nil)
					requireStatus(t, w, 200)
					var records struct {
						Evidence []domain.EvidenceRef `json:"evidence"`
					}
					json.Unmarshal(w.Body.Bytes(), &records)
					if len(records.Evidence) != 1 {
						t.Fatal(w.Body.String())
					}
				})
			}
		}
	}
}

func TestManualJournalProtectsPublicEvidenceAndCancellation(t *testing.T) {
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	root := t.TempDir()
	counter := &inputCounter{}
	env := newInputEnv(t, root, false, counter, nil)
	run, art := prepareInput(t, env.h, "reserved", raw)
	// A public caller can claim the same tool label, but it does not create a submission.
	forged := domain.EvidenceRef{ID: "client-evidence", Type: "input", Tool: "sas-input-validator", ToolVersion: "1", SourceURI: art.URI, SHA256: art.SHA256, ArtifactIDs: []string{art.ID}, Parameters: map[string]string{"schema": domain.InputSchema}}
	data, _ := json.Marshal(forged)
	requireStatus(t, inputCall(env.h, "POST", "/v1/runs/"+run.ID+"/evidence", "t", data, nil), 201)
	env.faults.stage.Store(3)
	submitInput(t, env.h, run, art, 500)
	journal, err := env.runs.GetInputJournal(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(journal.Evidence)
	requireStatus(t, inputCall(env.h, "POST", "/v1/runs/"+run.ID+"/evidence", "t", data, nil), 409)
	env.svc.Close()
	env = newInputEnv(t, root, false, counter, nil)
	requireStatus(t, inputCall(env.h, "POST", "/v1/runs/"+run.ID+"/evidence", "t", data, nil), 409)
	requireStatus(t, inputCall(env.h, "POST", "/v1/runs/"+run.ID+"/cancel", "t", []byte(`{}`), nil), 200)
	submitInput(t, env.h, run, art, 409)
	if err := env.svc.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if counter.calls.Load() != 0 {
		t.Fatal("cancelled candidate executed")
	}
}

type heldInputExecutor struct {
	inputCounter
	release <-chan struct{}
}

func (e *heldInputExecutor) Execute(ctx context.Context, req domain.ExecutionRequest) (domain.ExecutionResult, error) {
	n := e.calls.Add(1)
	if n == 1 {
		select {
		case <-e.release:
		case <-ctx.Done():
			return domain.ExecutionResult{}, ctx.Err()
		}
	}
	return domain.ExecutionResult{Status: domain.RunStatusFailed}, nil
}
func TestManualQueueFullRepairsWithoutRestart(t *testing.T) {
	release := make(chan struct{})
	counter := &heldInputExecutor{release: release}
	env := newInputEnv(t, t.TempDir(), false, counter, nil)
	if err := env.svc.Start(); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	run, art := prepareInput(t, env.h, "queue-1", raw)
	submitInput(t, env.h, run, art, 202)
	awaitCalls(t, &counter.inputCounter, 1)
	for i := 2; i <= 5; i++ {
		r, a := prepareInput(t, env.h, fmt.Sprintf("queue-%d", i), raw)
		submitInput(t, env.h, r, a, 202)
	}
	close(release)
	awaitCalls(t, &counter.inputCounter, 5)
}

func TestManualRecoveryFailsClosed(t *testing.T) {
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	for _, damage := range []string{"journal", "evidence", "bytes", "fingerprint", "inputs"} {
		t.Run(damage, func(t *testing.T) {
			root := t.TempDir()
			counter := &inputCounter{}
			env := newInputEnv(t, root, false, counter, nil)
			run, art := prepareInput(t, env.h, "corrupt", raw)
			submitInput(t, env.h, run, art, 202)
			env.svc.Close()
			switch damage {
			case "journal":
				if err := os.Remove(filepath.Join(root, "state/input-journals", run.ID+".json")); err != nil {
					t.Fatal(err)
				}
			case "evidence":
				entries, err := os.ReadDir(filepath.Join(root, "state/evidence", run.ID))
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".json") {
						if err := os.Remove(filepath.Join(root, "state/evidence", run.ID, e.Name())); err != nil {
							t.Fatal(err)
						}
					}
				}
			case "bytes":
				path := filepath.Join(root, "artifacts", run.ID, art.ID)
				if err := os.WriteFile(path, []byte(strings.Repeat("x", len(raw))), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				_, err := env.runs.Update(context.Background(), run.ID, func(r *domain.Run) error {
					if damage == "fingerprint" {
						r.CreationFingerprint = "sas.manual-create/v0:unknown"
					} else {
						r.Inputs = nil
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			env = newInputEnv(t, root, false, counter, nil)
			if err := env.svc.Start(); err == nil {
				t.Fatal("corrupt queued input started")
			}
			if counter.calls.Load() != 0 {
				t.Fatal("corrupt input executed")
			}
		})
	}
}

func TestManualInterruptedExecutionIsNotRetried(t *testing.T) {
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	for _, status := range []domain.RunStatus{domain.RunStatusValidating, domain.RunStatusRunning} {
		t.Run(string(status), func(t *testing.T) {
			root := t.TempDir()
			counter := &inputCounter{}
			env := newInputEnv(t, root, false, counter, nil)
			r, a := prepareInput(t, env.h, "interrupted", raw)
			submitInput(t, env.h, r, a, 202)
			_, err := env.runs.Update(context.Background(), r.ID, func(run *domain.Run) error {
				if err := run.Transition(domain.RunStatusValidating, "fault injection", "test", time.Now()); err != nil {
					return err
				}
				if status == domain.RunStatusRunning {
					return run.Transition(status, "fault injection", "test", time.Now())
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			env.svc.Close()
			env = newInputEnv(t, root, false, counter, nil)
			if err = env.svc.Start(); err != nil {
				t.Fatal(err)
			}
			w := inputCall(env.h, "GET", "/v1/runs/"+r.ID, "t", nil, nil)
			requireStatus(t, w, 200)
			var result domain.Run
			json.Unmarshal(w.Body.Bytes(), &result)
			if result.Status != domain.RunStatusFailed || result.Result.ErrorCode != "service_restarted" || counter.calls.Load() != 0 {
				t.Fatal(w.Body.String())
			}
			submitInput(t, env.h, r, a, 200)
		})
	}
}

func (e *interruptedEvidence) Get(ctx context.Context, tenant, run, id string) (domain.EvidenceRef, error) {
	if e.faults.fail(7) {
		return domain.EvidenceRef{ID: id, Tool: "public-preoccupied"}, nil
	}
	return e.EvidenceStore.Get(ctx, tenant, run, id)
}
func TestManualCandidateEvidencePreoccupationFailsClosed(t *testing.T) {
	counter := &inputCounter{}
	env := newInputEnv(t, t.TempDir(), false, counter, nil)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	run, art := prepareInput(t, env.h, "preoccupied", raw)
	env.faults.stage.Store(7)
	submitInput(t, env.h, run, art, 409)
	if _, err := env.runs.GetInputJournal(context.Background(), run.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("preoccupied ID published journal: %v", err)
	}
	w := inputCall(env.h, "GET", "/v1/runs/"+run.ID, "t", nil, nil)
	var got domain.Run
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Status != domain.RunStatusPreparing || got.Submission != nil || counter.calls.Load() != 0 {
		t.Fatal("preoccupied evidence became executable")
	}
}

type slowInputReader struct {
	entered chan struct{}
	release <-chan struct{}
	data    *strings.Reader
	once    sync.Once
}

func (r *slowInputReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.data.Read(p)
}
func TestSlowManualUploadDoesNotBlockAutomaticCancellation(t *testing.T) {
	counter := &inputCounter{}
	env := newInputEnv(t, t.TempDir(), false, counter, nil)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	manual, _ := prepareInput(t, env.h, "slow", raw)
	w := inputCall(env.h, "POST", "/v1/agents/event-triage/runs", "t", []byte(`{"request_id":"automatic","mode":"triage","scope":{"tenant_id":"t"}}`), nil)
	requireStatus(t, w, 202)
	var automatic domain.Run
	json.Unmarshal(w.Body.Bytes(), &automatic)
	release := make(chan struct{})
	entered := make(chan struct{})
	done := make(chan struct{})
	cancelled := make(chan *httptest.ResponseRecorder, 1)
	finished := false
	defer func() {
		close(release)
		<-done
		if !finished {
			<-cancelled
		}
	}()
	reader := &slowInputReader{entered: entered, release: release, data: strings.NewReader(string(raw))}
	go func() {
		defer close(done)
		_, _ = env.svc.UploadInput(context.Background(), "t", manual.ID, "slow.json", "application/json", fmt.Sprintf("%x", sha256.Sum256(raw)), reader)
	}()
	<-entered
	go func() {
		cancelled <- inputCall(env.h, "POST", "/v1/runs/"+automatic.ID+"/cancel", "t", []byte(`{}`), nil)
	}()
	select {
	case w := <-cancelled:
		finished = true
		requireStatus(t, w, 200)
	case <-time.After(time.Second):
		t.Fatal("untrusted manual body blocked automatic cancellation")
	}
}
