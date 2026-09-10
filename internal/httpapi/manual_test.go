package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	"github.com/Notyet1307/security-agent-suite/internal/observability"
	"github.com/Notyet1307/security-agent-suite/internal/policy"
	"github.com/Notyet1307/security-agent-suite/internal/prompt"
	filestore "github.com/Notyet1307/security-agent-suite/internal/store/file"
)

type inputCounter struct{ calls atomic.Int32 }

func (e *inputCounter) Name() string { return "input-test" }
func (e *inputCounter) Execute(context.Context, domain.ExecutionRequest) (domain.ExecutionResult, error) {
	e.calls.Add(1)
	return domain.ExecutionResult{Status: domain.RunStatusFailed, Result: domain.RunResult{ErrorCode: "test_only"}}, nil
}
func manualHTTP(t *testing.T) (http.Handler, *inputCounter) {
	t.Helper()
	root := t.TempDir()
	runs, err := filestore.New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	arts, err := artifacts.New(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := filestore.NewEvidenceStore(filepath.Join(root, "state"), runs, arts)
	if err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Load("../../configs/agents.json")
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	counter := &inputCounter{}
	svc := app.New(app.Config{Workers: 2, QueueSize: 1, InputArtifacts: arts}, runs, cat, policy.New(), counter, prompt.New(), metrics, logger, evidence)
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return New(Config{APIKey: "key", RateLimitPerMinute: 10000}, svc, arts, metrics, logger, evidence).Handler(), counter
}
func inputCall(h http.Handler, method, path, tenant string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-API-Key", "key")
	r.Header.Set("X-Tenant-ID", tenant)
	r.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func inputRequest(id string, raw []byte) []byte {
	return []byte(fmt.Sprintf(`{"request_id":%q,"execution_mode":"manual","mode":"triage","scope":{"tenant_id":"t"},"input_manifest":{"schema":"sas.synthetic-alert/v1","media_type":"application/json","sha256":"%x","size_bytes":%d}}`, id, sha256.Sum256(raw), len(raw)))
}
func requireStatus(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d want %d: %s", w.Code, code, w.Body.String())
	}
}
func TestManualPreparationDoesNotExecute(t *testing.T) {
	h, counter := manualHTTP(t)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest("prepare", raw), nil)
	requireStatus(t, w, 201)
	var run domain.Run
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if string(run.Status) != "preparing" {
		t.Fatalf("status %s", run.Status)
	}
	time.Sleep(20 * time.Millisecond)
	if counter.calls.Load() != 0 {
		t.Fatal("preparing run executed")
	}
}

func TestManualUploadSubmitAndReplay(t *testing.T) {
	h, counter := manualHTTP(t)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest("submit", raw), nil)
	requireStatus(t, w, 201)
	var run domain.Run
	json.Unmarshal(w.Body.Bytes(), &run)
	path := "/v1/runs/" + run.ID
	w = inputCall(h, "POST", path+"/artifacts?name=input.json", "t", raw, map[string]string{"X-Artifact-SHA256": fmt.Sprintf("%x", sha256.Sum256(raw))})
	requireStatus(t, w, 201)
	var art domain.ArtifactRef
	json.Unmarshal(w.Body.Bytes(), &art)
	if counter.calls.Load() != 0 {
		t.Fatal("upload executed")
	}
	body := []byte(fmt.Sprintf(`{"artifact_id":%q}`, art.ID))
	w = inputCall(h, "POST", path+"/submit", "t", body, nil)
	requireStatus(t, w, 202)
	w = inputCall(h, "POST", path+"/submit", "t", body, nil)
	requireStatus(t, w, 200)
	deadline := time.Now().Add(time.Second)
	for counter.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if counter.calls.Load() != 1 {
		t.Fatalf("executions=%d", counter.calls.Load())
	}
	w = inputCall(h, "GET", path+"/evidence", "t", nil, nil)
	requireStatus(t, w, 200)
	var result struct {
		Evidence []domain.EvidenceRef `json:"evidence"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Evidence) != 1 || result.Evidence[0].ArtifactIDs[0] != art.ID {
		t.Fatalf("evidence %s", w.Body.String())
	}
	w = inputCall(h, "POST", path+"/artifacts?name=again.json", "t", raw, nil)
	requireStatus(t, w, 409)
}

func TestManualFixturesThroughPublicAPI(t *testing.T) {
	h, counter := manualHTTP(t)
	data, err := os.ReadFile("../../evals/input-preparation-v1/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack struct {
		Fixtures []struct {
			ID       string `json:"id"`
			Path     string `json:"path"`
			Expected struct {
				Status int `json:"submit_http_status"`
			} `json:"expected"`
		} `json:"fixtures"`
	}
	if err = json.Unmarshal(data, &pack); err != nil {
		t.Fatal(err)
	}
	for _, f := range pack.Fixtures {
		t.Run(f.ID, func(t *testing.T) {
			raw, err := os.ReadFile("../../evals/input-preparation-v1/" + f.Path)
			if err != nil {
				t.Fatal(err)
			}
			w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest(f.ID, raw), nil)
			requireStatus(t, w, 201)
			var run domain.Run
			json.Unmarshal(w.Body.Bytes(), &run)
			p := "/v1/runs/" + run.ID
			w = inputCall(h, "POST", p+"/artifacts?name=fixture.json", "t", raw, map[string]string{"X-Artifact-SHA256": fmt.Sprintf("%x", sha256.Sum256(raw))})
			requireStatus(t, w, 201)
			var art domain.ArtifactRef
			json.Unmarshal(w.Body.Bytes(), &art)
			w = inputCall(h, "POST", p+"/submit", "t", []byte(fmt.Sprintf(`{"artifact_id":%q}`, art.ID)), nil)
			requireStatus(t, w, f.Expected.Status)
			if f.Expected.Status == 400 {
				w = inputCall(h, "GET", p, "t", nil, nil)
				json.Unmarshal(w.Body.Bytes(), &run)
				if run.Status != domain.RunStatusPreparing || run.Submission != nil {
					t.Fatalf("failed submission changed run: %+v", run)
				}
			}
		})
	}
	deadline := time.Now().Add(2 * time.Second)
	for counter.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if counter.calls.Load() != 3 {
		t.Fatalf("executor calls %d want 3", counter.calls.Load())
	}
}

func TestManualRequestAndUploadBoundaries(t *testing.T) {
	h, _ := manualHTTP(t)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	base := string(inputRequest("invalid", raw))
	for _, bad := range []string{
		strings.Replace(base, `"execution_mode"`, `"Execution_Mode"`, 1),
		strings.Replace(base, `"schema"`, `"SCHEMA"`, 1),
		strings.Replace(base, `"manual"`, `"manual","execution_mode":"automatic"`, 1),
		strings.Replace(base, `"mode":"triage"`, `"mode":"triage","mo\u0064e":"triage"`, 1),
		strings.Replace(base, `"scope":{`, `"scope":null,"unused":{`, 1),
		strings.Replace(base, `"request_id":"invalid"`, `"request_id":"bad\ud800"`, 1),
		strings.Replace(base, `"scope":`, `"policy":{"approval_id":""},"scope":`, 1),
		strings.Replace(base, `"scope":`, `"metadata":{"key":null},"scope":`, 1),
		strings.Replace(base, `"scope":`, `"input_manifest":null,"scope":`, 1),
		strings.Replace(base, `"scope":`, `"output":{"formats":["JSON","json"]},"scope":`, 1),
	} {
		w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(bad), nil)
		requireStatus(t, w, 400)
	}
	w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(strings.Replace(base, `"scope":`, `"policy":{"network_access":"bogus"},"scope":`, 1)), nil)
	requireStatus(t, w, 403)
	w = inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest("upload-errors", raw), nil)
	requireStatus(t, w, 201)
	var run domain.Run
	json.Unmarshal(w.Body.Bytes(), &run)
	path := "/v1/runs/" + run.ID
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	for _, headers := range []map[string]string{nil, {"X-Artifact-SHA256": strings.Repeat("0", 64)}, {"X-Artifact-SHA256": digest, "Content-Type": "text/plain"}, {"X-Artifact-SHA256": digest, "Content-Type": "application/json; charset=ascii"}} {
		w = inputCall(h, "POST", path+"/artifacts?name=a", "t", raw, headers)
		requireStatus(t, w, 400)
	}
	for _, body := range [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 32)} {
		w = inputCall(h, "POST", path+"/artifacts?name=a", "t", body, map[string]string{"X-Artifact-SHA256": digest})
		requireStatus(t, w, 400)
	}
	w = inputCall(h, "GET", path+"/artifacts", "t", nil, nil)
	if !strings.Contains(w.Body.String(), `"artifacts":[]`) {
		t.Fatal(w.Body.String())
	}
	w = inputCall(h, "POST", path+"/submit", "other", []byte(`{"artifact_id":"unknown"}`), nil)
	requireStatus(t, w, 404)
	w = inputCall(h, "POST", path+"/submit", "t", []byte(`{"artifact_id":"unknown"}`), nil)
	requireStatus(t, w, 404)
}

func TestManualFingerprintAndConcurrentCreation(t *testing.T) {
	h, _ := manualHTTP(t)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	req := []byte(strings.Replace(string(inputRequest("fp", raw)), `"scope":`, `"metadata":{"note":"中文<>&"},"scope":`, 1))
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			responses <- inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", req, nil)
		}()
	}
	wg.Wait()
	close(responses)
	created := 0
	runID := ""
	for w := range responses {
		if w.Code == 201 {
			created++
		} else {
			requireStatus(t, w, 200)
		}
		var run domain.Run
		json.Unmarshal(w.Body.Bytes(), &run)
		if runID != "" && run.ID != runID {
			t.Fatal("multiple runs")
		}
		runID = run.ID
		if run.CreationFingerprint != "sas.manual-create/v1:a9c515f41ea5683f91c762baa37b4c94ac8fb35e6c650d6859f5898c0f9ebd9a" {
			t.Fatalf("fingerprint %s", run.CreationFingerprint)
		}
	}
	if created != 1 {
		t.Fatalf("created %d", created)
	}
	explicit := strings.Replace(string(req), `"mode":"triage"`, `"mode":" triage ","case_id":"","inputs":[],"policy":{"network_access":"deny","active_validation":false,"max_requests":0,"max_duration":"1200s"},"output":{"language":" zh-CN ","formats":[" JSON "]}`, 1)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(explicit), nil), 200)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(strings.Replace(string(req), `中文`, `different`, 1)), nil), 409)
	legacy := []byte(`{"request_id":"fp","mode":"triage","scope":{"tenant_id":"t"}}`)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", legacy, nil), 409)
	legacy = []byte(`{"request_id":"legacy","mode":"triage","scope":{"tenant_id":"t"}}`)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", legacy, nil), 202)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest("legacy", raw), nil), 409)
	ordered := strings.Replace(string(inputRequest("arrays", raw)), `"tenant_id":"t"`, `"tenant_id":"t","assets":["a","b"]`, 1)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(ordered), nil), 201)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(strings.Replace(ordered, `["a","b"]`, `["b","a"]`, 1)), nil), 409)
}

func TestManualConcurrentSubmitCancelAndBinding(t *testing.T) {
	h, counter := manualHTTP(t)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	prepare := func(id string) (string, string) {
		w := inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest(id, raw), nil)
		requireStatus(t, w, 201)
		var run domain.Run
		json.Unmarshal(w.Body.Bytes(), &run)
		p := "/v1/runs/" + run.ID
		w = inputCall(h, "POST", p+"/artifacts?name=a", "t", raw, map[string]string{"X-Artifact-SHA256": fmt.Sprintf("%x", sha256.Sum256(raw))})
		requireStatus(t, w, 201)
		var art domain.ArtifactRef
		json.Unmarshal(w.Body.Bytes(), &art)
		return p, art.ID
	}
	p, a := prepare("concurrent")
	other, _ := prepare("other")
	body := []byte(fmt.Sprintf(`{"artifact_id":%q}`, a))
	requireStatus(t, inputCall(h, "POST", other+"/submit", "t", body, nil), 404)
	// Another upload with identical bytes is still another selected Artifact.
	w := inputCall(h, "POST", p+"/artifacts?name=second", "t", raw, map[string]string{"X-Artifact-SHA256": fmt.Sprintf("%x", sha256.Sum256(raw))})
	requireStatus(t, w, 201)
	var second domain.ArtifactRef
	json.Unmarshal(w.Body.Bytes(), &second)
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 16)
	for range 16 {
		wg.Add(1)
		go func() { defer wg.Done(); responses <- inputCall(h, "POST", p+"/submit", "t", body, nil) }()
	}
	wg.Wait()
	close(responses)
	accepted := 0
	for w := range responses {
		if w.Code == 202 {
			accepted++
		} else {
			requireStatus(t, w, 200)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d", accepted)
	}
	requireStatus(t, inputCall(h, "POST", p+"/submit", "t", []byte(fmt.Sprintf(`{"artifact_id":%q}`, second.ID)), nil), 409)
	deadline := time.Now().Add(time.Second)
	for counter.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if counter.calls.Load() != 1 {
		t.Fatalf("calls %d", counter.calls.Load())
	}
	requireStatus(t, inputCall(h, "POST", p+"/submit", "t", body, nil), 200)
	for i := 0; i < 8; i++ {
		p, a := prepare(fmt.Sprintf("cancel-%d", i))
		submit := make(chan *httptest.ResponseRecorder, 1)
		cancel := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			submit <- inputCall(h, "POST", p+"/submit", "t", []byte(fmt.Sprintf(`{"artifact_id":%q}`, a)), nil)
		}()
		go func() { cancel <- inputCall(h, "POST", p+"/cancel", "t", []byte(`{}`), nil) }()
		sw, cw := <-submit, <-cancel
		if sw.Code != 202 && sw.Code != 409 {
			t.Fatal(sw.Body.String())
		}
		if cw.Code != 200 && cw.Code != 202 {
			t.Fatal(cw.Body.String())
		}
		w = inputCall(h, "GET", p, "t", nil, nil)
		var final domain.Run
		json.Unmarshal(w.Body.Bytes(), &final)
		if sw.Code == 409 && final.Status != domain.RunStatusCancelled {
			t.Fatalf("cancel revived: %s", w.Body.String())
		}
	}
}

func TestManualByteLimitsAndStrictAlertFields(t *testing.T) {
	h, counter := manualHTTP(t)
	base := `{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`
	maxRaw := []byte(base + strings.Repeat(" ", int(domain.MaxInputBytes)-len(base)))
	run, art := prepareInput(t, h, "maximum", maxRaw)
	for _, unknownLength := range []bool{false, true} {
		r := httptest.NewRequest("POST", "/v1/runs/"+run.ID+"/artifacts?name=over", bytes.NewReader(append(append([]byte{}, maxRaw...), 32)))
		r.Header.Set("X-API-Key", "key")
		r.Header.Set("X-Tenant-ID", "t")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Artifact-SHA256", art.SHA256)
		if unknownLength {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		requireStatus(t, w, 413)
	}
	submitInput(t, h, run, art, 202)
	over := append(append([]byte{}, maxRaw...), 32)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", inputRequest("oversize", over), nil), 413)
	long := []byte(`{"execution_mode":"manual","padding":"` + strings.Repeat("x", int(domain.MaxInputBytes)) + `"}`)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", long, nil), 413)
	long = []byte(`{"padding":"` + strings.Repeat("x", int(domain.MaxInputBytes)) + `","execution_mode":"manual"}`)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", long, nil), 400)
	requireStatus(t, inputCall(h, "POST", "/v1/runs/"+run.ID+"/submit", "t", long, nil), 413)
	for i, raw := range []string{
		strings.Replace(base, `"schema"`, `"SCHEMA"`, 1),
		strings.Replace(base, `"synthetic":true`, `"synthetic":true,"Synthetic":false`, 1),
		strings.Replace(base, `"observations":[]`, `"observations":[{"source":"a","so\u0075rce":"b","text":"x"}]`, 1),
		strings.Replace(base, `"observations":[]`, `"observations":[{"source":"a","text":"\ud800"}]`, 1),
		strings.Replace(base, `"observations":[]`, `"observations":[{"source":"a","text":"\udc00"}]`, 1),
		strings.Replace(base, `"observations":[]`, `"observations":[{"source":"a","text":"`+strings.Repeat("x", 16385)+`"}]`, 1),
		strings.Replace(base, `"observations":[]`, `"observations":null`, 1),
		"\xef\xbb\xbf" + base,
	} {
		r, a := prepareInput(t, h, fmt.Sprintf("strict-%d", i), []byte(raw))
		submitInput(t, h, r, a, 400)
	}
	valid := strings.Replace(base, `"observations":[]`, `"observations":[{"source":"a","text":"\ud83d\ude00 \\ud800 �"}]`, 1)
	r, a := prepareInput(t, h, "valid-unicode", []byte(valid))
	submitInput(t, h, r, a, 202)
	awaitCalls(t, counter, 2)
}

func TestManualOversizedIntegerAndAutomaticManifestAlias(t *testing.T) {
	h, _ := manualHTTP(t)
	raw := []byte(`{"schema":"sas.synthetic-alert/v1","synthetic":true,"alert_id":"one","observations":[]}`)
	req := string(inputRequest("huge", raw))
	req = strings.Replace(req, fmt.Sprintf(`"size_bytes":%d`, len(raw)), `"size_bytes":9223372036854775808`, 1)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(req), nil), 413)
	duplicate := strings.Replace(req, `"request_id":"huge"`, `"request_id":"huge","request_id":"huge"`, 1)
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(duplicate), nil), 400)
	req = `{"request_id":"alias","mode":"triage","scope":{"tenant_id":"t"},"Input_Manifest":null}`
	requireStatus(t, inputCall(h, "POST", "/v1/agents/event-triage/runs", "t", []byte(req), nil), 400)
}
