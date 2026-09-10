package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/doctor"
	"github.com/Notyet1307/security-agent-suite/internal/store"
	"github.com/Notyet1307/security-agent-suite/internal/validation"
)

type doctorRunner func(context.Context, doctor.Config) doctor.Report

const maxValidationOutputBytes = 8 << 20

type client struct {
	baseURL   string
	apiKey    string
	tenantID  string
	http      *http.Client
	stdout    io.Writer
	stderr    io.Writer
	doctorRun doctorRunner
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, doctor.Run))
}

func run(args []string, stdout, stderr io.Writer, doctorRun doctorRunner) int {

	global := flag.NewFlagSet("sasctl", flag.ContinueOnError)
	global.SetOutput(stderr)
	baseURL := global.String("base-url", env("SAS_BASE_URL", "http://127.0.0.1:8080"), "Security Agent Suite API base URL")
	apiKey := global.String("api-key", os.Getenv("SAS_API_KEY"), "API key")
	tenantID := global.String("tenant", env("SAS_TENANT_ID", "default"), "tenant id")
	global.Usage = func() { writeUsage(stderr) }
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	args = global.Args()
	if len(args) == 0 {
		writeUsage(stderr)
		return 2
	}
	c := &client{
		baseURL: strings.TrimRight(*baseURL, "/"), apiKey: *apiKey, tenantID: *tenantID,
		http: &http.Client{Timeout: 90 * time.Second}, stdout: stdout, stderr: stderr, doctorRun: doctorRun,
	}

	var err error
	switch args[0] {
	case "doctor":
		err = c.doctor(args[1:])
	case "agents":
		err = c.print("GET", "/v1/agents", nil)
	case "list":
		err = c.listRuns(args[1:])
	case "run":
		err = c.createRun(args[1:])
	case "upload":
		err = c.upload(args[1:])
	case "submit":
		err = c.submit(args[1:])
	case "validate-output":
		err = c.validateOutput(args[1:])
	case "get":
		if len(args) != 2 {
			err = errors.New("usage: sasctl [global flags] get <run-id>")
		} else {
			err = c.print("GET", "/v1/runs/"+args[1], nil)
		}
	case "events":
		if len(args) != 2 {
			err = errors.New("usage: sasctl [global flags] events <run-id>")
		} else {
			err = c.print("GET", "/v1/runs/"+args[1]+"/events", nil)
		}
	case "approve":
		err = c.approve(args[1:])
	case "cancel":
		err = c.cancel(args[1:])
	case "wait":
		err = c.wait(args[1:])
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func writeUsage(w io.Writer) {

	fmt.Fprintln(w, `Usage:
  sasctl [global flags] doctor
  sasctl [global flags] agents
  sasctl [global flags] list [--agent ID] [--status STATUS] [--limit N]
  sasctl [global flags] run --agent ID --file request.json
  sasctl [global flags] upload RUN_ID --file PATH --sha256 DIGEST
  sasctl [global flags] submit RUN_ID --artifact-id ID
  sasctl [global flags] validate-output --agent ID --file output.json
  sasctl [global flags] get RUN_ID
  sasctl [global flags] events RUN_ID
  sasctl [global flags] approve RUN_ID --approval-id ID --actor NAME --reason TEXT
  sasctl [global flags] cancel RUN_ID [--actor NAME] [--reason TEXT]
  sasctl [global flags] wait RUN_ID [--interval 1s] [--timeout 30m]

Global flags must appear before the command.`)
}

func (c *client) doctor(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: sasctl [global flags] doctor")
	}
	report := c.doctorRun(context.Background(), doctor.FromEnvironment(c.baseURL, c.apiKey, c.tenantID))
	if err := report.WriteJSON(c.stdout); err != nil {
		return err
	}
	if report.RequiredFailures() {
		return errors.New("doctor found required check failures")
	}
	return nil
}

func (c *client) newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(c.stderr)
	return flags
}

func (c *client) createRun(args []string) error {
	flags := c.newFlagSet("run")
	agent := flags.String("agent", "", "agent id")
	filePath := flags.String("file", "", "request JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *agent == "" || *filePath == "" {
		return errors.New("--agent and --file are required")
	}
	data, err := os.ReadFile(*filePath)
	if err != nil {
		return err
	}
	return c.print("POST", "/v1/agents/"+*agent+"/runs", data)
}

func (c *client) validateOutput(args []string) error {
	flags := c.newFlagSet("validate-output")
	agent := flags.String("agent", "", "agent id")
	filePath := flags.String("file", "", "agent output JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *agent == "" || *filePath == "" {
		return errors.New("--agent and --file are required")
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sasctl validate-output --agent ID --file PATH")
	}
	file, err := openValidationOutput(*filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("agent output must be a regular file")
	}
	if info.Size() > maxValidationOutputBytes {
		return fmt.Errorf("agent output exceeds %d bytes", maxValidationOutputBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxValidationOutputBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxValidationOutputBytes {
		return fmt.Errorf("agent output exceeds %d bytes", maxValidationOutputBytes)
	}
	if _, err := validation.Parse(*agent, data); err != nil {
		return err
	}
	return json.NewEncoder(c.stdout).Encode(struct {
		AgentID string `json:"agent_id"`
		Valid   bool   `json:"valid"`
	}{AgentID: *agent, Valid: true})
}

func (c *client) listRuns(args []string) error {
	flags := c.newFlagSet("list")
	agent := flags.String("agent", "", "agent id")
	status := flags.String("status", "", "run status")
	limit := flags.Int("limit", 50, "maximum results")
	if err := flags.Parse(args); err != nil {
		return err
	}
	path := fmt.Sprintf("/v1/runs?limit=%d", *limit)
	if *agent != "" {
		path += "&agent_id=" + *agent
	}
	if *status != "" {
		path += "&status=" + *status
	}
	return c.print("GET", path, nil)
}

func (c *client) approve(args []string) error {
	if len(args) == 0 {
		return errors.New("run id is required")
	}
	runID := args[0]
	flags := c.newFlagSet("approve")
	approvalID := flags.String("approval-id", "", "approval reference")
	actor := flags.String("actor", "", "approver")
	reason := flags.String("reason", "", "approval reason")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"approval_id": *approvalID, "actor": *actor, "reason": *reason})
	return c.print("POST", "/v1/runs/"+runID+"/approve", body)
}

func (c *client) cancel(args []string) error {
	if len(args) == 0 {
		return errors.New("run id is required")
	}
	runID := args[0]
	flags := c.newFlagSet("cancel")
	actor := flags.String("actor", "sasctl", "actor")
	reason := flags.String("reason", "cancelled by operator", "reason")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"actor": *actor, "reason": *reason})
	return c.print("POST", "/v1/runs/"+runID+"/cancel", body)
}

func (c *client) wait(args []string) error {
	if len(args) == 0 {
		return errors.New("run id is required")
	}
	runID := args[0]
	flags := c.newFlagSet("wait")
	interval := flags.Duration("interval", time.Second, "poll interval")
	timeout := flags.Duration("timeout", 30*time.Minute, "maximum wait")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	deadline := time.Now().Add(*timeout)
	for {
		data, status, err := c.do("GET", "/v1/runs/"+runID, nil)
		if err != nil {
			return err
		}
		if status >= 400 {
			return fmt.Errorf("HTTP %d: %s", status, data)
		}
		var run struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(data, &run); err != nil {
			return err
		}
		switch run.Status {
		case "preparing":
			fmt.Fprintln(c.stderr, "input is preparing; upload bytes and explicitly submit the Artifact before waiting")
			return printJSONTo(c.stdout, data)
		case "queued", "validating", "running":
		case "succeeded", "partial", "failed", "cancelled", "waiting_approval":
			return printJSONTo(c.stdout, data)
		default:
			return fmt.Errorf("unsupported run status %q", run.Status)
		}
		if time.Now().After(deadline) {
			return errors.New("wait timeout exceeded")
		}
		time.Sleep(*interval)
	}
}

func (c *client) print(method, path string, body []byte) error {
	data, status, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	if err := printJSONTo(c.stdout, data); err != nil {
		fmt.Fprintln(c.stdout, string(data))
	}
	if status >= 400 {
		return fmt.Errorf("HTTP %d", status)
	}
	return nil
}

func (c *client) do(method, path string, body []byte) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	return c.doReader(method, path, reader, "")
}

func (c *client) doReader(method, path string, reader io.Reader, digest string) ([]byte, int, error) {
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tenant-ID", c.tenantID)
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if digest != "" {
		req.Header.Set("X-Artifact-SHA256", digest)
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return data, resp.StatusCode, err
}

func printJSONTo(w io.Writer, data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(pretty))
	return err
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func (c *client) upload(args []string) error {
	if len(args) == 0 || !store.ValidIdentifier(args[0]) {
		return errors.New("valid run id is required")
	}
	flags := c.newFlagSet("upload")
	path := flags.String("file", "", "raw input file")
	digest := flags.String("sha256", "", "manifest SHA-256")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || *digest == "" || flags.NArg() != 0 {
		return errors.New("usage: upload RUN_ID --file PATH --sha256 DIGEST")
	}
	f, err := os.Open(*path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("input must be a regular file")
	}
	data, status, err := c.doReader("POST", "/v1/runs/"+args[0]+"/artifacts?name="+url.QueryEscape(filepath.Base(*path)), f, *digest)
	if err != nil {
		return err
	}
	if err = printJSONTo(c.stdout, data); err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("HTTP %d", status)
	}
	return nil
}
func (c *client) submit(args []string) error {
	if len(args) == 0 || !store.ValidIdentifier(args[0]) {
		return errors.New("valid run id is required")
	}
	flags := c.newFlagSet("submit")
	artifact := flags.String("artifact-id", "", "uploaded Artifact ID")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if !store.ValidIdentifier(*artifact) || flags.NArg() != 0 {
		return errors.New("usage: submit RUN_ID --artifact-id ID")
	}
	body, _ := json.Marshal(map[string]string{"artifact_id": *artifact})
	return c.print("POST", "/v1/runs/"+args[0]+"/submit", body)
}
