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
	"os"
	"strings"
	"time"

	"github.com/Notyet1307/security-agent-suite/internal/doctor"
)

type client struct {
	baseURL  string
	apiKey   string
	tenantID string
	http     *http.Client
}

func main() {
	global := flag.NewFlagSet("sasctl", flag.ExitOnError)
	baseURL := global.String("base-url", env("SAS_BASE_URL", "http://127.0.0.1:8080"), "Security Agent Suite API base URL")
	apiKey := global.String("api-key", os.Getenv("SAS_API_KEY"), "API key")
	tenantID := global.String("tenant", env("SAS_TENANT_ID", "default"), "tenant id")
	global.Usage = usage
	_ = global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	c := &client{baseURL: strings.TrimRight(*baseURL, "/"), apiKey: *apiKey, tenantID: *tenantID, http: &http.Client{Timeout: 90 * time.Second}}

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
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  sasctl [global flags] doctor
  sasctl [global flags] agents
  sasctl [global flags] list [--agent ID] [--status STATUS] [--limit N]
  sasctl [global flags] run --agent ID --file request.json
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
	report := doctor.Run(context.Background(), doctor.FromEnvironment(c.baseURL, c.apiKey, c.tenantID))
	if err := report.WriteJSON(os.Stdout); err != nil {
		return err
	}
	if report.RequiredFailures() {
		return errors.New("doctor found required check failures")
	}
	return nil
}

func (c *client) createRun(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
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

func (c *client) listRuns(args []string) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
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
	flags := flag.NewFlagSet("approve", flag.ContinueOnError)
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
	flags := flag.NewFlagSet("cancel", flag.ContinueOnError)
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
	flags := flag.NewFlagSet("wait", flag.ContinueOnError)
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
		case "succeeded", "partial", "failed", "cancelled", "waiting_approval":
			return printJSON(data)
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
	if err := printJSON(data); err != nil {
		fmt.Println(string(data))
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
	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Tenant-ID", c.tenantID)
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if body != nil {
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

func printJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(pretty))
	return nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
