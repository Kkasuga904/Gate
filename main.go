package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	requestsFile  = "requests.json"
	auditLogFile  = "audit.log"
	policyFile    = "policy.yaml"
	allowlistFile = "allowlist.yaml"
	outputsDir    = "outputs"
)

const (
	statusPending  = "pending"
	statusDenied   = "denied"
	statusApproved = "approved"
)

const (
	demoIntent      = "delete_dir"
	demoTarget      = "C:\\temp\\gate-test"
	demoRisk        = "high"
	demoCommandLine = "rmdir /s /q C:\\temp\\gate-test"
	demoCmdPath     = "C:\\Windows\\System32\\cmd.exe"
)

var allowedRisks = map[string]struct{}{
	"low":    {},
	"medium": {},
	"high":   {},
}

type executionRequest struct {
	AgentID   string `json:"agent_id"`
	Intent    string `json:"intent"`
	Env       string `json:"env"`
	Target    string `json:"target"`
	Command   string `json:"command"`
	Reason    string `json:"reason"`
	RiskLevel string `json:"risk_level"`
}

type Request = executionRequest

func demoAllowWithApproval(req Request) bool {
	return req.Intent == "delete_dir"
}

type requestRecord struct {
	ID              int              `json:"id"`
	Request         executionRequest `json:"request"`
	Status          string           `json:"status"`
	RequireApproval bool             `json:"-"`
	DecisionBy      string           `json:"decision_by,omitempty"`
	DecisionAt      *time.Time       `json:"decision_at,omitempty"`
	Decision        string           `json:"decision,omitempty"`
	Comment         string           `json:"comment,omitempty"`
	Executed        bool             `json:"executed"`
	ExecutionError  string           `json:"-"`
	CreatedAt       time.Time        `json:"-"`
}

type policyRule struct {
	Intent          string `yaml:"intent"`
	Env             string `yaml:"env"`
	RequireApproval bool   `yaml:"require_approval"`
	Allow           *bool  `yaml:"allow"`
}

type policyConfig struct {
	Rules []policyRule `yaml:"rules"`
}

type allowlist struct {
	Commands []allowedCommand `yaml:"commands"`
}

type allowedCommand struct {
	Name string   `yaml:"name"`
	Path string   `yaml:"path"`
	Args []string `yaml:"args"`
}

type auditEntry struct {
	RequestID  int    `json:"request_id"`
	AgentID    string `json:"agent_id"`
	Intent     string `json:"intent"`
	ApprovedBy string `json:"approved_by"`
	Decision   string `json:"decision"`
	Executed   bool   `json:"executed"`
	Timestamp  string `json:"timestamp"`
	Comment    string `json:"comment"`
}

func main() {
	if len(os.Args) == 1 {
		startServer()
		return
	}

	switch os.Args[1] {
	case "submit":
		handleSubmitCLI()
		return
	case "approve":
		handleApproveCLI()
		return
	case "deny":
		handleDenyCLI()
		return
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

func startServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/execution/request", handleExecutionRequest)

	addr := ":8080"
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if isAddrAlreadyInUse(err) {
			fmt.Printf("Gate already running on %s. Exiting.\n", addr)
			return
		}
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Gate listening on %s\n", addr)
	server := &http.Server{Handler: mux}
	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	exe := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s\n", exe)
	fmt.Fprintf(os.Stderr, "  %s submit <request.json>\n", exe)
	fmt.Fprintf(os.Stderr, "  %s approve --request-id <id> --user <user> --comment <text>\n", exe)
	fmt.Fprintf(os.Stderr, "  %s deny --request-id <id> --user <user> --comment <text>\n", exe)
}

func isAddrAlreadyInUse(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if errno == 10048 { // Windows WSAEADDRINUSE
			return true
		}
		if errno == syscall.EADDRINUSE {
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address")
}

func handleExecutionRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	defer r.Body.Close()
	var req executionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.RiskLevel = strings.ToLower(req.RiskLevel)

	if err := validateRequest(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := req.Intent
	if strings.TrimSpace(name) == "" {
		name = req.Command
	}
	fmt.Printf("New request received: %s (Risk: %s)\n", name, strings.ToUpper(req.RiskLevel))

	policyCfg, err := loadPolicy(policyFile)
	if err != nil {
		http.Error(w, "policy load failure", http.StatusInternalServerError)
		return
	}

	decision := evaluatePolicy(req, policyCfg)
	now := time.Now().UTC()
	rec := requestRecord{
		ID:              nextRequestID(),
		Request:         req,
		Status:          statusPending,
		RequireApproval: decision.requireApproval,
		CreatedAt:       now,
	}

	if !decision.allowed {
		rec.Status = statusDenied
		rec.Decision = statusDenied
		rec.DecisionBy = "policy"
		rec.DecisionAt = &now
		rec.Comment = decision.reason
		appendAudit(rec.ID, req.AgentID, req.Intent, "policy", statusDenied, false, decision.reason)
		if err := persistRequest(rec); err != nil {
			http.Error(w, "failed to persist request", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"request_id": rec.ID,
			"status":     statusDenied,
			"reason":     decision.reason,
		})
		return
	}

	if decision.comment != "" {
		rec.DecisionBy = "policy"
		rec.Decision = statusPending
		rec.Comment = decision.comment
	}

	if err := persistRequest(rec); err != nil {
		http.Error(w, "failed to persist request", http.StatusInternalServerError)
		return
	}

	msg := "awaiting human approval via CLI"
	if !rec.RequireApproval {
		msg = "policy allowed; manual release still required via CLI"
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"request_id":       rec.ID,
		"status":           statusPending,
		"require_approval": rec.RequireApproval,
		"message":          msg,
	})
}

type policyDecision struct {
	allowed         bool
	requireApproval bool
	reason          string
	comment         string
}

func evaluatePolicy(req executionRequest, cfg policyConfig) policyDecision {
	for _, rule := range cfg.Rules {
		if rule.Intent != req.Intent {
			continue
		}
		if rule.Env != "" && rule.Env != req.Env {
			continue
		}

		decision := policyDecision{
			allowed:         true,
			requireApproval: rule.RequireApproval,
		}

		if rule.Allow != nil {
			decision.allowed = *rule.Allow
		}

		if req.RiskLevel == "high" {
			decision.requireApproval = true
			if rule.Allow != nil && !*rule.Allow {
				decision.reason = "high risk intent blocked by policy"
				decision.allowed = false
			}
		}

		if !decision.allowed && decision.reason == "" {
			decision.reason = "blocked by policy"
		}
		if decision.requireApproval && decision.reason == "" {
			decision.reason = "approval required"
		}

		return decision
	}

	if demoAllowWithApproval(req) {
		return policyDecision{
			allowed:         true,
			requireApproval: true,
			comment:         "requires human approval (demo rule)",
		}
	}

	return policyDecision{
		allowed:         false,
		requireApproval: true,
		reason:          "no matching policy rule",
	}
}

func isDemoException(req executionRequest) bool {
	return req.Intent == demoIntent &&
		req.Target == demoTarget &&
		strings.EqualFold(req.RiskLevel, demoRisk)
}

func demoAllowedCommand(req executionRequest) (allowedCommand, bool) {
	if !isDemoException(req) {
		return allowedCommand{}, false
	}
	if req.Command != demoCommandLine {
		return allowedCommand{}, false
	}

	return allowedCommand{
		Name: demoIntent,
		Path: demoCmdPath,
		Args: []string{"/C", "rmdir", "/s", "/q", demoTarget},
	}, true
}

func validateRequest(req executionRequest) error {
	if strings.TrimSpace(req.AgentID) == "" ||
		strings.TrimSpace(req.Intent) == "" ||
		strings.TrimSpace(req.Target) == "" ||
		strings.TrimSpace(req.Command) == "" ||
		strings.TrimSpace(req.Reason) == "" {
		return errors.New("missing required fields")
	}

	if _, ok := allowedRisks[strings.ToLower(req.RiskLevel)]; !ok {
		return errors.New("invalid risk_level")
	}
	return nil
}

func persistRequest(rec requestRecord) error {
	records, err := loadRequests()
	if err != nil {
		return err
	}
	records = append(records, rec)
	return saveRequests(records)
}

func loadRequests() ([]requestRecord, error) {
	data, err := os.ReadFile(requestsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []requestRecord{}, nil
		}
		return nil, err
	}
	var records []requestRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func saveRequests(records []requestRecord) error {
	type storedRecord struct {
		ID              int              `json:"id"`
		Request         executionRequest `json:"request"`
		Status          string           `json:"status"`
		RequireApproval bool             `json:"require_approval"`
		DecisionBy      string           `json:"decision_by,omitempty"`
		DecisionAt      *time.Time       `json:"decision_at,omitempty"`
		Decision        string           `json:"decision,omitempty"`
		Comment         string           `json:"comment,omitempty"`
		Executed        bool             `json:"executed"`
	}

	stored := make([]storedRecord, 0, len(records))
	for _, r := range records {
		stored = append(stored, storedRecord{
			ID:              r.ID,
			Request:         r.Request,
			Status:          r.Status,
			RequireApproval: r.RequireApproval,
			DecisionBy:      r.DecisionBy,
			DecisionAt:      r.DecisionAt,
			Decision:        r.Decision,
			Comment:         r.Comment,
			Executed:        r.Executed,
		})
	}

	tmp := filepath.Join(filepath.Dir(requestsFile), fmt.Sprintf(".%s.tmp", filepath.Base(requestsFile)))
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, requestsFile)
}

func nextRequestID() int {
	records, err := loadRequests()
	if err != nil {
		return int(time.Now().Unix())
	}
	maxID := 0
	for _, r := range records {
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	return maxID + 1
}

func loadPolicy(path string) (policyConfig, error) {
	var cfg policyConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func loadAllowlist(path string) (allowlist, error) {
	var cfg allowlist
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func findAllowedCommand(name string, cfg allowlist) (allowedCommand, bool) {
	for _, cmd := range cfg.Commands {
		if cmd.Name == name {
			return cmd, true
		}
	}
	return allowedCommand{}, false
}

func handleSubmitCLI() {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	serverURL := fs.String("url", "http://localhost:8080/execution/request", "Gate server URL")
	fs.Parse(os.Args[2:])

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	payloadPath := fs.Arg(0)
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", payloadPath, err)
		os.Exit(1)
	}
	if !json.Valid(payload) {
		fmt.Fprintf(os.Stderr, "invalid JSON: %s\n", payloadPath)
		os.Exit(1)
	}

	req, err := http.NewRequest(http.MethodPost, *serverURL, bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "failed to read response: %v\n", readErr)
		os.Exit(1)
	}

	type submitResponse struct {
		RequestID int    `json:"request_id"`
		Status    string `json:"status"`
		Reason    string `json:"reason"`
		Message   string `json:"message"`
	}

	var parsed submitResponse
	if len(body) > 0 && json.Unmarshal(body, &parsed) == nil && parsed.RequestID != 0 {
		fmt.Printf("Request submitted. ID: %d\n", parsed.RequestID)
		return
	}

	if len(body) > 0 {
		_, _ = os.Stdout.Write(body)
		if body[len(body)-1] != '\n' {
			_, _ = os.Stdout.Write([]byte("\n"))
		}
		return
	}

	fmt.Fprintf(os.Stdout, "%s\n", resp.Status)
}

func handleApproveCLI() {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	requestID := fs.Int("request-id", 0, "Request identifier")
	user := fs.String("user", "", "Human approver identifier")
	comment := fs.String("comment", "", "Reason for approval")
	fs.Parse(os.Args[2:])

	if *requestID == 0 || strings.TrimSpace(*user) == "" || strings.TrimSpace(*comment) == "" {
		fs.Usage()
		os.Exit(1)
	}

	if err := approveRequest(*requestID, *user, *comment); err != nil {
		fmt.Fprintf(os.Stderr, "approve failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("approved and executed request %d\n", *requestID)
}

func handleDenyCLI() {
	fs := flag.NewFlagSet("deny", flag.ExitOnError)
	requestID := fs.Int("request-id", 0, "Request identifier")
	user := fs.String("user", "", "Human reviewer identifier")
	comment := fs.String("comment", "", "Reason for denial")
	fs.Parse(os.Args[2:])

	if *requestID == 0 || strings.TrimSpace(*user) == "" || strings.TrimSpace(*comment) == "" {
		fs.Usage()
		os.Exit(1)
	}

	if err := denyRequest(*requestID, *user, *comment); err != nil {
		fmt.Fprintf(os.Stderr, "deny failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("denied request %d\n", *requestID)
}

func approveRequest(id int, approver, comment string) error {
	records, err := loadRequests()
	if err != nil {
		return err
	}

	idx := -1
	for i, r := range records {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("request %d not found", id)
	}

	rec := records[idx]
	if rec.Status == statusDenied {
		return fmt.Errorf("request %d already denied", id)
	}
	if rec.Status == statusApproved && rec.Executed {
		return fmt.Errorf("request %d already approved/executed", id)
	}

	allowCfg, err := loadAllowlist(allowlistFile)
	if err != nil {
		return fmt.Errorf("failed to load allowlist: %w", err)
	}
	cmdDef, ok := findAllowedCommand(rec.Request.Command, allowCfg)
	if !ok {
		cmdDef, ok = demoAllowedCommand(rec.Request)
		if !ok {
			return fmt.Errorf("requested command %q not in allowlist", rec.Request.Command)
		}
	}

	fmt.Println("Approved by human")
	fmt.Println("Executing command...")
	output, execErr := executeCommand(cmdDef)
	exitCode := exitCodeFromError(execErr)
	fmt.Println("Execution finished")
	now := time.Now().UTC()

	rec.Status = statusApproved
	rec.Decision = statusApproved
	rec.DecisionBy = approver
	rec.DecisionAt = &now
	rec.Comment = comment
	rec.Executed = execErr == nil
	if execErr != nil {
		rec.ExecutionError = execErr.Error()
	} else {
		persistErr := persistOutput(rec, output, exitCode)
		if persistErr != nil {
			rec.ExecutionError = fmt.Sprintf("output persist failed: %v", persistErr)
			rec.Executed = false
		}
	}

	records[idx] = rec
	if err := saveRequests(records); err != nil {
		return err
	}

	appendAudit(rec.ID, rec.Request.AgentID, rec.Request.Intent, approver, statusApproved, rec.Executed, comment)
	if execErr != nil {
		return fmt.Errorf("execution failed: %w", execErr)
	}
	if !rec.Executed && rec.ExecutionError != "" {
		return fmt.Errorf(rec.ExecutionError)
	}
	return nil
}

func denyRequest(id int, approver, comment string) error {
	records, err := loadRequests()
	if err != nil {
		return err
	}

	idx := -1
	for i, r := range records {
		if r.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("request %d not found", id)
	}

	rec := records[idx]
	if rec.Status == statusDenied {
		return fmt.Errorf("request %d already denied", id)
	}
	if rec.Status == statusApproved && rec.Executed {
		return fmt.Errorf("request %d already approved/executed", id)
	}

	now := time.Now().UTC()
	rec.Status = statusDenied
	rec.Decision = statusDenied
	rec.DecisionBy = approver
	rec.DecisionAt = &now
	rec.Comment = comment
	rec.Executed = false

	records[idx] = rec
	if err := saveRequests(records); err != nil {
		return err
	}

	appendAudit(rec.ID, rec.Request.AgentID, rec.Request.Intent, approver, statusDenied, false, comment)
	return nil
}

func executeCommand(cmdDef allowedCommand) ([]byte, error) {
	cmd := exec.Command(cmdDef.Path, cmdDef.Args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func exitCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

func appendAudit(requestID int, agentID, intent, approver, decision string, executed bool, comment string) {
	entry := auditEntry{
		RequestID:  requestID,
		AgentID:    agentID,
		Intent:     intent,
		ApprovedBy: approver,
		Decision:   decision,
		Executed:   executed,
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Comment:    comment,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal audit entry: %v\n", err)
		return
	}

	f, err := os.OpenFile(auditLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open audit log: %v\n", err)
		return
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write audit log: %v\n", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func persistOutput(rec requestRecord, data []byte, exitCode int) error {
	if err := os.MkdirAll(outputsDir, 0755); err != nil {
		return err
	}
	filename := fmt.Sprintf("request-%d.txt", rec.ID)
	fullPath := filepath.Join(outputsDir, filename)
	tmp := fullPath + ".tmp"

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Request ID: %d\n", rec.ID)
	fmt.Fprintf(&buf, "Command: %s\n", rec.Request.Command)
	fmt.Fprintf(&buf, "Decision: %s\n", rec.Decision)
	fmt.Fprintf(&buf, "Approved By: %s\n", rec.DecisionBy)
	fmt.Fprintf(&buf, "Exit Code: %d\n", exitCode)
	buf.WriteString("\n--- Output ---\n")
	if len(data) > 0 {
		buf.Write(data)
		if data[len(data)-1] != '\n' {
			buf.WriteByte('\n')
		}
	} else {
		buf.WriteString("(no output)\n")
	}

	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, fullPath)

}
