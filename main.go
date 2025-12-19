package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "approve":
			handleApproveCLI()
			return
		case "deny":
			handleDenyCLI()
			return
		}
	}
	startServer()
}

func startServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/execution/request", handleExecutionRequest)

	addr := ":8080"
	fmt.Printf("Gate listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
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

	return policyDecision{
		allowed:         false,
		requireApproval: true,
		reason:          "no matching policy rule",
	}
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
		return fmt.Errorf("requested command %q not in allowlist", rec.Request.Command)
	}

	output, execErr := executeCommand(cmdDef)
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
		persistErr := persistOutput(rec.ID, output)
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

func persistOutput(id int, data []byte) error {
	if err := os.MkdirAll(outputsDir, 0755); err != nil {
		return err
	}
	filename := fmt.Sprintf("request-%d.txt", id)
	fullPath := filepath.Join(outputsDir, filename)
	tmp := fullPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, fullPath)
}
