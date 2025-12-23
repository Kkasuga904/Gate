package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bmatcuk/doublestar/v4"
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
	policyActionDeny            = "deny"
	policyActionRequireApproval = "require_approval"
	policyActionAllow           = "allow"
)

const (
	policyDecisionDenied   = "policy_denied"
	policyDecisionApproved = "policy_approved"
)

const (
	reasonDenyCommand       = "DENY_COMMAND"
	reasonDenyCapability    = "DENY_CAPABILITY"
	reasonDenyOperation     = "DENY_OPERATION"
	reasonDenyPath          = "DENY_PATH"
	reasonRequireCommand    = "REQAPPROVAL_COMMAND"
	reasonRequireCapability = "REQAPPROVAL_CAPABILITY"
	reasonRequireOperation  = "REQAPPROVAL_OPERATION"
	reasonAllowPath         = "ALLOW_PATH"
	reasonDefaultDeny       = "DEFAULT_DENY"
	reasonDefaultRequire    = "DEFAULT_REQUIRE_APPROVAL"
	reasonDefaultAllow      = "DEFAULT_ALLOW"
)

var allowedRisks = map[string]struct{}{
	"low":    {},
	"medium": {},
	"high":   {},
}

var riskRank = map[string]int{
	"low":    1,
	"medium": 2,
	"high":   3,
}

// statusOutput routes human-facing status lines; MCP mode overrides it to stderr.
var statusOutput io.Writer = os.Stdout

var globalDenySubstrings = []string{
	"rm -rf",
	"mkfs",
	"dd if=",
	"| bash",
	"| sh",
	"invoke-expression",
	"iex ",
	"kubectl delete",
	"helm uninstall",
}

type capabilityPolicy struct {
	AllowedBins     []string
	AllowedSub      map[string]bool
	DenyArgs        []string
	RequireKeys     []string
	MinRiskByTarget map[string]string
}

var capabilityPolicies = map[string]capabilityPolicy{
	"terraform_plan": {
		AllowedBins: []string{"terraform"},
		AllowedSub: map[string]bool{
			"plan": true,
		},
		DenyArgs:        []string{"-destroy", "-auto-approve"},
		RequireKeys:     []string{"WORKDIR"},
		MinRiskByTarget: map[string]string{"prod": "high"},
	},
	"kubectl_diff": {
		AllowedBins: []string{"kubectl"},
		AllowedSub: map[string]bool{
			"diff": true,
		},
		RequireKeys:     []string{"KUBECONTEXT"},
		MinRiskByTarget: map[string]string{"prod": "high"},
	},
}

type executionRequest struct {
	AgentID    string            `json:"agent_id"`
	Intent     string            `json:"intent"`
	Env        string            `json:"env"`
	Target     string            `json:"target"`
	Command    string            `json:"command,omitempty"`
	Reason     string            `json:"reason"`
	RiskLevel  string            `json:"risk_level"`
	Resources  []string          `json:"resources,omitempty"`
	Operation  string            `json:"operation,omitempty"`
	Capability string            `json:"capability,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
}

type requestRecord struct {
	ID                 int              `json:"id"`
	Request            executionRequest `json:"request"`
	Status             string           `json:"status"`
	RequireApproval    bool             `json:"require_approval"`
	PolicyAction       string           `json:"policy_action,omitempty"`
	PolicyReasonCode   string           `json:"policy_reason_code,omitempty"`
	PolicyReasonDetail string           `json:"policy_reason_detail,omitempty"`
	DecisionBy         string           `json:"decision_by,omitempty"`
	DecisionAt         *time.Time       `json:"decision_at,omitempty"`
	Decision           string           `json:"decision,omitempty"`
	Comment            string           `json:"comment,omitempty"`
	LastReviewBy       string           `json:"last_review_by,omitempty"`
	LastReviewAt       *time.Time       `json:"last_review_at,omitempty"`
	LastReviewDecision string           `json:"last_review_decision,omitempty"`
	LastReviewComment  string           `json:"last_review_comment,omitempty"`
	ResolvedCommand    resolvedCommand  `json:"resolved_command,omitempty"`
	Executed           bool             `json:"executed"`
	Execution          *executionResult `json:"execution,omitempty"`
	ExecutionError     string           `json:"-"`
	CreatedAt          time.Time        `json:"created_at,omitempty"`
	UpdatedAt          time.Time        `json:"updated_at,omitempty"`
}

type policyConfig struct {
	Version                     string            `yaml:"version"`
	DefaultAction               string            `yaml:"default_action"`
	AllowPaths                  []string          `yaml:"allow_paths"`
	DenyPaths                   []string          `yaml:"deny_paths"`
	DenyCommands                []string          `yaml:"deny_commands"`
	RequireApprovalCommands     []string          `yaml:"require_approval_commands"`
	DenyCapabilities            []string          `yaml:"deny_capabilities,omitempty"`
	RequireApprovalCapabilities []string          `yaml:"require_approval_capabilities,omitempty"`
	DenyOperations              []string          `yaml:"deny_operations"`
	RequireApprovalOperations   []string          `yaml:"require_approval_operations"`
	ApproverAllowlist           []string          `yaml:"approver_allowlist"`
	AutoApprove                 autoApproveConfig `yaml:"auto_approve,omitempty"`
}

type allowlist struct {
	Commands []allowedCommand `yaml:"commands"`
}

type allowedCommand struct {
	Name string             `yaml:"name"`
	Path string             `yaml:"path"`
	Args []string           `yaml:"args"`
	Vars map[string]varRule `yaml:"vars,omitempty"`
}

type autoApproveConfig struct {
	Enabled         bool    `yaml:"enabled"`
	MinSimilarCases int     `yaml:"min_similar_cases"`
	MinSuccessRate  float64 `yaml:"min_success_rate"`
	MaxAnomalyScore float64 `yaml:"max_anomaly_score"`
}

type resolvedCommand struct {
	Path string   `json:"path,omitempty"`
	Args []string `json:"args,omitempty"`
}

type executionResult struct {
	ExitCode int    `json:"exit_code"`
	Status   string `json:"status"`
}

type varRule struct {
	Pattern string `yaml:"pattern"`
}

type requestParamError struct {
	Param   string
	Reason  string
	Pattern string
}

type policyValidationError struct {
	Message string
}

func (e policyValidationError) Error() string {
	return e.Message
}

type requestContextError struct {
	RequestID  int
	Capability string
	Err        error
}

func (e requestContextError) Error() string {
	capability := e.Capability
	if strings.TrimSpace(capability) == "" {
		capability = "unknown"
	}
	return fmt.Sprintf("%s [request_id=%d capability=%s]", e.Err.Error(), e.RequestID, capability)
}

func (e requestContextError) Unwrap() error {
	return e.Err
}

func (e requestParamError) Error() string {
	switch e.Reason {
	case "missing":
		return fmt.Sprintf("missing request param %s (required by allowlist)", e.Param)
	case "policy_missing":
		return fmt.Sprintf("missing request param %s (required by policy)", e.Param)
	case "not_allowed":
		return fmt.Sprintf("request param %s not allowed by allowlist", e.Param)
	case "pattern":
		if e.Pattern != "" {
			return fmt.Sprintf("request param %s does not match allowlist pattern %q", e.Param, e.Pattern)
		}
		return fmt.Sprintf("request param %s does not match allowlist pattern", e.Param)
	default:
		return fmt.Sprintf("invalid request param %s", e.Param)
	}
}

type auditEntry struct {
	RequestID          int    `json:"request_id"`
	AgentID            string `json:"agent_id"`
	Intent             string `json:"intent"`
	ApprovedBy         string `json:"approved_by"`
	Decision           string `json:"decision"`
	Executed           bool   `json:"executed"`
	Timestamp          string `json:"timestamp"`
	Comment            string `json:"comment"`
	PolicyAction       string `json:"policy_action,omitempty"`
	PolicyReasonCode   string `json:"policy_reason_code,omitempty"`
	PolicyReasonDetail string `json:"policy_reason_detail,omitempty"`
}

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
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
	case "mcp":
		startMCPServer()
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

func startMCPServer() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("")
	statusOutput = os.Stderr
	log.Println("Gate MCP server listening on stdio")
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)

	for {
		payload, err := readRPCMessage(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			fmt.Fprintf(os.Stderr, "mcp read error: %v\n", err)
			return
		}
		resp := handleMCPPayload(payload)
		if resp != nil {
			_ = writeRPCResponse(writer, *resp)
		}
	}
}

func handleMCPPayload(payload []byte) *jsonrpcResponse {
	req, err := decodeJSONRPCRequest(payload)
	if err != nil {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			Error: &jsonrpcError{
				Code:    -32600,
				Message: "invalid request",
			},
		}
	}
	if strings.TrimSpace(req.JSONRPC) == "" || strings.TrimSpace(req.Method) == "" {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonrpcError{
				Code:    -32600,
				Message: "invalid request",
			},
		}
	}
	if len(req.ID) == 0 {
		_ = handleMCPRequest(req)
		return nil
	}
	return handleMCPRequest(req)
}

func decodeJSONRPCRequest(payload []byte) (jsonrpcRequest, error) {
	trimmed := bytes.TrimPrefix(payload, []byte{0xEF, 0xBB, 0xBF})
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var req jsonrpcRequest
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}
	return req, nil
}

func readRPCMessage(reader *bufio.Reader) ([]byte, error) {
	var contentLength int
	seenNonBlankHeaderLine := false
	seenContentLength := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			if !seenNonBlankHeaderLine {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("missing Content-Length")
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			if !seenNonBlankHeaderLine {
				if errors.Is(err, io.EOF) {
					return nil, io.EOF
				}
				continue
			}
			break
		}
		seenNonBlankHeaderLine = true
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
			length, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid Content-Length")
			}
			contentLength = length
			seenContentLength = true
		}
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("missing Content-Length")
		}
	}

	if !seenContentLength || contentLength <= 0 {
		return nil, fmt.Errorf("missing Content-Length")
	}

	payload := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return payload, nil
}

func writeRPCResponse(writer *bufio.Writer, resp jsonrpcResponse) error {
	if resp.JSONRPC == "" {
		resp.JSONRPC = "2.0"
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(data))
	if _, err := writer.WriteString(header); err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Flush()
}

func handleMCPRequest(req jsonrpcRequest) *jsonrpcResponse {
	switch req.Method {
	case "initialize":
		result := map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "Gate",
				"version": "0.1",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "gate.execute_request":
		var args mcpExecuteRequestArgs
		if err := json.Unmarshal(req.Params, &args); err != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "invalid execute_request params"}}
		}
		if strings.TrimSpace(args.Command) != "" {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "command field is not supported; use capability"}}
		}
		result, err := submitExecutionRequest(executionRequest{
			AgentID:    args.AgentID,
			Intent:     args.Intent,
			Target:     args.Target,
			Reason:     args.Reason,
			RiskLevel:  args.RiskLevel,
			Capability: args.Capability,
			Params:     args.Params,
		})
		if err != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32603, Message: err.Error()}}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "gate.approve":
		args, rpcErr := parseReviewArgs(req.Params)
		if rpcErr != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		if err := approveRequest(args.RequestID, args.User, args.Comment); err != nil {
			code := -32603
			var paramErr requestParamError
			var policyErr policyValidationError
			if errors.As(err, &paramErr) || errors.As(err, &policyErr) {
				code = -32602
			}
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: code, Message: err.Error()}}
		}
		result := map[string]interface{}{
			"request_id": args.RequestID,
			"status":     statusApproved,
		}
		if rec, err := findRequestRecord(args.RequestID); err == nil {
			result["executed"] = rec.Executed
			if rec.ExecutionError != "" {
				result["execution_error"] = rec.ExecutionError
			}
			if rec.Executed {
				result["output_file"] = outputFilePath(rec.ID)
			}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "gate.deny":
		args, rpcErr := parseReviewArgs(req.Params)
		if rpcErr != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		if err := denyRequest(args.RequestID, args.User, args.Comment); err != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32603, Message: err.Error()}}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"request_id": args.RequestID,
			"status":     statusDenied,
		}}
	case "gate.get_request":
		requestID, rpcErr := parseRequestIDArgs(req.Params)
		if rpcErr != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		result, err := getRequestResult(requestID)
		if err != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32603, Message: err.Error()}}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "gate.list_requests":
		args, rpcErr := parseListRequestsArgs(req.Params)
		if rpcErr != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		result, err := listRequestsResult(args.Status, args.Limit)
		if err != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: err.Error()}}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "gate.review_request":
		requestID, rpcErr := parseRequestIDArgs(req.Params)
		if rpcErr != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		result, err := reviewRequestResult(requestID)
		if err != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32603, Message: err.Error()}}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	case "gate.list_capabilities":
		caps, err := listCapabilities()
		if err != nil {
			return &jsonrpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &jsonrpcError{
					Code:    -32603,
					Message: err.Error(),
				},
			}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"capabilities": caps,
		}}
	case "tools/list":
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{
			"tools": mcpToolDefinitions(),
		}}
	case "tools/call":
		result, rpcErr := handleMCPToolCall(req.Params)
		if rpcErr != nil {
			return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Error: rpcErr}
		}
		return &jsonrpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	default:
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &jsonrpcError{
				Code:    -32601,
				Message: "method not found",
			},
		}
	}
}

func mcpToolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "gate.execute_request",
			"description": "Submit an execution request to Gate.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"agent_id": map[string]interface{}{
						"type": "string",
					},
					"intent": map[string]interface{}{
						"type": "string",
					},
					"target": map[string]interface{}{
						"type": "string",
					},
					"reason": map[string]interface{}{
						"type": "string",
					},
					"risk_level": map[string]interface{}{
						"type": "string",
						"enum": []string{"low", "medium", "high"},
					},
					"capability": map[string]interface{}{
						"type": "string",
					},
					"params": map[string]interface{}{
						"type":                 "object",
						"additionalProperties": map[string]interface{}{"type": "string"},
					},
				},
				"required": []string{"agent_id", "intent", "target", "capability", "params", "reason", "risk_level"},
			},
		},
		{
			"name":        "gate.approve",
			"description": "Approve and execute a pending request.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"request_id": map[string]interface{}{
						"type": "integer",
					},
					"user": map[string]interface{}{
						"type": "string",
					},
					"comment": map[string]interface{}{
						"type": "string",
					},
				},
				"required": []string{"request_id", "user", "comment"},
			},
		},
		{
			"name":        "gate.deny",
			"description": "Deny a pending request.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"request_id": map[string]interface{}{
						"type": "integer",
					},
					"user": map[string]interface{}{
						"type": "string",
					},
					"comment": map[string]interface{}{
						"type": "string",
					},
				},
				"required": []string{"request_id", "user", "comment"},
			},
		},
		{
			"name":        "gate.get_request",
			"description": "Fetch a request by id.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"request_id": map[string]interface{}{
						"type": "integer",
					},
				},
				"required": []string{"request_id"},
			},
		},
		{
			"name":        "gate.list_requests",
			"description": "List requests by status.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"status": map[string]interface{}{
						"type": "string",
						"enum": []string{"pending", "approved", "denied", "executed", ""},
					},
					"limit": map[string]interface{}{
						"type": "integer",
					},
				},
			},
		},
		{
			"name":        "gate.review_request",
			"description": "Return a deterministic human-facing review payload.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"request_id": map[string]interface{}{
						"type": "integer",
					},
				},
				"required": []string{"request_id"},
			},
		},
		{
			"name":        "gate.list_capabilities",
			"description": "List allowlisted capabilities.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type mcpExecuteRequestArgs struct {
	AgentID    string            `json:"agent_id"`
	Intent     string            `json:"intent"`
	Target     string            `json:"target"`
	Command    string            `json:"command,omitempty"`
	Reason     string            `json:"reason"`
	RiskLevel  string            `json:"risk_level"`
	Capability string            `json:"capability,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
}

type mcpReviewArgs struct {
	RequestID int    `json:"request_id"`
	User      string `json:"user"`
	Comment   string `json:"comment"`
}

type mcpGetRequestArgs struct {
	RequestID int `json:"request_id"`
}

type mcpReviewRequestArgs struct {
	RequestID int `json:"request_id"`
}

type mcpListRequestsArgs struct {
	Status string `json:"status,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

func parseReviewArgs(raw json.RawMessage) (mcpReviewArgs, *jsonrpcError) {
	var args mcpReviewArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return args, &jsonrpcError{Code: -32602, Message: "invalid params"}
	}

	if strings.TrimSpace(args.Comment) == "" {
		var rawMap map[string]interface{}
		if err := json.Unmarshal(raw, &rawMap); err == nil {
			if val := readStringParam(rawMap, "TEXT"); val != "" {
				args.Comment = val
			} else if val := readStringParam(rawMap, "text"); val != "" {
				args.Comment = val
			}
		}
	}

	if args.RequestID == 0 {
		return args, &jsonrpcError{Code: -32602, Message: "missing param request_id"}
	}
	if strings.TrimSpace(args.User) == "" {
		return args, &jsonrpcError{Code: -32602, Message: "missing param user"}
	}
	if strings.TrimSpace(args.Comment) == "" {
		return args, &jsonrpcError{Code: -32602, Message: "missing param comment"}
	}
	return args, nil
}

func parseRequestIDArgs(raw json.RawMessage) (int, *jsonrpcError) {
	var args mcpGetRequestArgs
	if len(raw) == 0 {
		return 0, &jsonrpcError{Code: -32602, Message: "missing param request_id"}
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return 0, &jsonrpcError{Code: -32602, Message: "invalid params"}
	}
	if args.RequestID == 0 {
		return 0, &jsonrpcError{Code: -32602, Message: "missing param request_id"}
	}
	return args.RequestID, nil
}

func parseListRequestsArgs(raw json.RawMessage) (mcpListRequestsArgs, *jsonrpcError) {
	if len(raw) == 0 {
		return mcpListRequestsArgs{}, nil
	}
	var args mcpListRequestsArgs
	if err := json.Unmarshal(raw, &args); err != nil {
		return mcpListRequestsArgs{}, &jsonrpcError{Code: -32602, Message: "invalid params"}
	}
	return args, nil
}

func readStringParam(raw map[string]interface{}, key string) string {
	if raw == nil {
		return ""
	}
	val, ok := raw[key]
	if !ok {
		return ""
	}
	str, ok := val.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

func annotateRequestError(rec requestRecord, err error) error {
	var paramErr requestParamError
	if errors.As(err, &paramErr) {
		return requestContextError{
			RequestID:  rec.ID,
			Capability: rec.Request.Capability,
			Err:        paramErr,
		}
	}
	var policyErr policyValidationError
	if errors.As(err, &policyErr) {
		return requestContextError{
			RequestID:  rec.ID,
			Capability: rec.Request.Capability,
			Err:        policyErr,
		}
	}
	return err
}

func handleMCPToolCall(raw json.RawMessage) (interface{}, *jsonrpcError) {
	var call mcpToolCallParams
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, &jsonrpcError{Code: -32602, Message: "invalid params"}
	}

	switch call.Name {
	case "gate.execute_request":
		var args mcpExecuteRequestArgs
		if err := json.Unmarshal(call.Arguments, &args); err != nil {
			return nil, &jsonrpcError{Code: -32602, Message: "invalid execute_request args"}
		}
		if strings.TrimSpace(args.Command) != "" {
			return nil, &jsonrpcError{Code: -32602, Message: "command field is not supported; use capability"}
		}
		req := executionRequest{
			AgentID:    args.AgentID,
			Intent:     args.Intent,
			Target:     args.Target,
			Reason:     args.Reason,
			RiskLevel:  args.RiskLevel,
			Capability: args.Capability,
			Params:     args.Params,
		}
		result, err := submitExecutionRequest(req)
		if err != nil {
			return nil, &jsonrpcError{Code: -32602, Message: err.Error()}
		}
		return result, nil
	case "gate.approve":
		args, rpcErr := parseReviewArgs(call.Arguments)
		if rpcErr != nil {
			return nil, rpcErr
		}
		if err := approveRequest(args.RequestID, args.User, args.Comment); err != nil {
			code := -32603
			var paramErr requestParamError
			var policyErr policyValidationError
			if errors.As(err, &paramErr) || errors.As(err, &policyErr) {
				code = -32602
			}
			return nil, &jsonrpcError{Code: code, Message: err.Error()}
		}
		result := map[string]interface{}{
			"request_id": args.RequestID,
			"status":     statusApproved,
		}
		if rec, err := findRequestRecord(args.RequestID); err == nil {
			result["executed"] = rec.Executed
			if rec.ExecutionError != "" {
				result["execution_error"] = rec.ExecutionError
			}
			if rec.Executed {
				result["output_file"] = outputFilePath(rec.ID)
			}
		}
		return result, nil
	case "gate.deny":
		args, rpcErr := parseReviewArgs(call.Arguments)
		if rpcErr != nil {
			return nil, rpcErr
		}
		if err := denyRequest(args.RequestID, args.User, args.Comment); err != nil {
			return nil, &jsonrpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]interface{}{
			"request_id": args.RequestID,
			"status":     statusDenied,
		}, nil
	case "gate.get_request":
		requestID, rpcErr := parseRequestIDArgs(call.Arguments)
		if rpcErr != nil {
			return nil, rpcErr
		}
		result, err := getRequestResult(requestID)
		if err != nil {
			return nil, &jsonrpcError{Code: -32603, Message: err.Error()}
		}
		return result, nil
	case "gate.list_requests":
		args, rpcErr := parseListRequestsArgs(call.Arguments)
		if rpcErr != nil {
			return nil, rpcErr
		}
		result, err := listRequestsResult(args.Status, args.Limit)
		if err != nil {
			return nil, &jsonrpcError{Code: -32602, Message: err.Error()}
		}
		return result, nil
	case "gate.review_request":
		requestID, rpcErr := parseRequestIDArgs(call.Arguments)
		if rpcErr != nil {
			return nil, rpcErr
		}
		result, err := reviewRequestResult(requestID)
		if err != nil {
			return nil, &jsonrpcError{Code: -32603, Message: err.Error()}
		}
		return result, nil
	case "gate.list_capabilities":
		caps, err := listCapabilities()
		if err != nil {
			return nil, &jsonrpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]interface{}{
			"capabilities": caps,
		}, nil
	default:
		return nil, &jsonrpcError{Code: -32601, Message: "tool not found"}
	}
}

func submitExecutionRequest(req executionRequest) (map[string]interface{}, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/execution/request", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handleExecutionRequest(rec, httpReq)
	resp := rec.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var parsed map[string]interface{}
	if len(body) > 0 && json.Unmarshal(body, &parsed) == nil {
		if _, ok := parsed["request_id"]; ok {
			return parsed, nil
		}
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = fmt.Sprintf("request failed with status %d", resp.StatusCode)
	}
	return nil, fmt.Errorf(msg)
}

func findRequestRecord(id int) (requestRecord, error) {
	records, err := loadRequests()
	if err != nil {
		return requestRecord{}, err
	}
	for _, rec := range records {
		if rec.ID == id {
			return rec, nil
		}
	}
	return requestRecord{}, fmt.Errorf("request %d not found", id)
}

func outputFilePath(id int) string {
	return filepath.Join(outputsDir, fmt.Sprintf("request-%d.txt", id))
}

func listCapabilities() ([]string, error) {
	cfg, err := loadAllowlist(allowlistFile)
	if err != nil {
		return nil, err
	}
	caps := make([]string, 0, len(cfg.Commands))
	for _, cmd := range cfg.Commands {
		caps = append(caps, cmd.Name)
	}
	return caps, nil
}

func getRequestResult(id int) (map[string]interface{}, error) {
	rec, err := findRequestRecord(id)
	if err != nil {
		return nil, err
	}
	params := rec.Request.Params
	if params == nil {
		params = map[string]string{}
	}

	result := map[string]interface{}{
		"request_id":    rec.ID,
		"status":        displayStatus(rec),
		"agent_id":      rec.Request.AgentID,
		"intent":        rec.Request.Intent,
		"target":        rec.Request.Target,
		"capability":    rec.Request.Capability,
		"params":        params,
		"risk_level":    rec.Request.RiskLevel,
		"reason":        rec.Request.Reason,
		"policy_result": policyResultPayload(rec),
		"resolved_command": map[string]interface{}{
			"path": rec.ResolvedCommand.Path,
			"args": rec.ResolvedCommand.Args,
		},
		"approved_by":      nil,
		"approved_comment": nil,
		"output_file":      nil,
		"created_at":       formatTimeNullable(rec.CreatedAt),
		"updated_at":       formatTimeNullable(rec.UpdatedAt),
	}

	if rec.DecisionBy != "" && (rec.Status == statusApproved || rec.Decision == policyDecisionApproved) {
		result["approved_by"] = rec.DecisionBy
	}
	if rec.Comment != "" && (rec.Status == statusApproved || rec.Decision == policyDecisionApproved) {
		result["approved_comment"] = rec.Comment
	}
	if rec.Executed {
		result["output_file"] = outputFilePath(rec.ID)
	}
	return result, nil
}

func listRequestsResult(status string, limit int) ([]map[string]interface{}, error) {
	records, err := loadRequests()
	if err != nil {
		return nil, err
	}
	filter := strings.ToLower(strings.TrimSpace(status))
	if filter == "" {
		filter = statusPending
	}
	if limit <= 0 {
		limit = 50
	}

	filtered := make([]requestRecord, 0, len(records))
	for _, rec := range records {
		switch filter {
		case statusPending, statusApproved, statusDenied:
			if rec.Status == filter {
				filtered = append(filtered, rec)
			}
		case "executed":
			if rec.Executed {
				filtered = append(filtered, rec)
			}
		default:
			return nil, fmt.Errorf("invalid status filter %q", filter)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].ID < filtered[j].ID
	})

	if len(filtered) > limit {
		filtered = filtered[:limit]
	}

	summaries := make([]map[string]interface{}, 0, len(filtered))
	for _, rec := range filtered {
		summaries = append(summaries, map[string]interface{}{
			"request_id": rec.ID,
			"status":     displayStatus(rec),
			"capability": rec.Request.Capability,
			"target":     rec.Request.Target,
			"risk_level": rec.Request.RiskLevel,
			"reason":     truncateReason(rec.Request.Reason, 120),
			"created_at": formatTimeNullable(rec.CreatedAt),
		})
	}
	return summaries, nil
}

func reviewRequestResult(id int) (map[string]interface{}, error) {
	rec, err := findRequestRecord(id)
	if err != nil {
		return nil, err
	}
	policyCfg, err := loadPolicy(policyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}
	allowCfg, err := loadAllowlist(allowlistFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load allowlist: %w", err)
	}
	cmdDef, ok := findAllowedCommand(rec.Request.Capability, allowCfg)
	if !ok {
		return nil, fmt.Errorf("requested capability %q not in allowlist", rec.Request.Capability)
	}

	paramValidation := make([]map[string]interface{}, 0)
	if len(cmdDef.Vars) > 0 {
		keys := make([]string, 0, len(cmdDef.Vars))
		for key := range cmdDef.Vars {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			rule := cmdDef.Vars[key]
			value := ""
			if rec.Request.Params != nil {
				value = rec.Request.Params[key]
			}
			paramValidation = append(paramValidation, map[string]interface{}{
				"name":           key,
				"pattern":        rule.Pattern,
				"value_redacted": redactValue(key, value),
			})
		}
	}

	resolvedDisplay := formatCommandDisplay(rec.ResolvedCommand)
	if strings.TrimSpace(resolvedDisplay) == "" {
		resolvedDisplay = "(none)"
	}

	records, err := loadRequests()
	if err != nil {
		return nil, err
	}
	stats, basis := computeStatsForRequest(rec.Request, rec.ResolvedCommand, records, rec.ID)
	explanation := buildStatsExplanation(stats, basis)

	review := map[string]interface{}{
		"request_id":  rec.ID,
		"summary":     fmt.Sprintf("Execute %s on %s", rec.Request.Capability, rec.Request.Target),
		"why_blocked": policyResultPayload(rec),
		"resolved": map[string]interface{}{
			"path":    rec.ResolvedCommand.Path,
			"args":    rec.ResolvedCommand.Args,
			"display": resolvedDisplay,
		},
		"allowlist_match": map[string]interface{}{
			"capability": rec.Request.Capability,
			"path":       cmdDef.Path,
		},
		"param_validation": paramValidation,
		"risks":            []string{riskSummary(rec.Request.RiskLevel)},
		"next_actions":     []string{"approve", "deny"},
		"stats": map[string]interface{}{
			"anomaly_score":            stats.AnomalyScore,
			"historical_success_rate":  stats.HistoricalSuccessRate,
			"similar_cases_count":      stats.SimilarCasesCount,
			"capability_history_count": stats.CapabilityHistoryCount,
			"similar_pending_count":    stats.SimilarPendingCount,
			"similar_denied_count":     stats.SimilarDeniedCount,
			"similar_strict_count":     stats.SimilarStrictCount,
			"strict_success_rate":      stats.StrictSuccessRate,
			"similar_relaxed_count":    stats.SimilarRelaxedCount,
			"relaxed_success_rate":     stats.RelaxedSuccessRate,
		},
		"explanation_basis": explanation,
	}
	if policyCfg.AutoApprove.Enabled && rec.DecisionBy == "auto_approve" {
		review["auto_approved"] = true
		review["auto_approve_reason"] = []string{
			fmt.Sprintf("similar_cases_count >= %d", policyCfg.AutoApprove.MinSimilarCases),
			fmt.Sprintf("historical_success_rate >= %.2f", policyCfg.AutoApprove.MinSuccessRate),
			fmt.Sprintf("anomaly_score <= %.2f", policyCfg.AutoApprove.MaxAnomalyScore),
		}
	}
	return review, nil
}

func policyResultPayload(rec requestRecord) map[string]interface{} {
	return map[string]interface{}{
		"action":        rec.PolicyAction,
		"reason_code":   rec.PolicyReasonCode,
		"reason_detail": rec.PolicyReasonDetail,
	}
}

func riskSummary(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "low":
		return "Low risk request. Verify the target and intent."
	case "medium":
		return "Medium risk request. Confirm scope and impact."
	case "high":
		return "High risk request. Require explicit confirmation."
	default:
		return "Risk level unknown. Validate before approval."
	}
}

type statsSummary struct {
	AnomalyScore           float64
	HistoricalSuccessRate  *float64
	SimilarCasesCount      int
	CapabilityHistoryCount int
	SimilarPendingCount    int
	SimilarDeniedCount     int
	SimilarStrictCount     int
	StrictSuccessRate      *float64
	SimilarRelaxedCount    int
	RelaxedSuccessRate     *float64
}

type statsBasis struct {
	CapabilityCount     int
	StrictSimilarCount  int
	StrictSuccessCount  int
	RelaxedSimilarCount int
	RelaxedSuccessCount int
	Target              string
	SimilarPending      int
	SimilarDenied       int
}

type strictSignature struct {
	Capability string
	Target     string
	Path       string
	Args       []string
}

type relaxedSignature struct {
	Capability string
	Target     string
	Path       string
}

func computeStatsForRequest(req executionRequest, cmd resolvedCommand, records []requestRecord, excludeID int) (statsSummary, statsBasis) {
	strictTarget, ok := buildStrictSignature(req, cmd)
	if !ok {
		return statsSummary{}, statsBasis{}
	}
	relaxedTarget, ok := buildRelaxedSignature(req, cmd)
	if !ok {
		return statsSummary{}, statsBasis{}
	}

	basis := statsBasis{
		Target: relaxedTarget.Target,
	}
	sorted := make([]requestRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	for _, rec := range sorted {
		if rec.ID == excludeID {
			continue
		}
		capability := strings.ToLower(strings.TrimSpace(rec.Request.Capability))
		target := normalizeTarget(rec.Request.Target)
		if capability == relaxedTarget.Capability && target == relaxedTarget.Target {
			basis.CapabilityCount++
		} else {
			continue
		}

		relaxedSig, ok := buildRelaxedSignature(rec.Request, rec.ResolvedCommand)
		if !ok {
			continue
		}
		if relaxedSignaturesEqual(relaxedTarget, relaxedSig) {
			if isFinalizedExecution(rec) {
				basis.RelaxedSimilarCount++
				if requestSucceeded(rec) {
					basis.RelaxedSuccessCount++
				}
			} else if rec.Status == statusDenied || rec.Decision == statusDenied {
				basis.SimilarDenied++
			} else {
				basis.SimilarPending++
			}
		}

		strictSig, ok := buildStrictSignature(rec.Request, rec.ResolvedCommand)
		if !ok {
			continue
		}
		if strictSignaturesEqual(strictTarget, strictSig) {
			if isFinalizedExecution(rec) {
				basis.StrictSimilarCount++
				if requestSucceeded(rec) {
					basis.StrictSuccessCount++
				}
			}
		}
	}

	stats := statsSummary{
		AnomalyScore:           1.0,
		HistoricalSuccessRate:  nil,
		SimilarCasesCount:      basis.RelaxedSimilarCount,
		CapabilityHistoryCount: basis.CapabilityCount,
		SimilarPendingCount:    basis.SimilarPending,
		SimilarDeniedCount:     basis.SimilarDenied,
		SimilarStrictCount:     basis.StrictSimilarCount,
		StrictSuccessRate:      nil,
		SimilarRelaxedCount:    basis.RelaxedSimilarCount,
		RelaxedSuccessRate:     nil,
	}
	if basis.StrictSimilarCount > 0 {
		rate := float64(basis.StrictSuccessCount) / float64(basis.StrictSimilarCount)
		rate = roundScore(rate)
		stats.StrictSuccessRate = &rate
	}
	if basis.RelaxedSimilarCount > 0 {
		rate := float64(basis.RelaxedSuccessCount) / float64(basis.RelaxedSimilarCount)
		rate = roundScore(rate)
		stats.RelaxedSuccessRate = &rate
	}
	stats.HistoricalSuccessRate = stats.RelaxedSuccessRate

	denom := basis.CapabilityCount
	if denom < 1 {
		denom = 1
	}
	stats.AnomalyScore = 1.0 - float64(basis.RelaxedSimilarCount)/float64(denom)
	stats.AnomalyScore = roundScore(stats.AnomalyScore)
	return stats, basis
}

func buildStrictSignature(req executionRequest, cmd resolvedCommand) (strictSignature, bool) {
	capability := strings.ToLower(strings.TrimSpace(req.Capability))
	if capability == "" {
		return strictSignature{}, false
	}
	path := normalizePathForMatch(cmd.Path)
	if path == "" {
		return strictSignature{}, false
	}
	return strictSignature{
		Capability: capability,
		Target:     normalizeTarget(req.Target),
		Path:       path,
		Args:       normalizeArgs(cmd.Args),
	}, true
}

func buildRelaxedSignature(req executionRequest, cmd resolvedCommand) (relaxedSignature, bool) {
	capability := strings.ToLower(strings.TrimSpace(req.Capability))
	if capability == "" {
		return relaxedSignature{}, false
	}
	path := normalizePathForMatch(cmd.Path)
	if path == "" {
		return relaxedSignature{}, false
	}
	return relaxedSignature{
		Capability: capability,
		Target:     normalizeTarget(req.Target),
		Path:       path,
	}, true
}

func strictSignaturesEqual(a, b strictSignature) bool {
	if a.Capability != b.Capability || a.Target != b.Target || a.Path != b.Path {
		return false
	}
	if len(a.Args) != len(b.Args) {
		return false
	}
	for i := range a.Args {
		if a.Args[i] != b.Args[i] {
			return false
		}
	}
	return true
}

func relaxedSignaturesEqual(a, b relaxedSignature) bool {
	return a.Capability == b.Capability && a.Target == b.Target && a.Path == b.Path
}

func normalizeArgs(args []string) []string {
	normalized := make([]string, len(args))
	for i, arg := range args {
		normalized[i] = strings.TrimSpace(arg)
	}
	return normalized
}

func normalizeTarget(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "unknown"
	}
	return normalized
}

func requestSucceeded(rec requestRecord) bool {
	if rec.Status == statusDenied || rec.Decision == statusDenied {
		return false
	}
	if !isFinalizedExecution(rec) {
		return false
	}
	if rec.Execution != nil {
		return rec.Execution.ExitCode == 0
	}
	return false
}

func isFinalizedExecution(rec requestRecord) bool {
	if rec.Status == statusDenied || rec.Decision == statusDenied {
		return false
	}
	if !rec.Executed {
		return false
	}
	if rec.Execution == nil {
		return false
	}
	return true
}

func readExitCode(id int) (int, bool) {
	path := outputFilePath(id)
	file, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Exit Code:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "Exit Code:"))
			code, err := strconv.Atoi(value)
			if err != nil {
				return 0, false
			}
			return code, true
		}
	}
	return 0, false
}

func buildStatsExplanation(stats statsSummary, basis statsBasis) []string {
	denom := basis.CapabilityCount
	if denom < 1 {
		denom = 1
	}
	strictRate := "strict_success_rate=n/a (no similar strict cases)"
	if stats.StrictSuccessRate != nil {
		strictRate = fmt.Sprintf(
			"strict_success_rate=%.2f (%d/%d successful exit code 0)",
			*stats.StrictSuccessRate,
			basis.StrictSuccessCount,
			basis.StrictSimilarCount,
		)
	}
	relaxedRate := "relaxed_success_rate=n/a (no similar relaxed cases)"
	if stats.RelaxedSuccessRate != nil {
		relaxedRate = fmt.Sprintf(
			"relaxed_success_rate=%.2f (%d/%d successful exit code 0)",
			*stats.RelaxedSuccessRate,
			basis.RelaxedSuccessCount,
			basis.RelaxedSimilarCount,
		)
	}
	return []string{
		fmt.Sprintf("capability_history_count=%d (same capability/target, target=%s)", basis.CapabilityCount, basis.Target),
		fmt.Sprintf("similar_strict_count=%d (executed-only capability/path/args/target match, target=%s)", basis.StrictSimilarCount, basis.Target),
		fmt.Sprintf("similar_relaxed_count=%d (executed-only capability/path/target match, target=%s, args_ignored=true)", basis.RelaxedSimilarCount, basis.Target),
		strictRate,
		relaxedRate,
		fmt.Sprintf("similar_pending_count=%d (pending matches excluded)", basis.SimilarPending),
		fmt.Sprintf("similar_denied_count=%d (denied matches excluded)", basis.SimilarDenied),
		fmt.Sprintf("anomaly_score=1 - %d/%d = %.2f", basis.RelaxedSimilarCount, denom, stats.AnomalyScore),
	}
}

func roundScore(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func shouldAutoApprove(stats statsSummary, cfg policyConfig) bool {
	if !cfg.AutoApprove.Enabled {
		return false
	}
	if cfg.AutoApprove.MinSimilarCases <= 0 {
		return false
	}
	if stats.SimilarCasesCount < cfg.AutoApprove.MinSimilarCases {
		return false
	}
	if stats.HistoricalSuccessRate == nil {
		return false
	}
	if *stats.HistoricalSuccessRate < cfg.AutoApprove.MinSuccessRate {
		return false
	}
	if stats.AnomalyScore > cfg.AutoApprove.MaxAnomalyScore {
		return false
	}
	return true
}

func printUsage() {
	exe := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s\n", exe)
	fmt.Fprintf(os.Stderr, "  %s submit <request.json>\n", exe)
	fmt.Fprintf(os.Stderr, "  %s approve --request-id <id> --user <user> --comment <text>\n", exe)
	fmt.Fprintf(os.Stderr, "  %s deny --request-id <id> --user <user> --comment <text>\n", exe)
	fmt.Fprintf(os.Stderr, "  %s mcp\n", exe)
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

	cmdDef, err := resolveAllowedCommand(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resolvedCmd := toResolvedCommand(cmdDef)

	name := req.Intent
	if strings.TrimSpace(name) == "" {
		name = req.Capability
	}
	fmt.Fprintf(statusOutput, "New request received: %s (Risk: %s)\n", name, strings.ToUpper(req.RiskLevel))

	policyCfg, err := loadPolicy(policyFile)
	if err != nil {
		http.Error(w, "policy load failure", http.StatusInternalServerError)
		return
	}

	policyResult := evaluatePolicy(req, resolvedCmd, policyCfg)
	now := time.Now().UTC()
	rec := requestRecord{
		ID:                 nextRequestID(),
		Request:            req,
		Status:             statusPending,
		RequireApproval:    policyResult.Action == policyActionRequireApproval,
		PolicyAction:       policyResult.Action,
		PolicyReasonCode:   policyResult.ReasonCode,
		PolicyReasonDetail: policyResult.ReasonDetail,
		ResolvedCommand:    resolvedCmd,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	switch policyResult.Action {
	case policyActionDeny:
		rec.Status = statusDenied
		rec.Decision = policyDecisionDenied
		rec.DecisionBy = "policy"
		rec.DecisionAt = &now
		rec.Comment = policyResult.ReasonCode
		rec.UpdatedAt = now
		appendAudit(rec.ID, req.AgentID, req.Intent, "policy", policyDecisionDenied, false, policyResult.ReasonCode, rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)
		if err := persistRequest(rec); err != nil {
			http.Error(w, "failed to persist request", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"request_id":    rec.ID,
			"status":        statusDenied,
			"executed":      false,
			"reason":        policyResult.ReasonCode,
			"policy_result": policyResult,
		})
		return
	case policyActionAllow:
		rec.Status = statusApproved
		rec.Decision = policyDecisionApproved
		rec.DecisionBy = "policy"
		rec.DecisionAt = &now
		rec.Comment = policyResult.ReasonCode
		rec.RequireApproval = false
		rec.UpdatedAt = now
		_ = executeForRecord(&rec)

		if err := persistRequest(rec); err != nil {
			http.Error(w, "failed to persist request", http.StatusInternalServerError)
			return
		}
		appendAudit(rec.ID, req.AgentID, req.Intent, "policy", policyDecisionApproved, rec.Executed, policyResult.ReasonCode, rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)

		payload := map[string]interface{}{
			"request_id":       rec.ID,
			"status":           rec.Status,
			"require_approval": false,
			"executed":         rec.Executed,
			"policy_result":    policyResult,
		}
		if rec.ExecutionError != "" {
			payload["execution_error"] = rec.ExecutionError
		}
		writeJSON(w, http.StatusOK, payload)
		return
	case policyActionRequireApproval:
		records, loadErr := loadRequests()
		if loadErr == nil {
			stats, _ := computeStatsForRequest(req, resolvedCmd, records, 0)
			if shouldAutoApprove(stats, policyCfg) {
				rec.Status = statusApproved
				rec.Decision = policyDecisionApproved
				rec.DecisionBy = "auto_approve"
				rec.DecisionAt = &now
				rec.Comment = "auto_approved"
				rec.RequireApproval = false
				rec.UpdatedAt = now

				_ = executeForRecord(&rec)

				if err := persistRequest(rec); err != nil {
					http.Error(w, "failed to persist request", http.StatusInternalServerError)
					return
				}
				appendAudit(rec.ID, req.AgentID, req.Intent, "auto_approve", policyDecisionApproved, rec.Executed, rec.Comment, rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)
				payload := map[string]interface{}{
					"request_id":       rec.ID,
					"status":           rec.Status,
					"require_approval": false,
					"executed":         rec.Executed,
					"policy_result":    policyResult,
				}
				if rec.ExecutionError != "" {
					payload["execution_error"] = rec.ExecutionError
				}
				writeJSON(w, http.StatusOK, payload)
				return
			}
		}
		rec.Status = statusPending
		rec.RequireApproval = true
		rec.UpdatedAt = now
		if err := persistRequest(rec); err != nil {
			http.Error(w, "failed to persist request", http.StatusInternalServerError)
			return
		}
		appendAudit(rec.ID, req.AgentID, req.Intent, "policy", policyActionRequireApproval, false, policyResult.ReasonCode, rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"request_id":       rec.ID,
			"status":           statusPending,
			"require_approval": true,
			"executed":         false,
			"message":          "awaiting human approval via CLI",
			"policy_result":    policyResult,
		})
		return
	default:
		http.Error(w, "policy evaluation failure", http.StatusInternalServerError)
		return
	}
}

type policyResult struct {
	Action       string `json:"action"`
	ReasonCode   string `json:"reason_code"`
	ReasonDetail string `json:"reason_detail"`
}

func evaluatePolicy(req executionRequest, cmd resolvedCommand, cfg policyConfig) policyResult {
	normalizedCmd := normalizeCommand(commandForPolicy(cmd))
	operation := strings.TrimSpace(req.Operation)
	if operation == "" {
		operation = req.Intent
	}
	operation = strings.ToLower(operation)
	capability := strings.TrimSpace(req.Capability)
	resources := resolveResources(req)

	if pattern := matchAnyCapability(capability, cfg.DenyCapabilities); pattern != "" {
		return policyResult{
			Action:       policyActionDeny,
			ReasonCode:   reasonDenyCapability,
			ReasonDetail: fmt.Sprintf("capability matched deny_capabilities entry %q", pattern),
		}
	}

	if pattern := matchAnyCapability(capability, cfg.RequireApprovalCapabilities); pattern != "" {
		return policyResult{
			Action:       policyActionRequireApproval,
			ReasonCode:   reasonRequireCapability,
			ReasonDetail: fmt.Sprintf("capability matched require_approval_capabilities entry %q", pattern),
		}
	}

	if pattern := matchAnyCommand(normalizedCmd, cfg.DenyCommands); pattern != "" {
		return policyResult{
			Action:       policyActionDeny,
			ReasonCode:   reasonDenyCommand,
			ReasonDetail: fmt.Sprintf("command matched deny_commands pattern %q", pattern),
		}
	}

	if pattern := matchAnyOperation(operation, cfg.DenyOperations); pattern != "" {
		return policyResult{
			Action:       policyActionDeny,
			ReasonCode:   reasonDenyOperation,
			ReasonDetail: fmt.Sprintf("operation matched deny_operations entry %q", pattern),
		}
	}

	if len(resources) > 0 {
		if res, pattern := matchAnyPath(resources, cfg.DenyPaths); pattern != "" {
			return policyResult{
				Action:       policyActionDeny,
				ReasonCode:   reasonDenyPath,
				ReasonDetail: fmt.Sprintf("resource %q matched deny_paths pattern %q", res, pattern),
			}
		}
	}

	if pattern := matchAnyCommand(normalizedCmd, cfg.RequireApprovalCommands); pattern != "" {
		return policyResult{
			Action:       policyActionRequireApproval,
			ReasonCode:   reasonRequireCommand,
			ReasonDetail: fmt.Sprintf("command matched require_approval_commands pattern %q", pattern),
		}
	}

	if pattern := matchAnyOperation(operation, cfg.RequireApprovalOperations); pattern != "" {
		return policyResult{
			Action:       policyActionRequireApproval,
			ReasonCode:   reasonRequireOperation,
			ReasonDetail: fmt.Sprintf("operation matched require_approval_operations entry %q", pattern),
		}
	}

	defaultAction := normalizePolicyAction(cfg.DefaultAction)
	if defaultAction == "" {
		defaultAction = policyActionRequireApproval
	}

	if len(cfg.AllowPaths) > 0 && len(resources) > 0 {
		if allPathsAllowed(resources, cfg.AllowPaths) {
			if defaultAction == policyActionAllow {
				return policyResult{
					Action:       policyActionAllow,
					ReasonCode:   reasonAllowPath,
					ReasonDetail: "all resources match allow_paths",
				}
			}
		} else if defaultAction == policyActionAllow {
			return policyResult{
				Action:       policyActionRequireApproval,
				ReasonCode:   reasonDefaultRequire,
				ReasonDetail: "default_action allow overridden; resources outside allow_paths",
			}
		}
	}

	switch defaultAction {
	case policyActionAllow:
		return policyResult{
			Action:       policyActionAllow,
			ReasonCode:   reasonDefaultAllow,
			ReasonDetail: "default_action allow",
		}
	case policyActionDeny:
		return policyResult{
			Action:       policyActionDeny,
			ReasonCode:   reasonDefaultDeny,
			ReasonDetail: "default_action deny",
		}
	default:
		return policyResult{
			Action:       policyActionRequireApproval,
			ReasonCode:   reasonDefaultRequire,
			ReasonDetail: "default_action require_approval",
		}
	}
}

func normalizeCommand(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func toResolvedCommand(cmdDef allowedCommand) resolvedCommand {
	args := append([]string{}, cmdDef.Args...)
	return resolvedCommand{
		Path: cmdDef.Path,
		Args: args,
	}
}

func formatResolvedCommand(cmd resolvedCommand) string {
	parts := make([]string, 0, 1+len(cmd.Args))
	if strings.TrimSpace(cmd.Path) != "" {
		parts = append(parts, cmd.Path)
	}
	parts = append(parts, cmd.Args...)
	return strings.Join(parts, " ")
}

func formatAllowedCommand(cmdDef allowedCommand) string {
	return formatResolvedCommand(toResolvedCommand(cmdDef))
}

func commandForPolicy(cmd resolvedCommand) string {
	bin := normalizeBin(cmd.Path)
	if bin == "" {
		return strings.Join(cmd.Args, " ")
	}
	parts := append([]string{bin}, cmd.Args...)
	return strings.Join(parts, " ")
}

func displayStatus(rec requestRecord) string {
	if rec.Executed {
		return "executed"
	}
	if strings.TrimSpace(rec.Status) != "" {
		return rec.Status
	}
	return statusPending
}

func formatTimeNullable(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func truncateReason(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func formatCommandDisplay(cmd resolvedCommand) string {
	parts := make([]string, 0, 1+len(cmd.Args))
	if strings.TrimSpace(cmd.Path) != "" {
		parts = append(parts, quoteForDisplay(cmd.Path))
	}
	for _, arg := range cmd.Args {
		parts = append(parts, quoteForDisplay(arg))
	}
	return strings.Join(parts, " ")
}

func quoteForDisplay(value string) string {
	if value == "" {
		return "\"\""
	}
	needsQuote := strings.ContainsAny(value, " \t\"")
	escaped := strings.ReplaceAll(value, "\"", "\\\"")
	if needsQuote {
		return "\"" + escaped + "\""
	}
	return escaped
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "token") ||
		strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") ||
		strings.Contains(lower, "key")
}

func redactValue(key, value string) string {
	if isSensitiveKey(key) {
		return "***"
	}
	return value
}

func matchAnyCommand(command string, patterns []string) string {
	for _, pattern := range patterns {
		normalized := normalizeCommand(pattern)
		if normalized == "" {
			continue
		}
		if strings.HasPrefix(command, normalized) {
			return pattern
		}
	}
	return ""
}

func matchAnyOperation(operation string, patterns []string) string {
	for _, pattern := range patterns {
		if strings.EqualFold(strings.TrimSpace(pattern), operation) {
			return pattern
		}
	}
	return ""
}

func matchAnyCapability(capability string, patterns []string) string {
	if strings.TrimSpace(capability) == "" {
		return ""
	}
	for _, pattern := range patterns {
		if strings.EqualFold(strings.TrimSpace(pattern), capability) {
			return pattern
		}
	}
	return ""
}

func resolveResources(req executionRequest) []string {
	if len(req.Resources) > 0 {
		return append([]string{}, req.Resources...)
	}
	if isLikelyPath(req.Target) {
		return []string{req.Target}
	}
	return nil
}

func isLikelyPath(target string) bool {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return false
	}
	if filepath.IsAbs(trimmed) {
		return true
	}
	if strings.ContainsAny(trimmed, `/\`) {
		return true
	}
	if strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, "~") {
		return true
	}
	if ext := filepath.Ext(trimmed); ext != "" && ext != "." {
		return true
	}
	return false
}

func normalizePolicyAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case policyActionAllow:
		return policyActionAllow
	case policyActionDeny:
		return policyActionDeny
	case policyActionRequireApproval:
		return policyActionRequireApproval
	default:
		return ""
	}
}

func matchAnyPath(resources []string, patterns []string) (string, string) {
	for _, res := range resources {
		for _, pattern := range patterns {
			if matchPath(pattern, res) {
				return res, pattern
			}
		}
	}
	return "", ""
}

func allPathsAllowed(resources []string, patterns []string) bool {
	for _, res := range resources {
		matched := false
		for _, pattern := range patterns {
			if matchPath(pattern, res) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(resources) > 0
}

func matchPath(pattern, path string) bool {
	normalizedPattern := normalizePathForMatch(pattern)
	normalizedPath := normalizePathForMatch(path)
	if normalizedPattern == "" || normalizedPath == "" {
		return false
	}
	ok, err := doublestar.Match(normalizedPattern, normalizedPath)
	if err != nil {
		return false
	}
	return ok
}

func normalizePathForMatch(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	normalized := filepath.ToSlash(trimmed)
	if runtime.GOOS == "windows" {
		normalized = strings.ToLower(normalized)
	}
	return normalized
}

func validateRequest(req executionRequest) error {
	if strings.TrimSpace(req.Command) != "" {
		return errors.New("command field is not supported; use capability")
	}
	if strings.TrimSpace(req.AgentID) == "" ||
		strings.TrimSpace(req.Intent) == "" ||
		strings.TrimSpace(req.Target) == "" ||
		strings.TrimSpace(req.Capability) == "" ||
		strings.TrimSpace(req.Reason) == "" {
		return errors.New("missing required fields")
	}
	if req.Params == nil {
		return errors.New("missing params")
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
	tmp := filepath.Join(filepath.Dir(requestsFile), fmt.Sprintf(".%s.tmp", filepath.Base(requestsFile)))
	data, err := json.MarshalIndent(records, "", "  ")
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

func resolveAllowedCommand(req executionRequest) (allowedCommand, error) {
	allowCfg, err := loadAllowlist(allowlistFile)
	if err != nil {
		return allowedCommand{}, fmt.Errorf("failed to load allowlist: %w", err)
	}
	capability := strings.TrimSpace(req.Capability)
	if capability == "" {
		return allowedCommand{}, fmt.Errorf("missing capability")
	}

	cmdDef, ok := findAllowedCommand(capability, allowCfg)
	if !ok {
		return allowedCommand{}, fmt.Errorf("requested capability %q not in allowlist", capability)
	}

	cmdDef, err = buildExecutableCommand(cmdDef, req.Params)
	if err != nil {
		return allowedCommand{}, err
	}
	if err := validateAgainstPolicy(req, cmdDef); err != nil {
		return allowedCommand{}, err
	}
	return cmdDef, nil
}

func buildExecutableCommand(cmdDef allowedCommand, params map[string]string) (allowedCommand, error) {
	if len(cmdDef.Vars) == 0 {
		return cmdDef, nil
	}
	if params == nil {
		params = map[string]string{}
	}

	placeholderRe := regexp.MustCompile(`\{([A-Za-z0-9_]+)\}`)
	replacedArgs := make([]string, len(cmdDef.Args))
	checked := make(map[string]struct{})

	for i, arg := range cmdDef.Args {
		matches := placeholderRe.FindAllStringSubmatch(arg, -1)
		for _, match := range matches {
			name := match[1]
			rule, ok := cmdDef.Vars[name]
			if !ok {
				return allowedCommand{}, requestParamError{Param: name, Reason: "not_allowed"}
			}
			value, ok := params[name]
			if !ok {
				return allowedCommand{}, requestParamError{Param: name, Reason: "missing"}
			}
			if _, seen := checked[name]; !seen {
				if err := validateParam(name, value, rule); err != nil {
					return allowedCommand{}, err
				}
				checked[name] = struct{}{}
			}
		}

		replaced := arg
		for _, match := range matches {
			name := match[1]
			replaced = strings.ReplaceAll(replaced, "{"+name+"}", params[name])
		}
		replacedArgs[i] = replaced
	}

	cmdDef.Args = replacedArgs
	return cmdDef, nil
}

func validateParam(name, value string, rule varRule) error {
	pattern := strings.TrimSpace(rule.Pattern)
	if pattern == "" {
		return nil
	}
	ok, err := regexp.MatchString(pattern, value)
	if err != nil {
		return fmt.Errorf("invalid pattern for %s", name)
	}
	if !ok {
		return requestParamError{Param: name, Reason: "pattern", Pattern: pattern}
	}
	return nil
}

func validateAgainstPolicy(req executionRequest, cmdDef allowedCommand) error {
	if err := validateGlobalDeny(cmdDef); err != nil {
		return err
	}

	capability := strings.ToLower(strings.TrimSpace(req.Capability))
	policy, ok := capabilityPolicies[capability]
	if !ok {
		return nil
	}

	bin := normalizeBin(cmdDef.Path)
	if bin == "" {
		return policyValidationError{Message: "request binary missing for policy"}
	}
	if !stringInSlice(bin, policy.AllowedBins) {
		return policyValidationError{Message: fmt.Sprintf("request binary %q denied by policy", bin)}
	}

	if len(cmdDef.Args) < 1 {
		return policyValidationError{Message: "request subcommand missing for policy"}
	}
	sub := strings.ToLower(cmdDef.Args[0])
	if len(policy.AllowedSub) > 0 && !policy.AllowedSub[sub] {
		return policyValidationError{Message: fmt.Sprintf("request subcommand %q denied by policy", sub)}
	}

	for _, denyArg := range policy.DenyArgs {
		denyArg = strings.ToLower(denyArg)
		for _, token := range cmdDef.Args[1:] {
			if strings.HasPrefix(strings.ToLower(token), denyArg) {
				return policyValidationError{Message: fmt.Sprintf("request argument %q denied by policy", denyArg)}
			}
		}
	}

	for _, key := range policy.RequireKeys {
		if strings.TrimSpace(req.Params[key]) == "" {
			return requestParamError{Param: key, Reason: "policy_missing"}
		}
	}

	minRisk, ok := policy.MinRiskByTarget[strings.ToLower(strings.TrimSpace(req.Target))]
	if ok && riskLessThan(req.RiskLevel, minRisk) {
		return policyValidationError{Message: fmt.Sprintf("risk_level %s below minimum %s for target %s", strings.ToLower(req.RiskLevel), strings.ToLower(minRisk), req.Target)}
	}

	return nil
}

func validateGlobalDeny(cmdDef allowedCommand) error {
	normalized := strings.ToLower(strings.TrimSpace(formatAllowedCommand(cmdDef)))
	for _, denied := range globalDenySubstrings {
		if strings.Contains(normalized, strings.ToLower(denied)) {
			return policyValidationError{Message: "request command denied by global policy"}
		}
	}
	return nil
}

func normalizeBin(token string) string {
	base := filepath.Base(token)
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".cmd")
	base = strings.TrimSuffix(base, ".bat")
	return strings.ToLower(base)
}

func stringInSlice(value string, list []string) bool {
	for _, item := range list {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func riskLessThan(got, min string) bool {
	gotRank, ok := riskRank[strings.ToLower(got)]
	if !ok {
		return false
	}
	minRank, ok := riskRank[strings.ToLower(min)]
	if !ok {
		return false
	}
	return gotRank < minRank
}

func approverAllowed(approver string, cfg policyConfig) bool {
	if len(cfg.ApproverAllowlist) == 0 {
		return true
	}
	for _, allowed := range cfg.ApproverAllowlist {
		if strings.EqualFold(strings.TrimSpace(allowed), strings.TrimSpace(approver)) {
			return true
		}
	}
	return false
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

	policyCfg, err := loadPolicy(policyFile)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}
	if !approverAllowed(approver, policyCfg) {
		now := time.Now().UTC()
		rec.LastReviewBy = approver
		rec.LastReviewAt = &now
		rec.LastReviewDecision = "approval_rejected"
		rec.LastReviewComment = comment
		rec.UpdatedAt = now
		records[idx] = rec
		if err := saveRequests(records); err != nil {
			return err
		}
		appendAudit(rec.ID, rec.Request.AgentID, rec.Request.Intent, approver, "approval_rejected", false, "approver not in allowlist", rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)
		return fmt.Errorf("approver %q not in allowlist", approver)
	}

	log.Printf("approve debug: capability=%q params=%v resolved_path=%q", rec.Request.Capability, rec.Request.Params, rec.ResolvedCommand.Path)

	now := time.Now().UTC()

	rec.Status = statusApproved
	rec.Decision = statusApproved
	rec.DecisionBy = approver
	rec.DecisionAt = &now
	rec.Comment = comment
	rec.LastReviewBy = approver
	rec.LastReviewAt = &now
	rec.LastReviewDecision = statusApproved
	rec.LastReviewComment = comment
	rec.UpdatedAt = now

	fmt.Fprintln(statusOutput, "Approved by human")
	fmt.Fprintln(statusOutput, "Executing command...")
	execErr := executeForRecord(&rec)
	fmt.Fprintln(statusOutput, "Execution finished")

	records[idx] = rec
	if err := saveRequests(records); err != nil {
		return err
	}

	appendAudit(rec.ID, rec.Request.AgentID, rec.Request.Intent, approver, statusApproved, rec.Executed, comment, rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)
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
	rec.LastReviewBy = approver
	rec.LastReviewAt = &now
	rec.LastReviewDecision = statusDenied
	rec.LastReviewComment = comment
	rec.Executed = false
	rec.UpdatedAt = now

	records[idx] = rec
	if err := saveRequests(records); err != nil {
		return err
	}

	appendAudit(rec.ID, rec.Request.AgentID, rec.Request.Intent, approver, statusDenied, false, comment, rec.PolicyAction, rec.PolicyReasonCode, rec.PolicyReasonDetail)
	return nil
}

func executeCommand(cmdDef resolvedCommand) ([]byte, error) {
	cmd := exec.Command(cmdDef.Path, cmdDef.Args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func executeForRecord(rec *requestRecord) error {
	if strings.TrimSpace(rec.ResolvedCommand.Path) == "" {
		rec.ExecutionError = "request missing resolved command"
		rec.Executed = false
		return fmt.Errorf(rec.ExecutionError)
	}
	output, execErr := executeCommand(rec.ResolvedCommand)
	exitCode := exitCodeFromError(execErr)
	status := "success"
	if execErr != nil || exitCode != 0 {
		status = "failed"
	}
	rec.Execution = &executionResult{
		ExitCode: exitCode,
		Status:   status,
	}
	rec.Executed = execErr == nil
	if execErr != nil {
		rec.ExecutionError = execErr.Error()
		return execErr
	}
	if persistErr := persistOutput(*rec, output, exitCode); persistErr != nil {
		rec.ExecutionError = fmt.Sprintf("output persist failed: %v", persistErr)
		rec.Executed = false
		return persistErr
	}
	return nil
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

func appendAudit(requestID int, agentID, intent, approver, decision string, executed bool, comment, policyAction, policyReasonCode, policyReasonDetail string) {
	entry := auditEntry{
		RequestID:          requestID,
		AgentID:            agentID,
		Intent:             intent,
		ApprovedBy:         approver,
		Decision:           decision,
		Executed:           executed,
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		Comment:            comment,
		PolicyAction:       policyAction,
		PolicyReasonCode:   policyReasonCode,
		PolicyReasonDetail: policyReasonDetail,
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
	commandLine := formatResolvedCommand(rec.ResolvedCommand)
	if strings.TrimSpace(commandLine) == "" {
		commandLine = "(none)"
	}
	fmt.Fprintf(&buf, "Command: %s\n", commandLine)
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
