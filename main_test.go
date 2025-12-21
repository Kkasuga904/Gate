package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvaluatePolicyDenyPath(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
		DenyPaths:     []string{"infra/**"},
	}
	req := executionRequest{
		Intent:    "write_file",
		Command:   "echo test",
		Target:    "infra/main.tf",
		Resources: []string{"infra/main.tf"},
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionDeny || res.ReasonCode != reasonDenyPath {
		t.Fatalf("expected deny path, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyAllowPathsDefaultAllow(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "allow",
		AllowPaths:    []string{"src/**"},
	}
	req := executionRequest{
		Intent:    "read_file",
		Command:   "cat src/app.go",
		Target:    "src/app.go",
		Resources: []string{"src/app.go"},
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionAllow || res.ReasonCode != reasonAllowPath {
		t.Fatalf("expected allow path, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyDenyCommand(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
		DenyCommands:  []string{"terraform apply"},
	}
	req := executionRequest{
		Intent:  "run_shell",
		Command: "terraform apply -auto-approve",
		Target:  "infra",
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionDeny || res.ReasonCode != reasonDenyCommand {
		t.Fatalf("expected deny command, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyRequireApprovalCommand(t *testing.T) {
	cfg := policyConfig{
		DefaultAction:           "require_approval",
		RequireApprovalCommands: []string{"git push"},
	}
	req := executionRequest{
		Intent:  "run_shell",
		Command: "git push origin main",
		Target:  "repo",
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionRequireApproval || res.ReasonCode != reasonRequireCommand {
		t.Fatalf("expected require approval command, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyRequireApprovalOperation(t *testing.T) {
	cfg := policyConfig{
		DefaultAction:             "deny",
		RequireApprovalOperations: []string{"write_file"},
	}
	req := executionRequest{
		Intent:    "update",
		Operation: "write_file",
		Command:   "edit",
		Target:    "doc.txt",
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionRequireApproval || res.ReasonCode != reasonRequireOperation {
		t.Fatalf("expected require approval operation, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyResourcesEmptyDefaultRequire(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
	}
	req := executionRequest{
		Intent:  "run_shell",
		Command: "hostname",
		Target:  "host01",
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionRequireApproval || res.ReasonCode != reasonDefaultRequire {
		t.Fatalf("expected default require approval, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyDenyPemPath(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
		DenyPaths:     []string{"**/*.pem"},
	}
	req := executionRequest{
		Intent:    "read_file",
		Command:   "cat secrets/key.pem",
		Target:    "secrets/key.pem",
		Resources: []string{"secrets/key.pem"},
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionDeny || res.ReasonCode != reasonDenyPath {
		t.Fatalf("expected deny path for pem, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyCommandNormalization(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
		DenyCommands:  []string{"rm -rf"},
	}
	req := executionRequest{
		Intent:  "run_shell",
		Command: "rm   -rf   /tmp",
		Target:  "/tmp",
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionDeny || res.ReasonCode != reasonDenyCommand {
		t.Fatalf("expected deny command after normalization, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestResolveAllowedCommand_BackCompatExactMatch(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: cmd_echo
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "hello-approved"]
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Command: "cmd_echo",
	}
	cmdDef, err := resolveAllowedCommand(req)
	if err != nil {
		t.Fatalf("expected allowlist match, got error: %v", err)
	}
	if cmdDef.Path != "C:\\Windows\\System32\\cmd.exe" {
		t.Fatalf("unexpected path: %s", cmdDef.Path)
	}
	if len(cmdDef.Args) != 3 || cmdDef.Args[2] != "hello-approved" {
		t.Fatalf("unexpected args: %#v", cmdDef.Args)
	}
}

func TestResolveAllowedCommand_CapabilityTemplateOK(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: git_push_feature
    path: "C:\\Program Files\\Git\\bin\\git.exe"
    args: ["push", "origin", "{BRANCH}"]
    vars:
      BRANCH:
        pattern: "^(feature|bugfix|chore)\\/[A-Za-z0-9._-]+$"
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Command:    "git push origin feature/foo",
		Capability: "git_push_feature",
		Params: map[string]string{
			"BRANCH": "feature/foo",
		},
	}
	cmdDef, err := resolveAllowedCommand(req)
	if err != nil {
		t.Fatalf("expected allowlist match, got error: %v", err)
	}
	if len(cmdDef.Args) != 3 || cmdDef.Args[2] != "feature/foo" {
		t.Fatalf("unexpected args: %#v", cmdDef.Args)
	}
}

func TestResolveAllowedCommand_CapabilityTemplateReject(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: git_push_feature
    path: "C:\\Program Files\\Git\\bin\\git.exe"
    args: ["push", "origin", "{BRANCH}"]
    vars:
      BRANCH:
        pattern: "^(feature|bugfix|chore)\\/[A-Za-z0-9._-]+$"
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Capability: "git_push_feature",
		Params: map[string]string{
			"BRANCH": "main",
		},
	}
	if _, err := resolveAllowedCommand(req); err == nil || !strings.Contains(err.Error(), "does not match allowlist pattern") {
		t.Fatalf("expected pattern rejection, got %v", err)
	}
}

func TestResolveAllowedCommand_MissingParam(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: cmd_echo
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "{TEXT}"]
    vars:
      TEXT:
        pattern: "^[A-Za-z0-9._-]{1,32}$"
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Capability: "cmd_echo",
	}
	if _, err := resolveAllowedCommand(req); err == nil || !strings.Contains(err.Error(), "missing request param") {
		t.Fatalf("expected missing param error, got %v", err)
	}
}

func TestApproveRequestRejectsApproverNotAllowlisted(t *testing.T) {
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(orig)
	}()

	policy := `version: "0.1"
default_action: "require_approval"
approver_allowlist:
  - "manager_01"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	rec := requestRecord{
		ID:     1,
		Status: statusPending,
		Request: executionRequest{
			AgentID:   "agent-1",
			Intent:    "gather_logs",
			Env:       "test",
			Target:    "host01",
			Command:   "gather_logs",
			Reason:    "diag",
			RiskLevel: "low",
		},
	}
	if err := saveRequests([]requestRecord{rec}); err != nil {
		t.Fatalf("failed to save request: %v", err)
	}

	err = approveRequest(1, "human_01", "reviewed")
	if err == nil || !strings.Contains(err.Error(), "not in allowlist") {
		t.Fatalf("expected allowlist rejection, got %v", err)
	}

	records, err := loadRequests()
	if err != nil {
		t.Fatalf("failed to load requests: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].LastReviewBy != "human_01" || records[0].LastReviewDecision != "approval_rejected" {
		t.Fatalf("expected last review recorded, got by=%q decision=%q", records[0].LastReviewBy, records[0].LastReviewDecision)
	}
	if records[0].LastReviewComment != "reviewed" {
		t.Fatalf("expected last review comment saved, got %q", records[0].LastReviewComment)
	}
	if _, err := os.Stat(filepath.Join(dir, auditLogFile)); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected audit log error: %v", err)
	}
}

func TestEvaluatePolicyBackwardCompatibleTarget(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
		DenyPaths:     []string{"infra/**"},
	}
	req := executionRequest{
		Intent:  "read_file",
		Command: "cat infra/main.tf",
		Target:  "infra/main.tf",
	}
	res := evaluatePolicy(req, cfg)
	if res.Action != policyActionDeny || res.ReasonCode != reasonDenyPath {
		t.Fatalf("expected deny path for target fallback, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestReadRPCMessageWhitespaceEOF(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(" \r\n\n\t"))
	payload, err := readRPCMessage(reader)
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got payload=%q err=%v", string(payload), err)
	}
}

func TestReadRPCMessageHeaderOnlyEOF(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("Content-Length: 5"))
	_, err := readRPCMessage(reader)
	if err == nil || err.Error() != "missing Content-Length" {
		t.Fatalf("expected missing Content-Length, got %v", err)
	}
}

func TestReadRPCMessageHeaderOnlyCRLFEOF(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("Content-Length: 5\r\n"))
	_, err := readRPCMessage(reader)
	if err == nil || err.Error() != "missing Content-Length" {
		t.Fatalf("expected missing Content-Length, got %v", err)
	}
}

func TestReadRPCMessageOK(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("Content-Length: 5\r\n\r\nhello"))
	payload, err := readRPCMessage(reader)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("expected payload hello, got %q", string(payload))
	}
}

func TestReadRPCMessageShortBody(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("Content-Length: 5\r\n\r\nhe"))
	_, err := readRPCMessage(reader)
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected unexpected EOF, got %v", err)
	}
}

func TestReadRPCMessageLeadingBlankLines(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("\r\n\nContent-Length: 5\r\n\r\nhello"))
	payload, err := readRPCMessage(reader)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if string(payload) != "hello" {
		t.Fatalf("expected payload hello, got %q", string(payload))
	}
}

func TestMCPListCapabilitiesMethod(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: git_push_feature
    path: "C:\\Program Files\\Git\\bin\\git.exe"
    args: ["push", "origin", "feature/foo"]
  - name: cmd_echo
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "hi"]
`
	writeAllowlist(t, allowlist)

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "gate.list_capabilities",
	}
	resp := handleMCPRequest(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected success response, got %#v", resp)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected result map, got %#v", resp.Result)
	}
	caps, ok := result["capabilities"].([]string)
	if !ok {
		if iface, ok := result["capabilities"].([]interface{}); ok {
			if len(iface) != 2 {
				t.Fatalf("expected 2 capabilities, got %d", len(iface))
			}
			return
		}
		t.Fatalf("unexpected capabilities type: %#v", result["capabilities"])
	}
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}
}

func TestMCPExecuteRequestMethod(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	args := mcpExecuteRequestArgs{
		AgentID:   "agent-1",
		Intent:    "execute",
		Target:    "repo",
		Command:   "git push origin feature/foo",
		Reason:    "try push",
		RiskLevel: "high",
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "gate.execute_request",
		Params:  rawArgs,
	}
	resp := handleMCPRequest(req)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected success response, got %#v", resp)
	}
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected result map, got %#v", resp.Result)
	}
	if result["status"] != statusPending {
		t.Fatalf("expected pending status, got %#v", result["status"])
	}
	if _, ok := result["request_id"]; !ok {
		t.Fatalf("expected request_id in result, got %#v", result)
	}
}

func TestMCPExecuteRequestNoStdout(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	oldStatusOutput := statusOutput
	var statusBuf strings.Builder
	statusOutput = &statusBuf
	defer func() {
		statusOutput = oldStatusOutput
	}()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to pipe stdout: %v", err)
	}
	os.Stdout = writer

	args := mcpExecuteRequestArgs{
		AgentID:   "agent-1",
		Intent:    "execute",
		Target:    "repo",
		Command:   "git status",
		Reason:    "check",
		RiskLevel: "low",
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	resp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("1"),
		Method:  "gate.execute_request",
		Params:  rawArgs,
	})

	_ = writer.Close()
	os.Stdout = oldStdout

	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatalf("failed to read stdout: %v", readErr)
	}

	if resp == nil || resp.Error != nil {
		t.Fatalf("expected mcp execute_request ok, got %#v", resp)
	}
	if len(output) != 0 {
		t.Fatalf("expected no stdout output, got %q", string(output))
	}
	if !strings.Contains(statusBuf.String(), "New request received") {
		t.Fatalf("expected statusOutput to receive request status, got %q", statusBuf.String())
	}
}

func TestMCPApproveNoStdout(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
approver_allowlist: ["human_01"]
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	allowlist := `commands:
  - name: noop
    path: "C:\\nonexistent\\noop.exe"
    args: []
`
	writeAllowlist(t, allowlist)

	rec := requestRecord{
		ID:     101,
		Status: statusPending,
		Request: executionRequest{
			AgentID:   "agent-1",
			Intent:    "execute",
			Target:    "repo",
			Command:   "noop",
			Reason:    "check",
			RiskLevel: "low",
			Capability: "noop",
		},
	}
	if err := saveRequests([]requestRecord{rec}); err != nil {
		t.Fatalf("failed to save request: %v", err)
	}

	oldStatusOutput := statusOutput
	var statusBuf strings.Builder
	statusOutput = &statusBuf
	defer func() {
		statusOutput = oldStatusOutput
	}()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to pipe stdout: %v", err)
	}
	os.Stdout = writer

	args := mcpReviewArgs{
		RequestID: 101,
		User:      "human_01",
		Comment:   "ok",
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	resp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("2"),
		Method:  "gate.approve",
		Params:  rawArgs,
	})

	_ = writer.Close()
	os.Stdout = oldStdout

	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		t.Fatalf("failed to read stdout: %v", readErr)
	}

	if resp == nil {
		t.Fatalf("expected mcp approve response, got %#v", resp)
	}
	if len(output) != 0 {
		t.Fatalf("expected no stdout output, got %q", string(output))
	}
	if !strings.Contains(statusBuf.String(), "Approved by human") {
		t.Fatalf("expected statusOutput to receive approval status, got %q", statusBuf.String())
	}
	if !strings.Contains(statusBuf.String(), "Executing command...") {
		t.Fatalf("expected statusOutput to receive execution status, got %q", statusBuf.String())
	}
	if !strings.Contains(statusBuf.String(), "Execution finished") {
		t.Fatalf("expected statusOutput to receive completion status, got %q", statusBuf.String())
	}
}

func TestMCPApproveMethodDispatch(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	args := mcpReviewArgs{
		RequestID: 999,
		User:      "human_01",
		Comment:   "ok",
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("3"),
		Method:  "gate.approve",
		Params:  rawArgs,
	}
	resp := handleMCPRequest(req)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code == -32601 {
		t.Fatalf("unexpected method not found error")
	}
}

func TestMCPDenyMethodDispatch(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	args := mcpReviewArgs{
		RequestID: 999,
		User:      "human_01",
		Comment:   "no",
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("4"),
		Method:  "gate.deny",
		Params:  rawArgs,
	}
	resp := handleMCPRequest(req)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code == -32601 {
		t.Fatalf("unexpected method not found error")
	}
}

func TestMCPApproveParamsSchema(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("5"),
		Method:  "gate.approve",
		Params:  json.RawMessage(`{"request_id":8,"user":"manager_01","comment":"ok"}`),
	}
	resp := handleMCPRequest(req)
	if resp == nil {
		t.Fatalf("expected response")
	}
	if resp.Error == nil {
		return
	}
	if resp.Error.Code == -32602 {
		t.Fatalf("unexpected invalid params error: %s", resp.Error.Message)
	}
}

func TestMCPApproveParamsFallbackText(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	req := jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("6"),
		Method:  "gate.approve",
		Params:  json.RawMessage(`{"request_id":8,"user":"manager_01","comment":"","TEXT":"ok"}`),
	}
	resp := handleMCPRequest(req)
	if resp == nil {
		t.Fatalf("expected response")
	}
	if resp.Error == nil {
		return
	}
	if resp.Error.Code == -32602 {
		t.Fatalf("unexpected invalid params error: %s", resp.Error.Message)
	}
}

func TestPolicyTerraformPlanMissingWorkdir(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	reqRec := requestRecord{
		ID:     8,
		Status: statusPending,
		Request: executionRequest{
			AgentID:    "agent-1",
			Intent:     "execute",
			Target:     "dev",
			Command:    "terraform plan",
			Reason:     "plan",
			RiskLevel:  "low",
			Capability: "terraform_plan",
		},
	}
	if err := saveRequests([]requestRecord{reqRec}); err != nil {
		t.Fatalf("failed to save request: %v", err)
	}

	params := json.RawMessage(`{"request_id":8,"user":"manager_01","comment":"ok"}`)
	resp := handleMCPRequest(jsonrpcRequest{JSONRPC: "2.0", ID: json.RawMessage("10"), Method: "gate.approve", Params: params})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "missing request param WORKDIR") {
		t.Fatalf("unexpected error message: %s", resp.Error.Message)
	}
}

func TestPolicyTerraformPlanSubcommandDenied(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	reqRec := requestRecord{
		ID:     9,
		Status: statusPending,
		Request: executionRequest{
			AgentID:    "agent-1",
			Intent:     "execute",
			Target:     "dev",
			Command:    "terraform apply",
			Reason:     "apply",
			RiskLevel:  "low",
			Capability: "terraform_plan",
			Params:     map[string]string{"WORKDIR": "c:\\infra"},
		},
	}
	if err := saveRequests([]requestRecord{reqRec}); err != nil {
		t.Fatalf("failed to save request: %v", err)
	}

	params := json.RawMessage(`{"request_id":9,"user":"manager_01","comment":"ok"}`)
	resp := handleMCPRequest(jsonrpcRequest{JSONRPC: "2.0", ID: json.RawMessage("11"), Method: "gate.approve", Params: params})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "subcommand") {
		t.Fatalf("unexpected error message: %s", resp.Error.Message)
	}
}

func TestPolicyGlobalDenyKubectlDelete(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	reqRec := requestRecord{
		ID:     10,
		Status: statusPending,
		Request: executionRequest{
			AgentID:    "agent-1",
			Intent:     "execute",
			Target:     "dev",
			Command:    "kubectl delete pod x",
			Reason:     "cleanup",
			RiskLevel:  "medium",
			Capability: "kubectl_diff",
			Params:     map[string]string{"KUBECONTEXT": "dev"},
		},
	}
	if err := saveRequests([]requestRecord{reqRec}); err != nil {
		t.Fatalf("failed to save request: %v", err)
	}

	params := json.RawMessage(`{"request_id":10,"user":"manager_01","comment":"ok"}`)
	resp := handleMCPRequest(jsonrpcRequest{JSONRPC: "2.0", ID: json.RawMessage("12"), Method: "gate.approve", Params: params})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "global policy") {
		t.Fatalf("unexpected error message: %s", resp.Error.Message)
	}
}

func TestPolicyKubectlDiffMissingContext(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	reqRec := requestRecord{
		ID:     11,
		Status: statusPending,
		Request: executionRequest{
			AgentID:    "agent-1",
			Intent:     "execute",
			Target:     "dev",
			Command:    "kubectl diff",
			Reason:     "check",
			RiskLevel:  "medium",
			Capability: "kubectl_diff",
		},
	}
	if err := saveRequests([]requestRecord{reqRec}); err != nil {
		t.Fatalf("failed to save request: %v", err)
	}

	params := json.RawMessage(`{"request_id":11,"user":"manager_01","comment":"ok"}`)
	resp := handleMCPRequest(jsonrpcRequest{JSONRPC: "2.0", ID: json.RawMessage("13"), Method: "gate.approve", Params: params})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %d", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "missing request param KUBECONTEXT") {
		t.Fatalf("unexpected error message: %s", resp.Error.Message)
	}
}

func TestResolveAllowedCommandPolicyFallbackTerraformPlan(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	writeAllowlist(t, "commands: []\n")

	req := executionRequest{
		Command:    "terraform plan",
		Capability: "terraform_plan",
		Params: map[string]string{
			"WORKDIR": "C:\\infra",
		},
	}
	cmdDef, err := resolveAllowedCommand(req)
	if err != nil {
		t.Fatalf("expected fallback command, got error: %v", err)
	}
	if cmdDef.Path != "terraform" {
		t.Fatalf("unexpected path: %s", cmdDef.Path)
	}
	if len(cmdDef.Args) < 2 || cmdDef.Args[0] != "-chdir=C:\\infra" || cmdDef.Args[len(cmdDef.Args)-1] != "plan" {
		t.Fatalf("unexpected args: %#v", cmdDef.Args)
	}
}

func TestResolveAllowedCommandPolicyFallbackKubectlDiff(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	writeAllowlist(t, "commands: []\n")

	req := executionRequest{
		Command:    "kubectl diff",
		Capability: "kubectl_diff",
		Params: map[string]string{
			"KUBECONTEXT": "dev",
		},
	}
	cmdDef, err := resolveAllowedCommand(req)
	if err != nil {
		t.Fatalf("expected fallback command, got error: %v", err)
	}
	if cmdDef.Path != "kubectl" {
		t.Fatalf("unexpected path: %s", cmdDef.Path)
	}
	if len(cmdDef.Args) < 3 || cmdDef.Args[0] != "--context" || cmdDef.Args[1] != "dev" || cmdDef.Args[len(cmdDef.Args)-1] != "diff" {
		t.Fatalf("unexpected args: %#v", cmdDef.Args)
	}
}

func withTempDir(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to chdir: %v", err)
	}
	return dir, func() {
		_ = os.Chdir(orig)
	}
}

func writeAllowlist(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(allowlistFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write allowlist: %v", err)
	}
}
