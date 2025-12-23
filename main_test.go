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
		Target:    "infra/main.tf",
		Resources: []string{"infra/main.tf"},
	}
	res := evaluatePolicy(req, resolvedCmd("echo", "test"), cfg)
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
		Target:    "src/app.go",
		Resources: []string{"src/app.go"},
	}
	res := evaluatePolicy(req, resolvedCmd("cat", "src/app.go"), cfg)
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
		Intent: "run_shell",
		Target: "infra",
	}
	res := evaluatePolicy(req, resolvedCmd("terraform", "apply", "-auto-approve"), cfg)
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
		Intent: "run_shell",
		Target: "repo",
	}
	res := evaluatePolicy(req, resolvedCmd("git", "push", "origin", "main"), cfg)
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
		Target:    "doc.txt",
	}
	res := evaluatePolicy(req, resolvedCmd("edit"), cfg)
	if res.Action != policyActionRequireApproval || res.ReasonCode != reasonRequireOperation {
		t.Fatalf("expected require approval operation, got action=%s reason=%s", res.Action, res.ReasonCode)
	}
}

func TestEvaluatePolicyResourcesEmptyDefaultRequire(t *testing.T) {
	cfg := policyConfig{
		DefaultAction: "require_approval",
	}
	req := executionRequest{
		Intent: "run_shell",
		Target: "host01",
	}
	res := evaluatePolicy(req, resolvedCmd("hostname"), cfg)
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
		Target:    "secrets/key.pem",
		Resources: []string{"secrets/key.pem"},
	}
	res := evaluatePolicy(req, resolvedCmd("cat", "secrets/key.pem"), cfg)
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
		Intent: "run_shell",
		Target: "/tmp",
	}
	res := evaluatePolicy(req, resolvedCmd("rm", "-rf", "/tmp"), cfg)
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
		Capability: "cmd_echo",
		Params:     map[string]string{},
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
		Params:     map[string]string{},
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
			AgentID:    "agent-1",
			Intent:     "gather_logs",
			Env:        "test",
			Target:     "host01",
			Reason:     "diag",
			RiskLevel:  "low",
			Capability: "gather_logs",
			Params:     map[string]string{},
		},
		ResolvedCommand: resolvedCommand{
			Path: "C:\\Windows\\System32\\wevtutil.exe",
			Args: []string{"qe", "System", "/c:10"},
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
		Intent: "read_file",
		Target: "infra/main.tf",
	}
	res := evaluatePolicy(req, resolvedCmd("cat", "infra/main.tf"), cfg)
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

func TestComputeStatsNoSimilarCases(t *testing.T) {
	req := executionRequest{
		Capability: "echo_test",
		Target:     "dev",
	}
	cmd := resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "ok")
	records := []requestRecord{
		{
			ID: 1,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: resolvedCmd("C:\\Windows\\System32\\where.exe", "cmd.exe"),
			Executed:        true,
			Execution:       &executionResult{ExitCode: 0, Status: "success"},
		},
	}

	stats, basis := computeStatsForRequest(req, cmd, records, 0)
	if stats.SimilarRelaxedCount != 0 {
		t.Fatalf("expected no similar relaxed cases, got %d", stats.SimilarRelaxedCount)
	}
	if stats.CapabilityHistoryCount != 1 {
		t.Fatalf("expected capability history count 1, got %d", stats.CapabilityHistoryCount)
	}
	if stats.RelaxedSuccessRate != nil {
		t.Fatalf("expected relaxed success rate nil, got %v", *stats.RelaxedSuccessRate)
	}
	if stats.StrictSuccessRate != nil {
		t.Fatalf("expected strict success rate nil, got %v", *stats.StrictSuccessRate)
	}
	if stats.AnomalyScore != 1.0 {
		t.Fatalf("expected anomaly score 1.0, got %.2f", stats.AnomalyScore)
	}
	explanation := buildStatsExplanation(stats, basis)
	hasStrict := false
	hasRelaxed := false
	hasStrictNA := false
	hasRelaxedNA := false
	for _, line := range explanation {
		if strings.Contains(line, "similar_strict_count=0") {
			hasStrict = true
		}
		if strings.Contains(line, "capability_history_count=1") {
			hasRelaxed = true
		}
		if strings.Contains(line, "strict_success_rate=n/a") {
			hasStrictNA = true
		}
		if strings.Contains(line, "relaxed_success_rate=n/a") {
			hasRelaxedNA = true
		}
	}
	if !hasStrict || !hasRelaxed || !hasStrictNA || !hasRelaxedNA {
		t.Fatalf("unexpected explanation basis: %#v", explanation)
	}
}

func TestComputeStatsDeterministicOrder(t *testing.T) {
	req := executionRequest{
		Capability: "echo_test",
		Target:     "dev",
	}
	cmd := resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "ok")
	rec1 := requestRecord{
		ID: 2,
		Request: executionRequest{
			Capability: "echo_test",
			Target:     "dev",
		},
		ResolvedCommand: cmd,
		Executed:        true,
		Execution:       &executionResult{ExitCode: 0, Status: "success"},
	}
	rec2 := requestRecord{
		ID: 1,
		Request: executionRequest{
			Capability: "echo_test",
			Target:     "dev",
		},
		ResolvedCommand: cmd,
		Executed:        true,
		Execution:       &executionResult{ExitCode: 1, Status: "failed"},
	}
	statsA, basisA := computeStatsForRequest(req, cmd, []requestRecord{rec1, rec2}, 0)
	statsB, basisB := computeStatsForRequest(req, cmd, []requestRecord{rec2, rec1}, 0)

	if basisA != basisB {
		t.Fatalf("expected identical basis, got %#v vs %#v", basisA, basisB)
	}
	if statsA.SimilarRelaxedCount != statsB.SimilarRelaxedCount || statsA.SimilarStrictCount != statsB.SimilarStrictCount || statsA.CapabilityHistoryCount != statsB.CapabilityHistoryCount || statsA.AnomalyScore != statsB.AnomalyScore {
		t.Fatalf("expected identical stats, got %#v vs %#v", statsA, statsB)
	}
	if (statsA.RelaxedSuccessRate == nil) != (statsB.RelaxedSuccessRate == nil) {
		t.Fatalf("expected identical success rate presence, got %#v vs %#v", statsA.RelaxedSuccessRate, statsB.RelaxedSuccessRate)
	}
	if statsA.RelaxedSuccessRate != nil && statsB.RelaxedSuccessRate != nil && *statsA.RelaxedSuccessRate != *statsB.RelaxedSuccessRate {
		t.Fatalf("expected identical success rate, got %.2f vs %.2f", *statsA.RelaxedSuccessRate, *statsB.RelaxedSuccessRate)
	}
}

func TestComputeStatsTargetSeparation(t *testing.T) {
	cmd := resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "ok")
	records := []requestRecord{
		{
			ID: 1,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "Dev",
			},
			ResolvedCommand: cmd,
			Executed:        true,
			Execution:       &executionResult{ExitCode: 0, Status: "success"},
		},
	}

	devReq := executionRequest{
		Capability: "echo_test",
		Target:     "dev",
	}
	statsDev, _ := computeStatsForRequest(devReq, cmd, records, 0)
	if statsDev.SimilarRelaxedCount < 1 {
		t.Fatalf("expected similar relaxed cases for dev, got %d", statsDev.SimilarRelaxedCount)
	}

	devUpperReq := executionRequest{
		Capability: "echo_test",
		Target:     "DEV",
	}
	statsDevUpper, _ := computeStatsForRequest(devUpperReq, cmd, records, 0)
	if statsDevUpper.SimilarRelaxedCount < 1 {
		t.Fatalf("expected similar relaxed cases for DEV, got %d", statsDevUpper.SimilarRelaxedCount)
	}

	prodReq := executionRequest{
		Capability: "echo_test",
		Target:     "prod",
	}
	statsProd, _ := computeStatsForRequest(prodReq, cmd, records, 0)
	if statsProd.SimilarRelaxedCount != 0 {
		t.Fatalf("expected no similar relaxed cases for prod, got %d", statsProd.SimilarRelaxedCount)
	}
}

func TestRequestSucceededUsesExecutionInfo(t *testing.T) {
	rec := requestRecord{
		Status:    statusApproved,
		Executed:  true,
		Execution: &executionResult{ExitCode: 0, Status: "success"},
	}
	if !requestSucceeded(rec) {
		t.Fatalf("expected success from execution info")
	}
}

func TestComputeStatsStrictRelaxed(t *testing.T) {
	req := executionRequest{
		Capability: "echo_test",
		Target:     "dev",
	}
	cmd := resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "diff1")
	records := []requestRecord{
		{
			ID: 1,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "same"),
			Executed:        true,
			Execution:       &executionResult{ExitCode: 0, Status: "success"},
		},
	}

	stats, _ := computeStatsForRequest(req, cmd, records, 0)
	if stats.SimilarStrictCount != 0 {
		t.Fatalf("expected 0 strict cases, got %d", stats.SimilarStrictCount)
	}
	if stats.SimilarRelaxedCount != 1 {
		t.Fatalf("expected 1 relaxed case, got %d", stats.SimilarRelaxedCount)
	}
	if stats.RelaxedSuccessRate == nil || *stats.RelaxedSuccessRate != 1.0 {
		t.Fatalf("expected relaxed success rate 1.0, got %v", stats.RelaxedSuccessRate)
	}
	if stats.StrictSuccessRate != nil {
		t.Fatalf("expected strict success rate nil, got %v", *stats.StrictSuccessRate)
	}
}

func TestComputeStatsPendingDeniedExcluded(t *testing.T) {
	req := executionRequest{
		Capability: "echo_test",
		Target:     "dev",
	}
	cmd := resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "ok")
	records := []requestRecord{
		{
			ID: 1,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: cmd,
			Executed:        true,
			Execution:       &executionResult{ExitCode: 0, Status: "success"},
		},
		{
			ID: 2,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: cmd,
			Status:          statusPending,
		},
		{
			ID: 3,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: cmd,
			Status:          statusDenied,
		},
	}

	stats, _ := computeStatsForRequest(req, cmd, records, 0)
	if stats.SimilarRelaxedCount != 1 {
		t.Fatalf("expected 1 executed relaxed case, got %d", stats.SimilarRelaxedCount)
	}
	if stats.RelaxedSuccessRate == nil || *stats.RelaxedSuccessRate != 1.0 {
		t.Fatalf("expected relaxed success rate 1.0, got %v", stats.RelaxedSuccessRate)
	}
	if stats.SimilarPendingCount != 1 {
		t.Fatalf("expected 1 pending match, got %d", stats.SimilarPendingCount)
	}
	if stats.SimilarDeniedCount != 1 {
		t.Fatalf("expected 1 denied match, got %d", stats.SimilarDeniedCount)
	}
}

func TestComputeStatsPendingOnlyRelaxed(t *testing.T) {
	req := executionRequest{
		Capability: "echo_test",
		Target:     "dev",
	}
	cmd := resolvedCmd("C:\\Windows\\System32\\cmd.exe", "/C", "echo", "ok")
	records := []requestRecord{
		{
			ID: 1,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: cmd,
			Status:          statusPending,
		},
		{
			ID: 2,
			Request: executionRequest{
				Capability: "echo_test",
				Target:     "dev",
			},
			ResolvedCommand: cmd,
			Status:          statusPending,
		},
	}

	stats, _ := computeStatsForRequest(req, cmd, records, 0)
	if stats.SimilarRelaxedCount != 0 {
		t.Fatalf("expected 0 executed relaxed cases, got %d", stats.SimilarRelaxedCount)
	}
	if stats.RelaxedSuccessRate != nil {
		t.Fatalf("expected nil relaxed success rate, got %v", stats.RelaxedSuccessRate)
	}
	if stats.SimilarPendingCount != 2 {
		t.Fatalf("expected 2 pending matches, got %d", stats.SimilarPendingCount)
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

	allowlist := `commands:
  - name: echo_test
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "{TEXT}"]
    vars:
      TEXT:
        pattern: "^[A-Za-z0-9._-]{1,32}$"
`
	writeAllowlist(t, allowlist)

	args := mcpExecuteRequestArgs{
		AgentID:    "agent-1",
		Intent:     "execute",
		Target:     "repo",
		Reason:     "try push",
		RiskLevel:  "high",
		Capability: "echo_test",
		Params:     map[string]string{"TEXT": "ok"},
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

	allowlist := `commands:
  - name: echo_test
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "{TEXT}"]
    vars:
      TEXT:
        pattern: "^[A-Za-z0-9._-]{1,32}$"
`
	writeAllowlist(t, allowlist)

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
		AgentID:    "agent-1",
		Intent:     "execute",
		Target:     "repo",
		Reason:     "check",
		RiskLevel:  "low",
		Capability: "echo_test",
		Params:     map[string]string{"TEXT": "ok"},
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

func TestMCPExecuteRequestRejectsCommandField(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	args := mcpExecuteRequestArgs{
		AgentID:    "agent-1",
		Intent:     "execute",
		Target:     "repo",
		Command:    "whoami",
		Reason:     "check",
		RiskLevel:  "low",
		Capability: "echo_test",
		Params:     map[string]string{"TEXT": "ok"},
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	resp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("9"),
		Method:  "gate.execute_request",
		Params:  rawArgs,
	})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %#v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "command field is not supported") {
		t.Fatalf("unexpected error message: %s", resp.Error.Message)
	}
}

func TestMCPExecuteRequestRejectsUnknownCapability(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	policy := `version: "0.1"
default_action: "require_approval"
`
	if err := os.WriteFile(policyFile, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}
	writeAllowlist(t, "commands: []\n")

	args := mcpExecuteRequestArgs{
		AgentID:    "agent-1",
		Intent:     "execute",
		Target:     "repo",
		Reason:     "check",
		RiskLevel:  "low",
		Capability: "missing_cap",
		Params:     map[string]string{"_": "x"},
	}
	rawArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("failed to marshal args: %v", err)
	}

	resp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("9"),
		Method:  "gate.execute_request",
		Params:  rawArgs,
	})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if !strings.Contains(resp.Error.Message, "not in allowlist") {
		t.Fatalf("unexpected error message: %s", resp.Error.Message)
	}
}

func TestMCPRequestLifecycle(t *testing.T) {
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
  - name: echo_test
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "{TEXT}"]
    vars:
      TEXT:
        pattern: "^[A-Za-z0-9._-]{1,32}$"
`
	writeAllowlist(t, allowlist)

	execArgs := mcpExecuteRequestArgs{
		AgentID:    "agent-1",
		Intent:     "execute",
		Target:     "dev",
		Reason:     "mcp e2e",
		RiskLevel:  "low",
		Capability: "echo_test",
		Params:     map[string]string{"TEXT": "ok"},
	}
	rawExec, err := json.Marshal(execArgs)
	if err != nil {
		t.Fatalf("failed to marshal execute args: %v", err)
	}
	execResp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("10"),
		Method:  "gate.execute_request",
		Params:  rawExec,
	})
	if execResp == nil || execResp.Error != nil {
		t.Fatalf("expected execute_request ok, got %#v", execResp)
	}
	execResult, ok := execResp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected execute result map, got %#v", execResp.Result)
	}
	requestID, ok := toInt(execResult["request_id"])
	if !ok {
		t.Fatalf("expected request_id, got %#v", execResult["request_id"])
	}

	listArgs, err := json.Marshal(mcpListRequestsArgs{Status: "pending", Limit: 50})
	if err != nil {
		t.Fatalf("failed to marshal list args: %v", err)
	}
	listResp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("11"),
		Method:  "gate.list_requests",
		Params:  listArgs,
	})
	if listResp == nil || listResp.Error != nil {
		t.Fatalf("expected list_requests ok, got %#v", listResp)
	}
	found := false
	switch list := listResp.Result.(type) {
	case []interface{}:
		for _, item := range list {
			row, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if id, ok := toInt(row["request_id"]); ok && id == requestID {
				found = true
				break
			}
		}
	case []map[string]interface{}:
		for _, row := range list {
			if id, ok := toInt(row["request_id"]); ok && id == requestID {
				found = true
				break
			}
		}
	default:
		t.Fatalf("unexpected list response: %#v", listResp.Result)
	}
	if !found {
		t.Fatalf("expected request in list, got %#v", listResp.Result)
	}

	reviewArgs, err := json.Marshal(mcpReviewRequestArgs{RequestID: requestID})
	if err != nil {
		t.Fatalf("failed to marshal review args: %v", err)
	}
	reviewResp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("12"),
		Method:  "gate.review_request",
		Params:  reviewArgs,
	})
	if reviewResp == nil || reviewResp.Error != nil {
		t.Fatalf("expected review_request ok, got %#v", reviewResp)
	}
	reviewResult, ok := reviewResp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected review result map, got %#v", reviewResp.Result)
	}
	if reviewResult["why_blocked"] == nil {
		t.Fatalf("expected policy_result in review payload")
	}
	if reviewResult["stats"] == nil {
		t.Fatalf("expected stats in review payload")
	}
	if reviewResult["explanation_basis"] == nil {
		t.Fatalf("expected explanation_basis in review payload")
	}
	resolvedReview, ok := reviewResult["resolved"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected resolved map, got %#v", reviewResult["resolved"])
	}
	display, ok := resolvedReview["display"].(string)
	if !ok || strings.TrimSpace(display) == "" {
		t.Fatalf("expected resolved display")
	}

	getArgs, err := json.Marshal(mcpGetRequestArgs{RequestID: requestID})
	if err != nil {
		t.Fatalf("failed to marshal get args: %v", err)
	}
	getResp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("13"),
		Method:  "gate.get_request",
		Params:  getArgs,
	})
	if getResp == nil || getResp.Error != nil {
		t.Fatalf("expected get_request ok, got %#v", getResp)
	}

	approveArgs, err := json.Marshal(mcpReviewArgs{
		RequestID: requestID,
		User:      "human_01",
		Comment:   "ok",
	})
	if err != nil {
		t.Fatalf("failed to marshal approve args: %v", err)
	}
	approveResp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("14"),
		Method:  "gate.approve",
		Params:  approveArgs,
	})
	if approveResp == nil || approveResp.Error != nil {
		t.Fatalf("expected approve ok, got %#v", approveResp)
	}
	approveResult, ok := approveResp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("expected approve result map, got %#v", approveResp.Result)
	}
	outputFile, _ := approveResult["output_file"].(string)
	if strings.TrimSpace(outputFile) == "" {
		t.Fatalf("expected output_file in approve result, got %#v", approveResult)
	}
	if _, err := os.Stat(outputFile); err != nil {
		t.Fatalf("expected output file to exist, got %v", err)
	}
}

func TestMCPApproveFirstRequestNotInvalid(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	payload := []byte(`{"jsonrpc":"2.0","id":3,"method":"gate.approve","params":{"request_id":2,"user":"human_01","comment":"x"}}` + "\x00")
	resp := handleMCPPayload(payload)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code == -32600 {
		t.Fatalf("unexpected invalid request error: %#v", resp.Error)
	}
	if len(resp.ID) == 0 {
		t.Fatalf("expected error response to include id")
	}
}

func TestMCPDenyFirstRequestNotInvalid(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	payload := []byte(`{"jsonrpc":"2.0","id":4,"method":"gate.deny","params":{"request_id":2,"user":"human_01","comment":"x"}}` + "\x00")
	resp := handleMCPPayload(payload)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code == -32600 {
		t.Fatalf("unexpected invalid request error: %#v", resp.Error)
	}
	if len(resp.ID) == 0 {
		t.Fatalf("expected error response to include id")
	}
}

func TestMCPApproveMissingRequestIDReturnsInvalidParams(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	payload := []byte(`{"jsonrpc":"2.0","id":5,"method":"gate.approve","params":{"user":"human_01","comment":"x"}}`)
	resp := handleMCPPayload(payload)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
	}
	if resp.Error.Code != -32602 {
		t.Fatalf("expected invalid params, got %#v", resp.Error)
	}
	if len(resp.ID) == 0 {
		t.Fatalf("expected error response to include id")
	}
}

func TestMCPGetRequestNotFound(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	getArgs, err := json.Marshal(mcpGetRequestArgs{RequestID: 9999})
	if err != nil {
		t.Fatalf("failed to marshal get args: %v", err)
	}
	resp := handleMCPRequest(jsonrpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage("15"),
		Method:  "gate.get_request",
		Params:  getArgs,
	})
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response, got %#v", resp)
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
			AgentID:    "agent-1",
			Intent:     "execute",
			Target:     "repo",
			Reason:     "check",
			RiskLevel:  "low",
			Capability: "noop",
			Params:     map[string]string{},
		},
		ResolvedCommand: resolvedCommand{
			Path: "C:\\nonexistent\\noop.exe",
			Args: []string{},
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

	allowlist := `commands:
  - name: terraform_plan
    path: "terraform"
    args: ["plan"]
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Target:     "dev",
		RiskLevel:  "low",
		Capability: "terraform_plan",
		Params:     map[string]string{},
	}
	if _, err := resolveAllowedCommand(req); err == nil || !strings.Contains(err.Error(), "missing request param WORKDIR") {
		t.Fatalf("expected missing param error, got %v", err)
	}
}

func TestPolicyTerraformPlanSubcommandDenied(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: terraform_plan
    path: "terraform"
    args: ["apply"]
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Target:     "dev",
		RiskLevel:  "low",
		Capability: "terraform_plan",
		Params:     map[string]string{"WORKDIR": "c:\\infra"},
	}
	if _, err := resolveAllowedCommand(req); err == nil || !strings.Contains(err.Error(), "subcommand") {
		t.Fatalf("expected subcommand error, got %v", err)
	}
}

func TestPolicyGlobalDenyKubectlDelete(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: kubectl_diff
    path: "kubectl"
    args: ["delete", "pod", "x"]
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Target:     "dev",
		RiskLevel:  "medium",
		Capability: "kubectl_diff",
		Params:     map[string]string{"KUBECONTEXT": "dev"},
	}
	if _, err := resolveAllowedCommand(req); err == nil || !strings.Contains(err.Error(), "global policy") {
		t.Fatalf("expected global policy error, got %v", err)
	}
}

func TestPolicyKubectlDiffMissingContext(t *testing.T) {
	_, restore := withTempDir(t)
	defer restore()

	allowlist := `commands:
  - name: kubectl_diff
    path: "kubectl"
    args: ["diff"]
`
	writeAllowlist(t, allowlist)

	req := executionRequest{
		Target:     "dev",
		RiskLevel:  "medium",
		Capability: "kubectl_diff",
		Params:     map[string]string{},
	}
	if _, err := resolveAllowedCommand(req); err == nil || !strings.Contains(err.Error(), "missing request param KUBECONTEXT") {
		t.Fatalf("expected missing param error, got %v", err)
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

func resolvedCmd(path string, args ...string) resolvedCommand {
	return resolvedCommand{
		Path: path,
		Args: args,
	}
}

func toInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}
