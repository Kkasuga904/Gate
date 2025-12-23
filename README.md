

# Gate
Gate prevents AI agents from executing high-risk actions
without explicit human approval and audit logs.

AI can propose actions.
Humans (or policies) decide.
Gate is the only component that executes.
> **Vision & Standard:** Gate is part of a larger architecture for enterprise AI agent governance.  
> Read our [VISION.md](./VISION.md) for the core principles of the Gate execution model.

Gate is a **human-approval execution gateway** for AI agents and automation tools.

It enforces a strict separation between:
- **Decision & audit metadata** (lightweight, persistent)
- **Execution output** (heavy, file-based)

Gate is designed for environments where **AI must not execute actions autonomously** without explicit policy or human approval.

## Ecosystem
Gate is a standardized control plane. For specific implementations, see:
- **[RiskGuard](https://github.com/Kkasuga904/RiskGuard)**: The core policy and risk evaluation engine.
- **[WinOps-Guard](https://github.com/Kkasuga904/WinOps-Guard)**: A reference implementation for secure Windows infrastructure operations.

## Core concept

AI can propose actions. Humans (or policies) decide. Gate executes only after approval.

Gate guarantees:
- No silent execution
- No uncontrolled side effects
- Audit-friendly records
- Output isolation

## Architecture overview

```text
AI Agent
  |
  | (execution request)
  v
+-------------------------------+
| Gate                          |
| - Policy evaluation           |
| - Human approval              |
| - Execution control           |
+-------------------------------+
  |
  | (approved only)
  v
Command execution
  |
  +-> outputs/request-<id>.txt
```

## Data model

### requests.json (persistent audit index)

`requests.json` is **NOT** an execution log.

It stores only **decision and audit metadata**:
- Request identity
- Intent and parameters
- Approval / denial decisions
- Execution state

It never stores execution output.

Example:
```json
{
  "id": 5,
  "request": {
    "agent_id": "triage-ai",
    "intent": "gather_logs",
    "env": "test",
    "target": "host01",
    "capability": "gather_logs",
    "params": {},
    "reason": "diag",
    "risk_level": "medium"
  },
  "resolved_command": {
    "path": "C:\\Windows\\System32\\wevtutil.exe",
    "args": ["qe", "System", "/c:10"]
  },
  "status": "approved",
  "decision": "approved",
  "decision_by": "human_01",
  "decision_at": "2025-12-19T09:05:12Z",
  "comment": "safe to execute",
  "executed": true
}
```

### outputs/ (execution output store)

All execution results are written to files:

```text
outputs/
└── request-5.txt
```

Rules:
- Created only when a request is approved and executed
- Contains stdout / stderr of the execution
- Written atomically (`.tmp` → rename)
- Never embedded in `requests.json`

### Execution rules

| State | Executed | Output file |
| --- | --- | --- |
| policy denied | no | no |
| human denied | no | no |
| pending approval | no | no |
| approved & executed | yes | yes |

## API

### Submit execution request

```powershell
curl.exe -X POST http://localhost:8080/execution/request `
  -H "Content-Type: application/json" `
  -d '{
    "agent_id": "triage-ai",
    "intent": "gather_logs",
    "env": "test",
    "target": "host01",
    "capability": "gather_logs",
    "params": {},
    "reason": "diagnostics",
    "risk_level": "medium"
  }'
```

Response:
```json
{
  "message": "awaiting human approval via CLI",
  "request_id": 5,
  "require_approval": true,
  "status": "pending"
}
```

### Request schema (command-less)

Required fields:
- `agent_id`
- `intent`
- `target`
- `capability`
- `params`
- `reason`
- `risk_level`

Optional fields:
- `env`
- `resources`
- `operation`

The `command` field is rejected. Use `capability` + `params` only.

### Allowlist resolution

`allowlist.yaml` defines the executable path and args for each capability:

```yaml
commands:
  - name: restart_service
    path: "C:\\Windows\\System32\\net.exe"
    args: ["stop", "Spooler"]

  - name: echo_test
    path: "C:\\Windows\\System32\\cmd.exe"
    args: ["/C", "echo", "{TEXT}"]
    vars:
      TEXT:
        pattern: "^[A-Za-z0-9._-]{1,32}$"
```

Placeholders in args use `{PARAM}` and are replaced from request `params`.
If required params are missing or validation fails, the request is rejected.
Execution uses `exec.Command(path, args...)` only (no shell string execution).

## MCP (stdio JSON-RPC)

In MCP mode, stdout is reserved for JSON-RPC frames only. All logs and debug output go to stderr.

```powershell
go run . mcp
```

### MCP methods

Key methods:
- `gate.execute_request`
- `gate.approve`
- `gate.deny`
- `gate.get_request`
- `gate.list_requests`
- `gate.review_request`
- `gate.list_capabilities`

`gate.approve` and `gate.deny` work as the first request in a session (no warm-up call required).

Example `gate.execute_request`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "gate.execute_request",
  "params": {
    "agent_id": "triage-ai",
    "intent": "gather_logs",
    "target": "host01",
    "capability": "gather_logs",
    "params": {},
    "reason": "diagnostics",
    "risk_level": "medium"
  }
}
```

Example `gate.get_request`:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "gate.get_request",
  "params": { "request_id": 5 }
}
```

Example `gate.list_requests`:

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "gate.list_requests",
  "params": { "status": "pending", "limit": 50 }
}
```

Example `gate.review_request`:

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "gate.review_request",
  "params": { "request_id": 5 }
}
```

Review responses include deterministic stats:
- `similar_strict_count` / `strict_success_rate` (capability + path + args + target)
- `similar_relaxed_count` / `relaxed_success_rate` (capability + path + target, args ignored)
- `capability_history_count` (capability + target history)
- `anomaly_score` with an explicit formula in `explanation_basis` (relaxed-based)
- Similarity uses `target` (lowercased/trimmed, empty -> `unknown`)
Executed outcomes only:
- strict/relaxed success rates exclude pending/denied requests
- `similar_pending_count` and `similar_denied_count` are reported for context
Backward compatibility:
- `similar_cases_count` and `historical_success_rate` mirror the relaxed values

### MCP client (PowerShell)

Use `tools/mcp_send.ps1` to send multiple frames over a single MCP session.

```powershell
.\tools\mcp_send.ps1 -ServerExe go -ServerArgs @("run",".","mcp") `
  -RequestsFile .\tools\requests-demo.jsonl -Pretty -Verbose -TimeoutMs 5000
```

`tools/requests-demo.jsonl` uses a `{{request_id}}` placeholder in subsequent frames,
which is replaced with the `request_id` returned by `gate.execute_request`.
`-TimeoutMs` controls the stdout read timeout (milliseconds).

### MCP client (Go)

`cmd/gatec` provides the same framing behavior for automation:

```powershell
go run .\cmd\gatec\main.go send --file .\tools\requests-demo.jsonl --pretty
```

If auto-approve is enabled and triggered, review also includes `auto_approved` and `auto_approve_reason`.

## CLI approval flow

### Approve and execute

```powershell
go run . approve --request-id 5 --user human_01 --comment "Reviewed and safe"
```

Result:
```text
approved and executed request 5
```

Execution output:
```powershell
type outputs\request-5.txt
```

### Deny request

```powershell
go run . deny --request-id 5 --user human_01 --comment "Out of policy"
```

Effects:
- No execution
- No output file
- Status recorded in `requests.json`

## Design principles

### 1) Output isolation

Execution output can be large, sensitive, and noisy. Therefore:
- Never stored in JSON
- Always written to files
- JSON remains small and diff-friendly

### 2) Human-in-the-loop by default

AI cannot execute directly.

All non-trivial actions require:
- Explicit policy allow, or
- Explicit human approval

### 3) Audit first

`requests.json` acts as:
- An audit ledger
- A decision timeline
- A compliance artifact

Execution output is referenced by request-id, not embedded.

## Intended use cases
- AI-driven infrastructure remediation
- Windows / server operations with approval gates
- SOC / SRE runbook execution
- Regulated environments
- “AI suggests, humans approve” workflows

## Non-goals

Gate is not:
- A full orchestration engine
- A scheduler
- A general-purpose task runner

It is intentionally minimal and strict.

## Status
- Core execution flow implemented
- Output isolation enforced
- Human approval enforced
- Policy language extensibility (future)
- Remote output storage (future)

## Philosophy

AI should not be trusted with execution. AI should be trusted with suggestions. Humans stay accountable.

Gate exists to enforce that boundary.
