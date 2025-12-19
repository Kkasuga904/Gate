

# Gate

Gate is a **human-approval execution gateway** for AI agents and automation tools.

It enforces a strict separation between:
- **Decision & audit metadata** (lightweight, persistent)
- **Execution output** (heavy, file-based)

Gate is designed for environments where **AI must not execute actions autonomously** without explicit policy or human approval.

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
    "command": "gather_logs",
    "reason": "diag",
    "risk_level": "medium"
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
    "command": "gather_logs",
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
