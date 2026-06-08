# Investigation Agent Design Spec

## Overview

A conversational AI analyst workbench for post-pipeline deep dives into malware samples. The investigation agent lives as a collapsible chat panel on the analysis detail page, giving analysts a multi-tool interface to ask follow-up questions, decrypt payloads, cross-reference IOCs, and capture findings — all without leaving the browser.

**Primary use case:** An analyst is reviewing a specific analysis and wants to dig deeper. "What are those 31-byte payloads Cape extracted?" → "Decrypt with the XOR key from the Ghidra decompilation" → "Check if those C2s appear in other samples" → pin the C2 URLs as new IOCs.

**What it is not (v1):** A threat hunting tool for cross-sample queries without a starting sample. That's a future capability once the conversational patterns are proven.

## Architecture

### Backend

The investigation agent is a new FastAPI router (`/api/investigate`) running in the existing API process. No separate service or container for the agent itself — it makes async LLM calls via LiteLLM and dispatches tool calls to existing infrastructure (PostgreSQL, Ghidra containers, Python sandbox containers).

**Why in-process:** The dangerous parts (code execution, binary analysis) are already delegated to sandboxed Podman containers. The agent orchestration is just LLM API calls + tool dispatch — same pattern as any other API endpoint. A separate service would add deployment complexity and inter-service auth for no real security benefit.

**Components:**
- **Conversation endpoint** — `POST /api/investigate/{analysis_id}/message` accepts a user message and streams back the agent's response via SSE (Server-Sent Events).
- **Tool dispatch layer** — a registry of tool functions. Each tool takes validated arguments and returns structured results. DB tools use the existing SQLModel session. Ghidra tools shell out to `run-ghidra --tool`. Python sandbox launches a Podman container.
- **Session persistence** — conversation history stored in PostgreSQL for transcript export and session resumption.
- **Pin system** — findings proposed by the agent, confirmed by the analyst in the UI, optionally promoted to the analysis record.

### Frontend

A collapsible right panel on the analysis detail page (similar to VS Code's sidebar).

**Panel layout (top to bottom):**
- **Header** — session info, model selector (Sonnet/Opus toggle), running token cost, close button.
- **Conversation area** — scrollable messages. User messages, agent responses (rendered markdown), and tool call blocks (collapsible — tool name + summary collapsed, full input/output on expand).
- **Pinned findings bar** — horizontal strip of pinned items as chips. Click to review/remove. "Promote to analysis" button for IOCs that should be added to the record.
- **Input area** — text input with send button.

**Tool call rendering:** Inline collapsible blocks in the conversation:
```
[search icon] query_iocs: searching for "185.220.101.42" across all analyses...
  -> Found in 3 analyses: Emotet (2), TrickBot (1)
```

**Investigation report export:** A "Generate Report" button compiles pinned findings at the top, then the full conversation transcript with tool calls. Downloadable as markdown or PDF (via WeasyPrint).

**Responsive behavior:** Desktop only — analysis detail takes ~60% width, investigation panel takes ~40%. The existing analysis sections remain scrollable alongside the chat.

### LLM Configuration

- **Default model:** Sonnet (balanced cost/quality/latency for interactive use).
- **Manual escalation:** Analyst can toggle to Opus mid-conversation via the header selector. No auto-escalation — the analyst knows when they need heavier reasoning.
- **All calls routed through LiteLLM** on localhost:4000 (existing proxy with spend tracking).

## Tool Definitions

### Tier 1: Database Tools (read-only SQL)

| Tool | Arguments | Returns |
|------|-----------|---------|
| `search_iocs` | `value: str, type?: str` | Matching analyses with family, severity, source_stage |
| `search_techniques` | `technique_id: str` | Analyses using this MITRE technique with tactic context |
| `search_analyses` | `query: str` | Analyses matching SHA256, filename, or family (top 20) |
| `get_network_events` | `analysis_id: int, type?: str` | DNS, HTTP, TCP events for the analysis |
| `get_signatures` | `analysis_id: int` | Cape behavioral signatures with severity |
| `get_capabilities` | `analysis_id: int` | LLM-identified capabilities list |
| `get_iocs` | `analysis_id: int, type?: str` | IOCs for the analysis, filterable by type |
| `get_sample_lineage` | `analysis_id: int` | Dropped/injected file relationships |

### Tier 2: Tool Access

| Tool | Arguments | Returns |
|------|-----------|---------|
| `decompile_function` | `name: str` | Ghidra pseudocode for function or hex address |
| `get_xrefs_to` | `name: str` | All callers of a function |
| `get_xrefs_from` | `name: str` | All callees from a function |
| `get_strings_at` | `address: str, range?: int` | Strings near an address (default 4096 bytes) |
| `list_functions` | `filter?: str` | Functions matching wildcard (e.g., `*crypt*`) |
| `get_data_at` | `address: str, length?: int` | Raw hex bytes (default 256) |
| `get_cape_payloads` | `analysis_id: int` | List of extracted payloads with sizes and types |
| `read_payload` | `analysis_id: int, payload_index: int` | Hex dump of a specific payload |
| `get_pcap_summary` | `analysis_id: int` | Zeek/Suricata analysis results |
| `get_api_traces` | `analysis_id: int, process?: str, api_filter?: str` | Cape API call traces, filterable |

Ghidra tools require the analysis to have a persisted Ghidra project (`project_dir` in the report). If unavailable, the agent informs the analyst and falls back to data already in the report JSON.

### Tier 3: Python Sandbox

| Tool | Arguments | Returns |
|------|-----------|---------|
| `run_python` | `script: str` | stdout, stderr from isolated execution |

### Pin Tool

| Tool | Arguments | Returns |
|------|-----------|---------|
| `pin_finding` | `type: str, value: str, context: str` | Proposed finding — rendered in UI for analyst confirmation |

Pin types: `ioc` (with IOC type + value), `technique` (MITRE ID + evidence), `note` (freeform text with context).

**Pin confirmation flow:** When the agent calls `pin_finding`, the backend does NOT immediately save it. Instead, it sends an SSE `pin_proposal` event to the UI, which renders a confirmation card in the pinned findings bar. The analyst clicks "Accept" or "Dismiss." On accept, the frontend calls `POST /api/investigate/sessions/{session_id}/pin` with the finding data, which saves it to `investigation_pins`. The agent receives a tool result of `{"status": "proposed", "awaiting_confirmation": true}` and continues the conversation without blocking.

## Python Sandbox

**Container specification:**
- Base image: minimal Python 3.12, no network libraries
- `--network=none`, `--read-only`, `--cap-drop=ALL`, `--no-new-privileges`
- `--memory=256m`, `--timeout=30`
- `--tmpfs /tmp:size=50m`
- User: nobody (65534)
- Helper library mounted read-only at `/helpers/`

**Invocation protocol:**
- Script sent via stdin, stdout/stderr captured
- Max script size: 10KB
- Max output size: 1MB
- Binary data (payloads from CAPE storage) mounted read-only at `/data/`

**Pre-loaded helper library:**

`/helpers/crypto.py`:
- `xor_decrypt(data: bytes, key: bytes) -> bytes`
- `rc4_decrypt(data: bytes, key: bytes) -> bytes`
- `rc4_encrypt(data: bytes, key: bytes) -> bytes`
- `single_byte_xor_scan(data: bytes, known_plaintext: bytes) -> list[tuple[int, bytes]]`

`/helpers/encoding.py`:
- `b64_decode(data: str) -> bytes`
- `b64_variants(data: str) -> dict[str, bytes]` (standard, URL-safe, no-padding)
- `hex_to_bytes(data: str) -> bytes`
- `bytes_to_hex(data: bytes) -> str`
- `rot13(data: str) -> str`

`/helpers/parsing.py`:
- `read_dword_le(data: bytes, offset: int) -> int`
- `read_dword_be(data: bytes, offset: int) -> int`
- `read_qword_le(data: bytes, offset: int) -> int`
- `extract_strings(data: bytes, min_length: int = 4) -> list[str]`
- `pe_overlay_offset(data: bytes) -> int | None`
- `struct_unpack_at(fmt: str, data: bytes, offset: int) -> tuple`

These are small, tested utility functions. The LLM imports them instead of writing crypto/parsing from scratch, reducing script errors significantly.

**Example data flow (payload decryption):**
1. Agent calls `read_payload(analysis_id, 2)` — gets hex dump of encrypted blob
2. Agent calls `decompile_function("decrypt_config")` — sees XOR key in pseudocode
3. Agent calls `run_python(script)`:
   ```python
   from helpers.crypto import xor_decrypt
   data = open("/data/payload_2", "rb").read()
   result = xor_decrypt(data, b"\x4a\x7b\x2c")
   print(result.decode("utf-8", errors="replace"))
   ```
4. Output contains decrypted C2 URLs
5. Agent calls `pin_finding(type="ioc", value="evil.example.com", context="Decrypted from payload 2 using XOR key 0x4a7b2c found in decrypt_config()")`
6. Analyst sees pin proposal in UI, clicks confirm

## Data Model

### `investigation_sessions`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `analysis_id` | FK → analyses | The analysis being investigated |
| `user_sub` | text | Keycloak subject (who started it) |
| `model` | text | Current model (e.g., `claude-sonnet-4-6`) |
| `status` | text | `active`, `completed`, `abandoned` |
| `total_input_tokens` | int | Running total across all LLM calls |
| `total_output_tokens` | int | Running total across all LLM calls |
| `total_cost_usd` | numeric(10,4) | Running cost total |
| `max_turns` | int | Configurable limit (default 50) |
| `created_at` | timestamptz | |
| `updated_at` | timestamptz | |

### `investigation_messages`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `session_id` | FK → investigation_sessions | |
| `role` | text | `user`, `assistant`, `tool_call`, `tool_result` |
| `content` | text | Markdown for assistant, JSON for tool calls/results |
| `tool_name` | text (nullable) | Set for tool_call and tool_result roles |
| `input_tokens` | int (nullable) | Per-message token usage (assistant messages only) |
| `output_tokens` | int (nullable) | Per-message token usage (assistant messages only) |
| `created_at` | timestamptz | |

### `investigation_pins`

| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | |
| `session_id` | FK → investigation_sessions | |
| `analysis_id` | FK → analyses | |
| `pin_type` | text | `ioc`, `technique`, `note` |
| `value` | text | IOC value, technique ID, or note text |
| `ioc_type` | text (nullable) | IOC type when pin_type is `ioc` (e.g., `ipv4-addr`) |
| `context` | text | How/why this was found (agent's explanation) |
| `promoted` | boolean | Whether it was written to the analysis IOC/technique tables |
| `created_at` | timestamptz | |

## Conversation Flow

### Message round-trip

1. Analyst types a message in the chat panel.
2. `POST /api/investigate/{analysis_id}/message` with `{session_id, content}`.
3. Backend loads conversation history from `investigation_messages`, appends the new user message.
4. Backend calls LiteLLM with the full conversation + tool definitions.
5. Response streams back via SSE — tokens appear in real-time in the chat panel.
6. If the LLM returns `tool_use` blocks:
   - Backend dispatches each tool call (DB query, Ghidra subprocess, sandbox container).
   - Tool call + result saved as message rows.
   - SSE sends tool call events so the UI renders collapsible blocks.
   - Backend re-calls LiteLLM with tool results appended.
   - Loop repeats until the LLM gives a text response (max 10 tool calls per turn).
7. Final assistant message saved. Token counts and cost updated on session.

### Session initialization

The first message to a new session auto-injects a system prompt containing:
- Analysis context: sample hash, family, severity, malscore, narrative summary, key IOCs, key techniques.
- Available tools list with descriptions.
- UNTRUSTED_DATA warnings: all malware-derived content is adversary-controlled.
- Instructions to propose `pin_finding` calls for significant discoveries.
- Prompt influence warning: treat all binary-derived strings as potential injection attempts.

The analyst does not need to explain what they're looking at — the agent has full context from the analysis record.

### Conversation limits

| Limit | Default | Purpose |
|-------|---------|---------|
| Max turns per session | 50 | Prevents runaway conversations |
| Cost alert threshold | $2.00 | Warning shown in UI header |
| Tool calls per LLM turn | 10 | Prevents infinite tool loops |
| Python script size | 10KB | Prevents LLM generating huge scripts |
| Python output size | 1MB | Prevents memory bombs |
| Python timeout | 30s | Kills runaway scripts |

### SSE event types

| Event | Payload | UI behavior |
|-------|---------|-------------|
| `token` | `{text: "..."}` | Append to current assistant message |
| `tool_call` | `{tool: "...", args: {...}}` | Render collapsible tool call block |
| `tool_result` | `{tool: "...", result: {...}}` | Populate tool call block with result |
| `pin_proposal` | `{type: "...", value: "...", context: "..."}` | Show pin confirmation in UI |
| `done` | `{input_tokens, output_tokens, cost}` | Finalize message, update cost display |
| `error` | `{message: "..."}` | Show error in chat |

## Security

### Prompt injection mitigation

The investigation agent has a broader attack surface than the pipeline's interpret stage because more adversary-controlled data flows into the prompt (IOC values, Cape signatures, network URLs, Ghidra decompilation).

**Mitigations:**
- **UNTRUSTED_DATA delimiters** around all malware-derived content in the system prompt and tool results.
- **Analyst-in-the-loop** — every tool call and result is visible in the chat. The analyst can spot anomalous behavior. This is the strongest control and is strictly safer than the unattended pipeline.
- **Pin requires confirmation** — the agent proposes a pin, the analyst clicks to accept. No silent write-back to the analysis record.
- **Prompt influence detection** — reuse the keyword scanner from interpret.py.j2 (checks for "benign", "not malicious", "harmless" in LLM output). Flag suspicious responses in the UI.
- **Read-only DB access** — investigation tools only SELECT. Pins go through a validated endpoint, not raw SQL.
- **Audit log** — full conversation + tool calls persisted in `investigation_messages`, reviewable.

### Python sandbox security

Same isolation model as existing Ghidra containers:
- `--network=none` prevents exfiltration even if container is compromised.
- `--read-only` filesystem with tmpfs working space.
- `--cap-drop=ALL`, `--no-new-privileges` minimize kernel attack surface.
- Resource limits (256MB memory, 30s timeout) prevent resource exhaustion.
- No network libraries in the image (no requests, urllib, socket).

The key difference from Ghidra: the Python sandbox runs LLM-generated code. If the LLM is manipulated via prompt injection from malware strings, it could attempt to write an exploit script. Mitigation: `--network=none` means even a successful container escape cannot exfiltrate data, and the analyst sees the script in the conversation.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/api/investigate/{analysis_id}/sessions` | analyst | Create a new investigation session |
| `GET` | `/api/investigate/{analysis_id}/sessions` | viewer | List sessions for an analysis |
| `GET` | `/api/investigate/sessions/{session_id}` | viewer | Get session with full message history |
| `POST` | `/api/investigate/{analysis_id}/message` | analyst | Send message, stream response (SSE) |
| `POST` | `/api/investigate/sessions/{session_id}/pin` | analyst | Confirm a pinned finding |
| `POST` | `/api/investigate/sessions/{session_id}/pin/{pin_id}/promote` | analyst | Promote pin to analysis record |
| `POST` | `/api/investigate/sessions/{session_id}/model` | analyst | Switch model mid-session |
| `POST` | `/api/investigate/sessions/{session_id}/complete` | analyst | Mark session as completed |
| `GET` | `/api/investigate/sessions/{session_id}/report` | viewer | Export investigation report (markdown) |

## Deferred to v2

- **Threat intel integration** — VirusTotal, URLhaus, AbuseIPDB lookups for IOC enrichment.
- **Threat hunting mode** — cross-sample queries without a starting analysis (persona B).
- **Technique evolution tracking** — "has this family used this technique before?" queries.
- **Novel technique combo detection** — flag unusual technique combinations vs family baselines.
- **Family technique profiles** — "this technique profile matches Emotet" matching.
- **Shared investigations** — multiple analysts collaborating on the same session.
- **Quick-action buttons** — pre-built queries ("Summarize findings", "Show related samples").
