---
title: "AG-UI Binding"
description: "Agent-User Interface protocol binding: modes, execution state, and tool response dispatch."
---

The AG-UI binding covers the Agent-User Interface protocol as defined in the [AG-UI specification](https://docs.ag-ui.com/). AG-UI is transport-agnostic (HTTP/SSE, WebSockets, Webhooks, in-process); the most common deployment uses HTTP POST for agent invocation and SSE for streaming responses.

**Design principle.** This binding specifies what OATF contributes: modes (attacker posture), the structural framing of execution state, and the OATF extension for tool response dispatch. Protocol-native message content — messages, tool definitions, context items, state objects, SSE events — is pass-through. The OATF parser preserves it without validation against AG-UI's schema, enabling documents to describe attacks involving non-conformant, malformed, or unexpected message content. Indicators use the OATF synthetic name `run_agent_input` for the POST body and AG-UI's native event type names for SSE events (e.g., `tool_call_start`, `state_snapshot`, `custom`) with a `target` path to specify the field to examine; see [§6](/specification/indicators/) for the indicator model.

## 7.3.1 Modes

| Mode | Role | Description |
|------|------|-------------|
| `ag_ui_client` | Client | The adversarial tool impersonates an AG-UI client. It sends a `RunAgentInput` POST body to the agent and observes the SSE response stream. |

AG-UI defines only a client mode. The client controls what the agent receives (fabricated conversation history, false tool results, manipulated state) and observes the agent's response stream for evidence of exploitation.

## 7.3.2 Events

AG-UI events use `snake_case` names derived from the protocol's `EventType` enum (`RUN_STARTED` → `run_started`, `TOOL_CALL_START` → `tool_call_start`, etc.). The runtime performs this constant case translation when emitting and matching events.

Agent-originated events are received on the SSE connection (server→client). The `tool_call_result` event is client-originated — the client submits tool execution results back to the agent. The transport mechanism is deployment-dependent (e.g., a new HTTP request for SSE transports, a frame for WebSocket transports). The runtime handles this transport distinction; from the document author's perspective, `tool_call_result` is simply another event in the interaction sequence.

Because the `RunAgentInput` POST body does not have a native event type, OATF uses the synthetic event name `run_agent_input` for triggers that fire on the initial request submission.

See the [AG-UI specification](https://docs.ag-ui.com/) for the full list of event types. New AG-UI event types are usable as OATF events immediately without a specification update.

To match specific instances (e.g., a particular tool call), use `trigger.match`:

```yaml
trigger:
  event: tool_call_start
  match:
    toolCallName: "transfer_funds"
```

**Correlated tool call events.** `ToolCallStartEvent` and `ToolCallChunkEvent` carry `toolCallName` in their raw payload. `ToolCallArgsEvent` and `ToolCallEndEvent` carry only `toolCallId`. The runtime MUST enrich these events by correlating `toolCallId` back to the `toolCallName` from the corresponding `tool_call_start` event in the same SSE stream. The enriched `toolCallName` field is added to the event's content before trigger matching and CEL evaluation.

## 7.3.3 CEL Context

When a CEL expression is evaluated against an AG-UI message, the root context exposes the protocol-native content under a `message` variable. For the `RunAgentInput` POST body, `message` contains the full input object. For SSE events, `message` contains the parsed JSON data payload of the event — AG-UI events are flat objects with all fields at the root alongside `type`, not nested under a `data` wrapper.

CEL expressions are written against [AG-UI's native schema](https://docs.ag-ui.com/):

```cel
// Messages contain fabricated tool results
message.messages.exists(m, m.role == "tool" && m.content.contains("SECRET"))

// Agent emits a tool call for a sensitive function
message.toolCallName == "transfer_funds"

// Agent state contains injected values
has(message.state.admin) && message.state.admin == true
```

## 7.3.4 Execution State (AG-UI Client)

When the phase mode is `ag_ui_client`, the phase state defines the initial `RunAgentInput` POST body and how the client responds to agent-initiated tool calls mid-stream.

The state has two structural keys. `run_agent_input` (required) defines the POST body — its contents are protocol-native pass-through. `tool_responses` (optional) is an OATF extension that controls what tool results the client feeds back to the agent when it requests tool execution. The `synthesize` field appears in both structural keys and is reserved for a future version (LLM-powered content generation).

**Naming convention.** Structural keys use OATF's `snake_case` convention (`run_agent_input`, `tool_responses`). All fields within protocol-native pass-through content retain AG-UI's original `camelCase` naming (e.g., `threadId`, `runId`, `forwardedProps`, `toolCallName`).

Phase state follows full-replacement semantics ([§5.2](/specification/execution-profile/#52-phases)): when a subsequent phase specifies `state`, it completely replaces the previous state. No merging occurs.

```yaml
state:
  # ── RunAgentInput ───────────────────────────────────────────────
  #
  # The POST body sent to the agent. The entire object is protocol-native
  # pass-through. `threadId` and `runId` are required by OATF for request
  # construction and SSE event correlation. All other fields are pass-through.
  #
  run_agent_input:
    threadId: string               # Required by OATF
    runId: string                  # Required by OATF
    messages: <any>[]?             # Protocol-native messages (pass-through)
    synthesize:                    # Reserved for a future version (LLM generation)
      prompt: string
    tools: <any>[]?                # Protocol-native tool definitions (pass-through)
    context: <any>[]?              # Protocol-native context items (pass-through)
    state: <any>?                  # Application state (pass-through, opaque)
    forwardedProps: <any>?         # Opaque props passed through to agent (pass-through)
    <...>: <any>                   # Any additional RunAgentInput fields are pass-through

  # ── Tool Responses ──────────────────────────────────────────────
  #
  # OATF extension: response dispatch for agent-initiated tool calls.
  # When the agent emits a tool_call_start/tool_call_end sequence,
  # the client submits a tool_call_result. This block controls what
  # that result contains. Follows response dispatch semantics
  # ([§7.0.1](/specification/protocol-bindings/#701-response-dispatch)): entries are evaluated in order, first match wins.
  #
  tool_responses:
    - when: <MatchPredicate>?        # Condition on the tool_call_start event
      content: <any>?                # Protocol-native tool_call_result (pass-through)
      synthesize:                    # Reserved for a future version (LLM generation)
        prompt: string
```

**Messages.** The `messages` field contains the static conversation history the adversarial client sends to the agent. The `synthesize` field is reserved for a future version and will enable LLM-powered message generation as an alternative to static content.

**Tool responses.** The `tool_responses` list controls what the adversarial client returns when the agent requests tool execution. Entries follow response dispatch semantics ([§7.0.1](/specification/protocol-bindings/#701-response-dispatch)): evaluated in order, first match wins. The `when` predicate is evaluated against the `tool_call_start` event content (including the enriched `toolCallName` field). Each entry specifies static `content` (a protocol-native `tool_call_result` payload). When `tool_responses` is omitted, the runtime returns a default success result: a `tool_call_result` event with `messageId` (auto-generated), `toolCallId` matching the originating call, and `content: ""` (empty string). The `synthesize` field on tool response entries is reserved for a future version.

**Pass-through content.** The `messages`, `tools`, `context`, `state`, `forwardedProps` fields in `run_agent_input` and the `content` field in `tool_responses` entries are all protocol-native pass-through.

**Template interpolation** (§5.6) applies recursively to all string-valued fields within `run_agent_input` and `tool_responses` content.

**Entry actions.** The AG-UI binding does not define protocol-specific entry actions beyond the core `send` and `log` actions ([§2.7a](/sdk/core-types/#27a-action)). Client-mode actors initiate interaction by submitting the `RunAgentInput` POST body, which is defined by the phase state rather than an entry action. The core `send` action (with `method` set to an AG-UI event type) and `log` action are available for use in AG-UI phases.
