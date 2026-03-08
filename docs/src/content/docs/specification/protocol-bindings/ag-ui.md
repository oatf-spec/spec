---
title: "AG-UI Binding"
description: "Agent-User Interface protocol binding: surfaces, events, CEL context, and execution state."
---

The AG-UI binding covers the Agent-User Interface protocol as defined in the [AG-UI specification](https://docs.ag-ui.com/). AG-UI is transport-agnostic (HTTP/SSE, WebSockets, Webhooks, in-process); the most common deployment uses HTTP POST for agent invocation and SSE for streaming responses. This binding is provisional: core surfaces, event types, and execution state are defined, but behavioral modifiers and deterministic payload generation (`generate` blocks) are not yet specified. LLM-powered response generation (`synthesize`) is defined in [§7.4](/specification/protocol-bindings/llm-synthesis/). Future OATF minor versions will expand this binding.

## 7.3.1 Surfaces

| Surface | Description | Default Target | Applicable Context |
|---------|-------------|----------------|-------------------|
| `message_history` | The `messages` array in the RunAgentInput | `messages[*]` | Agent invocation |
| `tool_definition` | The `tools` array in the RunAgentInput | `tools[*]` | Agent invocation |
| `tool_result` | A tool result message in the messages array | `messages[*]` | Agent invocation |
| `agent_state` | The `state` object in the RunAgentInput | `state` | Agent invocation |
| `agent_context` | The `context` array in the RunAgentInput | `context[*]` | Agent invocation |
| `forwarded_props` | The `forwardedProps` in the RunAgentInput | `forwardedProps` | Agent invocation |
| `agent_event` | An SSE event in the agent's response stream | `""` (root) | Agent response |
| `agent_tool_call` | A tool call event in the response stream | `""` (root) | Agent response |

## 7.3.2 Event Types

AG-UI events are defined for `ag_ui_client` mode only. AG-UI uses a unidirectional streaming model where the client sends a `RunAgentInput` and the agent streams back SSE events, so all events are from the agent's response stream.

| Event | AG-UI EventType | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `run_started` | `RUN_STARTED` | Agent begins execution | — |
| `run_finished` | `RUN_FINISHED` | Agent completes execution | — |
| `run_error` | `RUN_ERROR` | Agent reports error | — |
| `step_started` | `STEP_STARTED` | Agent begins a step | — |
| `step_finished` | `STEP_FINISHED` | Agent completes a step | — |
| `text_message_start` | `TEXT_MESSAGE_START` | Agent begins text message | — |
| `text_message_content` | `TEXT_MESSAGE_CONTENT` | Agent streams text chunk | — |
| `text_message_end` | `TEXT_MESSAGE_END` | Agent completes text message | — |
| `tool_call_start` | `TOOL_CALL_START` | Agent initiates tool call | `:tool_name` |
| `tool_call_args` | `TOOL_CALL_ARGS` | Agent streams tool call arguments | `:tool_name` |
| `tool_call_end` | `TOOL_CALL_END` | Agent completes tool call | `:tool_name` |
| `tool_call_result` | `TOOL_CALL_RESULT` | Client returns tool result to agent | — |
| `state_snapshot` | `STATE_SNAPSHOT` | Agent sends full state | — |
| `state_delta` | `STATE_DELTA` | Agent sends state patch | — |
| `messages_snapshot` | `MESSAGES_SNAPSHOT` | Agent sends message history | — |
| `activity_snapshot` | `ACTIVITY_SNAPSHOT` | Agent sends full activity state | — |
| `activity_delta` | `ACTIVITY_DELTA` | Agent sends activity patch | — |
| `reasoning_start` | `REASONING_START` | Agent begins reasoning trace | — |
| `reasoning_message_start` | `REASONING_MESSAGE_START` | Agent begins reasoning message | — |
| `reasoning_message_content` | `REASONING_MESSAGE_CONTENT` | Agent streams reasoning chunk | — |
| `reasoning_message_end` | `REASONING_MESSAGE_END` | Agent completes reasoning message | — |
| `reasoning_message_chunk` | `REASONING_MESSAGE_CHUNK` | Agent streams reasoning chunk (compact) | — |
| `reasoning_end` | `REASONING_END` | Agent completes reasoning trace | — |
| `reasoning_encrypted_value` | `REASONING_ENCRYPTED_VALUE` | Agent emits encrypted reasoning value | — |
| `raw` | `RAW` | Raw passthrough event | — |
| `custom` | `CUSTOM` | Agent sends custom event | `:event_name` |

Event names use `snake_case` derived from AG-UI's `EventType` enum. The mapping from OATF event names to AG-UI's SCREAMING_SNAKE enum values is a constant translation. Adversarial tools MUST perform this translation when emitting events.

**Qualifier resolution** for AG-UI events:

- `tool_call_start:X` → matches when `toolCallName == "X"`
- `tool_call_args:X` → matches when `toolCallName == "X"`
- `tool_call_end:X` → matches when `toolCallName == "X"`
- `custom:X` → matches when `name == "X"`

For filtering by `toolCallId` or other structured fields, use `trigger.match`.

All AG-UI events are valid only on `ag_ui_client` actors. Using AG-UI events on any other mode is a validation error (V-029).

## 7.3.3 CEL Context (AG-UI)

When a CEL expression is evaluated against an AG-UI message, the root context object `message` is constructed as follows.

#### `RunAgentInput` POST body

See [AG-UI Types](https://docs.ag-ui.com/sdk/js/core/types) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.messages[]` | array | — | RunAgentInput |
| `message.tools[]` | array | — | RunAgentInput |
| `message.tools[].name` | string | — | Tool |
| `message.tools[].description` | string | — | Tool |
| `message.tools[].parameters` | object | — | Tool |
| `message.context[]` | array | — | RunAgentInput |
| `message.context[].description` | string | — | Context |
| `message.context[].value` | string | — | Context |
| `message.state` | object | — | RunAgentInput |
| `message.forwardedProps` | object | — | RunAgentInput |
| `message.threadId` | string | — | RunAgentInput |
| `message.runId` | string | — | RunAgentInput |
| `message.parentRunId` | string | — | RunAgentInput |

#### Agent response events (SSE)

AG-UI events are flat: all fields live alongside `type` at the root, not nested under a `data` wrapper. The exact fields vary by event type; common fields are shown below.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.type` | string | yes | BaseEvent |
| `message.timestamp` | number | — | BaseEvent |
| `message.rawEvent` | object | — | BaseEvent |
| `message.messageId` | string | — | TextMessageStartEvent, TextMessageEndEvent |
| `message.role` | string | — | TextMessageStartEvent |
| `message.delta` | string | — | TextMessageContentEvent |
| `message.toolCallId` | string | — | ToolCallStartEvent, ToolCallArgsEvent, ToolCallEndEvent |
| `message.toolCallName` | string | — | ToolCallStartEvent |
| `message.delta` | string | — | ToolCallArgsEvent |
| `message.result` | string | — | ToolCallEndEvent |
| `message.snapshot` | object | — | StateSnapshotEvent, MessagesSnapshotEvent, ActivitySnapshotEvent |

## 7.3.4 Execution State (AG-UI)

When the phase mode is `ag_ui_client`, the phase state defines the AG-UI client's request content:

```yaml
state:
  run_agent_input:
    messages:                        # Static content (mutually exclusive with synthesize)
      - id: string
        role: enum(developer, system, user, assistant, tool, activity, reasoning)
        content: string?             # String for most roles; structured for activity
        name: string?                # Optional sender name
        toolCallId: string?          # Required for tool role
        toolCalls:                   # For assistant messages proposing tool use
          - id: string
            type: "function"
            function:
              name: string
              arguments: string      # JSON string
    synthesize:                      # LLM generation (mutually exclusive with messages)
      prompt: string                 # Supports {{template}} interpolation
    tools:
      - name: string
        description: string
        parameters: object           # JSON Schema
    context:                         # Context items provided to the agent
      - description: string
        value: string
    state: object?
    forwardedProps: object?
    threadId: string?
    runId: string?
    parentRunId: string?             # Parent run ID for nested agent invocations
```

**Input synthesis semantics.** Within `run_agent_input`, `messages` and `synthesize` are mutually exclusive. When `synthesize` is present, the adversarial tool MUST generate the `messages` array at runtime using an LLM. The `prompt` field describes the conversation history to fabricate: the LLM produces the messages, not the entire `RunAgentInput`. The structural fields (`tools`, `context`, `state`, `forwardedProps`, `threadId`, `runId`) remain static because the attacker typically knows exactly what tool definitions, context, and state to inject; it is the conversation history that benefits from adaptive generation.

This follows the same principle as server-mode `synthesize` ([§7.4](/specification/protocol-bindings/llm-synthesis/)): the LLM generates the *content*, while the document author controls the *structure*. For MCP/A2A the content is the response payload; for AG-UI the content is the fabricated message history. See [§7.4](/specification/protocol-bindings/llm-synthesis/) for cross-protocol synthesis details. Template interpolation ([§5.6](/specification/execution-profile/#56-response-templates)) applies to string fields in `messages`, `tools`, and `synthesize.prompt`.

**Tool format.** AG-UI tools use a flat structure: `{ name, description, parameters }` where `parameters` is a JSON Schema object. This differs from the OpenAI function-calling wrapper format (`{ type: "function", function: { ... } }`). The `messages[].toolCalls` field within assistant messages does use the OpenAI wrapper format because AG-UI messages follow the OpenAI chat completion message shape.

## 7.3.5 AG-UI-Specific Attack Considerations

The primary attack surface is the client-to-agent direction: the `RunAgentInput` fields (`messages`, `tools`, `context`, `state`) in the POST body. The `context` array is particularly significant: each `Context` item has a `description` that the agent may display or use for reasoning, and a `value` that the agent may incorporate into its responses. Attacker-controlled `context[].description` values can mislead the agent about the nature of the provided context, while `context[].value` can inject arbitrary content into the agent's working memory.

The SSE response stream is a secondary surface: a compromised agent can emit events that manipulate client-side state or tool call flows. AG-UI events are flat objects (all fields at the root alongside `type`), not nested under a `data` wrapper.
