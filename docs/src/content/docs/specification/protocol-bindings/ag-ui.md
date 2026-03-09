---
title: "AG-UI Binding"
description: "Agent-User Interface protocol binding: surfaces, events, CEL context, and execution state."
---

The AG-UI binding covers the Agent-User Interface protocol as defined in the [AG-UI specification](https://docs.ag-ui.com/). AG-UI uses HTTP POST for agent invocation and SSE for streaming responses. This binding is provisional: core surfaces, event types, and execution state are defined, but behavioral modifiers and payload generation are not yet specified. Future OATF minor versions will expand this binding.

## 7.3.1 Surfaces

| Surface | Description | Default Target | Applicable Context |
|---------|-------------|----------------|-------------------|
| `message_history` | The `messages` array in the RunAgentInput | `messages[*]` | Agent invocation |
| `tool_definition` | The `tools` array in the RunAgentInput | `tools[*]` | Agent invocation |
| `tool_result` | A tool result message in the messages array | `messages[*]` | Agent invocation |
| `agent_state` | The `state` object in the RunAgentInput | `state` | Agent invocation |
| `forwarded_props` | The `forwardedProps` in the RunAgentInput | `forwardedProps` | Agent invocation |
| `agent_event` | An SSE event in the agent's response stream | `data` | Agent response |
| `agent_tool_call` | A tool call event in the response stream | `data` | Agent response |

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
| `tool_call_end` | `TOOL_CALL_END` | Agent completes tool call | `:tool_name` |
| `state_snapshot` | `STATE_SNAPSHOT` | Agent sends full state | — |
| `state_delta` | `STATE_DELTA` | Agent sends state patch | — |
| `messages_snapshot` | `MESSAGES_SNAPSHOT` | Agent sends message history | — |
| `interrupt` | `CUSTOM` (subtype) | Agent requests human input | — |
| `custom` | `CUSTOM` | Agent sends custom event | `:event_name` |

Event names use `snake_case` derived from AG-UI's `EventType` enum. The mapping from OATF event names to AG-UI's SCREAMING_SNAKE enum values is a constant translation. Adversarial tools MUST perform this translation when emitting events.

**Qualifier resolution** for AG-UI events:

- `tool_call_start:X` → matches when `toolCallName == "X"`
- `tool_call_end:X` → matches when `toolCallName == "X"`
- `custom:X` → matches when `name == "X"`

For filtering by `toolCallId` or other structured fields, use `trigger.match`.

All AG-UI events are valid only on `ag_ui_client` actors. Using AG-UI events on any other mode is a validation error (V-029).

## 7.3.3 CEL Context (AG-UI)

When a CEL expression is evaluated against an AG-UI message, the root context object `message` is constructed as follows.

#### `RunAgentInput` POST body

See [AG-UI Protocol](https://docs.ag-ui.com/) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.messages[]` | array | — | RunAgentInput |
| `message.tools[]` | array | — | RunAgentInput |
| `message.state` | object | — | RunAgentInput |
| `message.forwardedProps` | object | — | RunAgentInput |
| `message.threadId` | string | — | RunAgentInput |
| `message.runId` | string | — | RunAgentInput |

#### Agent response events (SSE)

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.type` | string | yes | BaseEvent |
| `message.data` | object | — | BaseEvent |

## 7.3.4 Execution State (AG-UI)

When the phase mode is `ag_ui_client`, the phase state defines the AG-UI client's request content:

```yaml
state:
  run_agent_input:
    messages:                        # Static content (mutually exclusive with synthesize)
      - id: string
        role: enum(user, assistant, system, tool)
        content: string?
        toolCallId: string?
        toolCalls:
          - id: string
            type: "function"
            function:
              name: string
              arguments: string   # JSON string
    synthesize:                    # LLM generation (mutually exclusive with messages)
      prompt: string               # Supports {{template}} interpolation
    tools:
      - type: "function"
        function:
          name: string
          description: string
          parameters: object      # JSON Schema
    state: object?
    forwardedProps: object?
    threadId: string?
    runId: string?
```

**Input synthesis semantics.** Within `run_agent_input`, `messages` and `synthesize` are mutually exclusive. When `synthesize` is present, the adversarial tool MUST generate the `messages` array at runtime using an LLM. The `prompt` field describes the conversation history to fabricate: the LLM produces the messages, not the entire `RunAgentInput`. The structural fields (`tools`, `state`, `forwardedProps`, `threadId`, `runId`) remain static because the attacker typically knows exactly what tool definitions and state to inject; it is the conversation history that benefits from adaptive generation.

This follows the same principle as server-mode `synthesize` ([§7.4](/specification/protocol-bindings/llm-synthesis/)): the LLM generates the *content*, while the document author controls the *structure*. For MCP/A2A the content is the response payload; for AG-UI the content is the fabricated message history. See [§7.4](/specification/protocol-bindings/llm-synthesis/) for cross-protocol synthesis details. Template interpolation ([§5.6](/specification/execution-profile/#56-response-templates)) applies to string fields in `messages`, `tools`, and `synthesize.prompt`.

## 7.3.5 AG-UI-Specific Attack Considerations

The primary attack surface is the client-to-agent direction: the `RunAgentInput` fields (`messages`, `tools`, `state`) in the POST body. The SSE response stream is a secondary surface: a compromised agent can emit events that manipulate client-side state or tool call flows.

