---
title: "Binding Architecture"
description: "Protocol binding architecture, extensibility model, and included bindings summary."
---

## 7.0 Binding Architecture

Protocol bindings are OATF's extension mechanism for supporting specific agent communication protocols. The core specification ([§1](/specification/)–6, [§8](/specification/cross-protocol-chains/)–11) is protocol-agnostic — it defines documents, phases, triggers, extractors, indicators, and verdicts without reference to any particular protocol. Bindings supply the protocol-specific details that make documents concrete and executable.

### What a Protocol Binding Defines

Each binding MUST define:

1. **Modes**: One or more mode strings following the `{protocol}_{role}` convention (e.g., `mcp_server`, `mcp_client`). Each mode represents a distinct attacker posture.
2. **Surfaces**: Named locations in the protocol's message structure where attacks manifest. Each surface has a protocol, a default target path, and prose describing what it represents.
3. **Event types**: The protocol events that can appear as trigger conditions. Each event is associated with the modes for which it is valid.
4. **Execution state**: The YAML structure for `phase.state` when operating in the binding's modes. This defines the protocol messages the adversarial tool presents.
5. **CEL context**: The variables available in CEL expressions for this binding's indicators, defining what fields of the protocol message are accessible.

A binding SHOULD also define:

6. **Entry actions**: Protocol-specific actions performed when entering a phase (e.g., sending notifications).
7. **Behavioral modifiers**: Fine-grained control over message delivery (delays, side effects).
8. **Payload generation**: Protocol-specific fuzzing strategies.

### Interaction Models

Each binding serves one of three fundamental interaction models:

| Interaction Model | Description | v0.1 Bindings |
|---|---|---|
| **User-to-Agent** | Human provides input, agent responds | AG-UI ([§7.3](/specification/protocol-bindings/ag-ui/)) |
| **Agent-to-Agent** | Agents delegate, collaborate, or discover | A2A ([§7.2](/specification/protocol-bindings/a2a/)) |
| **Agent-to-Tool** | Agent invokes external capabilities | MCP ([§7.1](/specification/protocol-bindings/mcp/)) |

These models are stable abstractions. The specific protocols serving them will evolve — new protocols may emerge, existing ones may be replaced or forked. OATF's binding architecture ensures the core specification remains stable across protocol changes.

### Extensibility

Adding a new protocol binding does not require changes to the core specification. A new binding defines its modes, surfaces, events, and state structures following the conventions above. Tools that do not implement the new binding parse documents using it without error but skip execution for unrecognized modes and skip validation for unrecognized surfaces and events.

Third-party bindings (not included in this specification) SHOULD use a namespaced protocol identifier to avoid collisions with future OATF-defined bindings (e.g., `vendor_protocol_server` rather than `protocol_server`).

### Maturity Levels

Each binding carries a maturity level:

- **Stable**: Complete coverage of the protocol's attack surface. All surfaces, event types, execution state structures, CEL context, behavioral modifiers, and payload generation are defined. Suitable for production use.
- **Provisional**: Structurally sound and usable, but incomplete. Core surfaces and event types are defined. Execution state covers the primary attack vectors. CEL context, behavioral modifiers, and payload generation may be absent. Future OATF minor versions will expand provisional bindings toward stable.

## 7.0.1 Included Bindings Summary

| Aspect | MCP ([§7.1](/specification/protocol-bindings/mcp/)) | A2A ([§7.2](/specification/protocol-bindings/a2a/)) | AG-UI ([§7.3](/specification/protocol-bindings/ag-ui/)) |
|--------|-----------|-----------|-------------|
| Maturity | Stable | Provisional | Provisional |
| Interaction model | Agent-to-Tool | Agent-to-Agent | User-to-Agent |
| Transport | JSON-RPC 2.0 over stdio/Streamable HTTP | HTTP + SSE | HTTP POST + SSE |
| Primary attack surface | Tool/resource/prompt descriptions, tool responses | Agent Card, skill descriptions, task messages | Message history, tool results, agent state |
| Default mode | `mcp_server` | `a2a_server` | `ag_ui_client` |
| Surfaces defined | 23 | 8 | 7 |
| Event types defined | 23 | 10 | 15 |
| Execution state | Full (tools, resources, prompts, elicitations, capabilities, behavior) | Partial (agent card, task responses) | Partial (RunAgentInput) |
| Behavioral modifiers | Defined (delivery, side effects) | Not yet defined | Not yet defined |
| Payload generation | Defined | Not yet defined | Not yet defined |

### Naming Conventions in Protocol Bindings

OATF structural fields (the format's own constructs: `phase.name`, `trigger.event`, `indicator.surface`) use `snake_case`. Protocol passthrough fields (values that an adversarial tool serializes directly onto the wire) use the protocol's native naming convention. This means execution state fields mirror MCP's `camelCase` (e.g., `inputSchema`, `isError`, `listChanged`), A2A's `camelCase` (e.g., `pushNotifications`), and AG-UI's `camelCase` (e.g., `forwardedProps`, `threadId`, `runId`). CEL context fields ([§7.1.3](/specification/protocol-bindings/mcp/#713-cel-context-mcp), [§7.2.3](/specification/protocol-bindings/a2a/#723-cel-context-a2a), [§7.3.3](/specification/protocol-bindings/ag-ui/#733-cel-context-ag-ui)) also use the protocol's native naming because CEL expressions evaluate against protocol messages.

Event type values follow the naming conventions of their respective protocols. MCP and A2A use slash-separated method names mirroring their JSON-RPC methods (e.g., `tools/call`, `message/send`). Non-RPC HTTP endpoints use an `entity/verb` pattern (e.g., `agent_card/get`). AG-UI uses `snake_case` names derived from its `EventType` enum (e.g., `tool_call_start`, `run_started`). A2A status values use the protocol's native naming, which includes hyphens (e.g., `input-required`).

### Event-Mode Validity Matrix

The following matrix defines which event types are valid for each mode defined by the v0.1 protocol bindings. Using an event type not listed for the actor's mode is a validation error that MUST be rejected at document load time. For modes defined by bindings not included in this specification, tools MUST skip event validation.

| Event | `mcp_server` | `mcp_client` | `a2a_server` | `a2a_client` | `ag_ui_client` |
|-------|:---:|:---:|:---:|:---:|:---:|
| `initialize` | ✓ | ✓ | | | |
| `tools/list` | ✓ | ✓ | | | |
| `tools/call` | ✓ | ✓ | | | |
| `resources/list` | ✓ | ✓ | | | |
| `resources/read` | ✓ | ✓ | | | |
| `resources/subscribe` | ✓ | | | | |
| `resources/unsubscribe` | ✓ | | | | |
| `prompts/list` | ✓ | ✓ | | | |
| `prompts/get` | ✓ | ✓ | | | |
| `completion/complete` | ✓ | | | | |
| `sampling/createMessage` | ✓ | ✓ | | | |
| `elicitation/create` | ✓ | ✓ | | | |
| `tasks/get` | ✓ | ✓ | ✓ | | |
| `tasks/result` | ✓ | ✓ | | | |
| `tasks/list` | ✓ | | | | |
| `tasks/cancel` | ✓ | | ✓ | | |
| `roots/list` | ✓ | ✓ | | | |
| `ping` | ✓ | ✓ | | | |
| `notifications/tools/list_changed` | | ✓ | | | |
| `notifications/resources/list_changed` | | ✓ | | | |
| `notifications/resources/updated` | | ✓ | | | |
| `notifications/prompts/list_changed` | | ✓ | | | |
| `notifications/tasks/status` | | ✓ | | | |
| `notifications/elicitation/complete` | | ✓ | | | |
| `message/send` | | | ✓ | ✓ | |
| `message/stream` | | | ✓ | ✓ | |
| `tasks/resubscribe` | | | ✓ | | |
| `tasks/pushNotification/set` | | | ✓ | | |
| `tasks/pushNotification/get` | | | ✓ | | |
| `agent_card/get` | | | ✓ | ✓ | |
| `task/status` | | | | ✓ | |
| `task/artifact` | | | | ✓ | |
| `run_started` | | | | | ✓ |
| `run_finished` | | | | | ✓ |
| `run_error` | | | | | ✓ |
| `step_started` | | | | | ✓ |
| `step_finished` | | | | | ✓ |
| `text_message_start` | | | | | ✓ |
| `text_message_content` | | | | | ✓ |
| `text_message_end` | | | | | ✓ |
| `tool_call_start` | | | | | ✓ |
| `tool_call_end` | | | | | ✓ |
| `state_snapshot` | | | | | ✓ |
| `state_delta` | | | | | ✓ |
| `messages_snapshot` | | | | | ✓ |
| `interrupt` | | | | | ✓ |
| `custom` | | | | | ✓ |

