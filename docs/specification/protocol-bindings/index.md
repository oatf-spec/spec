---
title: "Binding Architecture"
description: "Protocol binding architecture, extensibility model, and included bindings summary."
---

## 7.0 Binding Architecture

Protocol bindings are OATF's extension mechanism for supporting specific agent communication protocols. The core specification ([§1](/specification/) through 6, [§8](/specification/cross-protocol-chains/) through 11) is protocol-agnostic: it defines documents, phases, triggers, extractors, indicators, and verdicts without reference to any particular protocol. Bindings supply the protocol-specific details that make documents concrete and executable.

### What a Protocol Binding Defines

Each binding MUST define:

1. **Modes**: One or more mode strings following the `{protocol}_{role}` convention (e.g., `mcp_server`, `mcp_client`). Each mode represents a distinct attacker posture.
2. **Events**: The protocol-native method names or event types that can appear as trigger conditions. Each binding documents which events apply to which modes.
3. **CEL context**: The variables available in CEL expressions for this binding's indicators, defining what fields of the protocol message are accessible.
4. **Execution state**: The YAML structure for `phase.state` when operating in the binding's modes. State has two layers: structural keys (defined by the binding) that tell the runtime how to map content to protocol operations, and pass-through content (within structural keys) that is preserved verbatim without OATF validation.

A binding SHOULD also define:

5. **Entry actions**: Protocol-specific actions performed when entering a phase (e.g., sending notifications).

### 7.0.1 Response Dispatch

Bindings that support request-response operations use a response dispatch pattern. The v0.1 bindings define five dispatch lists: `responses` (MCP tools and prompts), `sampling_responses` (MCP sampling), `elicitation_responses` (MCP elicitation), `task_responses` (A2A), and `tool_responses` (AG-UI). Each dispatchable operation includes an ordered list of response entries:

- **`when`**: Optional match predicate evaluated against the incoming request or binding-defined triggering event payload. Absent on the default (fallback) entry.
- **`content`**: Protocol-native response content (pass-through).
- **`synthesize`**: Reserved for a future version (LLM-powered generation).

Entries are evaluated in order; the first entry whose `when` predicate matches the triggering request/event payload (or the first entry without `when`) is selected. At most one entry may omit `when` (the catch-all), and it should be the last entry.

The `select_response` primitive ([§5.7](/sdk/execution-primitives/#57-select_response)) implements this evaluation.

### 7.0.2 Synthetic Event Names

When a protocol operation does not have a native method name or event type, the binding defines a synthetic name following the `entity/verb` or `snake_case` pattern consistent with the protocol's naming conventions. Synthetic names are documented in each binding's Events section. Examples:
- `agent_card/get` (A2A: HTTP GET has no JSON-RPC method)
- `run_agent_input` (AG-UI: POST body has no SSE event type)

### 7.0.3 Pass-Through Principle

Protocol-native message content within execution state is pass-through: the OATF parser preserves it without validation against the upstream protocol's schema. This enables documents to describe attacks involving non-conformant, malformed, or version-skewed protocol messages.

Each binding's state schema has two layers:
- **Structural keys** (defined by the binding): Tell the runtime how to map state content to protocol operations (e.g., `tools` → `tools/list` response, `agent_card` → Agent Card endpoint).
- **Pass-through content** (within structural keys): Protocol-native fields preserved verbatim. No OATF validation applied.

**Naming convention.** Structural keys use OATF's `snake_case` convention (`protocol_version`, `server_info`, `agent_card`, `run_agent_input`). Fields within pass-through content retain the protocol's native naming (e.g., MCP's `inputSchema`, A2A's `pushNotifications`, AG-UI's `forwardedProps`).

### Interaction Models

Each binding serves one of three fundamental interaction models:

| Interaction Model | Description | v0.1 Bindings |
|---|---|---|
| **User-to-Agent** | Human provides input, agent responds | AG-UI ([§7.3](/specification/protocol-bindings/ag-ui/)) |
| **Agent-to-Agent** | Agents delegate, collaborate, or discover | A2A ([§7.2](/specification/protocol-bindings/a2a/)) |
| **Agent-to-Tool** | Agent invokes external capabilities | MCP ([§7.1](/specification/protocol-bindings/mcp/)) |

These models are stable abstractions. The protocols serving them may change; the core specification does not depend on any particular protocol.

### Extensibility

Adding a new protocol binding does not require changes to the core specification. A new binding defines its modes, events, and state structures following the conventions above. Tools that do not implement the new binding parse documents using it without error but skip execution for unrecognized modes and skip validation for unrecognized events.

Third-party bindings (not included in this specification) SHOULD use a namespaced protocol identifier to avoid collisions with future OATF-defined bindings (e.g., `vendor_protocol_server` rather than `protocol_server`).

### Maturity Levels

Each binding carries a maturity level:

- **Stable**: Complete coverage of the protocol's attack surface. All events, execution state structures, CEL context, and entry actions are defined. Suitable for production use.
- **Provisional**: Structurally sound and usable, but incomplete. Core events are defined, and execution state covers the primary attack vectors. CEL context and entry actions may be absent or incomplete. Future OATF minor versions will expand provisional bindings toward stable.

## 7.0.4 Included Bindings Summary

| Aspect | MCP ([§7.1](/specification/protocol-bindings/mcp/)) | A2A ([§7.2](/specification/protocol-bindings/a2a/)) | AG-UI ([§7.3](/specification/protocol-bindings/ag-ui/)) |
|--------|-----------|-----------|-------------|
| Maturity | Provisional | Provisional | Provisional |
| Interaction model | Agent-to-Tool | Agent-to-Agent | User-to-Agent |
| Transport | JSON-RPC 2.0 over stdio/Streamable HTTP | JSON-RPC 2.0 over HTTP(S), SSE for streaming | Transport-agnostic (typically HTTP POST + SSE) |
| Primary attack surface | Tool/resource/prompt descriptions, tool responses | Agent Card, skill descriptions, task messages | Message history, tool results, context, agent state |
| Default mode | `mcp_server` | `a2a_server` | `ag_ui_client` |
| Execution state | Full (tools, resources, prompts, elicitations, capabilities); pass-through content | Partial (agent card, task responses); pass-through content | Partial (RunAgentInput, tool responses); pass-through content |

### Naming Conventions in Protocol Bindings

OATF structural fields (the format's own constructs: `phase.name`, `trigger.event`, `indicator.surface`) use `snake_case`. Protocol pass-through fields (values that an adversarial tool serializes directly onto the wire) use the protocol's native naming convention. This means execution state fields mirror MCP's `camelCase` (e.g., `inputSchema`, `isError`, `listChanged`), A2A's `camelCase` (e.g., `pushNotifications`), and AG-UI's `camelCase` (e.g., `forwardedProps`, `threadId`, `runId`). CEL context fields ([§7.1.3](/specification/protocol-bindings/mcp/#713-cel-context), [§7.2.3](/specification/protocol-bindings/a2a/#723-cel-context), [§7.3.3](/specification/protocol-bindings/ag-ui/#733-cel-context)) also use the protocol's native naming because CEL expressions evaluate against protocol messages.

Event type values follow the naming conventions of their respective protocols. MCP and A2A use slash-separated method names mirroring their JSON-RPC methods (e.g., `tools/call`, `message/send`). Non-RPC HTTP endpoints use an `entity/verb` pattern (e.g., `agent_card/get`). AG-UI uses `snake_case` names derived from its `EventType` enum (e.g., `tool_call_start`, `run_started`). A2A status values use the protocol's native naming, which includes hyphens (e.g., `input-required`).
