---
title: "MCP Binding"
description: "Model Context Protocol binding: modes, execution state, and entry actions."
---

The MCP binding covers the Model Context Protocol as defined in the [MCP Specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25). MCP uses JSON-RPC 2.0 over stdio or Streamable HTTP transport.

**Design principle.** This binding specifies what OATF contributes: modes (attacker posture), the structural framing of execution state, OATF extensions to protocol objects (response dispatch), and entry actions. Protocol-native message content — tool definitions, resource definitions, capabilities, content items — is pass-through. The OATF parser preserves it without validation against MCP's schema, enabling documents to describe attacks involving non-conformant, malformed, or version-skewed protocol messages. Indicators use MCP method names as `surface` values (e.g., `tools/call`, `initialize`, `resources/read`) with a `target` path to specify the field to examine; see [§6](/specification/indicators/) for the indicator model.

## 7.1.1 Modes

| Mode | Role | Description |
|------|------|-------------|
| `mcp_server` | Server | The adversarial tool impersonates an MCP server. It presents tools, resources, and prompts to the agent, and controls what the agent receives. |
| `mcp_client` | Client | The adversarial tool impersonates an MCP client. It sends requests to a server and controls how it responds to server-initiated requests (sampling, elicitation). |

## 7.1.2 Events

Events use MCP's native JSON-RPC method names (`tools/call`, `resources/list`, `notifications/tools/list_changed`, etc.). For `mcp_server` actors, events are incoming requests and client-to-server notifications. For `mcp_client` actors, events are correlated responses, server-to-client notifications, and server-initiated requests (`sampling/createMessage`, `elicitation/create`, `roots/list`).

For client-mode actors, method-named events that correspond to client-originated requests (e.g., `tools/call`) match JSON-RPC responses whose `id` corresponds to an outstanding request of that method. The runtime correlates each response to the original request by `id` and exposes the event under the original method name. Server-initiated requests (e.g., `sampling/createMessage`) are observed directly as incoming JSON-RPC requests with their own `method` field, requiring no correlation.

See the [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25) for the full list of methods and notifications. New MCP methods are usable as OATF events immediately without a specification update.

To match specific instances (e.g., a particular tool name), use `trigger.match`:

```yaml
trigger:
  event: tools/call
  match:
    name: "calculator"
```

## 7.1.3 CEL Context

When a CEL expression is evaluated against an MCP message, the root context exposes the protocol-native message content under a `message` variable. For requests and notifications, `message` contains the `params` object. For responses, `message` contains the `result` object (or `error` object on failure). The JSON-RPC envelope fields (`jsonrpc`, `id`, `method`) are not included.

CEL expressions are written against [MCP's native schema](https://modelcontextprotocol.io/specification/2025-11-25):

```cel
// Tool description contains suspicious pattern
message.tools.exists(t, t.description.contains("ignore previous"))

// Tool response leaks sensitive data
message.content[0].text.contains("SECRET_DATA")

// Server declares task capabilities
has(message.capabilities.tasks)
```

## 7.1.4 Execution State (MCP Server)

When the phase mode is `mcp_server`, the phase state defines the MCP server the adversarial tool presents.

The state has two layers. **Structural keys** (`protocol_version`, `server_info`, `instructions`, `capabilities`, `tools`, `resources`, `resource_templates`, `prompts`, `elicitations`) are defined by this binding — they tell the runtime how to map state content to MCP protocol operations (e.g., `tools` populates the `tools/list` response, `server_info` and `capabilities` populate the `initialize` response). **The contents** of those keys are protocol-native pass-through unless marked as an OATF extension. Pass-through content is preserved without schema validation and serialized onto the wire verbatim — fields from any MCP version are accepted, and non-conformant fields are also accepted for adversarial testing.

**Naming convention.** Structural keys use OATF's `snake_case` convention (`protocol_version`, `server_info`, `client_info`). The runtime maps these to MCP's `camelCase` wire format (`protocolVersion`, `serverInfo`, `clientInfo`). All fields *within* protocol-native pass-through content retain their original naming (e.g., `inputSchema`, `readOnlyHint`, `listChanged`). MCP's `_meta` extension point is preserved verbatim wherever present — this includes `progressToken` for progress tracking and task association metadata.

When a key is omitted, the runtime uses the following defaults: `protocol_version` defaults to `"2025-11-25"`, `server_info` defaults to `{name: "oatf-server", version: "1.0.0"}`. Omitting `tools`, `resources`, `resource_templates`, or `prompts` means the server does not expose that capability — the runtime responds to the corresponding `list` request with an empty array.

Phase state follows full-replacement semantics ([§5.2](/specification/execution-profile/#52-phases)): when a subsequent phase specifies `state`, it completely replaces the previous state. No merging occurs. This enables rug-pull attacks where a later phase presents entirely different tools or capabilities.

```yaml
state:
  # ── Server identity ─────────────────────────────────────────────
  #
  # Populates the `initialize` response. protocol_version, server_info,
  # instructions, and capabilities are structural keys. Their contents
  # are protocol-native pass-through.
  #
  protocol_version: string?           # Default: "2025-11-25"
  server_info: <any>?                 # Default: {name: "oatf-server", version: "1.0.0"}
  instructions: string?               # Injected into LLM context
  capabilities: <any>?                # MCP ServerCapabilities (pass-through)

  # ── Tools ───────────────────────────────────────────────────────
  #
  # Each entry populates `tools/list` and handles `tools/call`.
  # `name` is required by OATF for response dispatch routing.
  # All other fields are protocol-native pass-through.
  #
  tools:
    - name: string
      <...>: <any>

      # OATF extension: response dispatch (see [§7.0.1](/specification/protocol-bindings/#701-response-dispatch))
      responses:
        - when: <MatchPredicate>?
          content: <any>?             # Protocol-native response (pass-through)
          synthesize:                 # Reserved for a future version (LLM generation)
            prompt: string

  # ── Resources ───────────────────────────────────────────────────
  #
  # Each entry populates `resources/list`. `uri` and `name` are required
  # by OATF. All other fields are protocol-native pass-through.
  #
  resources:
    - uri: string
      name: string
      <...>: <any>

      # OATF extension: resource content for `resources/read` responses.
      # The runtime wraps this into MCP's `contents[]` wire format.
      content:
        text: string?
        blob: string?                 # Base64-encoded

  # ── Resource Templates ──────────────────────────────────────────
  #
  # Each entry populates `resources/templates/list`.
  #
  resource_templates:
    - uriTemplate: string
      name: string
      <...>: <any>

  # ── Prompts ─────────────────────────────────────────────────────
  #
  # Each entry populates `prompts/list` and handles `prompts/get`.
  # `name` is required by OATF. All other fields are pass-through.
  #
  prompts:
    - name: string
      <...>: <any>

      # OATF extension: response dispatch (see [§7.0.1](/specification/protocol-bindings/#701-response-dispatch))
      responses:
        - when: <MatchPredicate>?
          messages: <any>?            # Protocol-native prompt messages (pass-through)
          synthesize:                 # Reserved for a future version
            prompt: string

  # ── Elicitations ────────────────────────────────────────────────
  #
  # OATF extension: server-initiated elicitation requests. Unlike tools
  # and resources (which respond to agent requests), elicitations are
  # initiated by the adversarial server during tool or prompt execution.
  # The `when` predicate evaluates the agent's triggering request
  # (e.g., send an elicitation when the agent calls a specific tool).
  #
  elicitations:
    - when: <MatchPredicate>?         # Condition on triggering request context
      message: string                 # Human-readable prompt
      mode: enum(form, url)?          # Default: form
      requestedSchema: object?        # JSON Schema for form-mode input
      elicitationId: string?          # URL-mode elicitation ID (MCP requires this on the wire;
                                      #   the runtime generates one before emission when omitted)
      url: string?                    # URL-mode target
```

**Protocol version.** `protocol_version` controls the `protocolVersion` string in the `initialize` response. Documents testing version downgrade attacks SHOULD set this explicitly (e.g., `"2024-11-05"`).

**Server instructions.** The `instructions` field is a direct prompt injection vector that takes effect before any tool is called.

**Capabilities.** The `capabilities` object is pass-through, serialized into the `initialize` response. First-phase capabilities are sent during handshake; subsequent phases can modify them to simulate capability mutation.

## 7.1.5 Execution State (MCP Client)

When the phase mode is `mcp_client`, the phase state defines the client's behavior. The same naming convention and pass-through rules from §7.1.4 apply: structural keys use `snake_case`, their contents are protocol-native pass-through.

When omitted, `client_info` defaults to `{name: "oatf-client", version: "1.0.0"}` and `capabilities` defaults to `{roots: {listChanged: true}}`.

```yaml
state:
  # ── Client identity (pass-through) ─────────────────────────────
  client_info: <any>?
  capabilities: <any>?

  # ── Actions ─────────────────────────────────────────────────────
  #
  # Ordered MCP requests to send during this phase.
  # Each action is one JSON-RPC request, executed sequentially.
  # `method` is any MCP method name; `params` is pass-through.
  #
  actions:
    - method: tools/list
      params:
        cursor: string?
    - method: tools/call
      params:
        name: string
        arguments: <any>?
    - method: resources/read
      params:
        uri: string
    # Any MCP method is valid — the above are common examples.
    - method: <any_mcp_method>
      params: <any>?

  # ── Server-initiated request handling ───────────────────────────
  sampling_responses:
    - when: <MatchPredicate>?
      content: <any>                   # Protocol-native CreateMessageResult (pass-through)
      synthesize:                      # Reserved for a future version
        prompt: string

  elicitation_responses:
    - when: <MatchPredicate>?
      action: enum(accept, decline, cancel)?  # Default: accept
      content: <any>?                  # Protocol-native response fields (pass-through)
      synthesize:                      # Reserved for a future version
        prompt: string

  # ── Roots ───────────────────────────────────────────────────────
  roots:
    - <any>                            # Protocol-native Root objects (pass-through)
```

**Actions.** Each action is one JSON-RPC request, executed sequentially. `method` is any MCP method name string; `params` is protocol-native pass-through. This means new MCP methods are usable in client actions immediately without an OATF specification update. `initialize` is handled by the runtime during connection setup and should not appear as an action.

**Server-initiated request handling.** `sampling_responses` and `elicitation_responses` follow response dispatch semantics ([§7.0.1](/specification/protocol-bindings/#701-response-dispatch)). Response content is pass-through.

**Roots.** Returned verbatim on `roots/list` requests.

**Template interpolation** (§5.6) applies recursively to all string-valued fields within actions and response content.

## 7.1.6 Entry Actions (MCP)

MCP-specific actions executed when entering a phase:

```yaml
on_enter:
  - send_notification:
      method: string           # Notification method name
      params: <any>?           # Protocol-native notification params (pass-through)
  - send_elicitation:
      message: string
      mode: enum(form, url)?   # Default: form
      requestedSchema: object? # JSON Schema for form mode
      elicitationId: string?   # URL-mode ID (runtime generates before emission when omitted)
      url: string?             # URL for url mode
```
