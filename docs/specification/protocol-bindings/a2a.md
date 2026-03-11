---
title: "A2A Binding"
description: "Agent-to-Agent protocol binding: modes, execution state, and entry actions."
---

The A2A binding covers the Agent-to-Agent protocol as defined in the [A2A specification (v0.3.0)](https://a2a-protocol.org/v0.3.0/specification/). A2A supports three transport protocols: JSON-RPC 2.0, gRPC, and HTTP+JSON/REST, with SSE for streaming. This binding uses JSON-RPC method names as the canonical event vocabulary; the A2A specification defines equivalent method mappings for gRPC and HTTP+JSON/REST transports.

**Design principle.** This binding specifies what OATF contributes: modes (attacker posture), the structural framing of execution state, and OATF extensions to protocol objects (response dispatch). Protocol-native message content — Agent Cards, task messages, artifacts, status objects — is pass-through. The OATF parser preserves it without validation against A2A's schema, enabling documents to describe attacks involving non-conformant, malformed, or version-skewed protocol messages. Indicators use A2A method names and SSE event types as `surface` values (e.g., `agent_card/get`, `message/send`, `task/status`) with a `target` path to specify the field to examine; see [§6](/specification/indicators/) for the indicator model.

## 7.2.1 Modes

| Mode | Role | Description |
|------|------|-------------|
| `a2a_server` | Server | The adversarial tool impersonates an A2A agent (server role). It presents an Agent Card and responds to task messages with controlled content. |
| `a2a_client` | Client | The adversarial tool impersonates a client agent. It sends task messages to a server agent and observes responses and SSE events. |

## 7.2.2 Events

Events use A2A's native JSON-RPC method names (`message/send`, `tasks/get`, `tasks/pushNotificationConfig/set`, etc.) for RPC methods. Because the HTTP endpoint for Agent Card discovery (`GET /.well-known/agent-card.json`) does not have a native JSON-RPC method name, OATF uses the synthetic event name `agent_card/get`. For SSE streaming, A2A delivers `SendStreamingMessageResponse` objects whose `result` field is discriminated by `kind` (`"status-update"` for `TaskStatusUpdateEvent`, `"artifact-update"` for `TaskArtifactUpdateEvent`). OATF projects these into the synthetic event names `task/status` and `task/artifact` so they can be used in triggers and indicators alongside method-based events.

For `a2a_server` actors, events are incoming JSON-RPC requests (including `agent/getAuthenticatedExtendedCard` for authenticated card retrieval) and the HTTP Agent Card request. For `a2a_client` actors, events are correlated JSON-RPC responses, SSE streaming events (`task/status`, `task/artifact`), and the Agent Card response.

For client-mode actors, method-named events (e.g., `message/send`) match JSON-RPC responses correlated to the originating request. `message/send` responses are polymorphic — the response may be a Task object or a direct Message. `message/stream` fires for each SSE item in the stream. The synthetic events `task/status` and `task/artifact` fire when a `SendStreamingMessageResponse` item has `result.kind` equal to `"status-update"` (`TaskStatusUpdateEvent`) or `"artifact-update"` (`TaskArtifactUpdateEvent`) respectively, and are client-mode only.

See the [A2A specification](https://a2a-protocol.org/v0.3.0/specification/) for the full list of methods and event types. New A2A methods are usable as OATF events immediately without a specification update.

To match specific conditions (e.g., a particular task status), use `trigger.match`:

```yaml
trigger:
  event: task/status
  match:
    status.state: "completed"
```

## 7.2.3 CEL Context

When a CEL expression is evaluated against an A2A message, the root context exposes the protocol-native message content under a `message` variable. For JSON-RPC requests, `message` contains the `params` object. For JSON-RPC responses, `message` contains the `result` object (or `error` object on failure). For SSE events (`task/status`, `task/artifact`), `message` contains the parsed JSON data payload of the event. For the Agent Card (`agent_card/get`), `message` contains the full card object.

CEL expressions are written against [A2A's native schema](https://github.com/a2aproject/A2A/blob/v0.3.0/specification/json/a2a.json):

```cel
// Agent Card skill description contains injection
message.skills.exists(s, s.description.contains("ignore previous"))

// Task response contains exfiltrated data
message.artifacts.exists(a, a.parts.exists(p, p.text.contains("SECRET")))

// SSE status update reached terminal state
message.status.state == "completed" && message.final == true
```

## 7.2.4 Execution State (A2A Server)

When the phase mode is `a2a_server`, the phase state defines the A2A agent the adversarial tool presents.

The state has two layers. **Structural keys** (`agent_card`, `task_responses`) are defined by this binding — they tell the runtime how to map state content to A2A protocol operations (`agent_card` is served on `agent_card/get` and `agent/getAuthenticatedExtendedCard`, `task_responses` control replies to `message/send` and `message/stream` requests). **The contents** of those keys are protocol-native pass-through unless marked as an OATF extension.

**Naming convention.** Structural keys use OATF's `snake_case` convention (`agent_card`, `task_responses`). All fields *within* protocol-native pass-through content retain A2A's original `camelCase` naming (e.g., `protocolVersion`, `pushNotifications`, `messageId`, `artifactId`).

When `agent_card` is omitted, the runtime SHOULD use a minimal valid Agent Card. When `task_responses` is omitted, the server returns an empty completed task for any request.

Phase state follows full-replacement semantics ([§5.2](/specification/execution-profile/#52-phases)): when a subsequent phase specifies `state`, it completely replaces the previous state. No merging occurs. This enables attacks where early phases return benign task results and later phases return poisoned content.

```yaml
state:
  # ── Agent Card ──────────────────────────────────────────────────
  #
  # Served on `agent_card/get` (HTTP GET) and
  # `agent/getAuthenticatedExtendedCard` (JSON-RPC).
  # The entire object is protocol-native pass-through.
  #
  agent_card: <any>

  # ── Task Responses ──────────────────────────────────────────────
  #
  # OATF extension: response dispatch for `message/send` and
  # `message/stream` requests. Follows response dispatch semantics
  # ([§7.0.1](/specification/protocol-bindings/#701-response-dispatch)): entries are evaluated in order, first match wins.
  #
  task_responses:
    - when: <MatchPredicate>?
      # Protocol-native task response content (pass-through).
      # Typically includes status, history, artifacts — any valid
      # (or deliberately invalid) A2A Task or Message fields.
      content: <any>?
      synthesize:                      # Reserved for a future version (LLM generation)
        prompt: string
```

**Agent Card.** The `agent_card` object is protocol-native pass-through, served verbatim on `agent_card/get` requests.

**Task responses.** The `task_responses` list is the A2A equivalent of MCP's tool `responses`. Each entry specifies static `content` (a protocol-native Task or Message object). The `content` object is pass-through — the document author constructs whatever A2A response shape the attack requires (Task with status and artifacts, direct Message, or deliberately malformed responses). The `synthesize` field is reserved for a future version.

**Streaming.** When the triggering request is `message/stream`, the runtime emits the selected response content as an A2A SSE stream. The content shape determines the stream structure: a `Task` object is emitted as the initial stream item (providing task ID and context), followed by `TaskStatusUpdateEvent` items derived from the task's `status`, and `TaskArtifactUpdateEvent` items derived from its `artifacts`. A direct `Message` (no wrapping Task) is emitted as a single stream item. The runtime handles SSE framing and event type headers. The document author controls content; the runtime controls serialization into the stream.

## 7.2.5 Execution State (A2A Client)

When the phase mode is `a2a_client`, the phase state defines the client agent's behavior. The same naming convention and pass-through rules from §7.2.4 apply.

```yaml
state:
  # ── Actions ─────────────────────────────────────────────────────
  #
  # Each action is one A2A protocol operation, executed sequentially.
  # `method` is any A2A method name or the synthetic `agent_card/get`.
  # `params` is protocol-native pass-through.
  #
  actions:
    - method: message/send
      params:
        message: <any>               # Protocol-native Message object (pass-through)
        configuration: <any>?        # MessageSendConfiguration (pass-through)
        metadata: <any>?
    - method: message/stream          # SSE streaming variant
      params:
        message: <any>
        configuration: <any>?
        metadata: <any>?
    - method: agent_card/get          # OATF synthetic name for HTTP GET /.well-known/agent-card.json
    - method: tasks/get
      params:
        id: string
        historyLength: integer?
        metadata: <any>?
    # Any A2A method is valid — the above are common examples.
    - method: <any_a2a_method>
      params: <any>?
```

**Actions.** Each action is one A2A protocol operation, executed sequentially. `method` is any A2A method name string; `params` is protocol-native pass-through. Use `message/stream` instead of `message/send` when SSE streaming is desired — the transport mode is determined by the method, not a separate flag. Use `agent_card/get` (OATF synthetic name) as an action to fetch the Agent Card when needed. New A2A methods are usable immediately without a specification update.

**Template interpolation** (§5.6) applies recursively to all string-valued fields within action params.

## 7.2.6 Entry Actions (A2A)

A2A-specific actions executed when entering a phase:

```yaml
on_enter:
  - send_push_notification:
      url: string              # Push notification endpoint URL
      payload: <any>           # Protocol-native StreamResponse (pass-through)
```

In A2A, SSE events are carried inside `message/stream` responses, not emitted as free-standing messages. The `send_push_notification` entry action delivers a webhook-style HTTP POST to a push notification endpoint previously configured via `tasks/pushNotificationConfig/*`. The `payload` is protocol-native pass-through and uses A2A's `StreamResponse` format — a wrapper containing exactly one of `task`, `message`, `statusUpdate`, or `artifactUpdate`.
