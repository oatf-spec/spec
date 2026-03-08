---
title: "A2A Binding"
description: "Agent-to-Agent protocol binding: surfaces, events, CEL context, and execution state."
---

The A2A binding covers the Agent-to-Agent protocol as defined in the [A2A specification (v0.3.0)](https://a2a-protocol.org/v0.3.0/specification/). A2A uses JSON-RPC 2.0 over HTTP(S), with support for streaming via SSE. This binding is provisional and models a subset of the A2A v0.3.0 surface area: core surfaces, event types, and execution state are defined, but behavioral modifiers, payload generation, gRPC transport, and HTTP+JSON transport are not yet specified. Future OATF minor versions will expand this binding.

## 7.2.1 Surfaces

| Surface | Description | Default Target | Applicable Context |
|---------|-------------|----------------|-------------------|
| `agent_card` | The Agent Card (/.well-known/agent-card.json) | `""` (root object) | Agent discovery |
| `card_name` | The `name` field of the Agent Card | `name` | Agent discovery |
| `card_description` | The `description` field of the Agent Card | `description` | Agent discovery |
| `skill_description` | The `description` field of a skill | `skills[*].description` | Agent Card skills array |
| `skill_name` | The `name` field of a skill | `skills[*].name` | Agent Card skills array |
| `task_message` | A message in the task history | `history[*]` | Task send/update |
| `task_artifact` | An artifact produced by a task | `artifacts[*]` | Task completion |
| `task_status` | The status of a task | `status.state` | Task state transitions |

## 7.2.2 Event Types

A2A events are per-actor scoped. An actor's mode determines which events it observes. Adversarial tools MUST only emit events valid for the actor's mode.

**For `a2a_server` actors**: events are JSON-RPC requests and HTTP requests the client agent sends to this server:

| Event | Protocol Method | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `message/send` | `message/send` | Client sends a message | — |
| `message/stream` | `message/stream` | Client opens streaming channel | — |
| `tasks/get` | `tasks/get` | Client polls task status | — |
| `tasks/cancel` | `tasks/cancel` | Client cancels a task | — |
| `tasks/resubscribe` | `tasks/resubscribe` | Client resubscribes to task | — |
| `tasks/pushNotificationConfig/set` | `tasks/pushNotificationConfig/set` | Client configures push notifications | — |
| `tasks/pushNotificationConfig/get` | `tasks/pushNotificationConfig/get` | Client queries push config | — |
| `tasks/pushNotificationConfig/list` | `tasks/pushNotificationConfig/list` | Client lists push configs | — |
| `tasks/pushNotificationConfig/delete` | `tasks/pushNotificationConfig/delete` | Client deletes push config | — |
| `agent/getAuthenticatedExtendedCard` | `agent/getAuthenticatedExtendedCard` | Client requests authenticated card | — |
| `agent_card/get` | GET `/.well-known/agent-card.json` | Client fetches Agent Card | — |

`agent_card/get` is an HTTP GET endpoint, not a JSON-RPC method. It uses the `entity/verb` naming pattern for non-RPC endpoints (see [§7](/specification/protocol-bindings/) naming conventions).

**For `a2a_client` actors**: events are responses and SSE events received from the server agent:

| Event | Protocol Method | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `message/send` | `message/send` | Server responds to message | — |
| `message/stream` | `message/stream` | Server opens SSE connection | — |
| `task/status` | SSE `TaskStatusUpdateEvent` | Server streams status update | `:state` |
| `task/artifact` | SSE `TaskArtifactUpdateEvent` | Server streams artifact | — |
| `agent/getAuthenticatedExtendedCard` | `agent/getAuthenticatedExtendedCard` | Server returns authenticated card | — |
| `agent_card/get` | GET `/.well-known/agent-card.json` | Server returns Agent Card | — |

For `a2a_client`, `message/send` fires when the initial HTTP response is received acknowledging task creation. `message/stream` fires when the SSE connection is successfully opened.

**Qualifier resolution** for A2A events:

- `task/status:X` → matches when `status.state == "X"` (e.g., `task/status:completed`, `task/status:failed`, `task/status:input-required`)

`task/status` and `task/artifact` are client-mode only (SSE events from server). Using them as triggers on an `a2a_server` actor is a validation error (V-029).

## 7.2.3 CEL Context (A2A)

When a CEL expression is evaluated against an A2A message, the root context object `message` is constructed as follows:

For Agent Card responses (`agent_card/get`), `message` contains:
- `message.name`: The agent name.
- `message.description`: The agent description.
- `message.url`: The agent URL.
- `message.version`: The agent card version.
- `message.protocolVersion`: The A2A protocol version (e.g., `"0.3.0"`).
- `message.skills[]`: Array of skills, each with `id`, `name`, `description`, `tags[]`, `examples[]`, `inputModes[]`, `outputModes[]`.
- `message.capabilities`: Object with `streaming`, `pushNotifications`.
- `message.defaultInputModes[]`: Array of default input MIME types.
- `message.defaultOutputModes[]`: Array of default output MIME types.
- `message.provider`: Object with `organization`, `url`.
- `message.documentationUrl`: Documentation URL.
- `message.iconUrl`: Icon URL.

For server-mode request events (`message/send`, `message/stream` on `a2a_server`), `message` contains the inbound `params.message` (a Message object):
- `message.role`: The sender role (`"user"` or `"agent"`).
- `message.parts[]`: Array of content parts, each with `type` and type-specific fields (e.g., `text`, `file`, `data`).
- `message.messageId`: The message ID.
- `message.contextId`: The context ID linking related tasks.
- `message.taskId`: The task ID (when continuing an existing task).

For client-mode response events (`message/send`, `message/stream` on `a2a_client`), `message` contains the response payload. When the response is a Task:
- `message.id`: The task ID.
- `message.contextId`: The context ID linking related tasks.
- `message.status.state`: The task status.
- `message.history[]`: Array of messages, each with `role` and `parts[]`.
- `message.artifacts[]`: Array of artifacts, each with `name` and `parts[]`.

When the response is a direct Message (no task created), the structure matches the server-mode request shape above.

## 7.2.4 Execution State (A2A)

When the phase mode is `a2a_server`, the phase state defines the A2A agent's identity and behavior:

```yaml
state:
  agent_card:
    name: string
    description: string
    url: string
    version: string?
    protocolVersion: string?               # default: "0.3.0"
    skills:
      - id: string
        name: string
        description: string
        tags: string[]?
        examples: string[]?
        inputModes: string[]?
        outputModes: string[]?
    capabilities:
      streaming: boolean?
      pushNotifications: boolean?
    defaultInputModes: string[]?
    defaultOutputModes: string[]?
    provider:                              # optional
      organization: string
      url: string?
    documentationUrl: string?
    iconUrl: string?
    preferredTransport: string?            # "JSONRPC", "GRPC", "HTTP+JSON"
    supportsAuthenticatedExtendedCard: boolean?
    securitySchemes: map?                  # named security scheme definitions
    security: object[]?                    # required security scheme combinations
  
  task_responses:
    - when: <MatchPredicate>?
      status: enum(submitted, working, input-required, completed, failed, canceled, auth-required, rejected)
      history:                     # Static content (mutually exclusive with synthesize)
        - role: enum(agent, user)
          parts:
            - type: enum(text, file, data)
              # Type-specific fields
      artifacts:
        - name: string?
          parts:
            - type: enum(text, file, data)
              # Type-specific fields
      synthesize:                  # LLM generation (mutually exclusive with history/artifacts)
        prompt: string             # Supports {{template}} interpolation
```

The `task_responses` list follows the same ordered-match semantics as MCP tool `responses` ([§7.1.4](/specification/protocol-bindings/mcp/#714-execution-state-mcp)): Entries MUST be evaluated in order; the first matching entry wins. Entries without `when` serve as catch-all defaults. Each entry specifies either static content (`history`/`artifacts`) or LLM `synthesize`; they are mutually exclusive. When `synthesize` is present, the `status` field is still required; the runtime generates the message content but the document author controls the task status. See [§7.4](/specification/protocol-bindings/llm-synthesis/) for cross-protocol synthesis details.

The `status` values (`submitted`, `working`, `input-required`, `completed`, `failed`, `canceled`, `auth-required`, `rejected`) use A2A's protocol-native naming convention, which includes hyphens. These values are serialized directly as A2A task status strings.

## 7.2.4a Execution State (A2A Client)

When the phase mode is `a2a_client`, the phase state defines the client agent's request:

```yaml
state:
  task_message:                        # The A2A message to send
    role: enum(user)
    parts:
      - type: enum(text, file, data)
        # Type-specific fields (same as a2a_server task_responses history)
    messageId: string?
    synthesize:                        # LLM generation (mutually exclusive with parts)
      prompt: string

  streaming: boolean?                  # Use message/stream (SSE) vs message/send. Default: false.
  fetch_agent_card: boolean?           # Fetch Agent Card before sending. Default: true.

  task_query:                          # Optional: tasks/get request
    taskId: string
    historyLength: integer?

  task_cancel:                         # Optional: tasks/cancel request
    taskId: string

  task_resubscribe:                    # Optional: tasks/resubscribe request
    taskId: string

  push_notification_config:            # Optional: push notification config CRUD
    operation: enum(set, get, list, delete)   # default: set
    taskId: string
    config:                            # Required for set; ignored for get/list/delete
      url: string
      token: string?

  get_authenticated_extended_card: boolean?   # Optional: request authenticated card
```

`task_message`, `task_query`, `task_cancel`, `task_resubscribe`, `push_notification_config`, and `get_authenticated_extended_card` are mutually exclusive per phase. Each phase performs one client operation.

**Task message semantics.** Each phase MUST send exactly one task message. Multi-turn interactions use multi-phase execution where each phase defines the next message to send based on the server's response (observed via triggers and extractors). `task_message` is the client-mode counterpart of `a2a_server`'s `task_responses`. Within `task_message`, `parts` (static content) and `synthesize` (LLM generation) are mutually exclusive.

**Transport mode.** `streaming` controls transport mode: `true` uses `message/stream` (SSE), `false` uses `message/send` (polling). Default is `false`. Adversarial tools MUST respect this setting.

**Agent Card fetch.** `fetch_agent_card` controls whether the runtime fetches the Agent Card (`GET /.well-known/agent-card.json`) before sending the first message. Default is `true`. Adversarial tools MUST respect this setting. Set to `false` when the Agent Card is not needed or was fetched in a prior phase.

**Template interpolation** ([§5.6](/specification/execution-profile/#56-response-templates)) applies to string fields in `parts` and `synthesize.prompt`.

## 7.2.5 A2A-Specific Attack Considerations

A2A attacks may involve multi-turn stateful interactions where early phases return benign task results and later phases return poisoned content. OATF models this through multi-phase execution profiles.

The `description` and `skills[].description` fields in A2A Agent Cards are consumed by LLMs to make delegation decisions, serving the same role as MCP tool descriptions. OATF models attacks against these fields through the `card_description` and `skill_description` surfaces.

