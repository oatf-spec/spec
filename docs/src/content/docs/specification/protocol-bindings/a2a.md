---
title: "A2A Binding"
description: "Agent-to-Agent protocol binding: surfaces, events, CEL context, and execution state."
---

The A2A binding covers the Agent-to-Agent protocol as defined in the [A2A specification (v0.3.0)](https://a2a-protocol.org/v0.3.0/specification/). A2A uses JSON-RPC 2.0 over HTTP(S), with support for streaming via SSE. This binding is provisional and covers the A2A v0.3.0 data model: surfaces, event types, CEL context, and execution state are defined at full v0.3.0 schema parity, but behavioral modifiers, payload generation, gRPC transport, and HTTP+JSON transport are not yet specified. Future OATF minor versions will expand this binding.

## 7.2.1 Surfaces

| Surface | Description | Default Target | Applicable Context |
|---------|-------------|----------------|-------------------|
| `agent_card` | The Agent Card (/.well-known/agent-card.json) | `""` (root object) | Agent discovery |
| `card_name` | The `name` field of the Agent Card | `name` | Agent discovery |
| `card_description` | The `description` field of the Agent Card | `description` | Agent discovery |
| `skill_description` | The `description` field of a skill | `skills[*].description` | Agent Card skills array |
| `skill_name` | The `name` field of a skill | `skills[*].name` | Agent Card skills array |
| `task_message` | A message in an A2A exchange | `parts[*]` | Message send/receive |
| `task_artifact` | An artifact produced by a task | `artifacts[*]` | Task completion |
| `task_status` | The status of a task | `status.state` | Task state transitions |

**Surface target resolution notes.** The default targets above assume the most common payload shape for each surface. A2A v0.3.0 responses are polymorphic: `message/send` may return a Task or a direct Message, and SSE streams carry distinct event types. When the actual payload shape differs from the default target, indicators MUST specify an explicit `target`:

- `task_message` defaults to `parts[*]` (Message object). For indicators inspecting Task-shaped responses where messages are nested in history, use `target: history[*].parts[*]`.
- `task_artifact` defaults to `artifacts[*]` (Task object). For indicators inspecting `task/artifact` SSE events where the artifact is a singular root field, use `target: artifact.parts[*]`.

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
| `tasks/get` | `tasks/get` | Server returns task status | — |
| `tasks/cancel` | `tasks/cancel` | Server returns canceled task | — |
| `tasks/resubscribe` | `tasks/resubscribe` | Server reopens SSE stream | — |
| `tasks/pushNotificationConfig/set` | `tasks/pushNotificationConfig/set` | Server confirms push config | — |
| `tasks/pushNotificationConfig/get` | `tasks/pushNotificationConfig/get` | Server returns push config | — |
| `tasks/pushNotificationConfig/list` | `tasks/pushNotificationConfig/list` | Server returns push config list | — |
| `tasks/pushNotificationConfig/delete` | `tasks/pushNotificationConfig/delete` | Server confirms push config deletion | — |
| `task/status` | SSE `TaskStatusUpdateEvent` | Server streams status update | `:state` |
| `task/artifact` | SSE `TaskArtifactUpdateEvent` | Server streams artifact | — |
| `agent/getAuthenticatedExtendedCard` | `agent/getAuthenticatedExtendedCard` | Server returns authenticated card | — |
| `agent_card/get` | GET `/.well-known/agent-card.json` | Server returns Agent Card | — |

For `a2a_client`, `message/send` fires when the server returns a response, which may be a Task object or a direct Message. `message/stream` fires for each item in the SSE stream; streamed items may be Task objects, Message objects, `TaskStatusUpdateEvent` payloads, or `TaskArtifactUpdateEvent` payloads. The `task/status` and `task/artifact` events fire for the specific SSE event types.

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
- `message.skills[]`: Array of skills, each with `id`, `name`, `description`, `tags[]`, `examples[]`, `inputModes[]`, `outputModes[]`, `security[]`.
- `message.capabilities`: Object with `streaming`, `pushNotifications`, `stateTransitionHistory`, `extensions[]`.
- `message.defaultInputModes[]`: Array of default input MIME types.
- `message.defaultOutputModes[]`: Array of default output MIME types.
- `message.provider`: Object with `organization`, `url`.
- `message.documentationUrl`: Documentation URL.
- `message.iconUrl`: Icon URL.
- `message.preferredTransport`: Preferred transport (e.g., `"JSONRPC"`).
- `message.supportsAuthenticatedExtendedCard`: Whether the agent supports authenticated extended cards.
- `message.securitySchemes`: Map of named security scheme definitions.
- `message.security[]`: Array of security requirement objects.
- `message.additionalInterfaces[]`: Array of additional transport endpoints, each with `url`, `transport`.
- `message.signatures[]`: Array of JWS signatures, each with `protected`, `signature`, and optional `header`.

For server-mode request events (`message/send`, `message/stream` on `a2a_server`), `message` contains the inbound `params.message` (a Message object):
- `message.kind`: The literal `"message"`.
- `message.role`: The sender role (`"user"` or `"agent"`).
- `message.parts[]`: Array of content parts, each with `kind` and kind-specific fields (e.g., `"text"`, `"file"`, `"data"`). Each part may have `metadata`.
- `message.messageId`: The message ID.
- `message.contextId`: The context ID linking related tasks.
- `message.taskId`: The task ID (when continuing an existing task).
- `message.referenceTaskIds[]`: Array of referenced task IDs.
- `message.extensions[]`: Array of extension identifiers.
- `message.metadata`: Untyped key-value metadata attached to the message.

For client-mode response events (`message/send`, `message/stream` on `a2a_client`), `message` contains the response payload. When the response is a Task:
- `message.kind`: The literal `"task"`.
- `message.id`: The task ID.
- `message.contextId`: The context ID linking related tasks.
- `message.status`: Object with `state` (required), `timestamp` (optional, RFC 3339), and `message` (optional Message object).
- `message.history[]`: Array of messages, each with `kind`, `role`, and `parts[]`.
- `message.artifacts[]`: Array of artifacts, each with `artifactId`, `name`, `description`, and `parts[]`.
- `message.metadata`: Untyped key-value metadata attached to the task.

When the response is a direct Message (no task created), the structure matches the server-mode request shape above.

For `task/status` SSE events (`TaskStatusUpdateEvent`), `message` contains:
- `message.kind`: The literal `"status-update"`.
- `message.taskId`: The task ID.
- `message.contextId`: The context ID.
- `message.status`: The TaskStatus object with `state` (required), `timestamp` (optional), and `message` (optional Message object).
- `message.final`: Whether this is the final event in the stream (required boolean).
- `message.metadata`: Untyped key-value metadata.

For `task/artifact` SSE events (`TaskArtifactUpdateEvent`), `message` contains:
- `message.kind`: The literal `"artifact-update"`.
- `message.taskId`: The task ID.
- `message.contextId`: The context ID.
- `message.artifact`: The Artifact object with `artifactId`, `parts[]`, and optional `name`, `description`, `extensions`, `metadata`.
- `message.append`: Whether to append to an existing artifact (optional boolean).
- `message.lastChunk`: Whether this is the final chunk (optional boolean).
- `message.metadata`: Untyped key-value metadata.

## 7.2.4 Execution State (A2A)

When the phase mode is `a2a_server`, the phase state defines the A2A agent's identity and behavior:

```yaml
state:
  agent_card:
    name: string                           # required
    description: string                    # required
    url: string                            # required
    version: string                        # required
    protocolVersion: string                # required (e.g., "0.3.0")
    skills:                                # required (may be empty)
      - id: string
        name: string
        description: string
        tags: string[]                     # required (may be empty)
        examples: string[]?
        inputModes: string[]?
        outputModes: string[]?
        security: object[]?                # security requirements ({scheme: scopes[]}[])
    capabilities:                          # required
      streaming: boolean?
      pushNotifications: boolean?
      stateTransitionHistory: boolean?
      extensions:                          # optional AgentExtension[]
        - uri: string                      # extension URI (required)
          required: boolean?               # whether extension is required
          description: string?
          params: map?                     # extension-specific parameters
    defaultInputModes: string[]            # required (e.g., ["text/plain"])
    defaultOutputModes: string[]           # required (e.g., ["text/plain"])
    provider:                              # optional
      organization: string
      url: string                          # required
    documentationUrl: string?
    iconUrl: string?
    preferredTransport: string?            # "JSONRPC", "GRPC", "HTTP+JSON"
    supportsAuthenticatedExtendedCard: boolean?
    securitySchemes: map?                  # named security scheme definitions
    security: object[]?                    # security requirements ({scheme: scopes[]}[])
    additionalInterfaces:                  # optional additional transport endpoints
      - url: string
        transport: string                  # required: "JSONRPC", "GRPC", "HTTP+JSON"
    signatures:                            # optional JWS signatures (RFC 7515)
      - protected: string                # base64url-encoded JWS header
        signature: string                # base64url-encoded signature
        header: map?                     # unprotected header
  
  task_responses:
    - when: <MatchPredicate>?
      status: enum(submitted, working, input-required, completed, failed, canceled, auth-required, rejected, unknown)
      metadata: map?                 # Untyped key-value metadata on the Task
      history:                     # Static content (mutually exclusive with synthesize)
        - kind: "message"            # required literal
          role: enum(agent, user)
          parts:
            - kind: enum(text, file, data)
              # Kind-specific fields
              metadata: map?         # Per-part metadata
          messageId: string          # required (runtime auto-generates if omitted)
          referenceTaskIds: string[]?
          extensions: string[]?
          metadata: map?             # Untyped key-value metadata on the Message
      artifacts:
        - artifactId: string         # required artifact identifier
          name: string?
          description: string?
          parts:
            - kind: enum(text, file, data)
              # Kind-specific fields
              metadata: map?         # Per-part metadata
          extensions: string[]?
          metadata: map?             # Untyped key-value metadata on the Artifact
      synthesize:                  # LLM generation (mutually exclusive with history/artifacts)
        prompt: string             # Supports {{template}} interpolation
```

The `task_responses` list follows the same ordered-match semantics as MCP tool `responses` ([§7.1.4](/specification/protocol-bindings/mcp/#714-execution-state-mcp)): Entries MUST be evaluated in order; the first matching entry wins. Entries without `when` serve as catch-all defaults. Each entry specifies either static content (`history`/`artifacts`) or LLM `synthesize`; they are mutually exclusive. When `synthesize` is present, the `status` field is still required; the runtime generates the message content but the document author controls the task status. See [§7.4](/specification/protocol-bindings/llm-synthesis/) for cross-protocol synthesis details.

The `status` values (`submitted`, `working`, `input-required`, `completed`, `failed`, `canceled`, `auth-required`, `rejected`, `unknown`) use A2A's protocol-native naming convention, which includes hyphens. These values are serialized directly as A2A task status strings. The `unknown` value is the v0.3.0 sentinel for unrecognized states.

## 7.2.4a Execution State (A2A Client)

When the phase mode is `a2a_client`, the phase state defines the client agent's request:

```yaml
state:
  task_message:                        # The A2A message to send (MessageSendParams)
    message:
      kind: "message"                  # required literal
      role: enum(user, agent)
      parts:
        - kind: enum(text, file, data)
          # Kind-specific fields
          metadata: map?               # Per-part metadata
      messageId: string              # required (runtime auto-generates if omitted)
      referenceTaskIds: string[]?
      extensions: string[]?
      metadata: map?                   # Untyped key-value metadata on the Message
    configuration:                     # Optional: MessageSendConfiguration
      acceptedOutputModes: string[]?   # Acceptable response MIME types
      historyLength: integer?          # Max history entries to include in response
      pushNotificationConfig:          # Inline push config for this request (PushNotificationConfig)
        url: string
        id: string?                    # Config identifier
        token: string?
        authentication:                # Optional auth for push endpoint
          schemes: string[]            # required authentication schemes
          credentials: string?
      blocking: boolean?               # Block until terminal state. Default: false.
    metadata: map?                     # Request-level metadata
    synthesize:                        # LLM generation (mutually exclusive with message)
      prompt: string

  streaming: boolean?                  # Use message/stream (SSE) vs message/send. Default: false.
  fetch_agent_card: boolean?           # Fetch Agent Card before sending. Default: true.

  task_query:                          # Optional: tasks/get (TaskQueryParams)
    id: string                         # Task ID
    historyLength: integer?
    metadata: map?

  task_cancel:                         # Optional: tasks/cancel (TaskIdParams)
    id: string                         # Task ID
    metadata: map?

  task_resubscribe:                    # Optional: tasks/resubscribe (TaskIdParams)
    id: string                         # Task ID
    metadata: map?

  push_notification_config:            # Optional: push notification config CRUD
    operation: enum(set, get, list, delete)   # default: set
    id: string                         # Task ID
    pushNotificationConfigId: string?  # Config ID (required for delete, optional for get)
    metadata: map?                     # Request-level metadata
    config:                            # Required for set; ignored for get/list/delete
      url: string
      id: string?                      # Config identifier
      token: string?
      authentication:                  # Optional auth for push endpoint
        schemes: string[]             # required authentication schemes
        credentials: string?

  get_authenticated_extended_card: boolean?   # Optional: request authenticated card
```

`task_message`, `task_query`, `task_cancel`, `task_resubscribe`, `push_notification_config`, and `get_authenticated_extended_card` are mutually exclusive per phase. Each phase performs one client operation.

**Task message semantics.** Each phase MUST send exactly one task message. Multi-turn interactions use multi-phase execution where each phase defines the next message to send based on the server's response (observed via triggers and extractors). `task_message` models A2A's `MessageSendParams`: `message` contains the Message object, `configuration` contains optional delivery parameters, and `metadata` carries request-level metadata. Within `task_message`, `message` (static content) and `synthesize` (LLM generation) are mutually exclusive.

**Transport mode.** `streaming` controls transport mode: `true` uses `message/stream` (SSE), `false` uses `message/send` (polling). Default is `false`. Adversarial tools MUST respect this setting.

**Agent Card fetch.** `fetch_agent_card` controls whether the runtime fetches the Agent Card (`GET /.well-known/agent-card.json`) before sending the first message. Default is `true`. Adversarial tools MUST respect this setting. Set to `false` when the Agent Card is not needed or was fetched in a prior phase.

**Template interpolation** ([§5.6](/specification/execution-profile/#56-response-templates)) applies to string fields in `parts` and `synthesize.prompt`.

## 7.2.5 A2A-Specific Attack Considerations

A2A attacks may involve multi-turn stateful interactions where early phases return benign task results and later phases return poisoned content. OATF models this through multi-phase execution profiles.

The `description` and `skills[].description` fields in A2A Agent Cards are consumed by LLMs to make delegation decisions, serving the same role as MCP tool descriptions. OATF models attacks against these fields through the `card_description` and `skill_description` surfaces.

