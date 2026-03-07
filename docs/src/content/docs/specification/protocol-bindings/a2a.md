---
title: "A2A Binding"
description: "Agent-to-Agent protocol binding: surfaces, events, CEL context, and execution state."
---

The A2A binding covers the Agent-to-Agent protocol as defined in the [A2A specification](https://google.github.io/A2A/). A2A uses HTTP+SSE transport with JSON message bodies. This binding is provisional: core surfaces, event types, and execution state are defined, but behavioral modifiers and payload generation are not yet specified. Future OATF minor versions will expand this binding.

## 7.2.1 Surfaces

| Surface | Description | Default Target | Applicable Context |
|---------|-------------|----------------|-------------------|
| `agent_card` | The Agent Card (/.well-known/agent.json) | `""` (root object) | Agent discovery |
| `card_name` | The `name` field of the Agent Card | `name` | Agent discovery |
| `card_description` | The `description` field of the Agent Card | `description` | Agent discovery |
| `skill_description` | The `description` field of a skill | `skills[*].description` | Agent Card skills array |
| `skill_name` | The `name` field of a skill | `skills[*].name` | Agent Card skills array |
| `task_message` | A message within a task | `messages[*]` | Task send/update |
| `task_artifact` | An artifact produced by a task | `artifacts[*]` | Task completion |
| `task_status` | The status of a task | `status.state` | Task state transitions |

## 7.2.2 Event Types

A2A events are per-actor scoped. An actor's mode determines which events it observes.

**For `a2a_server` actors**: events are JSON-RPC requests and HTTP requests the client agent sends to this server:

| Event | Protocol Method | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `message/send` | `message/send` | Client sends a message | — |
| `message/stream` | `message/stream` | Client opens streaming channel | — |
| `tasks/get` | `tasks/get` | Client polls task status | — |
| `tasks/cancel` | `tasks/cancel` | Client cancels a task | — |
| `tasks/resubscribe` | `tasks/resubscribe` | Client resubscribes to task | — |
| `tasks/pushNotification/set` | `tasks/pushNotification/set` | Client configures push notifications | — |
| `tasks/pushNotification/get` | `tasks/pushNotification/get` | Client queries push config | — |
| `agent_card/get` | GET `/.well-known/agent.json` | Client fetches Agent Card | — |

`agent_card/get` is an HTTP GET endpoint, not a JSON-RPC method. It uses the `entity/verb` naming pattern for non-RPC endpoints (see [§7](/specification/protocol-bindings/) naming conventions).

**For `a2a_client` actors**: events are responses and SSE events received from the server agent:

| Event | Protocol Method | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `message/send` | `message/send` | Server responds to message | — |
| `message/stream` | `message/stream` | Server opens SSE connection | — |
| `task/status` | SSE `TaskStatusUpdateEvent` | Server streams status update | `:state` |
| `task/artifact` | SSE `TaskArtifactUpdateEvent` | Server streams artifact | — |
| `agent_card/get` | GET `/.well-known/agent.json` | Server returns Agent Card | — |

For `a2a_client`, `message/send` fires when the initial HTTP response is received acknowledging task creation. `message/stream` fires when the SSE connection is successfully opened.

**Qualifier resolution** for A2A events:

- `task/status:X` → matches when `status.state == "X"` (e.g., `task/status:completed`, `task/status:failed`, `task/status:input-required`)

`task/status` and `task/artifact` are client-mode only (SSE events from server). Using them as triggers on an `a2a_server` actor is a validation error.

## 7.2.3 CEL Context (A2A)

When a CEL expression is evaluated against an A2A message, the root context object `message` is constructed as follows:

For Agent Card responses (`agent_card/get`), `message` contains:
- `message.name`: The agent name.
- `message.description`: The agent description.
- `message.url`: The agent URL.
- `message.skills[]`: Array of skills, each with `id`, `name`, `description`, `tags[]`, `examples[]`.
- `message.capabilities`: Object with `streaming`, `pushNotifications`.

For task messages (`message/send`, `message/stream`), `message` contains:
- `message.id`: The task ID.
- `message.status.state`: The task status.
- `message.messages[]`: Array of messages, each with `role` and `parts[]`.
- `message.artifacts[]`: Array of artifacts, each with `name` and `parts[]`.

## 7.2.4 Execution State (A2A)

When the phase mode is `a2a_server`, the phase state defines the A2A agent's identity and behavior:

```yaml
state:
  agent_card:
    name: string
    description: string
    url: string
    skills:
      - id: string
        name: string
        description: string
        tags: string[]?
        examples: string[]?
    capabilities:
      streaming: boolean?
      pushNotifications: boolean?
    authentication:
      schemes: string[]?
  
  task_responses:
    - when: <MatchPredicate>?
      status: enum(submitted, working, input-required, completed, failed, canceled)
      messages:                    # Static content (mutually exclusive with synthesize)
        - role: enum(agent, user)
          parts:
            - type: enum(text, file, data)
              # Type-specific fields
      artifacts:
        - name: string?
          parts:
            - type: enum(text, file, data)
              # Type-specific fields
      synthesize:                  # LLM generation (mutually exclusive with messages/artifacts)
        prompt: string             # Supports {{template}} interpolation
```

The `task_responses` list follows the same ordered-match semantics as MCP tool `responses` ([§7.1.4](/specification/protocol-bindings/mcp/#714-execution-state-mcp)): entries are evaluated in order, the first match wins, and entries without `when` are catch-alls. Each entry specifies either static content (`messages`/`artifacts`) or LLM `synthesize`; they are mutually exclusive. When `synthesize` is present, the `status` field is still required; the runtime generates the message content but the document author controls the task status. See [§7.4](/specification/protocol-bindings/llm-synthesis/) for cross-protocol synthesis details.

The `status` values (`submitted`, `working`, `input-required`, `completed`, `failed`, `canceled`) use A2A's protocol-native naming convention, which includes hyphens. These values are serialized directly as A2A task status strings.

## 7.2.4a Execution State (A2A Client)

When the phase mode is `a2a_client`, the phase state defines the client agent's request:

```yaml
state:
  task_message:                        # The A2A message to send
    role: enum(user)
    parts:
      - type: enum(text, file, data)
        # Type-specific fields (same as a2a_server task_responses messages)
    messageId: string?
    synthesize:                        # LLM generation (mutually exclusive with parts)
      prompt: string

  streaming: boolean?                  # Use message/stream (SSE) vs message/send. Default: false.
  fetch_agent_card: boolean?           # Fetch Agent Card before sending. Default: true.
```

**Task message semantics.** Each phase sends one task message. Multi-turn interactions use multi-phase execution where each phase defines the next message to send based on the server's response (observed via triggers and extractors). `task_message` is the client-mode counterpart of `a2a_server`'s `task_responses`. Within `task_message`, `parts` (static content) and `synthesize` (LLM generation) are mutually exclusive.

**Transport mode.** `streaming` controls transport mode: `true` uses `message/stream` (SSE), `false` uses `message/send` (polling). Default is `false`.

**Agent Card fetch.** `fetch_agent_card` controls whether the runtime fetches the Agent Card (`GET /.well-known/agent.json`) before sending the first message. Default is `true`. Set to `false` when the Agent Card is not needed or was fetched in a prior phase.

**Template interpolation** ([§5.6](/specification/execution-profile/#56-response-templates)) applies to string fields in `parts` and `synthesize.prompt`.

## 7.2.5 A2A-Specific Attack Considerations

A2A attacks may involve multi-turn stateful interactions where early phases return benign task results and later phases return poisoned content. OATF models this through multi-phase execution profiles.

The `description` and `skills[].description` fields in A2A Agent Cards are consumed by LLMs to make delegation decisions, serving the same role as MCP tool descriptions. OATF models attacks against these fields through the `card_description` and `skill_description` surfaces.

