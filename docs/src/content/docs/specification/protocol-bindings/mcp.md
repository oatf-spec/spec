---
title: "MCP Binding"
description: "Model Context Protocol binding: surfaces, events, CEL context, execution state, and behavioral modifiers."
---

The MCP binding covers the Model Context Protocol as defined in the [MCP Specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25). MCP uses JSON-RPC 2.0 over stdio or Streamable HTTP transport.

## 7.1.1 Surfaces

The following surface values are defined for MCP indicators. The **Default Target** column specifies the canonical dot-path used when `pattern.target` or `semantic.target` is omitted.

| Surface | Description | Default Target | Applicable Message Types |
|---------|-------------|----------------|--------------------------|
| `tool_description` | The `description` field of a tool definition | `tools[*].description` | `tools/list` response |
| `tool_title` | The human-readable display name of a tool | `tools[*].title` | `tools/list` response |
| `tool_input_schema` | The `inputSchema` field of a tool definition | `tools[*].inputSchema` | `tools/list` response |
| `tool_name` | The `name` field of a tool definition | `tools[*].name` | `tools/list` response |
| `tool_annotations` | The `annotations` field of a tool definition (behavioral hints: `readOnlyHint`, `destructiveHint`, etc.) | `tools[*].annotations` | `tools/list` response |
| `tool_output_schema` | The `outputSchema` field of a tool definition | `tools[*].outputSchema` | `tools/list` response |
| `tool_icons` | The display icons of a tool definition | `tools[*].icons` | `tools/list` response |
| `tool_response` | The unstructured content returned by a tool call | `content[*]` | `tools/call` response |
| `tool_structured_response` | The structured content returned by a tool call | `structuredContent` | `tools/call` response |
| `tool_arguments` | The arguments passed to a tool call | `arguments` | `tools/call` request |
| `resource_content` | The content of a resource | `contents[*]` | `resources/read` response |
| `resource_uri` | The URI of a resource | `resources[*].uri` | `resources/list` response, `resources/read` request |
| `resource_title` | The human-readable display name of a resource | `resources[*].title` | `resources/list` response |
| `resource_description` | The description of a resource | `resources[*].description` | `resources/list` response |
| `resource_icons` | The display icons of a resource | `resources[*].icons` | `resources/list` response |
| `prompt_content` | The content of a prompt's messages | `messages[*].content` | `prompts/get` response |
| `prompt_arguments` | The arguments passed to a prompt | `arguments` | `prompts/get` request |
| `prompt_title` | The human-readable display name of a prompt | `prompts[*].title` | `prompts/list` response |
| `prompt_description` | The description of a prompt | `prompts[*].description` | `prompts/list` response |
| `prompt_icons` | The display icons of a prompt | `prompts[*].icons` | `prompts/list` response |
| `server_notification` | A server-to-client notification | `""` (root) | Any notification message |
| `server_capability` | The server's declared capabilities | `capabilities` | `initialize` response |
| `server_info` | The server's identity (name, title, version, description, icons, websiteUrl) | `serverInfo` | `initialize` response |
| `server_instructions` | Server-provided instructions injected into the LLM's context | `instructions` | `initialize` response |
| `sampling_request` | A server-initiated request for LLM completion (may include tool definitions) | `""` (root) | `sampling/createMessage` request |
| `elicitation_request` | A server-initiated request for user input | `""` (root) | `elicitation/create` request |
| `elicitation_response` | The user's response to an elicitation request | `""` (root) | `elicitation/create` response |
| `mcp_task_status` | The status of an MCP task | `task` | `tasks/get` response, `notifications/tasks/status` |
| `mcp_task_result` | The deferred result of a completed task | `""` (root) | `tasks/result` response |
| `roots_response` | The client's filesystem roots | `roots[*]` | `roots/list` response |

## 7.1.2 Event Types

MCP events are per-actor scoped. An actor's mode determines which events it observes and their semantics.

**For `mcp_server` actors**: events are JSON-RPC requests the agent sends to this server:

| Event | Protocol Method | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `initialize` | `initialize` | Agent opens connection | — |
| `tools/list` | `tools/list` | Agent discovers tools | — |
| `tools/call` | `tools/call` | Agent invokes a tool | `:tool_name` |
| `resources/list` | `resources/list` | Agent discovers resources | — |
| `resources/read` | `resources/read` | Agent reads a resource | — |
| `resources/subscribe` | `resources/subscribe` | Agent subscribes to resource | — |
| `resources/unsubscribe` | `resources/unsubscribe` | Agent unsubscribes | — |
| `resources/templates/list` | `resources/templates/list` | Agent discovers resource templates | — |
| `prompts/list` | `prompts/list` | Agent discovers prompts | — |
| `prompts/get` | `prompts/get` | Agent gets a prompt | `:prompt_name` |
| `completion/complete` | `completion/complete` | Agent requests completion | — |
| `sampling/createMessage` | `sampling/createMessage` | Server requests LLM sampling from agent | — |
| `elicitation/create` | `elicitation/create` | Server requests user input via agent | — |
| `tasks/get` | `tasks/get` | Agent polls task status | — |
| `tasks/result` | `tasks/result` | Agent retrieves deferred task result | — |
| `tasks/list` | `tasks/list` | Agent lists known tasks | — |
| `tasks/cancel` | `tasks/cancel` | Agent cancels a task | — |
| `roots/list` | `roots/list` | Agent responds to roots request | — |
| `ping` | `ping` | Keepalive | — |
| `notifications/initialized` | `notifications/initialized` | Client signals initialization complete | — |
| `notifications/roots/list_changed` | `notifications/roots/list_changed` | Client signals roots changed | — |
| `notifications/cancelled` | `notifications/cancelled` | Client cancels an outstanding request | — |

Resource events (`resources/read`, `resources/subscribe`, `resources/unsubscribe`) do not support qualifiers because resource URIs commonly contain colons that conflict with qualifier syntax. Use `trigger.match` for URI-based filtering.

**For `mcp_client` actors**: events are responses and notifications received from the server:

For client-mode actors, method-named events (e.g., `tools/call`, `tools/list`) match JSON-RPC responses whose `id` corresponds to an outstanding request of that method. JSON-RPC responses carry only `id`, `result`, and `error`, not a `method` field. The runtime correlates each response to the original request by `id` and exposes the event under the original method name. Qualifiers are resolved against the original request's parameters (e.g., `tools/call:calculator` matches a response whose originating request had `params.name == "calculator"`).

Notification events (`notifications/*`) are true wire-level events with their own `method` field and require no correlation.

| Event | Protocol Method | Description | Qualifier |
|-------|-----------------|-------------|-----------|
| `initialize` | `initialize` | Server responds to init | — |
| `tools/list` | `tools/list` | Server returns tool list | — |
| `tools/call` | `tools/call` | Server returns tool result | `:tool_name` |
| `resources/list` | `resources/list` | Server returns resource list | — |
| `resources/read` | `resources/read` | Server returns resource content | — |
| `resources/templates/list` | `resources/templates/list` | Server returns resource template list | — |
| `prompts/list` | `prompts/list` | Server returns prompt list | — |
| `prompts/get` | `prompts/get` | Server returns prompt content | `:prompt_name` |
| `notifications/tools/list_changed` | `notifications/tools/list_changed` | Server signals tools changed | — |
| `notifications/resources/list_changed` | `notifications/resources/list_changed` | Server signals resources changed | — |
| `notifications/resources/updated` | `notifications/resources/updated` | Server signals resource updated | — |
| `notifications/prompts/list_changed` | `notifications/prompts/list_changed` | Server signals prompts changed | — |
| `notifications/tasks/status` | `notifications/tasks/status` | Server signals task status change | — |
| `notifications/elicitation/complete` | `notifications/elicitation/complete` | Server signals URL-mode elicitation completed | — |
| `notifications/cancelled` | `notifications/cancelled` | Server cancels an outstanding request | — |
| `notifications/message` | `notifications/message` | Server sends log message | — |
| `notifications/progress` | `notifications/progress` | Server sends progress update | — |
| `completion/complete` | `completion/complete` | Server returns completion suggestions | — |
| `sampling/createMessage` | `sampling/createMessage` | Server requests LLM sampling (may include tools) | — |
| `elicitation/create` | `elicitation/create` | Server requests user input | — |
| `tasks/get` | `tasks/get` | Server returns task status | — |
| `tasks/result` | `tasks/result` | Server returns deferred task result | — |
| `tasks/list` | `tasks/list` | Server returns task list | — |
| `tasks/cancel` | `tasks/cancel` | Server confirms task cancellation | — |
| `roots/list` | `roots/list` | Server requests filesystem roots | — |
| `ping` | `ping` | Keepalive | — |

Most `notifications/*` events are directional: server-to-client notifications (`notifications/tools/list_changed`, `notifications/resources/*`, `notifications/prompts/list_changed`, `notifications/tasks/status`, `notifications/elicitation/complete`, `notifications/message`, `notifications/progress`) appear on `mcp_client` only. Client-to-server notifications (`notifications/initialized`, `notifications/roots/list_changed`) appear on `mcp_server` only. `notifications/cancelled` is bidirectional (either party can cancel an outstanding request).

`tasks/get`, `tasks/result`, `tasks/list`, and `tasks/cancel` are valid on both `mcp_server` actors (agent sends requests to this server) and `mcp_client` actors (server returns responses). MCP 2025-11-25 tasks are bidirectional: both client and server can be requestor or receiver.

**Qualifier resolution** for MCP events:

- `tools/call:X` → matches when `params.name == "X"` (server-mode: request params; client-mode: correlated request params)
- `prompts/get:X` → matches when `params.name == "X"` (same correlation rules)

## 7.1.3 CEL Context (MCP)

When a CEL expression is evaluated against an MCP message, the root context object `message` is constructed as follows depending on the message type.

**Shared field groups** referenced by `{{Name}}` in tables below:

| Group | Fields |
|-------|--------|
| {{Icon}} | `src` (string, req), `mimeType` (string), `sizes` (string[]), `theme` (string) |
| {{ContentAnnotations}} | `audience` (string[]), `priority` (number), `lastModified` (string) |

#### `tools/list` response

See [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/tools) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.tools[]` | array | — | Tool |
| `message.tools[].name` | string | yes | Tool |
| `message.tools[].title` | string | — | Tool |
| `message.tools[].description` | string | — | Tool |
| `message.tools[].inputSchema` | object | yes | Tool |
| `message.tools[].outputSchema` | object | — | Tool |
| `message.tools[].icons[]` | {{Icon}} | — | Tool |
| `message.tools[].annotations.title` | string | — | ToolAnnotations |
| `message.tools[].annotations.readOnlyHint` | boolean | — | ToolAnnotations |
| `message.tools[].annotations.destructiveHint` | boolean | — | ToolAnnotations |
| `message.tools[].annotations.idempotentHint` | boolean | — | ToolAnnotations |
| `message.tools[].annotations.openWorldHint` | boolean | — | ToolAnnotations |
| `message.tools[].execution.taskSupport` | string | — | ToolExecution |
| `message.nextCursor` | string | — | PaginatedResult |

#### `tools/call` request

See [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/tools) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.name` | string | yes | CallToolRequestParams |
| `message.arguments` | object | — | CallToolRequestParams |

#### `tools/call` response

See [MCP Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/tools) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.content[]` | array | yes | CallToolResult |
| `message.content[].type` | `"text" ∣ "image" ∣ "audio" ∣ "resource" ∣ "resource_link"` | yes | — |
| `message.content[].text` | string; when type="text" | yes | TextContent |
| `message.content[].data` | string; when type="image" or type="audio" | yes | ImageContent, AudioContent |
| `message.content[].mimeType` | string; when type="image" or type="audio" or type="resource_link" | yes | ImageContent, AudioContent, ResourceLink |
| `message.content[].resource` | object; when type="resource" | yes | EmbeddedResource |
| `message.content[].uri` | string; when type="resource_link" | yes | ResourceLink |
| `message.content[].name` | string; when type="resource_link" | yes | ResourceLink |
| `message.content[].title` | string; when type="resource_link" | — | ResourceLink |
| `message.content[].description` | string; when type="resource_link" | — | ResourceLink |
| `message.content[].size` | number; when type="resource_link" | — | ResourceLink |
| `message.content[].icons[]` | {{Icon}}; when type="resource_link" | — | ResourceLink |
| `message.content[].annotations` | {{ContentAnnotations}} | — | TextContent, ImageContent, AudioContent, EmbeddedResource, ResourceLink |
| `message.structuredContent` | object | — | CallToolResult |
| `message.isError` | boolean | — | CallToolResult |

#### `resources/list` response

See [MCP Resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.resources[]` | array | — | Resource |
| `message.resources[].uri` | string | yes | Resource |
| `message.resources[].name` | string | yes | Resource |
| `message.resources[].title` | string | — | Resource |
| `message.resources[].description` | string | — | Resource |
| `message.resources[].mimeType` | string | — | Resource |
| `message.resources[].size` | number | — | Resource |
| `message.resources[].icons[]` | {{Icon}} | — | Resource |
| `message.resources[].annotations` | {{ContentAnnotations}} | — | Resource |
| `message.nextCursor` | string | — | PaginatedResult |

#### `resources/templates/list` response

See [MCP Resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.resourceTemplates[]` | array | — | ResourceTemplate |
| `message.resourceTemplates[].uriTemplate` | string | yes | ResourceTemplate |
| `message.resourceTemplates[].name` | string | yes | ResourceTemplate |
| `message.resourceTemplates[].title` | string | — | ResourceTemplate |
| `message.resourceTemplates[].description` | string | — | ResourceTemplate |
| `message.resourceTemplates[].mimeType` | string | — | ResourceTemplate |
| `message.resourceTemplates[].icons[]` | {{Icon}} | — | ResourceTemplate |
| `message.resourceTemplates[].annotations` | {{ContentAnnotations}} | — | ResourceTemplate |
| `message.nextCursor` | string | — | PaginatedResult |

#### `resources/read` response

See [MCP Resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.contents[]` | array | — | TextResourceContents, BlobResourceContents |
| `message.contents[].uri` | string | yes | TextResourceContents, BlobResourceContents |
| `message.contents[].mimeType` | string | — | TextResourceContents, BlobResourceContents |
| `message.contents[].text` | string; when text resource | yes | TextResourceContents |
| `message.contents[].blob` | string; when blob resource | yes | BlobResourceContents |

#### `prompts/list` response

See [MCP Prompts](https://modelcontextprotocol.io/specification/2025-11-25/server/prompts) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.prompts[]` | array | — | Prompt |
| `message.prompts[].name` | string | yes | Prompt |
| `message.prompts[].title` | string | — | Prompt |
| `message.prompts[].description` | string | — | Prompt |
| `message.prompts[].icons[]` | {{Icon}} | — | Prompt |
| `message.prompts[].arguments[]` | array | — | Prompt |
| `message.prompts[].arguments[].name` | string | yes | PromptArgument |
| `message.prompts[].arguments[].title` | string | — | PromptArgument |
| `message.prompts[].arguments[].description` | string | — | PromptArgument |
| `message.prompts[].arguments[].required` | boolean | — | PromptArgument |
| `message.nextCursor` | string | — | PaginatedResult |

#### `prompts/get` response

See [MCP Prompts](https://modelcontextprotocol.io/specification/2025-11-25/server/prompts) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.description` | string | — | GetPromptResult |
| `message.messages[]` | array | yes | GetPromptResult |
| `message.messages[].role` | string | yes | PromptMessage |
| `message.messages[].content` | object | yes | PromptMessage |

#### `sampling/createMessage` request

See [MCP Sampling](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/sampling) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.messages[]` | array | yes | CreateMessageRequestParams |
| `message.messages[].role` | string | yes | SamplingMessage |
| `message.messages[].content` | object | yes | SamplingMessage |
| `message.modelPreferences` | object | — | CreateMessageRequestParams |
| `message.modelPreferences.hints[]` | array | — | ModelPreferences |
| `message.modelPreferences.hints[].name` | string | — | ModelHint |
| `message.modelPreferences.costPriority` | number | — | ModelPreferences |
| `message.modelPreferences.speedPriority` | number | — | ModelPreferences |
| `message.modelPreferences.intelligencePriority` | number | — | ModelPreferences |
| `message.systemPrompt` | string | — | CreateMessageRequestParams |
| `message.maxTokens` | number | yes | CreateMessageRequestParams |
| `message.tools[]` | array | — | CreateMessageRequestParams |
| `message.toolChoice` | object | — | CreateMessageRequestParams |
| `message.toolChoice.mode` | string | — | ToolChoice |

#### `elicitation/create` request

See [MCP Elicitation](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/elicitation) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.message` | string | yes | ElicitRequestFormParams, ElicitRequestURLParams |
| `message.requestedSchema` | object | yes | ElicitRequestFormParams |
| `message.mode` | string | — | ElicitRequestFormParams, ElicitRequestURLParams |
| `message.elicitationId` | string; when mode="url" | yes | ElicitRequestURLParams |
| `message.url` | string; when mode="url" | yes | ElicitRequestURLParams |

#### `elicitation/create` response

See [MCP Elicitation](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/elicitation) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.action` | `"accept" ∣ "decline" ∣ "cancel"` | yes | ElicitResult |
| `message.content` | object | — | ElicitResult |

#### `tasks/get` response and `notifications/tasks/status`

See [MCP Tasks](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/tasks) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.task.taskId` | string | yes | Task |
| `message.task.status` | `"working" ∣ "input_required" ∣ "completed" ∣ "failed" ∣ "cancelled"` | yes | Task |
| `message.task.statusMessage` | string | — | Task |
| `message.task.createdAt` | string | yes | Task |
| `message.task.lastUpdatedAt` | string | yes | Task |
| `message.task.ttl` | number | yes | Task |
| `message.task.pollInterval` | number | — | Task |

#### `tasks/result` response

The result structure matches the original request type (e.g., a `CallToolResult` for a task wrapping `tools/call`). No fixed table — the shape is polymorphic.

#### Empty notifications

`notifications/tools/list_changed`, `notifications/resources/list_changed`, `notifications/prompts/list_changed`, and `notifications/initialized` carry no parameters — `message` is an empty object.

#### `notifications/resources/updated`

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.uri` | string | yes | ResourceUpdatedNotificationParams |

#### `notifications/elicitation/complete`

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.elicitationId` | string | yes | ElicitationCompleteNotification |

#### `notifications/cancelled`

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.requestId` | string ∣ number | — | CancelledNotificationParams |
| `message.reason` | string | — | CancelledNotificationParams |

#### `notifications/message`

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.level` | `"debug" ∣ "info" ∣ "notice" ∣ "warning" ∣ "error" ∣ "critical" ∣ "alert" ∣ "emergency"` | yes | LoggingMessageNotificationParams |
| `message.logger` | string | — | LoggingMessageNotificationParams |
| `message.data` | any | yes | LoggingMessageNotificationParams |

#### `notifications/progress`

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.progressToken` | string ∣ number | yes | ProgressNotificationParams |
| `message.progress` | number | yes | ProgressNotificationParams |
| `message.total` | number | — | ProgressNotificationParams |
| `message.message` | string | — | ProgressNotificationParams |

#### `completion/complete` response

See [MCP Completion](https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/completion) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.completion.values[]` | string[] | — | CompletionResult |
| `message.completion.total` | number | — | CompletionResult |
| `message.completion.hasMore` | boolean | — | CompletionResult |

#### `initialize` response

See [MCP Lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) for field semantics.

| Path | Type | Req | Source |
|------|------|-----|--------|
| `message.protocolVersion` | string | yes | InitializeResult |
| `message.capabilities` | object | yes | InitializeResult |
| `message.serverInfo` | object | yes | InitializeResult |
| `message.serverInfo.name` | string | yes | Implementation |
| `message.serverInfo.version` | string | yes | Implementation |
| `message.serverInfo.title` | string | — | Implementation |
| `message.serverInfo.description` | string | — | Implementation |
| `message.serverInfo.icons[]` | {{Icon}} | — | Implementation |
| `message.serverInfo.websiteUrl` | string | — | Implementation |
| `message.instructions` | string | — | InitializeResult |

In all cases, `message` corresponds to the `params` (for requests and notifications) or `result` (for responses) field of the JSON-RPC message, not the full JSON-RPC envelope. The `jsonrpc`, `id`, and `method` fields of the envelope are not included in the CEL context. The notification method is identified by the event name, not by a CEL field.

## 7.1.4 Execution State (MCP)

When the phase mode is `mcp_server`, the phase state defines the MCP server's exposed capabilities:

```yaml
state:
  protocol_version: string?          # MCP protocol version. Defaults to "2025-11-25" when omitted.

  server_info:                       # Server identity in initialize response
    name: string                     # Server name
    title: string?                   # Human-readable display name
    version: string?                 # Server version. Defaults to "1.0.0" when omitted.
    description: string?             # Server description
    icons:                           # Display icons
      - src: string                  # Icon URI
        mimeType: string?            # e.g. "image/png"
        sizes: string[]?             # e.g. ["48x48"]
        theme: enum(light, dark)?    # Icon theme variant
    websiteUrl: string?              # Server website URL

  instructions: string?              # Server instructions injected into the LLM's context

  tools:
    - name: string
      title: string?                 # Human-readable display name
      description: string?
      icons:                         # Display icons
        - src: string
          mimeType: string?
          sizes: string[]?
          theme: enum(light, dark)?
      inputSchema: object?  # JSON Schema Draft 7+. Defaults to {"type": "object"} when omitted.
      outputSchema: object?  # JSON Schema for structured output
      annotations:           # Behavioral hints (untrusted unless from trusted server)
        title: string?               # Display name override (takes precedence over top-level title)
        readOnlyHint: boolean?
        destructiveHint: boolean?
        idempotentHint: boolean?
        openWorldHint: boolean?
      execution:                     # Execution-related properties
        taskSupport: enum(forbidden, optional, required)?  # Default: forbidden
      responses:                           # Ordered response entries
        - when: <MatchPredicate>?          # Optional condition (first match wins)
          content:                         # Unstructured content (mutually exclusive with synthesize)
            - type: enum(text, image, audio, resource, resource_link)
              # Type-specific fields:
              text: string?                # type: text
              mimeType: string?            # type: image, audio, resource_link
              data: string?                # Base64-encoded (type: image, audio)
              uri: string?                 # type: resource, resource_link
              name: string?                # type: resource_link, REQUIRED for resource_link
              title: string?               # type: resource_link, display name
              description: string?         # type: resource_link, description
              icons:                       # type: resource_link, display icons
                - src: string
                  mimeType: string?
                  sizes: string[]?
                  theme: enum(light, dark)?
              size: integer?               # type: resource_link, raw content size in bytes
              annotations:                 # Content metadata
                audience: string[]?        # ["user"], ["assistant"], or ["user", "assistant"]
                priority: number?          # 0.0–1.0 processing priority hint
                lastModified: string?      # ISO 8601 datetime
          structuredContent: object?       # Structured content (returned alongside content when outputSchema is declared)
          isError: boolean?
          synthesize:                      # LLM generation (mutually exclusive with content)
            prompt: string                 # Supports {{template}} interpolation
  
  resources:
    - uri: string
      name: string
      title: string?                 # Human-readable display name
      description: string?
      mimeType: string?
      size: integer?                 # Raw content size in bytes
      icons:                         # Display icons
        - src: string
          mimeType: string?
          sizes: string[]?
          theme: enum(light, dark)?
      annotations:                   # Resource metadata (appears in resources/list responses)
        audience: string[]?          # ["user"], ["assistant"], or ["user", "assistant"]
        priority: number?            # 0.0–1.0 processing priority hint
        lastModified: string?        # ISO 8601 datetime
      content:
        text: string?
        blob: string?          # Base64-encoded

  resource_templates:
    - uriTemplate: string              # URI template (RFC 6570)
      name: string
      title: string?                   # Human-readable display name
      description: string?
      mimeType: string?
      icons:                           # Display icons
        - src: string
          mimeType: string?
          sizes: string[]?
          theme: enum(light, dark)?
      annotations:                     # Resource metadata
        audience: string[]?
        priority: number?
        lastModified: string?

  prompts:
    - name: string
      title: string?                 # Human-readable display name
      description: string?
      icons:                         # Display icons
        - src: string
          mimeType: string?
          sizes: string[]?
          theme: enum(light, dark)?
      arguments:
        - name: string
          title: string?               # Human-readable display name
          description: string?
          required: boolean?
      responses:
        - when: <MatchPredicate>?
          messages:
            - role: enum(user, assistant)
              content:
                type: enum(text, image, audio, resource, resource_link)
                # Type-specific fields as above
          synthesize:
            prompt: string?

  elicitations:
    - when: <MatchPredicate>?            # Optional condition on the triggering request context
      message: string                    # Human-readable prompt for the user
      mode: enum(form, url)?             # Elicitation mode (default: form)
      requestedSchema: object?           # JSON Schema for form-mode input (required when mode is form)
      elicitationId: string?             # Unique ID for url-mode elicitation (required when mode is url)
      url: string?                       # URL for url-mode elicitation (required when mode is url)

  capabilities:
    tools:
      listChanged: boolean?
    resources:
      subscribe: boolean?
      listChanged: boolean?
    prompts:
      listChanged: boolean?
    completions: object?                 # Present to declare completion support
    logging: object?                     # Present to declare logging support
    experimental: object?                # Experimental capabilities
    elicitation: object?                 # Present to declare elicitation support
    tasks:                               # Present to declare task support
      list: object?                      # Declare task listing support
      cancel: object?                    # Declare task cancellation support
      requests:                          # Which request types can become async tasks
        tools:
          call: object?
```

**Response entry semantics.** A tool's `responses` list is an ordered sequence of response entries. When the tool is called, entries are evaluated in order; the first entry whose `when` predicate matches (or the first entry without `when`) is selected. The `when` predicate is evaluated against the incoming request parameters, the same content root as `trigger.match` for the corresponding event (e.g., for `tools/call`, the root contains `name` and `arguments`). Each entry specifies exactly one content strategy: static `content` or LLM `synthesize`; they are mutually exclusive on the same entry. When `responses` is omitted, the tool returns an empty success response (content: `[]`, isError: `false`). The same pattern applies to prompts. When a tool declares `outputSchema`, its response entries SHOULD include `structuredContent` alongside `content` for backward compatibility. The `structuredContent` object MUST conform to the declared `outputSchema`.

**Protocol version.** The `protocol_version` field controls the `protocolVersion` string in the `initialize` response. When omitted, conforming tools MUST default to `"2025-11-25"` (the current MCP specification version). Attack documents testing version downgrade attacks (where a malicious server claims an older protocol version to force the client into a degraded capability mode) SHOULD set this field explicitly (e.g., `"2024-11-05"` to test whether the client falls back to a mode without structured output validation or elicitation support).

**Server identity.** The `server_info` object controls the `serverInfo` field in the `initialize` response. When omitted, tools SHOULD default to `{name: "oatf-server", version: "1.0.0"}`. Attack documents that impersonate specific servers (e.g., testing whether an agent trusts a particular server name) SHOULD set this field explicitly. The `icons` array provides display icons for the server in client UIs; each icon MAY specify a `theme` (`light` or `dark`) to target specific client appearances. The `websiteUrl` field may direct users to a phishing site if attacker-controlled.

**Server instructions.** The `instructions` field is returned in the `initialize` response and is intended to be incorporated into the LLM's context by the client. This makes it a direct prompt injection vector that takes effect before any tool is called. Attack documents testing instruction-based attacks (system prompt override, behavioral manipulation, goal hijacking) SHOULD use this field as the primary payload delivery surface rather than embedding the payload in tool descriptions. Unlike tool descriptions which are processed per-call, instructions are processed once during initialization and influence all subsequent interactions.

**Tool field defaults.** Only `name` is required on a tool definition. When `inputSchema` is omitted, it defaults to `{"type": "object"}` (accepts any arguments). When `description` is omitted, it defaults to an empty string. These defaults minimize boilerplate for simple attacks where the attack payload is in a single field (typically `description`) and the rest is scaffolding.

**Content types.** Tool response content items and prompt message content support five types: `text` (plain text), `image` (base64-encoded image), `audio` (base64-encoded audio), `resource` (embedded resource with inline content), and `resource_link` (a URI reference to a resource the client may fetch or subscribe to). The `resource_link` type has a required `name` field and optional `title`, `description`, `mimeType`, `icons`, and `size` fields, as it inherits the full Resource structure. Resource links returned by tools are not guaranteed to appear in `resources/list` results, making them a vector for directing the client to attacker-controlled resources.

**Content annotations.** All content items in tool responses and prompt messages MAY include `annotations`. Resources themselves also carry `annotations` in `resources/list` responses. The `audience` field is particularly security-relevant: content or resources marked `audience: ["assistant"]` are intended to be invisible to the user, creating an attack vector where malicious instructions can be hidden from human oversight. The `priority` field (0.0 to 1.0) hints at processing importance, potentially allowing an attacker to ensure their payload is prioritized. Attack documents testing oversight bypass SHOULD use annotations to control content visibility.

**Resource content mapping.** Each resource in the state defines a single `content` object (`text` or `blob`). The adversarial tool constructs the MCP wire-format `resources/read` response by wrapping this into the protocol's `contents[]` array (a single-element array containing `uri`, `mimeType`, and the content). This is the same projection pattern used for tools (state defines individual tool objects; the tool constructs the `tools/list` response array). Indicator surfaces and CEL contexts reference the wire-format structure (`contents[*]`), not the state-level definition.

**Elicitation state.** The `elicitations` list defines elicitation requests the server issues during tool or prompt execution. Elicitation entries use the same ordered-match semantics as tool `responses`: entries are evaluated in order, first match wins. A malicious MCP server can use elicitation to phish for user credentials, request sensitive information, or redirect users to malicious URLs via url-mode elicitation. The `requestedSchema` field is attacker-controlled and may craft misleading field labels or descriptions.

**LLM synthesis.** When `synthesize` is present, the adversarial tool MUST generate the response content at runtime using an LLM. The `prompt` field is a free-text instruction to the LLM, supporting `{{template}}` interpolation from extractors and request fields. The runtime is responsible for model selection, structured output enforcement, caching, and retry. Conforming tools MUST validate synthesized output against the protocol binding's message structure (MCP tool call result for tools, prompt get result for prompts) before injection into the protocol stream. When the tool declares an `outputSchema`, the synthesized output MUST also include a valid `structuredContent` object conforming to that schema. Generation failures MUST NOT be sent to the target agent. This specification does not define model configuration (model name, temperature, seed); these are runtime concerns defined by the consuming tool's configuration. See [§7.4](/specification/protocol-bindings/llm-synthesis/) for cross-protocol synthesis details.

The `capabilities` object declares which protocol features the adversarial tool supports. Capabilities within the first phase's `state` are sent during the `initialize` handshake before phase execution begins; subsequent phases can modify declared capabilities to simulate capability changes (e.g., rug pull attacks). Declaring `elicitation` enables server-initiated user input requests. Declaring `completions` enables argument completion. Declaring `logging` enables the server to send `notifications/message` log events. The `tasks` capability is structured: `tasks.requests.tools.call` declares that `tools/call` requests can be deferred into asynchronous tasks. For backward compatibility, `tasks: {}` (empty object) is equivalent to declaring task support with no specific request type restrictions. The `list` and `cancel` sub-objects declare whether the server supports listing and cancelling tasks. MCP 2025-11-25 tasks are bidirectional: both `mcp_server` and `mcp_client` actors can declare task capabilities. Client-side `tasks.requests.sampling.createMessage` and `tasks.requests.elicitation.create` enable the client to defer server-initiated requests into async tasks.

**Tool execution hints.** The `execution` object on a tool provides metadata about how the tool should be executed. The `taskSupport` field declares whether the tool supports task-augmented (async) execution: `"forbidden"` (default) means the tool does not support async execution, `"optional"` means it may be called either synchronously or asynchronously, and `"required"` means it must be called with task augmentation. Attack documents testing temporal manipulation or race conditions SHOULD set `taskSupport: "required"` to force the client into async polling mode, where the server can manipulate timing via `pollInterval` and deferred results.

## 7.1.4a Execution State (MCP Client)

When the phase mode is `mcp_client`, the phase state defines the client's behavior: what MCP requests to send and how to respond to server-initiated requests:

```yaml
state:
  client_info:                           # Client identity in initialize request
    name: string                         # Client name
    title: string?                       # Human-readable display name
    version: string?                     # Client version
    description: string?                 # Client description
    icons:                               # Display icons
      - src: string
        mimeType: string?
        sizes: string[]?
        theme: enum(light, dark)?
    websiteUrl: string?                  # Client website URL

  capabilities:                          # Client capabilities declared during initialize
    roots:
      listChanged: boolean?              # Whether client sends notifications/roots/list_changed
    sampling:
      tools: object?                     # Declare support for tool use in sampling
      context: object?                   # Declare support for includeContext parameter
    elicitation:
      form: object?                      # Declare support for form-mode elicitation
      url: object?                       # Declare support for URL-mode elicitation
    tasks:                               # Client-side task capabilities
      list: object?                      # Declare task listing support
      cancel: object?                    # Declare task cancellation support
      requests:                          # Which request types can become async tasks
        sampling:
          createMessage: object?         # Task-augmented sampling/createMessage
        elicitation:
          create: object?                # Task-augmented elicitation/create

  actions:                             # Ordered MCP requests to send during this phase
    - list_tools:                      # Send tools/list request
        cursor: string?               # Pagination cursor from previous nextCursor
    - call_tool:                       # Send tools/call request
        name: string                   # Tool name. Supports {{template}} interpolation.
        arguments: object?             # Tool arguments. Supports {{template}} interpolation.
    - list_resources:                  # Send resources/list request
        cursor: string?               # Pagination cursor from previous nextCursor
    - read_resource:                   # Send resources/read request
        uri: string
    - list_resource_templates:        # Send resources/templates/list request
        cursor: string?               # Pagination cursor from previous nextCursor
    - list_prompts:                    # Send prompts/list request
        cursor: string?               # Pagination cursor from previous nextCursor
    - get_prompt:                      # Send prompts/get request
        name: string
        arguments: object?
    - subscribe_resource:              # Send resources/subscribe request
        uri: string
    - unsubscribe_resource:            # Send resources/unsubscribe request
        uri: string
    - get_task:                        # Send tasks/get request
        taskId: string
    - cancel_task:                     # Send tasks/cancel request
        taskId: string
    - list_tasks:                      # Send tasks/list request
        cursor: string?               # Pagination cursor from previous nextCursor
    - complete:                        # Send completion/complete request
        ref: object
        argument: object
    - get_task_result:                 # Send tasks/result request
        taskId: string

  sampling_responses:                  # Responses to server-initiated sampling/createMessage
    - when: <MatchPredicate>?          # Predicate on sampling request params
      content:                         # Static response (mutually exclusive with synthesize)
        role: enum(user, assistant)
        model: string?
        content:                       # Single block or array of blocks
          - type: enum(text, image, audio, tool_use, tool_result)
            # Type-specific fields:
            text: string?              # type: text
            data: string?              # Base64-encoded (type: image, audio)
            mimeType: string?          # type: image, audio
            id: string?               # type: tool_use (tool use ID)
            name: string?             # type: tool_use (tool name)
            input: object?            # type: tool_use (tool arguments)
            toolUseId: string?        # type: tool_result (references tool_use.id)
            content: array?           # type: tool_result (required — array of content blocks)
            structuredContent: object? # type: tool_result (optional structured output)
            isError: boolean?         # type: tool_result
            annotations:               # Content metadata
              audience: string[]?
              priority: number?
              lastModified: string?
      synthesize:                      # LLM generation (mutually exclusive with content)
        prompt: string

  elicitation_responses:               # Responses to server-initiated elicitation/create
    - when: <MatchPredicate>?          # Predicate on elicitation request params
      action: enum(accept, decline, cancel)?  # Default: accept
      content: object?                 # Response fields matching requestedSchema (static, mutually exclusive with synthesize)
      synthesize:                      # LLM generation (mutually exclusive with content)
        prompt: string

  roots:                               # Filesystem roots for roots/list responses
    - uri: string                      # Root URI (e.g., file:///workspace)
      name: string?                    # Human-readable label
```

**Action semantics.** The `actions` list is the client-mode equivalent of server tools/resources: it defines what the client does during each phase. Actions are executed sequentially in list order; each action is one MCP JSON-RPC request. Each action object MUST contain exactly one action key (same constraint as [`on_enter` actions](/sdk/core-types/#27a-action), V-043).

**Client identity.** The `client_info` object controls the `clientInfo` field in the `initialize` request. When omitted, tools SHOULD default to `{name: "oatf-client", version: "1.0.0"}`. Attack documents testing client impersonation SHOULD set this field explicitly.

**Client capabilities.** The `capabilities` object is sent during `initialize`. It declares which server-initiated features the client supports: `sampling` (LLM completion requests, with optional `tools` and `context` sub-capabilities), `elicitation` (user input requests, with `form` and `url` mode support), `roots` (filesystem roots with optional `listChanged` notifications), and `tasks` (client-side task support including `list`, `cancel`, and request-type-specific augmentation). When omitted, tools SHOULD default to `{roots: {listChanged: true}}`.

**Excluded methods.** `initialize` and `ping` are not actions. `initialize` is performed automatically by the runtime before phase execution begins (part of connection setup), and `ping` is a transport-level keepalive. The `actions` list covers application-level requests only.

**Server-initiated request handling.** `sampling_responses` and `elicitation_responses` follow the same ordered-match semantics as server `responses` ([§7.1.4](/specification/protocol-bindings/mcp/#714-execution-state-mcp)): entries are evaluated in order, first match wins, and entries without `when` are catch-alls. Static content and `synthesize` are mutually exclusive on the same entry. Sampling response content is an array of content blocks supporting `text`, `image`, `audio`, `tool_use`, and `tool_result` types. The `tool_use` and `tool_result` types enable multi-turn tool-use loops within sampling, where the client proposes tool calls and returns tool results to the server's LLM.

**Filesystem roots.** The `roots` list is returned verbatim on `roots/list` requests. When absent, the client does not advertise filesystem roots.

**Template interpolation** ([§5.6](/specification/execution-profile/#56-response-templates)) applies recursively to all string-valued fields within actions (including `name`, `uri`, and any string values nested at any depth inside `arguments` objects/arrays) and response content, matching the SDK's `interpolate_value` semantics.

## 7.1.5 Entry Actions (MCP)

Actions executed when entering a phase:

```yaml
on_enter:
  - send_notification:
      method: string         # Notification method name
      params: object?        # Notification parameters
  - send_elicitation:
      message: string        # Human-readable prompt
      mode: enum(form, url)? # Default: form
      requestedSchema: object? # JSON Schema for form mode
      elicitationId: string? # Unique ID for url mode (auto-generated if omitted)
      url: string?           # URL for url mode
  - log:
      message: string
      level: enum(info, warn, error)?
```

## 7.1.6 Behavioral Modifiers (MCP)

The format describes attack *content* (what the messages contain), not delivery *mechanics* (how fast they arrive). However, certain attacks require observable behavioral characteristics to be meaningful. These are expressed as behavioral modifiers on the phase state:

```yaml
state:
  behavior:
    delivery: enum(normal, delayed, slow_stream, unbounded)
    parameters:
      delay_ms: integer?          # For delayed: pause before response
      byte_delay_ms: integer?     # For slow_stream: pause between bytes
      max_line_length: integer?   # For unbounded: single-line length
      nesting_depth: integer?     # For unbounded: JSON nesting depth
    
    side_effects:
      - type: enum(notification_flood, id_collision, connection_reset)
        parameters: object?
```

Behavioral modifiers are OPTIONAL. Their semantics are:

- `normal`: Standard protocol-compliant delivery. This is the default.
- `delayed`: Response is delayed by the specified duration. Simulates resource exhaustion or intentional timing attacks.
- `slow_stream`: Response bytes are delivered incrementally with pauses. Simulates slow loris-style availability attacks.
- `unbounded`: Response contains oversized payloads (excessively long lines, deeply nested JSON). Simulates parser exhaustion attacks.

Side effects are protocol actions that occur alongside the primary response:

- `notification_flood`: Send a high volume of notifications concurrently with the response.
- `id_collision`: Use a JSON-RPC response ID that collides with a pending request.
- `connection_reset`: Terminate the connection after delivering a partial response.

Conforming adversarial tools SHOULD implement behavioral modifiers for realistic simulation. Tools that cannot implement a specific modifier MUST document the limitation and SHOULD still execute the attack content without the modifier.

## 7.1.7 Payload Generation (MCP)

Certain attacks require payloads that are impractical to define inline (large binary blobs, deeply nested structures, randomized fuzzing data). These are expressed as deterministic generated payloads within content items:

```yaml
responses:
  - content:
      - type: text
        generate:
          kind: enum(nested_json, random_bytes, unbounded_line, unicode_stress)
          seed: integer?
          parameters:
            depth: integer?
            size: string?        # Human-readable size ("10mb", "1kb")
            length: string?
            categories: string[]?  # For unicode_stress
```

When `generate` is present on a content item, it replaces the static `text` or `data` field. The adversarial tool MUST generate the payload at execution time according to the specified kind and parameters. This content-item-level `generate` is deterministic and seeded, distinct from the response-level `synthesize` which is LLM-powered and non-deterministic.

## `generate.seed` (OPTIONAL)

A seed value for deterministic payload generation. When provided, the tool MUST produce identical output for identical seed, kind, and parameters, enabling reproducible regression testing. When omitted, the tool MUST generate a seed at execution time, MUST log or report the generated seed in its output, and MUST accept a seed as a runtime parameter for reproduction of a previous run.

This specification does not mandate a specific PRNG algorithm. Seed-based reproducibility is guaranteed within a single tool implementation but not across tools using different PRNGs. Cross-tool reproduction of generated payloads requires sharing the generated output, not regenerating from the seed.

