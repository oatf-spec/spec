#!/usr/bin/env python3
"""Check binding coverage against upstream protocol JSON schemas.

Compares upstream JSON schema type definitions against what's documented
in the OATF protocol binding markdown files. Reports coverage gaps
(missing fields, missing events, undocumented types).

This is a *coverage* checker, not a *conformance* checker. It answers
"is the field mentioned somewhere in the binding?" — not "is it described
with the correct type, requiredness, or shape." Specifically:

- Requiredness is displayed but not validated: a required upstream field
  documented as optional in the binding still counts as covered.
- A field covered in ANY mapped context counts as covered globally.
  Context-specific omissions (e.g., a field present in Task CEL but
  missing from SSE event CEL) are not detected.

Usage:
    python3 tools/check-binding-coverage.py --protocol a2a --fetch
    python3 tools/check-binding-coverage.py --protocol a2a --strict
    python3 tools/check-binding-coverage.py --protocol a2a --discover
    python3 tools/check-binding-coverage.py --protocol all --json
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = REPO_ROOT / ".cache" / "upstream-schemas"

# ---------------------------------------------------------------------------
# A2A v0.3.0 configuration
# ---------------------------------------------------------------------------

# Maps upstream type name -> where it appears in the binding.
# "cel" paths indicate where fields show up in CEL context documentation.
# "state" paths indicate where fields show up in execution state documentation.
# A type can appear in multiple CEL contexts (listed as a list).
A2A_TYPE_MAP = {
    "AgentCard": {
        "cel": ["message"],
        "state": ["agent_card"],
    },
    "AgentSkill": {
        "cel": ["message.skills[]"],
        "state": ["agent_card.skills"],
    },
    "AgentCapabilities": {
        "cel": ["message.capabilities"],
        "state": ["agent_card.capabilities"],
    },
    "AgentExtension": {
        "cel": ["message.capabilities.extensions[]"],
        "state": ["agent_card.capabilities.extensions"],
    },
    "AgentProvider": {
        "cel": ["message.provider"],
        "state": ["agent_card.provider"],
    },
    "AgentInterface": {
        "cel": ["message.additionalInterfaces[]"],
        "state": ["agent_card.additionalInterfaces"],
    },
    "AgentCardSignature": {
        "cel": ["message.signatures[]"],
        "state": ["agent_card.signatures"],
    },
    "Message": {
        "cel": ["message"],
        "state": ["task_responses.history", "task_message.message"],
    },
    "Task": {
        "cel": ["message"],
        "state": [],
    },
    "TaskStatus": {
        "cel": ["message.status"],
        "state": [],
    },
    "Artifact": {
        "cel": ["message.artifacts[]"],
        "state": ["task_responses.artifacts"],
    },
    "TaskStatusUpdateEvent": {
        "cel": ["message"],
        "state": [],
    },
    "TaskArtifactUpdateEvent": {
        "cel": ["message"],
        "state": [],
    },
    "TextPart": {
        "cel": ["message.parts[]"],
        "state": ["parts"],
        # "text" is documented as a kind-specific field, not by name
        "prose_covered": {"text"},
    },
    "FilePart": {
        "cel": ["message.parts[]"],
        "state": ["parts"],
        # "file" is documented as a kind-specific field, not by name
        "prose_covered": {"file"},
    },
    "DataPart": {
        "cel": ["message.parts[]"],
        "state": ["parts"],
        # "data" is documented as a kind-specific field, not by name
        "prose_covered": {"data"},
    },
    "MessageSendParams": {
        "cel": [],
        "state": ["task_message"],
    },
    "MessageSendConfiguration": {
        "cel": [],
        "state": ["task_message.configuration"],
    },
    "PushNotificationConfig": {
        "cel": [],
        "state": ["push_notification_config.config",
                   "task_message.configuration.pushNotificationConfig"],
    },
    "PushNotificationAuthenticationInfo": {
        "cel": [],
        "state": ["push_notification_config.config.authentication",
                   "task_message.configuration.pushNotificationConfig.authentication"],
    },
    "TaskIdParams": {
        "cel": [],
        "state": ["task_cancel", "task_resubscribe"],
    },
    "TaskQueryParams": {
        "cel": [],
        "state": ["task_query"],
    },
    "DeleteTaskPushNotificationConfigParams": {
        "cel": [],
        "state": ["push_notification_config"],
    },
    "GetTaskPushNotificationConfigParams": {
        "cel": [],
        "state": ["push_notification_config"],
    },
    "ListTaskPushNotificationConfigParams": {
        "cel": [],
        "state": ["push_notification_config"],
    },
    "TaskState": {
        "cel": [],
        "state": ["task_responses"],
        "enum": True,
    },
}

# Types intentionally not mapped — JSON-RPC envelope, error, union, and
# OAuth flow internals that don't represent attack surfaces.
A2A_UNMAPPED = {
    # JSON-RPC envelope types
    "JSONRPCMessage", "JSONRPCRequest", "JSONRPCResponse",
    "JSONRPCSuccessResponse", "JSONRPCErrorResponse", "JSONRPCError",
    # Request/Response wrappers
    "SendMessageRequest", "SendMessageResponse", "SendMessageSuccessResponse",
    "SendStreamingMessageRequest", "SendStreamingMessageResponse",
    "SendStreamingMessageSuccessResponse",
    "GetTaskRequest", "GetTaskResponse", "GetTaskSuccessResponse",
    "CancelTaskRequest", "CancelTaskResponse", "CancelTaskSuccessResponse",
    "TaskResubscriptionRequest",
    "SetTaskPushNotificationConfigRequest",
    "SetTaskPushNotificationConfigResponse",
    "SetTaskPushNotificationConfigSuccessResponse",
    "DeleteTaskPushNotificationConfigRequest",
    "DeleteTaskPushNotificationConfigResponse",
    "DeleteTaskPushNotificationConfigSuccessResponse",
    "GetTaskPushNotificationConfigRequest",
    "GetTaskPushNotificationConfigResponse",
    "GetTaskPushNotificationConfigSuccessResponse",
    "ListTaskPushNotificationConfigRequest",
    "ListTaskPushNotificationConfigResponse",
    "ListTaskPushNotificationConfigSuccessResponse",
    "GetAuthenticatedExtendedCardRequest",
    "GetAuthenticatedExtendedCardResponse",
    "GetAuthenticatedExtendedCardSuccessResponse",
    # Union wrapper types
    "A2ARequest", "A2AError", "Part", "SecurityScheme",
    # Base types (checked via concrete subtypes)
    "PartBase", "FileBase", "SecuritySchemeBase",
    # File variants (checked via FilePart)
    "FileWithBytes", "FileWithUri",
    # Error types
    "TaskNotFoundError", "TaskNotCancelableError",
    "PushNotificationNotSupportedError", "InternalError",
    "InvalidParamsError", "InvalidRequestError",
    "MethodNotFoundError", "JSONParseError",
    "ContentTypeNotSupportedError", "InvalidAgentResponseError",
    "UnsupportedOperationError",
    "AuthenticatedExtendedCardNotConfiguredError",
    # Response envelope (not an attack surface)
    "TaskPushNotificationConfig",
    # Enum for transport protocol values
    "TransportProtocol",
    # OAuth flow types (auth internals, not attack surfaces)
    "OAuthFlows", "AuthorizationCodeOAuthFlow", "ClientCredentialsOAuthFlow",
    "ImplicitOAuthFlow", "PasswordOAuthFlow",
    # Security scheme variants (auth internals)
    "OAuth2SecurityScheme", "HTTPAuthSecurityScheme",
    "OpenIdConnectSecurityScheme", "APIKeySecurityScheme",
    "MutualTLSSecurityScheme",
}

# A2A expected events per mode.
# Server mode: JSON-RPC requests + HTTP GET the client sends to this server.
# Client mode: responses + SSE events received from the server.
A2A_EVENTS = {
    "server": {
        "message/send", "message/stream",
        "tasks/get", "tasks/cancel", "tasks/resubscribe",
        "tasks/pushNotificationConfig/set",
        "tasks/pushNotificationConfig/get",
        "tasks/pushNotificationConfig/list",
        "tasks/pushNotificationConfig/delete",
        "agent/getAuthenticatedExtendedCard",
        "agent_card/get",  # HTTP GET, not JSON-RPC
    },
    "client": {
        "message/send", "message/stream",
        "tasks/get", "tasks/cancel", "tasks/resubscribe",
        "tasks/pushNotificationConfig/set",
        "tasks/pushNotificationConfig/get",
        "tasks/pushNotificationConfig/list",
        "tasks/pushNotificationConfig/delete",
        "agent/getAuthenticatedExtendedCard",
        "agent_card/get",  # HTTP GET response
        "task/status",     # SSE TaskStatusUpdateEvent
        "task/artifact",   # SSE TaskArtifactUpdateEvent
    },
}

# ---------------------------------------------------------------------------
# MCP 2025-11-25 configuration
# ---------------------------------------------------------------------------

# _meta is MCP's generic extension point, present on nearly every type.
# Not an attack surface — excluded from all MCP type checks.
MCP_IGNORED_FIELDS = {"_meta"}

MCP_TYPE_MAP = {
    # --- Initialize / Server identity ---
    "InitializeResult": {
        "cel": ["message"],  # initialize response
        "state": [],
    },
    "Implementation": {
        "cel": ["message.serverInfo"],
        "state": ["server_info"],
    },
    "ServerCapabilities": {
        "cel": ["message.capabilities"],
        "state": ["capabilities"],
        # completions, logging, experimental are not attack surfaces;
        # the binding documents tools, resources, prompts, elicitation, tasks
        "prose_covered": {"completions", "logging", "experimental"},
    },

    # --- Tool types ---
    "Tool": {
        "cel": ["message.tools"],
        "state": ["tools"],
    },
    "ToolAnnotations": {
        # Inline sub-fields from CEL get flattened under message.tools
        "cel": ["message.tools", "message.tools.annotations"],
        "state": ["tools.annotations"],
    },
    "ToolExecution": {
        "cel": ["message.tools", "message.tools.execution"],
        "state": ["tools.execution"],
    },
    "CallToolRequestParams": {
        "cel": ["message"],  # tools/call request
        "state": ["actions"],
        # task augmentation param is runtime-level, not documented per-field
        "ignored": {"task"},
    },
    "CallToolResult": {
        "cel": ["message"],  # tools/call response
        "state": ["tools.responses"],
    },

    # --- Content types ---
    "TextContent": {
        "cel": ["message.content"],
        "state": ["tools.responses.content", "prompts.responses.messages.content"],
        # "type" is documented as enum discriminator, not by field name
        "prose_covered": {"type"},
    },
    "ImageContent": {
        "cel": ["message.content"],
        "state": ["tools.responses.content"],
        "prose_covered": {"type"},
    },
    "AudioContent": {
        "cel": ["message.content"],
        "state": ["tools.responses.content"],
        "prose_covered": {"type"},
    },
    "EmbeddedResource": {
        "cel": ["message.content"],
        "state": [],  # not separately in state
        "prose_covered": {"type"},
    },
    "ResourceLink": {
        "cel": ["message.content"],
        "state": ["tools.responses.content"],
        "prose_covered": {"type"},
    },
    "Annotations": {
        "cel": ["message.content.annotations", "message.resources.annotations"],
        "state": ["tools.responses.content.annotations", "resources.annotations"],
    },
    "Icon": {
        "cel": ["message.tools"],  # inline sub-fields under tools
        "state": ["server_info.icons", "tools.icons", "resources.icons",
                  "prompts.icons"],
    },

    # --- Resource types ---
    "Resource": {
        "cel": ["message.resources"],
        "state": ["resources"],
    },
    "TextResourceContents": {
        "cel": ["message.contents"],
        "state": ["resources.content"],
    },
    "BlobResourceContents": {
        "cel": ["message.contents"],
        "state": ["resources.content"],
    },
    "ResourceTemplate": {
        "cel": ["message.resourceTemplates"],
        "state": [],
    },

    # --- Prompt types ---
    "Prompt": {
        "cel": ["message.prompts"],
        "state": ["prompts"],
    },
    "PromptArgument": {
        "cel": ["message.prompts.arguments"],
        "state": ["prompts.arguments"],
        # title is in the MCP schema but not in binding (added in 2025-11-25)
    },
    "PromptMessage": {
        "cel": ["message.messages"],
        "state": ["prompts.responses.messages"],
    },
    "GetPromptResult": {
        "cel": ["message"],  # prompts/get response
        "state": [],
    },

    # --- Sampling types ---
    "CreateMessageRequestParams": {
        "cel": ["message"],  # sampling/createMessage request
        "state": [],
        # Non-attack-relevant params
        "ignored": {"task", "includeContext", "stopSequences", "temperature",
                    "metadata"},
    },
    "CreateMessageResult": {
        "cel": [],
        "state": ["sampling_responses.content"],
        # stopReason is a response field, not modeled in state
        "prose_covered": {"stopReason"},
    },
    "SamplingMessage": {
        "cel": ["message.messages"],
        "state": [],
    },
    "ModelPreferences": {
        "cel": ["message.modelPreferences"],
        "state": [],
    },
    "ModelHint": {
        "cel": ["message.modelPreferences"],  # hints[] inline
        "state": [],
    },
    "ToolChoice": {
        "cel": ["message.toolChoice", "message"],
        "state": [],
    },

    # --- Elicitation types ---
    "ElicitRequestFormParams": {
        "cel": ["message"],  # elicitation/create request (form mode)
        "state": ["elicitations"],
        "ignored": {"task"},
    },
    "ElicitRequestURLParams": {
        "cel": ["message"],  # elicitation/create request (url mode)
        "state": ["elicitations"],
        "ignored": {"task"},
    },
    "ElicitResult": {
        "cel": ["message"],  # elicitation/create response
        "state": ["elicitation_responses"],
    },

    # --- Task types (MCP) ---
    "Task": {
        "cel": ["message.task"],
        "state": [],
    },
    "TaskStatus": {
        "cel": [],
        "state": [],
        "enum": True,
    },

    # --- Root types ---
    "Root": {
        "cel": ["message.roots"],
        "state": ["roots"],
    },

    # --- Enums ---
    "Role": {
        "cel": [],
        "state": [],
        "enum": True,
    },
}

MCP_UNMAPPED = {
    # JSON-RPC base/envelope types
    "JSONRPCMessage", "JSONRPCRequest", "JSONRPCNotification",
    "JSONRPCResponse", "JSONRPCResultResponse", "JSONRPCErrorResponse",
    "Request", "RequestParams", "RequestId",
    "Notification", "NotificationParams",
    "Result", "EmptyResult",
    "PaginatedRequest", "PaginatedRequestParams", "PaginatedResult",
    "Error", "Cursor", "ProgressToken",

    # Request envelope types
    "InitializeRequest", "PingRequest",
    "ListToolsRequest", "CallToolRequest",
    "ListResourcesRequest", "ReadResourceRequest",
    "ListResourceTemplatesRequest",
    "SubscribeRequest", "UnsubscribeRequest",
    "ListPromptsRequest", "GetPromptRequest", "CompleteRequest",
    "CreateMessageRequest", "ElicitRequest",
    "SetLevelRequest",
    "GetTaskRequest", "CancelTaskRequest", "ListTasksRequest",
    "GetTaskPayloadRequest",
    "ListRootsRequest",

    # Client capabilities (declared by agent, not attack-controlled)
    "ClientCapabilities",

    # Request params (not individually mapped — actions use simplified forms)
    "InitializeRequestParams",
    "ReadResourceRequestParams", "ResourceRequestParams",
    "SubscribeRequestParams", "UnsubscribeRequestParams",
    "GetPromptRequestParams",
    "CompleteRequestParams",
    "SetLevelRequestParams",
    "PaginatedRequestParams",
    "CancelledNotificationParams",
    "TaskAugmentedRequestParams",

    # Result envelope types
    "ListToolsResult", "ListResourcesResult", "ReadResourceResult",
    "ListResourceTemplatesResult",
    "ListPromptsResult", "CompleteResult",
    "ListRootsResult", "ListTasksResult",
    "CreateTaskResult", "GetTaskResult", "CancelTaskResult",
    "GetTaskPayloadResult",

    # Notification envelope types
    "InitializedNotification", "CancelledNotification",
    "ToolListChangedNotification", "ResourceListChangedNotification",
    "ResourceUpdatedNotification", "PromptListChangedNotification",
    "ProgressNotification", "LoggingMessageNotification",
    "RootsListChangedNotification",
    "TaskStatusNotification", "ElicitationCompleteNotification",

    # Notification params types
    "ProgressNotificationParams",
    "LoggingMessageNotificationParams",
    "ResourceUpdatedNotificationParams",
    "TaskStatusNotificationParams",

    # Union types
    "ClientNotification", "ClientRequest", "ClientResult",
    "ServerNotification", "ServerRequest", "ServerResult",
    "ContentBlock", "SamplingMessageContentBlock",
    "ElicitRequestParams", "PrimitiveSchemaDefinition",
    "EnumSchema", "SingleSelectEnumSchema", "MultiSelectEnumSchema",

    # Elicitation schema types (form schema internals)
    "BooleanSchema", "NumberSchema", "StringSchema",
    "LegacyTitledEnumSchema",
    "TitledSingleSelectEnumSchema", "UntitledSingleSelectEnumSchema",
    "TitledMultiSelectEnumSchema", "UntitledMultiSelectEnumSchema",

    # Base types (checked via concrete subtypes)
    "BaseMetadata", "ResourceContents", "Icons",

    # Error types
    "URLElicitationRequiredError",

    # Logging levels (not an attack surface)
    "LoggingLevel",

    # Content types checked via specific subtypes
    "ToolResultContent", "ToolUseContent",

    # Task metadata (internal)
    "TaskMetadata", "RelatedTaskMetadata",

    # Reference types (completion)
    "PromptReference", "ResourceTemplateReference",

    # Prompt message is mapped; sampling message is mapped
    # PromptMessage is mapped above
}

# MCP expected events per mode.
MCP_EVENTS = {
    "server": {
        "initialize", "ping",
        "tools/list", "tools/call",
        "resources/list", "resources/read",
        "resources/subscribe", "resources/unsubscribe",
        "prompts/list", "prompts/get",
        "completion/complete",
        "sampling/createMessage",
        "elicitation/create",
        "tasks/get", "tasks/result", "tasks/list", "tasks/cancel",
        "roots/list",
    },
    "client": {
        "initialize", "ping",
        "tools/list", "tools/call",
        "resources/list", "resources/read",
        "prompts/list", "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
        "tasks/get", "tasks/result",
        "roots/list",
        "notifications/tools/list_changed",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/prompts/list_changed",
        "notifications/tasks/status",
        "notifications/elicitation/complete",
    },
}

# ---------------------------------------------------------------------------
# Protocol registry
# ---------------------------------------------------------------------------

PROTOCOLS = {
    "a2a": {
        "schema_url": "https://raw.githubusercontent.com/a2aproject/A2A/v0.3.0/specification/json/a2a.json",
        "cache_file": "a2a-v0.3.0.json",
        "pinned": True,  # URL points at a git tag — stable
        "binding_path": "docs/src/content/docs/specification/protocol-bindings/a2a.md",
        "type_map": A2A_TYPE_MAP,
        "unmapped_types": A2A_UNMAPPED,
        "expected_events": A2A_EVENTS,
    },
    "mcp": {
        # NOTE: This URL points at the main branch, not a tag. The directory
        # name (2025-11-25) provides some stability, but main could reorganize
        # paths. If the URL breaks, manually download the schema and place it
        # at .cache/upstream-schemas/mcp-2025-11-25.json
        "schema_url": "https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.json",
        "cache_file": "mcp-2025-11-25.json",
        "pinned": False,  # main branch — use --fetch to refresh
        "binding_path": "docs/src/content/docs/specification/protocol-bindings/mcp.md",
        "type_map": MCP_TYPE_MAP,
        "unmapped_types": MCP_UNMAPPED,
        "ignored_fields": MCP_IGNORED_FIELDS,
        "expected_events": MCP_EVENTS,
    },
}


# ---------------------------------------------------------------------------
# Schema fetching and caching
# ---------------------------------------------------------------------------

def fetch_schema(protocol_key, force=False):
    """Fetch upstream schema, caching to .cache/upstream-schemas/."""
    cfg = PROTOCOLS[protocol_key]
    cache_path = CACHE_DIR / cfg["cache_file"]

    if cache_path.exists() and not force:
        if cfg["pinned"]:
            # Pinned tag — cache is always valid
            return json.loads(cache_path.read_text())
        else:
            # Main branch — warn but use cache unless --fetch
            print(f"  Using cached {cfg['cache_file']} (use --fetch to refresh)",
                  file=sys.stderr)
            return json.loads(cache_path.read_text())

    print(f"  Fetching {cfg['schema_url']}...", file=sys.stderr)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(cfg["schema_url"])
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read()
    cache_path.write_bytes(data)
    return json.loads(data)


def get_schema_types(schema):
    """Extract type definitions from JSON schema $defs or definitions."""
    return schema.get("$defs") or schema.get("definitions") or {}


def _resolve_allof(type_def, schema_types=None):
    """Merge properties and required from allOf-composed schemas."""
    if "allOf" not in type_def:
        return type_def

    merged_props = dict(type_def.get("properties", {}))
    merged_required = list(type_def.get("required", []))

    for sub in type_def["allOf"]:
        # Resolve $ref if present
        if "$ref" in sub and schema_types:
            ref_name = sub["$ref"].rsplit("/", 1)[-1]
            sub = schema_types.get(ref_name, sub)
        merged_props.update(sub.get("properties", {}))
        merged_required.extend(sub.get("required", []))

    return {
        "properties": merged_props,
        "required": merged_required,
    }


def get_type_fields(type_def, schema_types=None):
    """Get field names from a schema type definition.

    Resolves allOf composition by merging properties from all sub-schemas.
    """
    # Resolve allOf first
    resolved = _resolve_allof(type_def, schema_types)

    props = resolved.get("properties", {})
    if props:
        return set(props.keys())

    # Union types (oneOf/anyOf) — no direct fields
    if "oneOf" in type_def or "anyOf" in type_def:
        return set()

    # Enum types
    if "enum" in type_def:
        return set()

    return set()


def get_required_fields(type_def, schema_types=None):
    """Get required field names from a schema type definition.

    Resolves allOf composition by merging required from all sub-schemas.
    """
    resolved = _resolve_allof(type_def, schema_types)
    return set(resolved.get("required", []))


# ---------------------------------------------------------------------------
# Binding markdown parsing
# ---------------------------------------------------------------------------

def _normalize_path(path):
    """Strip [] suffixes from all segments of a dotted path."""
    return re.sub(r"\[\]", "", path)


def parse_binding_cel_fields(text):
    """Extract field paths documented in CEL context sections.

    Returns a set of normalized dotted field paths (no [] suffixes) like:
        {"message.name", "message.description", "message.skills.id", ...}
    """
    fields = set()
    in_cel = False

    for line in text.split("\n"):
        # Detect CEL context section headers
        if re.search(r"CEL Context", line, re.IGNORECASE):
            in_cel = True
            continue
        # Stop at next major section
        if in_cel and re.match(r"^##\s", line) and "CEL" not in line:
            in_cel = False
            continue

        if not in_cel:
            continue

        # Match lines like: - `message.name`: description
        # or: - `message.skills[]`: Array of ...
        m = re.match(r"^-\s+`?(message\.\S+?)`?[:\s]", line)
        if m:
            path = _normalize_path(m.group(1).rstrip("`.,: "))
            fields.add(path)

            # Check for inline sub-field lists:
            # "each with `id`, `name`, `description`, `tags[]`, ..."
            inline = re.findall(r"each with (.+)", line)
            if inline:
                sub_fields = re.findall(r"`(\w+)(?:\[\])?`", inline[0])
                for sf in sub_fields:
                    fields.add(f"{path}.{sf}")

            # "Object with `field1`, `field2`" pattern
            obj_match = re.findall(r"[Oo]bject with (.+)", line)
            if obj_match:
                sub_fields = re.findall(r"`(\w+)(?:\[\])?`", obj_match[0])
                for sf in sub_fields:
                    fields.add(f"{path}.{sf}")

    return fields


def parse_binding_state_fields(text):
    """Extract field paths from execution state YAML code blocks.

    Returns a set of paths like:
        {"agent_card.name", "agent_card.description", ...}
    The "state." prefix is stripped.
    """
    fields = set()
    in_state_section = False
    in_code_block = False
    indent_stack = []  # (indent_level, field_name)

    for line in text.split("\n"):
        # Detect execution state section
        if re.search(r"Execution State", line, re.IGNORECASE) and re.match(r"^##", line):
            in_state_section = True
            continue
        if in_state_section and re.match(r"^##\s", line) and "Execution State" not in line:
            in_state_section = False
            in_code_block = False
            indent_stack = []
            continue

        if not in_state_section:
            continue

        # Track code blocks
        if line.strip().startswith("```"):
            if in_code_block:
                in_code_block = False
                indent_stack = []
            else:
                in_code_block = True
                indent_stack = []
            continue

        if not in_code_block:
            continue

        # Skip comments and blank lines
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue

        # Match list items: "  - field_name: ..."
        # Use the field name's position (not dash position) as indent
        m_list = re.match(r"^(\s*)-\s+(\w+):", line)
        # Match plain field definitions: "  field_name: ..."
        m_plain = re.match(r"^(\s*)(\w+):", line)

        if m_list:
            # For list items, indent = position of the field name itself
            indent = m_list.start(2)
            field_name = m_list.group(2)
        elif m_plain:
            indent = len(m_plain.group(1))
            field_name = m_plain.group(2)
        else:
            continue

        # Pop stack to find parent
        while indent_stack and indent_stack[-1][0] >= indent:
            indent_stack.pop()

        if indent_stack:
            parent_path = indent_stack[-1][1]
            path = f"{parent_path}.{field_name}"
        else:
            path = field_name

        indent_stack.append((indent, path))
        fields.add(path)

    # Strip "state." prefix from all paths
    result = set()
    for f in fields:
        if f.startswith("state."):
            result.add(f[6:])  # len("state.") == 6
        else:
            result.add(f)

    return result


def parse_binding_events(text):
    """Extract event names from event tables in the binding, per mode.

    Only scans tables within "Event Types" sections. Detects mode headers
    like "**For `a2a_server` actors**:" to separate server vs client events.

    Returns a dict:
        {"server": {"message/send", ...}, "client": {"message/send", ...},
         "all": {"message/send", ...}}
    "all" is the union. If no mode headers are found, all events go into "all".
    """
    events = {"server": set(), "client": set(), "all": set()}
    in_event_section = False
    current_mode = None  # "server" or "client"

    for line in text.split("\n"):
        # Detect event type section headers
        if re.search(r"Event Types", line, re.IGNORECASE) and re.match(r"^##", line):
            in_event_section = True
            current_mode = None
            continue
        # Stop at next major section (but not sub-sections within events)
        if in_event_section and re.match(r"^##\s", line) and "Event" not in line:
            in_event_section = False
            current_mode = None
            continue

        if not in_event_section:
            continue

        # Detect mode headers: **For `xxx_server` actors**:
        mode_match = re.search(r"For `\w+_(server|client)` actors", line)
        if mode_match:
            current_mode = mode_match.group(1)
            continue

        # Match table rows: | `event/name` | ...
        m = re.match(r"^\|\s*`([^`]+)`\s*\|", line)
        if m:
            event = m.group(1)
            # Skip table headers
            if event in ("Event", "Surface"):
                continue
            events["all"].add(event)
            if current_mode:
                events[current_mode].add(event)

    return events


def parse_binding_surfaces(text):
    """Extract surface names from surface tables."""
    surfaces = set()
    in_surface_section = False

    for line in text.split("\n"):
        if re.search(r"Surfaces", line) and re.match(r"^##", line):
            in_surface_section = True
            continue
        if in_surface_section and re.match(r"^##\s", line) and "Surface" not in line:
            in_surface_section = False
            continue

        if not in_surface_section:
            continue

        m = re.match(r"^\|\s*`(\w+)`\s*\|", line)
        if m:
            surface = m.group(1)
            if surface != "Surface":
                surfaces.add(surface)

    return surfaces


# ---------------------------------------------------------------------------
# Field matching logic
# ---------------------------------------------------------------------------

def check_field_in_cel(field_name, cel_paths, cel_fields):
    """Check if an upstream field is documented in CEL context.

    All paths are already normalized (no [] suffixes) in cel_fields.
    """
    for cp in cel_paths:
        base = _normalize_path(cp)
        candidate = f"{base}.{field_name}"
        if candidate in cel_fields:
            return True

    return False


def check_field_in_state(field_name, state_paths, state_fields):
    """Check if an upstream field is documented in execution state.

    Uses flexible matching: the field must appear somewhere under the
    expected path prefix, allowing for intermediate OATF fields (like
    'when' in task_responses).
    """
    suffix = f".{field_name}"
    for sp in state_paths:
        # Direct child
        candidate = f"{sp}.{field_name}"
        if candidate in state_fields:
            return True
        # Flexible: field appears anywhere under the state path prefix
        for sf in state_fields:
            if sf.endswith(suffix) and sf.startswith(sp):
                return True

    return False


# ---------------------------------------------------------------------------
# Coverage analysis
# ---------------------------------------------------------------------------

def analyze_type_coverage(protocol_key, schema, binding_text):
    """Analyze field coverage for all mapped types.

    Returns a list of type results:
        [{"type": str, "total": int, "covered": int, "fields": [...]}]
    """
    cfg = PROTOCOLS[protocol_key]
    type_map = cfg["type_map"]
    schema_types = get_schema_types(schema)

    cel_fields = parse_binding_cel_fields(binding_text)
    state_fields = parse_binding_state_fields(binding_text)

    results = []

    for type_name, mapping in sorted(type_map.items()):
        type_def = schema_types.get(type_name)
        if not type_def:
            results.append({
                "type": type_name,
                "total": 0,
                "covered": 0,
                "fields": [],
                "error": f"Type not found in upstream schema",
            })
            continue

        # Enum types — check values against binding text
        if mapping.get("enum"):
            enum_vals = type_def.get("enum", [])
            enum_results = []
            for val in enum_vals:
                # Check if the enum value appears in the binding text.
                # Search for the value in backticks, quotes, or as a bare word
                # in enum() declarations or status lists.
                found = (
                    f"`{val}`" in binding_text
                    or f'"{val}"' in binding_text
                    or f"'{val}'" in binding_text
                    or re.search(rf"\benum\([^)]*\b{re.escape(val)}\b", binding_text)
                    is not None
                )
                enum_results.append({
                    "name": val,
                    "cel": False,
                    "state": False,
                    "covered": found,
                })
            covered = sum(1 for r in enum_results if r["covered"])
            results.append({
                "type": type_name,
                "total": len(enum_vals),
                "covered": covered,
                "fields": enum_results,
                "enum": True,
            })
            continue

        upstream_fields = get_type_fields(type_def, schema_types)
        required = get_required_fields(type_def, schema_types)

        if not upstream_fields:
            # Union or enum type with no properties
            continue

        # Remove globally and per-type ignored fields before checking
        global_ignored = cfg.get("ignored_fields", set())
        type_ignored = mapping.get("ignored", set())
        all_ignored = global_ignored | type_ignored
        upstream_fields = upstream_fields - all_ignored

        if not upstream_fields:
            continue

        cel_paths = mapping.get("cel", [])
        state_paths = mapping.get("state", [])
        prose_covered = mapping.get("prose_covered", set())
        field_results = []

        for field_name in sorted(upstream_fields):
            in_cel = check_field_in_cel(field_name, cel_paths, cel_fields)
            in_state = check_field_in_state(field_name, state_paths, state_fields)
            in_prose = field_name in prose_covered
            covered = in_cel or in_state or in_prose

            field_results.append({
                "name": field_name,
                "cel": in_cel,
                "state": in_state,
                "prose": in_prose,
                "covered": covered,
                "required": field_name in required,
            })

        covered_count = sum(1 for f in field_results if f["covered"])
        results.append({
            "type": type_name,
            "total": len(field_results),
            "covered": covered_count,
            "fields": field_results,
        })

    return results


def analyze_event_coverage(protocol_key, binding_text):
    """Check event coverage per mode (server/client).

    Returns a dict with per-mode results:
        {"server": {"missing": [...], "extra": [...]},
         "client": {"missing": [...], "extra": [...]}}
    """
    cfg = PROTOCOLS[protocol_key]
    expected_events = cfg["expected_events"]
    documented = parse_binding_events(binding_text)

    results = {}
    for mode in ("server", "client"):
        expected = expected_events.get(mode, set())
        doc_mode = documented.get(mode, set())

        missing = expected - doc_mode
        extra = doc_mode - expected

        results[mode] = {
            "expected": sorted(expected),
            "documented": sorted(doc_mode),
            "missing": sorted(missing),
            "extra": sorted(extra),
        }

    return results


def discover_unmapped_types(protocol_key, schema):
    """Find types not in either the mapping or the unmapped allowlist."""
    cfg = PROTOCOLS[protocol_key]
    schema_types = get_schema_types(schema)
    mapped = set(cfg["type_map"].keys())
    unmapped = cfg["unmapped_types"]
    known = mapped | unmapped

    unknown = set(schema_types.keys()) - known
    return sorted(unknown)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_text_report(protocol_key, type_results, event_results, schema):
    """Print human-readable coverage report."""
    cfg = PROTOCOLS[protocol_key]
    version = cfg["cache_file"].replace(".json", "").split("-", 1)[1]
    print(f"\n=== {protocol_key.upper()} {version} Binding Coverage ===\n")

    total_fields = 0
    covered_fields = 0
    gap_types = []

    for tr in type_results:
        if "error" in tr:
            print(f"  !! {tr['type']}: {tr['error']}")
            continue

        total_fields += tr["total"]
        covered_fields += tr["covered"]

        pct = (tr["covered"] / tr["total"] * 100) if tr["total"] else 100
        dots = "." * max(1, 50 - len(tr["type"]) - len(str(tr["total"])))
        status = "OK" if tr["covered"] == tr["total"] else "GAPS"

        if tr.get("enum"):
            print(f"{tr['type']} (enum, {tr['total']} values) {dots} {status}")
            continue

        print(f"{tr['type']} ({tr['total']} fields) {dots} "
              f"{tr['covered']}/{tr['total']} ({pct:.0f}%)")

        for f in tr["fields"]:
            if f["covered"]:
                loc = []
                if f["cel"]:
                    loc.append("CEL")
                if f["state"]:
                    loc.append("STATE")
                if f.get("prose"):
                    loc.append("PROSE")
                marker = " + ".join(loc)
                print(f"  \u2713 {f['name']:30s} {marker}")
            else:
                req = " [REQUIRED]" if f.get("required") else ""
                print(f"  \u2717 {f['name']:30s} --- GAP ---{req}")
                gap_types.append((tr["type"], f["name"]))

    print()

    # Event coverage (per mode)
    event_issues = False
    for mode in ("server", "client"):
        mode_result = event_results.get(mode, {})
        missing = mode_result.get("missing", [])
        extra = mode_result.get("extra", [])
        if missing or extra:
            event_issues = True
            print(f"--- Events ({mode}) ---")
            for e in missing:
                print(f"  \u2717 {e}  MISSING")
            for e in extra:
                print(f"  ? {e}  EXTRA (not in expected set)")
            print()

    # Skipped types
    unmapped = sorted(cfg["unmapped_types"])
    if unmapped:
        print(f"--- Skipped (intentionally unmapped, {len(unmapped)} types) ---")
        # Print in rows of 4
        for i in range(0, len(unmapped), 4):
            chunk = unmapped[i:i+4]
            print(f"  {', '.join(chunk)}")
        print()

    # Discovery
    unknown = discover_unmapped_types(protocol_key, schema)
    if unknown:
        print("--- UNKNOWN types (not mapped or allowlisted) ---")
        for t in unknown:
            print(f"  ? {t}")
        print()

    # Summary
    if total_fields:
        pct = covered_fields / total_fields * 100
        print(f"TOTAL: {covered_fields}/{total_fields} fields covered ({pct:.1f}%)")
    else:
        print("TOTAL: no mapped types with fields")

    if gap_types:
        print(f"\n{len(gap_types)} gap(s) found.")
    else:
        print("\nNo gaps found.")

    has_event_gaps = any(
        event_results.get(mode, {}).get("missing")
        or event_results.get(mode, {}).get("extra")
        for mode in ("server", "client")
    )
    return len(gap_types) == 0 and not has_event_gaps and not unknown


def build_json_report(protocol_key, type_results, event_results, schema):
    """Build machine-readable JSON report dict."""
    cfg = PROTOCOLS[protocol_key]
    unknown = discover_unmapped_types(protocol_key, schema)

    report = {
        "protocol": protocol_key,
        "cache_file": cfg["cache_file"],
        "types": type_results,
        "events": event_results,
        "unknown_types": unknown,
        "skipped_types": sorted(cfg["unmapped_types"]),
    }

    total = sum(tr["total"] for tr in type_results if "error" not in tr)
    covered = sum(tr["covered"] for tr in type_results if "error" not in tr)
    missing_events = sum(
        len(event_results.get(m, {}).get("missing", []))
        for m in ("server", "client")
    )
    extra_events = sum(
        len(event_results.get(m, {}).get("extra", []))
        for m in ("server", "client")
    )
    report["summary"] = {
        "total_fields": total,
        "covered_fields": covered,
        "coverage_pct": round(covered / total * 100, 1) if total else 100.0,
        "gaps": total - covered,
        "missing_events": missing_events,
        "extra_events": extra_events,
        "unknown_types": len(unknown),
        "clean": (total == covered
                  and missing_events == 0
                  and extra_events == 0
                  and not unknown),
    }

    return report


def print_discover(protocol_key, schema):
    """Print types not in either mapping or allowlist."""
    unknown = discover_unmapped_types(protocol_key, schema)
    if unknown:
        print(f"\n{protocol_key.upper()}: {len(unknown)} undiscovered type(s):\n")
        for t in unknown:
            schema_types = get_schema_types(schema)
            td = schema_types.get(t, {})
            fields = sorted(get_type_fields(td, get_schema_types(schema)))
            fields_str = ", ".join(fields) if fields else "(no properties)"
            print(f"  {t}: {fields_str}")
    else:
        print(f"\n{protocol_key.upper()}: all types triaged (mapped or allowlisted)")
    return len(unknown) == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_protocol(protocol_key, args):
    """Run coverage check for a single protocol.

    Returns (clean: bool, json_report: dict|None).
    In JSON mode, the report dict is returned for aggregation by main().
    In text mode, output is printed directly and json_report is None.
    """
    cfg = PROTOCOLS[protocol_key]

    if not cfg["type_map"]:
        print(f"\n{protocol_key.upper()}: type map not yet configured, skipping.",
              file=sys.stderr)
        return True, None

    # Fetch/load schema
    schema = fetch_schema(protocol_key, force=args.fetch)

    # Discover mode
    if args.discover:
        return print_discover(protocol_key, schema), None

    # Load binding
    binding_path = REPO_ROOT / cfg["binding_path"]
    if not binding_path.exists():
        print(f"ERROR: Binding not found: {binding_path}", file=sys.stderr)
        return False, None
    binding_text = binding_path.read_text()

    # Analyze
    type_results = analyze_type_coverage(protocol_key, schema, binding_text)
    event_results = analyze_event_coverage(protocol_key, binding_text)

    # Report
    if args.json:
        report = build_json_report(protocol_key, type_results, event_results, schema)
        return report["summary"]["clean"], report
    else:
        clean = print_text_report(protocol_key, type_results, event_results, schema)
        return clean, None


def main():
    parser = argparse.ArgumentParser(
        description="Check OATF binding coverage against upstream protocol schemas.")
    parser.add_argument("--protocol", choices=["a2a", "mcp", "all"], default="all",
                        help="Protocol to check (default: all)")
    parser.add_argument("--fetch", action="store_true",
                        help="Force re-download of upstream schemas")
    parser.add_argument("--json", action="store_true",
                        help="Machine-readable JSON output")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 on any gap")
    parser.add_argument("--discover", action="store_true",
                        help="Show types not in mapping or allowlist")
    args = parser.parse_args()

    protocols = ["a2a", "mcp"] if args.protocol == "all" else [args.protocol]
    all_clean = True
    json_reports = []

    for p in protocols:
        clean, report = run_protocol(p, args)
        if not clean:
            all_clean = False
        if report is not None:
            json_reports.append(report)

    # In JSON mode, emit a single valid JSON document
    if args.json and json_reports:
        if len(json_reports) == 1:
            print(json.dumps(json_reports[0], indent=2))
        else:
            print(json.dumps(json_reports, indent=2))

    if args.strict and not all_clean:
        sys.exit(1)


if __name__ == "__main__":
    main()
