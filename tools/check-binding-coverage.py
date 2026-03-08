#!/usr/bin/env python3
"""Check binding coverage against upstream protocol JSON schemas.

Compares upstream JSON schema type definitions against what's documented
in the OATF protocol binding markdown files. Reports coverage gaps
(missing fields, missing events, undocumented types).

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

# A2A JSON-RPC methods extracted from the schema's request type method enums
A2A_METHODS = {
    "message/send", "message/stream",
    "tasks/get", "tasks/cancel", "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
    "agent/getAuthenticatedExtendedCard",
}

# Non-JSON-RPC events defined by the binding (HTTP endpoints, SSE events)
A2A_EXTRA_EVENTS = {
    "agent_card/get",   # HTTP GET, not JSON-RPC
    "task/status",      # SSE TaskStatusUpdateEvent
    "task/artifact",    # SSE TaskArtifactUpdateEvent
}

# ---------------------------------------------------------------------------
# MCP 2025-11-25 configuration (stub — will be expanded)
# ---------------------------------------------------------------------------

MCP_TYPE_MAP = {}   # TODO: populate when MCP binding reaches same rigor
MCP_UNMAPPED = set()

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
        "methods": A2A_METHODS,
        "extra_events": A2A_EXTRA_EVENTS,
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
        "methods": set(),
        "extra_events": set(),
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


def get_type_fields(type_def):
    """Get field names from a schema type definition."""
    props = type_def.get("properties", {})
    if props:
        return set(props.keys())

    # Union types (oneOf/anyOf) — no direct fields
    if "oneOf" in type_def or "anyOf" in type_def:
        return set()

    # Enum types
    if "enum" in type_def:
        return set()

    return set()


def get_required_fields(type_def):
    """Get required field names from a schema type definition."""
    return set(type_def.get("required", []))


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
    """Extract event names from event tables in the binding.

    Returns a set of event names like:
        {"message/send", "tasks/get", "agent_card/get", ...}
    """
    events = set()

    for line in text.split("\n"):
        # Match table rows: | `event/name` | ...
        m = re.match(r"^\|\s*`([^`]+)`\s*\|", line)
        if m:
            event = m.group(1)
            # Skip table headers
            if event in ("Event", "Surface"):
                continue
            events.add(event)

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

        # Enum types — check values, not fields
        if mapping.get("enum"):
            enum_vals = type_def.get("enum", [])
            results.append({
                "type": type_name,
                "total": len(enum_vals),
                "covered": len(enum_vals),
                "fields": [{"name": v, "cel": False, "state": True, "covered": True}
                           for v in enum_vals],
                "enum": True,
            })
            continue

        upstream_fields = get_type_fields(type_def)
        required = get_required_fields(type_def)

        if not upstream_fields:
            # Union or enum type with no properties
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
    """Check that all upstream methods appear in the binding's event tables."""
    cfg = PROTOCOLS[protocol_key]
    expected = cfg["methods"] | cfg["extra_events"]
    documented = parse_binding_events(binding_text)

    missing = expected - documented
    extra = documented - expected  # binding events not in upstream

    return {
        "expected": sorted(expected),
        "documented": sorted(documented),
        "missing": sorted(missing),
        "extra": sorted(extra),
    }


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

    # Event coverage
    if event_results["missing"]:
        print("--- Missing Events ---")
        for e in event_results["missing"]:
            print(f"  \u2717 {e}")
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

    return len(gap_types) == 0 and not event_results["missing"] and not unknown


def print_json_report(protocol_key, type_results, event_results, schema):
    """Print machine-readable JSON report."""
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
    report["summary"] = {
        "total_fields": total,
        "covered_fields": covered,
        "coverage_pct": round(covered / total * 100, 1) if total else 100.0,
        "gaps": total - covered,
        "missing_events": len(event_results["missing"]),
        "unknown_types": len(unknown),
        "clean": (total == covered
                  and not event_results["missing"]
                  and not unknown),
    }

    print(json.dumps(report, indent=2))
    return report["summary"]["clean"]


def print_discover(protocol_key, schema):
    """Print types not in either mapping or allowlist."""
    unknown = discover_unmapped_types(protocol_key, schema)
    if unknown:
        print(f"\n{protocol_key.upper()}: {len(unknown)} undiscovered type(s):\n")
        for t in unknown:
            schema_types = get_schema_types(schema)
            td = schema_types.get(t, {})
            fields = sorted(get_type_fields(td))
            fields_str = ", ".join(fields) if fields else "(no properties)"
            print(f"  {t}: {fields_str}")
    else:
        print(f"\n{protocol_key.upper()}: all types triaged (mapped or allowlisted)")
    return len(unknown) == 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_protocol(protocol_key, args):
    """Run coverage check for a single protocol. Returns True if clean."""
    cfg = PROTOCOLS[protocol_key]

    if not cfg["type_map"]:
        print(f"\n{protocol_key.upper()}: type map not yet configured, skipping.",
              file=sys.stderr)
        return True

    # Fetch/load schema
    schema = fetch_schema(protocol_key, force=args.fetch)

    # Discover mode
    if args.discover:
        return print_discover(protocol_key, schema)

    # Load binding
    binding_path = REPO_ROOT / cfg["binding_path"]
    if not binding_path.exists():
        print(f"ERROR: Binding not found: {binding_path}", file=sys.stderr)
        return False
    binding_text = binding_path.read_text()

    # Analyze
    type_results = analyze_type_coverage(protocol_key, schema, binding_text)
    event_results = analyze_event_coverage(protocol_key, binding_text)

    # Report
    if args.json:
        return print_json_report(protocol_key, type_results, event_results, schema)
    else:
        return print_text_report(protocol_key, type_results, event_results, schema)


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

    for p in protocols:
        clean = run_protocol(p, args)
        if not clean:
            all_clean = False

    if args.strict and not all_clean:
        sys.exit(1)


if __name__ == "__main__":
    main()
