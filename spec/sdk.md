# OATF SDK Specification

**Version:** 0.1.0-draft  
**Status:** Draft  
**Date:** 2026-02-16  
**License:** Apache 2.0

## Abstract

This specification defines the language-agnostic API contract for OATF SDK implementations. An OATF SDK is a library that parses, validates, normalizes, evaluates, and serializes OATF documents. Any tool that consumes or produces OATF documents (adversarial simulation tools, evaluation scanners, CI pipeline integrations, IDE plugins) builds on an SDK rather than reimplementing the format's semantics.

This specification defines the abstract types, entry points, evaluation interfaces, execution primitives, extension points, and error taxonomy that every conforming SDK MUST expose. Language-specific idioms (error signaling mechanisms, collection types, concurrency models, naming conventions) are left to individual SDK implementations. The behavioral contracts are language-agnostic and testable via the OATF conformance test suite.

This specification references the OATF Format Specification v0.1 throughout. Section references (§) refer to that document unless otherwise noted.

## 1. Scope

### 1.1 What the SDK Does

The SDK implements the portable logic defined by the OATF format specification:

- Parsing YAML into a typed document model.
- Validating documents against the structural and semantic rules of §11.1.
- Normalizing documents to canonical form per §11.2.
- Resolving dot-paths, match predicates, and template expressions.
- Evaluating indicators against protocol messages.
- Computing attack-level verdicts from indicator results.
- Serializing documents back to YAML in fully-expanded form.

### 1.2 What the SDK Does Not Do

The SDK has no knowledge of:

- Protocol transports (stdio, HTTP, SSE, WebSocket).
- Protocol wire formats (JSON-RPC framing, HTTP headers).
- Attack execution (connecting to servers, sending messages, managing sessions).
- Traffic capture (proxying, recording, replaying).
- Reporting, visualization, or user interfaces.
- Configuration management, environment variables, or file inclusion.

These are concerns of the tools that consume the SDK.

### 1.3 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

A conforming OATF SDK:

1. MUST implement all entry points defined in §3.
2. MUST implement all core types defined in §2.
3. MUST implement pattern indicator evaluation (§4.2).
4. MUST implement all verdict computation modes (§4.5).
5. MUST implement all execution primitives defined in §5.
6. MUST define extension point interfaces for CEL evaluation and semantic evaluation (§6).
7. MUST use the error taxonomy defined in §7.
8. SHOULD implement expression indicator evaluation via the CEL extension point (§4.3, §6.1).
9. SHOULD pass the OATF conformance test suite without failure.
10. MUST document which optional capabilities it supports.

---

## 2. Core Types

This section defines the abstract types that constitute the OATF document model. Each type is described as a set of named fields with specified types and constraints. SDKs MUST expose these types in their public API. Field names SHOULD match those listed here, adapted to the target language's naming conventions (for example, `snake_case` in Rust and Python, `camelCase` in JavaScript and Go).

### 2.1 Primitive Types

The following primitive types are used throughout this specification:

| Type | Description |
|---|---|
| `String` | A UTF-8 string. |
| `Integer` | A signed integer of at least 64 bits. |
| `Float` | An IEEE 754 double-precision floating point number. |
| `Boolean` | `true` or `false`. |
| `Duration` | A time span. SDKs MUST accept both shorthand (`30s`, `5m`, `1h`, `2d`) and ISO 8601 format (`PT30S`, `PT5M`, `P1DT12H`). |
| `Date` | An ISO 8601 date (`YYYY-MM-DD`). |
| `DateTime` | An ISO 8601 date-time with timezone. |
| `Value` | A dynamically-typed JSON-like value: null, boolean, number, string, array of Value, or map of String to Value. Used for protocol message content and match predicate targets. |
| `Optional<T>` | A value that may be absent. |
| `List<T>` | An ordered sequence of values. |
| `Map<K, V>` | An unordered mapping from keys to values. |

### 2.2 Document

The top-level container for a parsed OATF document.

| Field | Type | Description |
|---|---|---|
| `oatf` | `String` | Specification version declared by this document. |
| `schema` | `Optional<String>` | JSON Schema URL (`$schema` in YAML). Preserved through round-trips but ignored during processing. |
| `attack` | `Attack` | The attack definition. |

### 2.3 Attack

The attack envelope and all contained structures.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `Optional<String>` | No | — | Unique identifier (for example, `OATF-003`, `ACME-001`). Required for publication. |
| `name` | `Optional<String>` | No | `"Untitled"` | Human-readable attack name. |
| `version` | `Optional<Integer>` | No | `1` | Document version (positive integer, higher is newer). |
| `status` | `Optional<Status>` | No | `draft` | Lifecycle status. |
| `created` | `Optional<DateTime>` | No | — | First published date/time. Bare dates accepted (interpreted as midnight UTC). |
| `modified` | `Optional<DateTime>` | No | — | Last modified date/time. Bare dates accepted. |
| `author` | `Optional<String>` | No | — | Author or organization. |
| `description` | `Optional<String>` | No | — | Prose description of the attack. |
| `grace_period` | `Optional<Duration>` | No | — | Post-terminal-phase observation window. When present, tools observe for this duration after all terminal phases complete before computing the verdict. Parsed by `parse_duration` (§5.2). |
| `severity` | `Optional<Severity>` | No | — | Absent when not assessed. Always in object form after normalization when present. |
| `impact` | `Optional<List<Impact>>` | No | — | Categories of harm. |
| `classification` | `Optional<Classification>` | No | — | Framework mappings and taxonomy. |
| `references` | `Optional<List<Reference>>` | No | — | External references. |
| `execution` | `Execution` | Yes | — | Execution profile. |
| `indicators` | `Optional<List<Indicator>>` | No | — | Patterns for determining agent compliance. When absent, document is simulation-only. |
| `correlation` | `Optional<Correlation>` | No | — | How indicator verdicts combine. See §2.3a. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

**Post-normalization guarantee:** After `normalize` (§3.3), `name`, `version`, and `status` are always present with their default values applied. Code that operates on normalized documents MAY assert their presence.

### 2.3a Correlation

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `logic` | `CorrelationLogic` | No | `any` | How indicator verdicts combine to produce the attack-level verdict. |

`correlation` MUST only be present when `indicators` is also present (the JSON Schema enforces this via `dependentRequired`). Correlation governs how indicator verdicts combine and is meaningless without indicators.

### 2.4 Severity

Always represented in object form. SDKs MUST expand scalar input during normalization.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `level` | `SeverityLevel` | Yes | — | One of: `informational`, `low`, `medium`, `high`, `critical`. |
| `confidence` | `Integer` | No | `50` | Author confidence in the assigned severity level, 0–100. |

### 2.5 Classification

| Field | Type | Description |
|---|---|---|
| `category` | `Optional<Category>` | OATF taxonomy category. |
| `mappings` | `Optional<List<FrameworkMapping>>` | External security framework mappings. |
| `tags` | `Optional<List<String>>` | Free-form tags. Lowercase, hyphenated. |

### 2.6 Execution

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | `Optional<String>` | No | — | Attacker posture. Must match `{protocol}_{role}` convention. Required when `state` is present. |
| `state` | `Optional<Value>` | No | — | Protocol-specific state (single-phase form only). |
| `phases` | `Optional<List<Phase>>` | No | — | Ordered phase sequence (multi-phase form only). |
| `actors` | `Optional<List<Actor>>` | No | — | Named concurrent actors (multi-actor form only). |

Three forms are mutually exclusive: `state`, `phases`, and `actors` MUST NOT coexist. The single-phase form (`state`) normalizes to multi-actor form via N-006. The multi-phase form (`phases`) normalizes to multi-actor form via N-007.

Extension fields (`x-` prefixed) on `Execution` are stored in an `extensions: Optional<Map<String, Value>>` and preserved through round-trips.

### 2.6a Actor

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `String` | Yes | — | Unique identifier. Must match `[a-z][a-z0-9_]*`. |
| `mode` | `String` | Yes | — | Attacker posture for this actor. Must match `{protocol}_{role}` convention. |
| `phases` | `List<Phase>` | Yes | — | Ordered phase sequence. At least one required. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

### 2.7 Phase

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `Optional<String>` | No | `"phase-{N}"` (1-based index) | Human-readable phase label. Auto-generated when omitted. |
| `description` | `Optional<String>` | No | — | Phase purpose. |
| `mode` | `Optional<String>` | No | Inherited from `execution.mode` or `actor.mode` | Attacker posture for this phase. Required when `execution.mode` is absent and not in multi-actor form. |
| `state` | `Optional<Value>` | No | Inherited from preceding phase | Protocol-specific state. Required on first phase. |
| `extractors` | `Optional<List<Extractor>>` | No | — | Value extractors for this phase. |
| `on_enter` | `Optional<List<Action>>` | No | — | Entry actions executed when this phase begins. See §2.7a. |
| `trigger` | `Optional<Trigger>` | No | — | Trigger condition. Absent on terminal phase. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

> **Note on `state` type:** `state` uses `Value` to permit deserialization of structurally invalid documents for diagnostic reporting. The format specification and JSON Schema constrain `state` to an object; validation (§3.2) rejects non-object values.

### 2.7a Action

An entry action executed when a phase begins. Exactly one action key MUST be present per action object. The v0.1 specification defines three known actions; protocol bindings MAY define additional actions.

**Known actions (v0.1):**

| Key | Required Fields | Description |
|---|---|---|
| `send_notification` | `method: String` | Send a protocol notification. Optional `params: Map<String, Value>` for notification parameters. |
| `log` | `message: String` | Emit a log message. `message` supports `{{template}}` interpolation. Optional `level: LogLevel`. |
| `send_elicitation` | `message: String` | Send an elicitation request to the client (MCP server-mode only). Optional `mode: ElicitationMode` (default: `form`), `requestedSchema: Map<String, Value>` (JSON Schema object, for form mode), `url: String` (for url mode). |

**Associated enums:**

| Enumeration | Values |
|---|---|
| `LogLevel` | `info`, `warn`, `error` |
| `ElicitationMode` | `form`, `url` |

**Binding-specific actions:** Action objects MAY contain a single key not in the known set above (e.g., `delay_ms: 500`, `send_ui_event: {...}`). The value type is unconstrained — it may be an object, string, number, or any JSON value. SDKs MUST preserve unrecognized action keys through parse → normalize → serialize round-trips. When evaluating, SDKs SHOULD skip actions they do not recognize and emit a warning diagnostic.

**Extension fields:** Each action object MAY include `x-` prefixed keys alongside the action key. Extension fields are preserved but do not affect action execution.

### 2.8 Trigger

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `event` | `Optional<String>` | No | — | Protocol event to match. |
| `count` | `Optional<Integer>` | No | `1` (when `event` present) | Number of matching events required. |
| `match` | `Optional<MatchPredicate>` | No | — | Content predicate on matching events. |
| `after` | `Optional<Duration>` | No | — | Unconditional time-based advancement. |

### 2.8a ProtocolEvent

Represents a protocol-level event observed during execution. Used by `evaluate_trigger` (§5.8) to match against trigger conditions.

| Field | Type | Required | Description |
|---|---|---|---|
| `event_type` | `String` | Yes | The base event type (e.g., `tools/call`, `message/send`, `run_started`). |
| `qualifier` | `Optional<String>` | No | Pre-resolved event qualifier, if present (the portion after `:` in `tools/call:calculator`). When set, `evaluate_trigger` uses this value directly instead of calling `resolve_event_qualifier`. When absent, the qualifier is resolved from `content` at trigger evaluation time. |
| `content` | `Value` | Yes | The event payload. Evaluated against `trigger.match` predicates via `evaluate_predicate`. |

### 2.8b TriggerResult

Returned by `evaluate_trigger` (§5.8) to indicate whether a phase should advance.

| Variant | Fields | Description |
|---|---|---|
| `Advanced` | `reason: AdvanceReason` | The trigger condition is satisfied; advance to the next phase. |
| `NotAdvanced` | — | The trigger condition is not yet satisfied; remain in the current phase. |

`AdvanceReason` is one of: `event_matched` (the required number of matching events was reached), `timeout` (the `after` duration elapsed).

### 2.8c TriggerState

Mutable state tracked per-actor-per-phase for trigger evaluation. The runtime creates a fresh `TriggerState` when an actor enters a phase and passes it to every `evaluate_trigger` call for that phase. The function updates the state internally; the caller persists it across calls but does not inspect or modify its fields.

| Field | Type | Default | Description |
|---|---|---|---|
| `event_count` | `Integer` | `0` | Number of fully-matched events observed so far in this phase. Initialized to `0` on phase entry; incremented by `evaluate_trigger` (§5.8) when base event, qualifier, and predicate all match. |

### 2.9 Extractor

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `String` | Yes | Variable name for interpolation. Must match `[a-z][a-z0-9_]*`. |
| `source` | `ExtractorSource` | Yes | `request` or `response`. |
| `type` | `ExtractorType` | Yes | `json_path` or `regex`. |
| `selector` | `String` | Yes | The extraction selector. |

### 2.10 MatchPredicate

A match predicate is a map from dot-path field references to conditions. All entries are combined with AND logic. Each entry maps a simple dot-path string (§5.1.1) to either a scalar value (equality check) or a `MatchCondition` object.

```
type MatchPredicate = Map<String, MatchEntry>
```

Where `MatchEntry` is either:
- A scalar `Value` (equality comparison), or
- A `MatchCondition` object.

This is a type alias, not a struct. In YAML, predicates are written as flat mappings (e.g., `{arguments.command: "ls", headers.x-api-key: "secret"}`). The SDK MUST parse them directly as maps without introducing an intermediate `entries` key. Languages without algebraic types may represent `MatchEntry` as a tagged union or untyped `Value` with runtime type checking.

### 2.11 MatchCondition

A condition applied to a resolved field value. At least one operator MUST be present. When multiple operators are present, they are combined with AND logic — the value must satisfy every operator for the condition to match. For example, `{contains: "secret", regex: "key_[0-9]+"}` matches only if both conditions are satisfied.

| Field | Type | Description |
|---|---|---|
| `contains` | `Optional<String>` | Substring match (case-sensitive). |
| `starts_with` | `Optional<String>` | Prefix match (case-sensitive). |
| `ends_with` | `Optional<String>` | Suffix match (case-sensitive). |
| `regex` | `Optional<String>` | RE2-compatible regular expression. |
| `any_of` | `Optional<List<Value>>` | Matches if field equals any listed value. |
| `gt` | `Optional<Float>` | Greater than. |
| `lt` | `Optional<Float>` | Less than. |
| `gte` | `Optional<Float>` | Greater than or equal. |
| `lte` | `Optional<Float>` | Less than or equal. |
| `exists` | `Optional<Boolean>` | Field presence check. `true`: matches if the path resolved to a value (including `null`). `false`: matches if the path did not resolve. |

### 2.12 Indicator

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `Optional<String>` | No | Auto-generated (see N-003) | Unique indicator identifier. Always present after normalization. |
| `protocol` | `Optional<String>` | No | Protocol component of `execution.mode` | Protocol this indicator targets. Required when `execution.mode` is absent. |
| `surface` | `Surface` | Yes | — | Protocol surface being examined. |
| `description` | `Optional<String>` | No | — | What this indicator evaluates. |
| `pattern` | `Optional<PatternMatch>` | No | — | Pattern evaluation definition. Exactly one of `pattern`, `expression`, `semantic` required. |
| `expression` | `Optional<ExpressionMatch>` | No | — | CEL evaluation definition. |
| `semantic` | `Optional<SemanticMatch>` | No | — | Semantic evaluation definition. |
| `confidence` | `Optional<Integer>` | No | — | Indicator-specific confidence override. |
| `severity` | `Optional<SeverityLevel>` | No | — | Indicator-specific severity override. |
| `false_positives` | `Optional<List<String>>` | No | — | Known false positive scenarios. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

### 2.13 PatternMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | Surface default target | Wildcard dot-path to field to inspect (§5.1.2). |
| `condition` | `Optional<Condition>` | No | — | Absent in shorthand form. Always present after normalization. |

A `Condition` is either:
- A bare `Value` (string, number, boolean, array, null) for equality matching, or
- A `MatchCondition` object containing one or more operator keys.

Languages without algebraic types may represent `Condition` as an untyped `Value` with runtime type checking: if it's an object with operator keys, treat as `MatchCondition`; otherwise treat as equality.

The YAML representation supports two forms:

- **Standard form:** `target` + `condition` (both explicit). `condition` may be a bare value (e.g., `condition: "ls"`) or an operator object (e.g., `condition: {contains: "ls"}`).
- **Shorthand form:** a single condition operator as a direct key (e.g., `contains: "foo"`). No `condition` wrapper.

Normalization (N-005): When a `PatternMatch` is parsed in shorthand form, the SDK MUST expand it to standard form with an explicit `condition` field (as a `MatchCondition` object) and `target` defaulted from the surface. Bare-value conditions in standard form are preserved as-is (not wrapped in an operator object).

### 2.14 ExpressionMatch

| Field | Type | Required | Description |
|---|---|---|---|
| `cel` | `String` | Yes | CEL expression evaluating to boolean. |
| `variables` | `Optional<Map<String, String>>` | No | Named variables as dot-paths into message. Keys must be valid CEL identifiers (`[_a-zA-Z][_a-zA-Z0-9]*`). |

### 2.15 SemanticMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | Surface default target | Dot-path to field to analyze. |
| `intent` | `String` | Yes | — | Natural-language intent description. |
| `intent_class` | `Optional<SemanticIntentClass>` | No | — | Intent category hint for classification engines. |
| `threshold` | `Optional<Float>` | No | — | Similarity/confidence threshold, 0.0–1.0. |
| `examples` | `Optional<SemanticExamples>` | No | — | Positive and negative examples. |

### 2.16 SemanticExamples

| Field | Type | Required | Description |
|---|---|---|---|
| `positive` | `Optional<List<String>>` | No | Strings that SHOULD trigger the indicator. |
| `negative` | `Optional<List<String>>` | No | Strings that SHOULD NOT trigger the indicator. |

When `examples` is present, at least one of `positive` or `negative` MUST be provided (the JSON Schema enforces this via `minProperties: 1`). Documents with `semantic` indicators SHOULD include at least two positive and two negative examples to enable cross-tool calibration (format specification §6.4).

### 2.17 Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | `String` | Yes | URL of the external reference. |
| `title` | `Optional<String>` | No | Human-readable title. |
| `description` | `Optional<String>` | No | Brief description of the reference. |

### 2.18 FrameworkMapping

| Field | Type | Required | Description |
|---|---|---|---|
| `framework` | `Framework` | Yes | The external framework being referenced. |
| `id` | `String` | Yes | Identifier of the specific entry within the framework. |
| `name` | `Optional<String>` | No | Human-readable name of the referenced entry. |
| `url` | `Optional<String>` | No | Permalink to the referenced entry. |
| `relationship` | `Optional<Relationship>` | No | `primary` (default) or `related`. |

### 2.19 Verdict Types

#### IndicatorVerdict

| Field | Type | Required | Description |
|---|---|---|---|
| `indicator_id` | `String` | Yes | The indicator that produced this verdict. |
| `result` | `IndicatorResult` | Yes | One of: `matched`, `not_matched`, `error`, `skipped`. |
| `timestamp` | `Optional<DateTime>` | No | When the verdict was produced. |
| `evidence` | `Optional<String>` | No | The matched content or error diagnostic. |
| `source` | `Optional<String>` | No | The tool that produced the verdict. |

#### AttackVerdict

| Field | Type | Required | Description |
|---|---|---|---|
| `attack_id` | `Optional<String>` | No | The attack that was evaluated. Absent when the document has no `attack.id`. |
| `result` | `AttackResult` | Yes | One of: `exploited`, `not_exploited`, `partial`, `error`. |
| `indicator_verdicts` | `List<IndicatorVerdict>` | Yes | All individual indicator results. |
| `evaluation_summary` | `EvaluationSummary` | Yes | Counts of each indicator result. Prevents `skipped → not_matched` aggregation from masking evaluation gaps. |
| `timestamp` | `Optional<DateTime>` | No | When the verdict was produced. |
| `source` | `Optional<String>` | No | The tool that produced the verdict. |

#### EvaluationSummary

| Field | Type | Required | Description |
|---|---|---|---|
| `matched` | `Integer` | Yes | Number of indicators that produced `matched`. |
| `not_matched` | `Integer` | Yes | Number of indicators that produced `not_matched`. |
| `error` | `Integer` | Yes | Number of indicators that produced `error`. |
| `skipped` | `Integer` | Yes | Number of indicators that produced `skipped`. |

### 2.20 Enumerations

SDKs MUST define named types for the following enumerations. The canonical string values listed here are the serialization form in YAML documents.

| Enumeration | Values |
|---|---|
| `SeverityLevel` | `informational`, `low`, `medium`, `high`, `critical` |
| `Impact` | `behavior_manipulation`, `data_exfiltration`, `data_tampering`, `unauthorized_actions`, `information_disclosure`, `credential_theft`, `service_disruption`, `privilege_escalation` |
| `Category` | `capability_poisoning`, `response_fabrication`, `context_manipulation`, `oversight_bypass`, `temporal_manipulation`, `availability_disruption`, `cross_protocol_chain` |
| `Protocol` | Open string. v0.1 values: `mcp`, `a2a`, `ag_ui`. Must match `[a-z][a-z0-9_]*`. |
| `Mode` | Open string. v0.1 values: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`. Must match `[a-z][a-z0-9_]*_(server\|client)`. |
| `Status` | `draft`, `experimental`, `stable`, `deprecated` |
| `CorrelationLogic` | `any`, `all` |
| `IndicatorResult` | `matched`, `not_matched`, `error`, `skipped` |
| `AttackResult` | `exploited`, `not_exploited`, `partial`, `error` |
| `ExtractorSource` | `request`, `response` |
| `ExtractorType` | `json_path`, `regex` |
| `SemanticIntentClass` | `prompt_injection`, `data_exfiltration`, `privilege_escalation`, `social_engineering`, `instruction_override` |
| `Framework` | Open string. v0.1 values: `atlas`, `mitre_attack`, `owasp_llm`, `owasp_mcp`, `owasp_agentic`, `cwe`, `other`. Tools MUST accept unrecognized values and treat them as equivalent to `other`. |
| `Relationship` | `primary`, `related` |
| `GenerationErrorKind` | `provider_unavailable`, `model_error`, `validation_failure`, `timeout`, `content_policy` |
| `EvaluationErrorKind` | `path_resolution`, `regex_timeout`, `cel_error`, `type_error`, `semantic_error`, `unsupported_method` |
| `ParseErrorKind` | `syntax`, `type_mismatch`, `unknown_variant` |
| `DiagnosticSeverity` | `error`, `warning` |
| `LogLevel` | `info`, `warn`, `error` |
| `ElicitationMode` | `form`, `url` |
| `Surface` | Open string. Values defined per-protocol in format spec §7 surface tables. |
| `AdvanceReason` | `event_matched`, `timeout` |

**Open vs closed enums:** `Protocol`, `Mode`, `Surface` (§2.21), and `Framework` are open strings — unknown values are accepted (with optional warnings for unrecognized bindings, per §3.2). All other enumerations in this table are closed: unknown values MUST be rejected during parsing (`ParseError` with `kind: unknown_variant`). This distinction ensures extensibility for protocol bindings and framework mappings while maintaining strict validation for lifecycle, verdict, and structural enums.

### 2.21 Surface Registry

SDKs MUST maintain a registry mapping each `Surface` value to its protocol and default target path. This registry is used during normalization to resolve omitted `target` fields and during validation to verify that surfaces match their indicator's protocol. The registry is a compile-time constant populated with the v0.1 binding data (MCP, A2A, AG-UI). For indicators targeting unrecognized protocols (not in the registry), SDKs MUST skip surface validation and require explicit `target` fields.

| Surface | Protocol | Default Target |
|---|---|---|
| `tool_description` | `mcp` | `tools[*].description` |
| `tool_title` | `mcp` | `tools[*].title` |
| `tool_input_schema` | `mcp` | `tools[*].inputSchema` |
| `tool_name` | `mcp` | `tools[*].name` |
| `tool_annotations` | `mcp` | `tools[*].annotations` |
| `tool_output_schema` | `mcp` | `tools[*].outputSchema` |
| `tool_icons` | `mcp` | `tools[*].icons` |
| `tool_response` | `mcp` | `content[*]` |
| `tool_structured_response` | `mcp` | `structuredContent` |
| `tool_arguments` | `mcp` | `arguments` |
| `resource_content` | `mcp` | `contents[*]` |
| `resource_uri` | `mcp` | `resources[*].uri` |
| `resource_title` | `mcp` | `resources[*].title` |
| `resource_description` | `mcp` | `resources[*].description` |
| `resource_icons` | `mcp` | `resources[*].icons` |
| `prompt_content` | `mcp` | `messages[*].content` |
| `prompt_arguments` | `mcp` | `arguments` |
| `prompt_title` | `mcp` | `prompts[*].title` |
| `prompt_description` | `mcp` | `prompts[*].description` |
| `prompt_icons` | `mcp` | `prompts[*].icons` |
| `server_notification` | `mcp` | `params` |
| `server_capability` | `mcp` | `capabilities` |
| `server_info` | `mcp` | `serverInfo` |
| `server_instructions` | `mcp` | `instructions` |
| `sampling_request` | `mcp` | `params` |
| `elicitation_request` | `mcp` | `params` |
| `elicitation_response` | `mcp` | `result` |
| `mcp_task_status` | `mcp` | `task` |
| `mcp_task_result` | `mcp` | `result` |
| `roots_response` | `mcp` | `roots[*]` |
| `agent_card` | `a2a` | `""` (root) |
| `card_name` | `a2a` | `name` |
| `card_description` | `a2a` | `description` |
| `skill_description` | `a2a` | `skills[*].description` |
| `skill_name` | `a2a` | `skills[*].name` |
| `task_message` | `a2a` | `messages[*]` |
| `task_artifact` | `a2a` | `artifacts[*]` |
| `task_status` | `a2a` | `status.state` |
| `message_history` | `ag_ui` | `messages[*]` |
| `tool_definition` | `ag_ui` | `tools[*]` |
| `tool_result` | `ag_ui` | `messages[*]` |
| `agent_state` | `ag_ui` | `state` |
| `forwarded_props` | `ag_ui` | `forwardedProps` |
| `agent_event` | `ag_ui` | `data` |
| `agent_tool_call` | `ag_ui` | `data` |

### 2.22 Event-Mode Validity Registry

SDKs MUST maintain a registry mapping each event type to the set of modes for which it is valid. This registry is used during validation (V-029) to reject trigger events that are invalid for the actor's resolved mode. Events are identified by their base name (without qualifier).

SDKs MUST define this as a compile-time constant data structure. The complete mapping for v0.1 bindings is defined in the Event-Mode Validity Matrix (format specification §7). Event types with qualifiers are validated by stripping the qualifier (everything after the first `:`) and looking up the base event name. For modes not present in the registry (from unrecognized protocol bindings), SDKs MUST skip event type validation.

### 2.23 SynthesizeBlock

Defines an LLM-powered response generation request. See format specification §7.4.

| Field | Type | Required | Description |
|---|---|---|---|
| `prompt` | `String` | Yes | Free-text prompt for the LLM. Supports `{{template}}` interpolation from extractors and request fields. |

`SynthesizeBlock` appears within response entries (MCP tool `responses`, MCP prompt `responses`, A2A `task_responses`) as a mutually exclusive alternative to static content, and within AG-UI `run_agent_input` as a mutually exclusive alternative to static `messages`. The SDK parses and validates `SynthesizeBlock` but does not execute LLM generation — that is a runtime concern handled by the consuming tool's `GenerationProvider` (§6.3).

### 2.24 ResponseEntry

A conditional response entry used for request-specific response dispatch. Appears in MCP tool/prompt `responses` and A2A `task_responses`. AG-UI uses a different structure: `messages` and `synthesize` are mutually exclusive directly on `run_agent_input`, not within an ordered response list.

| Field | Type | Required | Description |
|---|---|---|---|
| `when` | `Optional<MatchPredicate>` | No | Predicate evaluated against the incoming request. Absent on the default (fallback) entry. |
| `synthesize` | `Optional<SynthesizeBlock>` | No | LLM-generated response. Mutually exclusive with static content fields. |

Static content fields are protocol-binding-specific: MCP tools use `content`, MCP prompts use `messages`, A2A uses `messages`/`artifacts`, AG-UI uses `messages`. See format specification §7 for the complete structure of each binding's response entries.

### 2.25 Qualifier Resolution Registry

SDKs MUST maintain a compile-time registry mapping `(protocol, base_event)` pairs to a content field path used for qualifier resolution. This registry is used by `resolve_event_qualifier` (§5.9a) to determine whether a protocol event matches a trigger's qualifier token. The mapping is derived from the qualifier resolution rules in the format specification (§7.1.2, §7.2.2, §7.3.2).

| Protocol | Base Event | Content Field Path |
|---|---|---|
| `mcp` | `tools/call` | `params.name` |
| `mcp` | `prompts/get` | `params.name` |
| `a2a` | `task/status` | `status.state` |
| `ag_ui` | `tool_call_start` | `toolCallName` |
| `ag_ui` | `tool_call_end` | `toolCallName` |
| `ag_ui` | `custom` | `name` |

The content field path is resolved against the event's `content` field using `resolve_simple_path` (§5.1.1). A qualifier matches when the resolved value, converted to its string representation, equals the qualifier token. Events whose `(protocol, base_event)` pair is not in the registry do not support qualifier resolution — `resolve_event_qualifier` returns `None` for such events.

**Correlated response events.** For protocols that use request/response correlation rather than embedding all necessary fields in the response payload (notably MCP JSON-RPC for `mcp_client` actors), SDKs MUST construct `ProtocolEvent.content` for correlated response events so that the qualifier paths in this registry are resolvable. Specifically, for MCP `tools/call` and `prompts/get` events observed in client mode, `content` MUST be an enriched object that includes the originating request's `params` (in addition to any response payload fields), since JSON-RPC responses do not themselves carry `params`. When the registry specifies `params.name` for these MCP entries, it resolves against this enriched `content` derived from the correlated original request. See format specification §7.1.2 for the full correlation semantics.

SDKs SHOULD define this as a compile-time constant data structure, paralleling the Event-Mode Validity Registry (§2.22) and Surface Registry (§2.21).

---

## 3. Entry Points

These are the public operations every SDK MUST expose. Each entry point is described as a function signature with named parameters, return types, and behavioral contracts.

### 3.1 parse

```
parse(input: String) → Result<Document, List<ParseError>>
```

Parses a YAML string into an unvalidated document model. This operation performs YAML deserialization and type mapping only. It does NOT validate document conformance or apply normalization.

**Preconditions:** `input` is a UTF-8 string.

**Behavior:**

1. Deserialize `input` as YAML 1.2.
2. Map YAML nodes to the core types defined in §2.
3. Preserve all fields, including unknown fields prefixed with `x-` (extensions).
4. Return the typed document on success.
5. On failure, return at least one `ParseError` value identifying the location and nature of a deserialization problem. SDKs SHOULD attempt to report multiple errors where feasible, but MAY stop at the first fatal error.

Most language deserialization frameworks (serde in Rust, Jackson in Java, encoding/json in Go) fail fast on the first type error or syntax violation. Requiring multiple error collection would prevent SDKs from using derive-based deserialization, which is the dominant approach in most ecosystems. Multi-error reporting is deferred to `validate`, which operates on the successfully parsed document model and can check all semantic rules independently.

**Error conditions:**

- Invalid YAML syntax → `ParseError` with `kind: syntax`.
- Type mismatch (for example, `severity.confidence` is a string instead of integer) → `ParseError` with `kind: type_mismatch`.
- Unknown enum value → `ParseError` with `kind: unknown_variant`.

`parse` MUST NOT reject documents based on semantic constraints (conditional field requirements, duplicate IDs, invalid cross-references). Those are `validate`'s responsibility. Fields marked `Required: Yes` in §2 produce a `ParseError` with `kind: type_mismatch` when absent, since deserialization into the target type requires their presence. Constraints that depend on document context (e.g., `phase.mode` required only when `execution.mode` is absent, first phase must include `state`) are `validate`'s responsibility. The separation allows tools to parse a partial document for editing or introspection without requiring full validity.

### 3.2 validate

```
validate(document: Document) → ValidationResult
```

Validates a parsed document against the conformance rules of OATF format specification §11.1. Returns a `ValidationResult` containing all errors and warnings found.

**Return type:**

| Field | Type | Description |
|---|---|---|
| `errors` | `List<ValidationError>` | Conformance violations. Non-empty means the document is non-conforming. |
| `warnings` | `List<Diagnostic>` | Non-fatal diagnostics (e.g., unrecognized mode, `oatf` not first key, deprecated patterns). |

A document is conforming when `errors` is empty, regardless of warnings. SDKs MUST expose both lists so consuming tools can surface warnings without failing validation.

**Preconditions:** `document` is a value returned by `parse`.

**Behavior:**

The following rules are checked. Each rule references the normative requirement in the format specification. SDKs MUST check all rules and MUST return all violations found (not just the first).

| Rule | Spec Ref | Check |
|---|---|---|
| V-001 | §11.1.1 | `oatf` field is present and is a supported version string. |
| V-002 | §11.1.2 | `oatf` SHOULD be the first key in the document. This is a canonical form recommendation, not a validity requirement. SDKs that can detect key ordering SHOULD emit a warning (not an error) when `oatf` is not first. SDKs that cannot preserve key ordering MAY skip this check. SDKs that serialize OATF documents MUST emit `oatf` as the first key. |
| V-003 | §11.1.3 | Exactly one `attack` object is present. |
| V-004 | §11.1.4 | Required fields present: `execution`. |
| V-005 | §11.1.5 | All closed enumeration values are valid members of their respective types. Open enumerations (§2.20: Protocol, Mode, Surface, Framework) are validated by their pattern or format constraints only, not by membership in a fixed set. |
| V-006 | §11.1.6 | `indicators`, when present, contains at least one entry. |
| V-007 | §11.1.8, §11.1.9 | In multi-phase form: `execution.phases` contains at least one entry. In multi-actor form: each actor's `phases` contains at least one entry. (Single-phase form always has exactly one implicit phase.) |
| V-008 | §11.1.8 | At most one terminal phase per actor (no `trigger`), and it is the last phase in the actor's list. |
| V-009 | §11.1.8 | First phase in each actor includes `state`. In single-phase form, `execution.state` is present, which always satisfies this. In multi-phase and multi-actor forms, check `phases[0].state` directly. |
| V-010 | §11.1.10 | All explicitly specified `indicator.id` values are unique. |
| V-011 | §11.1.8 | In multi-phase form: all explicitly specified `phase.name` values are unique. In multi-actor form: explicitly specified phase names are unique within each actor (but MAY duplicate across actors). Omitted names (auto-generated) are guaranteed unique by their positional generation. |
| V-012 | §11.1.11 | Each indicator has exactly one detection key (`pattern`, `expression`, or `semantic`). |
| V-013 | §5.7 | All regular expressions are syntactically valid RE2. |
| V-014 | §5.7 | All CEL expressions are syntactically valid (parse without error). |
| V-015 | §5.7 | All JSONPath expressions are syntactically valid. |
| V-016 | §5.7 | All template references use valid syntax (no unclosed `{{`). Escaped sequences (`\{{`) are not template references and MUST NOT be flagged. |
| V-017 | §4.3 | `severity.confidence` is in range 0–100 when present. |
| V-018 | §7 | Indicator `surface` is valid for the indicator's resolved protocol. |
| V-019 | §5.3 | Trigger `count` and `match` are only present when `event` is also present. |
| V-020 | §11.1.1 | Document does not contain YAML anchors, aliases, or merge keys. SDKs that parse via a YAML library exposing anchor/alias information SHOULD check this; SDKs whose parsers silently resolve aliases MAY skip this check. |
| V-021 | §6.2, §6.4 | All explicit `target` fields on `PatternMatch` and `SemanticMatch` are syntactically valid wildcard dot-path expressions per the grammar in SDK spec §5.1.2. Valid paths consist of identifiers (alphanumeric, underscores, hyphens) separated by `.`, with optional `[*]` (wildcard) suffix on any segment. The empty string `""` is valid (targets root). Numeric indices (`[0]`, `[1]`) are not valid in target paths. Invalid examples: `tools[*.description` (unclosed bracket), `tools..name` (empty segment), `tools[0]` (numeric index). |
| V-022 | §6.4 | `semantic.threshold`, when explicitly present, is in range [0.0, 1.0] inclusive. The default threshold (0.7, applied at evaluation time per SDK spec §4.4) is not subject to this check. |
| V-023 | §4.2 | `attack.id`, when present, matches the pattern `^[A-Z][A-Z0-9-]*-[0-9]{3,}$`. |
| V-024 | §6.1 | Each explicitly specified `indicator.id`, when `attack.id` is present, matches the pattern `^[A-Z][A-Z0-9-]*-[0-9]{3,}-[0-9]{2,}$` AND its prefix (the portion before the final `-NN` segment) equals `attack.id`. For example, indicator `ACME-003-02` is valid in attack `ACME-003` but invalid in attack `ACME-007`. When `attack.id` is absent, explicitly specified indicator IDs are accepted without pattern constraints but MUST still be unique (V-010). |
| V-025 | §6.1 | `indicator.confidence`, when explicitly present, is in range 0–100 inclusive. |
| V-026 | §6.3 | All `expression.variables` values are syntactically valid simple dot-path expressions per the grammar in §5.1.1. No wildcards or indices. These values are resolved via `resolve_simple_path` at evaluation time (§4.3) and malformed paths should be caught early. |
| V-027 | §5.4 | All dot-path keys in `MatchPredicate` entries are syntactically valid simple dot-path expressions per the grammar in SDK spec §5.1.1. No wildcards or indices. This applies to match predicates in `trigger.match` (phase advancement conditions) and in response entry `when` predicates within execution state (MCP tool/prompt `responses`, A2A `task_responses`). A typo in a predicate key (e.g., `argumens.command` instead of `arguments.command`) causes the predicate to silently never match; this rule catches such errors at validation time. |
| V-028 | §5.1 | When `execution.mode` is absent and `execution.actors` is absent (mode-less multi-phase form), every phase MUST specify `phase.mode`. When `execution.mode` is absent — regardless of whether `execution.actors` is present — every indicator (when `indicators` is present) MUST specify `indicator.protocol`. In multi-actor form, `actor.mode` provides phase-level inheritance (so `phase.mode` is typically omitted), but indicators are document-level and `indicator.protocol` remains required. |
| V-029 | §7 | For recognized modes (v0.1: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`), all trigger event types (after stripping qualifier) MUST be valid per the Event-Mode Validity Registry (§2.22). For unrecognized modes, skip event validation. |
| V-030 | §5.1 | Exactly one of `execution.state`, `execution.phases`, or `execution.actors` MUST be present. A document with more than one is invalid. When `execution.state` is present, `execution.mode` MUST also be present. |
| V-031 | §5.1 | In multi-actor form: all `actor.name` values MUST be unique. Each name MUST match `[a-z][a-z0-9_]*`. Each actor MUST declare `mode`. Each actor MUST have at least one phase. Phase names MUST be unique within each actor. |
| V-032 | §5.5 | Cross-actor extractor references (`{{actor_name.extractor_name}}`) MUST reference an `actor.name` that exists in the document. |
| V-033 | §11.1.14 | In MCP tool and prompt `responses` entries: `content` (or `messages` for prompts) and `synthesize` are mutually exclusive — each entry MUST specify at most one. In A2A `task_responses` entries: `messages`/`artifacts` and `synthesize` are mutually exclusive. In AG-UI `run_agent_input`: `messages` and `synthesize` are mutually exclusive. |
| V-034 | §11.1.15 | In any `responses` or `task_responses` list, at most one entry MAY omit `when`. An entry without `when` following another entry without `when` is invalid. |
| V-035 | §11.1.16 | `synthesize.prompt` MUST be a non-empty string when `synthesize` is present. |
| V-036 | §5.1 | All mode values (`execution.mode`, `actor.mode`, `phase.mode`) MUST match the pattern `[a-z][a-z0-9_]*_(server\|client)`. All `indicator.protocol` values MUST match `[a-z][a-z0-9_]*`. |
| V-037 | §4.2 | `attack.version`, when present, MUST be a positive integer (≥ 1). |
| V-038 | §5.3 | `trigger.after`, when present, MUST be a valid duration (shorthand or ISO 8601). |
| V-039 | §5.5 | Extractor names MUST match the pattern `[a-z][a-z0-9_]*`. |
| V-040 | §11.1.8 | `phase.extractors`, when present, MUST contain at least one entry. |
| V-041 | §11.1.17 | All `expression.variables` keys MUST be valid CEL identifiers, matching `^[_a-zA-Z][_a-zA-Z0-9]*$`. Names containing hyphens, dots, or other non-identifier characters are rejected because CEL would parse them as operators rather than variable references. |
| V-042 | §5.2, §5.3 | Trigger MUST specify at least one of `event` or `after`. An empty trigger object is invalid. |
| V-043 | §5.2 | Binding-specific action objects (those containing no known action key) MUST contain exactly one non-`x-` key. |

**Unrecognized binding diagnostics:** SDKs SHOULD expose a `known_modes()` function returning the set of modes defined by included protocol bindings (v0.1: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`) and a `known_protocols()` function returning the corresponding protocols (v0.1: `mcp`, `a2a`, `ag_ui`). When a mode or protocol passes V-036 pattern validation but is not in the known set, `validate` SHOULD emit a warning (not an error) indicating the value is unrecognized. This catches typos like `mpc_server` while allowing intentional use of custom bindings. Tools MAY provide a mechanism to suppress these warnings.

**Error conditions:** Each failed rule produces a `ValidationError` (§7.2).

### 3.3 normalize

```
normalize(document: Document) → Document
```

Transforms a validated document into its canonical fully-expanded form. All defaults are materialized, all shorthand forms are expanded, and all inferrable fields are computed.

**Preconditions:** `document` has passed `validate` without error.

**Behavior:**

The following transformations are applied in order. Each references the normative requirement in the format specification.

| Step | Spec Ref | Transformation |
|---|---|---|
| N-001 | §11.2.1 | Apply default values: `name` → `"Untitled"`, `version` → `1`, `status` → `draft`, `severity.confidence` → `50` (when `severity` is present), `phase.name` → `"phase-{N}"` (1-based index within actor, when omitted), `phase.mode` → `execution.mode` (when present); in multi-actor form (including after N-006/N-007 conversion) `phase.mode` → `actor.mode` (when `phase.mode` is still absent), `trigger.count` → `1` (when `trigger.event` is present and `trigger.count` is absent), `indicator.protocol` → protocol component of `execution.mode` (when both `indicators` and `execution.mode` are present), `correlation.logic` → `any` (when `indicators` is present), `mapping.relationship` → `"primary"`. |
| N-002 | §11.2.2 | When `severity` is present, expand scalar form to object form: `"high"` → `{level: "high", confidence: 50}`. When `severity` is absent, leave it absent. |
| N-003 | §11.2.3 | Auto-generate `indicator.id` for indicators that omit it. When `attack.id` is present, format as `{attack.id}-{NN}`. When `attack.id` is absent, format as `indicator-{NN}`. `NN` is the 1-based zero-padded indicator index. |
| N-004 | §11.2.4 | Resolve `pattern.target` and `semantic.target` from the surface registry (§2.21) when omitted. |
| N-005 | §11.2.5 | Expand pattern shorthand form to standard form: move condition operator into explicit `condition` field. |
| N-006 | §5.1 | Normalize single-phase form to multi-actor form: when `execution.state` is present (and `execution.phases` and `execution.actors` are absent), wrap it in `actors: [{name: "default", mode: <execution.mode>, phases: [{name: "phase-1", state: <execution.state>}]}]`. Remove the top-level `mode` and `state` from `execution`. |
| N-007 | §5.1 | Normalize multi-phase form to multi-actor form: when `execution.phases` is present (and `execution.actors` is absent), wrap it in `actors: [{name: "default", mode: <execution.mode>, phases: <execution.phases>}]`. When `execution.mode` is absent (mode-less multi-phase form), set `actor.mode` from `phases[0].mode`. Remove the top-level `mode` and `phases` from `execution`. All subsequent normalization steps and all runtime processing operate on the `actors` array. |
| N-008 | §7.1.4 | Apply MCP tool field defaults: `inputSchema` → `{"type": "object"}` when omitted, `description` → `""` when omitted. Applied to all tool definitions in all phases of `mcp_server` actors. |

`normalize` MUST be idempotent: `normalize(normalize(doc))` produces the same result as `normalize(doc)`.

The caller MUST receive a normalized document. The original document MUST NOT be observably mutated through any retained reference. SDKs MAY implement this in either of two ways:

- **Copy semantics**: accept a reference, return a new document (for example, `fn normalize(&Document) -> Document` in Rust, or returning a new object in Python/JS). The input remains usable after the call.
- **Consuming semantics**: accept ownership, return a transformed document (for example, `fn normalize(Document) -> Document` in Rust). The input is consumed and unavailable after the call. This avoids unnecessary allocation in languages with move semantics.

SDKs that offer consuming semantics SHOULD also offer a copy variant (or document that callers should clone before calling) for cases where the original document is needed after normalization.

After normalization, the following guarantees hold and consuming code MAY rely on them:

- `attack.name` is present (default `"Untitled"`).
- `attack.version` is present (default `1`).
- `attack.status` is present (default `draft`).
- `attack.severity`, when present, is always in object form with `level` and `confidence` present.
- `execution.actors` is always present (all forms have been normalized to multi-actor form with at least a `"default"` actor).
- Every actor has a `name` and `mode`.
- Every phase has a `name` (auto-generated when omitted, e.g. `"phase-1"`).
- Every phase has a resolved `mode` (inherited from its actor's `mode`).
- For `mcp_server` actors, every tool has `inputSchema` (default `{"type": "object"}`) and `description` (default `""`).

When `indicators` is present:

- `attack.correlation.logic` is present (default `any`).
- Every indicator has an `id`.
- Every indicator has a resolved `protocol`.
- Every indicator has a detection method determined by which method-specific key is present.
- Every `PatternMatch` is in standard form with an explicit `condition` field.
- Every `PatternMatch` and `SemanticMatch` has a resolved `target` (or validation would have rejected the document if the surface has no default and target was omitted).

Always:

- Every trigger with an `event` has a `count`.

### 3.4 serialize

```
serialize(document: Document) → String
```

Serializes a document to YAML. SDKs SHOULD emit the fully-expanded normalized form per §11.2.10.

**Preconditions:** `document` is a well-formed document model (typically the output of `normalize`).

**Behavior:**

1. Serialize all fields to YAML 1.2.
2. Preserve field ordering: `oatf` first, then `attack` fields in specification order.
3. Emit explicit values for all fields that have defaults (do not rely on consumer normalization).
4. Preserve `x-` extension fields in their original position.
5. Use block style for readability.

### 3.5 load

```
load(input: String) → Result<LoadResult, List<OATFError>>
```

Convenience entry point that composes `parse`, `validate`, and `normalize` into a single operation. Returns a fully-normalized, valid document (with any warnings) or the combined errors from parsing and validation.

**Return type:**

| Field | Type | Description |
|---|---|---|
| `document` | `Document` | The normalized, valid document. |
| `warnings` | `List<Diagnostic>` | Non-fatal diagnostics from validation. |

**Behavior:** Equivalent to:
```
document = parse(input)?
result = validate(document)
if result.errors is non-empty, return Err(result.errors)
normalize(document)
return Ok(LoadResult { document, warnings: result.warnings })
```

If `parse` fails, return parse errors. If `validate` finds errors, return validation errors. If both succeed, return the normalized document with any warnings.

Most tool integrations will call `load` rather than the individual steps. The separate entry points exist for tools that need partial processing (IDE plugins that parse for syntax highlighting without requiring validity, linters that validate without normalizing).

---

## 4. Evaluation

The evaluation interface allows tools to assess whether observed protocol traffic matches the indicators defined in an OATF document. These operations are the foundation for evaluation tools, but adversarial tools MAY also use them for self-verification.

### 4.1 Message Abstraction

Indicator evaluation operates on protocol messages represented as `Value`, a dynamically-typed JSON-like tree. The SDK does not define message types for specific protocols. The consuming tool is responsible for constructing the `Value` from whatever wire format it captures.

The `Value` passed to indicator evaluation corresponds to the `result` (for responses) or `params` (for requests/notifications) field of the JSON-RPC message, not the full JSON-RPC envelope. This is the convention defined in the format specification §7.1.3. For non-JSON-RPC bindings (e.g., AG-UI, or future protocols that do not use JSON-RPC framing), tools SHOULD pass the protocol-specific message payload — the semantic equivalent of "the content the agent produced or received." Indicators evaluate whatever structure is present; the dot-path and CEL machinery is format-agnostic.

SDKs MUST NOT require messages to conform to any particular protocol schema. Indicators evaluate against whatever structure is present. Missing fields produce `not_matched` verdicts, not errors.

### 4.2 evaluate_pattern

```
evaluate_pattern(pattern: PatternMatch, message: Value) → Result<Boolean, EvaluationError>
```

Evaluates a pattern indicator against a protocol message.

**Preconditions:** `pattern` is in normalized standard form (explicit `condition`, resolved `target`).

**Behavior:**

1. Resolve `pattern.target` against `message` using `resolve_wildcard_path` (§5.1.2). This may produce zero, one, or many values (when the path contains wildcards).
2. For each resolved value, evaluate the condition (§5.3) against the value. If a regex condition exceeds the tool's match time limit, return `Err(EvaluationError { kind: regex_timeout })`.
3. Return `Ok(true)` if any resolved value matches the condition. Return `Ok(false)` if no values match or if the target path resolves to nothing.

### 4.3 evaluate_expression

```
evaluate_expression(
    expression: ExpressionMatch,
    message: Value,
    cel_evaluator: CelEvaluator
) → Result<Boolean, EvaluationError>
```

Evaluates a CEL expression indicator against a protocol message using the provided CEL evaluator.

**Preconditions:** `expression.cel` is syntactically valid (verified during `validate`).

**Behavior:**

1. Construct the CEL evaluation context:
   - Bind `message` as the root variable `message`.
   - If `expression.variables` is present, for each entry `(name, path)`, resolve `path` against `message` using `resolve_simple_path` (§5.1.1) and bind the result as variable `name`.
2. Pass the CEL string and context to `cel_evaluator.evaluate()` (§6.1).
3. If the evaluator returns a boolean, return `Ok(value)`.
4. If the evaluator returns a non-boolean value, propagate it as `Err(EvaluationError)` with `kind: type_error`. The `CelEvaluator` contract (§6.1) requires the evaluator to return a type error for non-boolean results; `evaluate_expression` does not silently coerce non-booleans.
5. If the evaluator returns an error, propagate it as `Err(EvaluationError)`. This preserves diagnostic information for the calling `evaluate_indicator`, which maps it to `IndicatorVerdict { result: error, evidence }`.

SDKs that do not bundle a CEL evaluator MUST still define this function. When called without a configured evaluator, it MUST return `Err(EvaluationError)` indicating that CEL evaluation is not available.

### 4.4 evaluate_indicator

```
evaluate_indicator(
    indicator: Indicator,
    message: Value,
    cel_evaluator: Optional<CelEvaluator>,
    semantic_evaluator: Optional<SemanticEvaluator>
) → IndicatorVerdict
```

Top-level indicator evaluation. Dispatches to the appropriate method evaluator and wraps the result in a verdict.

**Behavior:**

1. Dispatch on the present detection key:
   - `pattern` → call `evaluate_pattern(indicator.pattern, message)`. If it returns `Ok(bool)`, the verdict result is `matched`/`not_matched` accordingly. If it returns `Err(EvaluationError)`, return verdict with `result: error` and the error message as evidence.
   - `expression` → if `cel_evaluator` is absent, return verdict with `result: skipped` and evidence indicating CEL support is unavailable. Otherwise call `evaluate_expression(indicator.expression, message, cel_evaluator)`. If it returns `Ok(bool)`, the result is that boolean. If it returns `Err(EvaluationError)`, return verdict with `result: error` and the error as evidence.
   - `semantic` → if `semantic_evaluator` is absent, return verdict with `result: skipped` and evidence indicating semantic evaluation is unavailable. Otherwise:
     a. Resolve `indicator.semantic.target` against `message` using `resolve_wildcard_path` (§5.1.2). If the path resolves to nothing, return verdict with `result: not_matched`.
     b. For each resolved value, serialize to string and call `semantic_evaluator.evaluate(text, indicator.semantic.intent, indicator.semantic.intent_class, indicator.semantic.threshold, indicator.semantic.examples)`. When `intent_class` is absent, pass `None`; the evaluator MUST handle this gracefully.
     c. Determine the effective threshold: use `indicator.semantic.threshold` if present, otherwise `0.7` (per format specification §6.4).
     d. If the highest returned score across all resolved values ≥ the effective threshold, the result is `true` (matched). Otherwise `false` (not matched). Use the highest score as evidence.
2. Catch any runtime evaluation error. On error, return verdict with `result: error` and the diagnostic as `evidence`.
3. On successful evaluation, return verdict with `result: matched` (if true) or `result: not_matched` (if false).
4. Populate `indicator_id` from the indicator, `timestamp` from the current time.

### 4.5 compute_verdict

```
compute_verdict(
    attack: Attack,
    indicator_verdicts: Map<String, IndicatorVerdict>
) → AttackVerdict
```

Computes the attack-level verdict from a set of indicator verdicts according to the attack's `correlation.logic`. The verdict answers one question: did the agent comply with the attack?

**Preconditions:** The attack MUST have indicators. If `attack.indicators` is absent, return an `AttackVerdict` with result `error` and a diagnostic indicating the document has no indicators. `indicator_verdicts` maps indicator IDs to their individual verdicts. All indicator IDs referenced in the attack SHOULD be present. If an indicator ID present in `attack.indicators` has no entry in `indicator_verdicts`, treat it as `skipped` and count it in `evaluation_summary`. This ensures missing evaluations are visible in coverage metrics rather than silently ignored.

**Behavior by logic mode:**

**`any` (default):**
- If all indicator verdicts are `skipped`, return `error`.
- If any indicator verdict is `error`, return `error`.
- Else if any indicator verdict is `matched`, return `exploited`.
- Else return `not_exploited`.

**`all`:**
- If all indicator verdicts are `skipped`, return `error`.
- If any indicator verdict is `error`, return `error`.
- If all indicator verdicts are `matched`, return `exploited`.
- If at least one is `matched` and at least one is `not_matched` or `skipped`, return `partial`.
- If all are `not_matched` or `skipped`, return `not_exploited`.

**Treatment of `skipped` verdicts:** A `skipped` verdict means the indicator could not be evaluated (absent evaluator, unsupported method). For verdict computation purposes, `skipped` is treated equivalently to `not_matched`: the indicator did not produce evidence of agent compliance. This is semantically correct: the agent was not shown to be exploited by that indicator, regardless of why. **The sole exception: when ALL indicators are `skipped`, the result is `error` rather than `not_exploited`. A verdict produced without any evaluation is not a legitimate pass — it indicates a configuration gap (missing evaluator, unsupported indicator types) that must be surfaced.** Consuming tools that need to distinguish between "evaluated and not matched" versus "not evaluated" SHOULD inspect the individual `IndicatorVerdict` results or the `evaluation_summary` in the returned `AttackVerdict`.

**Evaluation summary:** The returned `AttackVerdict` MUST include an `evaluation_summary` containing counts of each indicator result (`matched`, `not_matched`, `error`, `skipped`). This enables consumers to detect evaluation gaps — for example, a `not_exploited` verdict with a high `skipped` count signals incomplete coverage rather than confirmed resilience.

---

## 5. Execution Primitives

Shared utility operations used by both entry points and evaluation. SDKs MUST implement these and SHOULD expose them in the public API for use by consuming tools.

### 5.1 Path Resolution

OATF defines two path variants with different capabilities, matching the format specification (§5.4):

#### 5.1.1 Simple Dot-Path

Used for: `MatchPredicate` keys (§2.10), `{{request.*}}` and `{{response.*}}` template references (§5.5), `expression.variables` values (§2.14).

```
resolve_simple_path(path: String, value: Value) → Optional<Value>
```

Resolves a simple dot-path against a value tree. Returns the single value at the path, or nothing if any segment fails to resolve.

**Path syntax:**

| Segment | Meaning | Example |
|---|---|---|
| `field_name` | Access named field on object | `arguments.command` |
| `.` | Segment separator | `capabilities.tools` |

Segments consist of alphanumeric characters, underscores, and hyphens (`[a-zA-Z0-9_-]+`). No wildcard or index support. Resolution proceeds left to right: if any segment encounters a non-object, a missing key, or an array, resolution fails and returns nothing.

**Empty path:** When `path` is the empty string `""`, returns the root value itself. This is the canonical representation for targeting the entire message.

#### 5.1.2 Wildcard Dot-Path

Used for: `pattern.target` (§2.13), `semantic.target` (§2.15).

```
resolve_wildcard_path(path: String, value: Value) → List<Value>
```

Resolves a wildcard dot-path against a value tree. Returns all values that match, potentially expanding across array elements. Returns an empty list if the path does not match.

**Path syntax:**

| Segment | Meaning | Example |
|---|---|---|
| `field_name` | Access named field on object | `capabilities` |
| `[*]` | Wildcard: all elements of array | `tools[*]` |
| `.` | Segment separator | `tools[*].description` |

Segments consist of alphanumeric characters, underscores, and hyphens, with optional `[*]` suffix. Numeric indexing (`[0]`, `[1]`) is not supported — use CEL expressions for positional access.

**Behavior:**

1. Split `path` on `.` segment boundaries (respecting `[*]` as atomic suffixes).
2. Starting from `value` as the root, traverse each segment:
   - For a field name: if the current value is an object, access the named field. If the field is absent or the current value is not an object, produce no results for this branch.
   - For `[*]`: if the current value is an array, fan out to all elements. Each element continues independently through remaining segments. If the current value is not an array, produce no results for this branch (not an error).
3. Collect all terminal values reached after processing all segments.

**Empty path:** When `path` is the empty string `""`, returns the root value itself as a single-element list.

**Examples:**

- `resolve_wildcard_path("tools[*].description", {"tools": [{"description": "A"}, {"description": "B"}]})` → `["A", "B"]`
- `resolve_wildcard_path("capabilities.tools", {"capabilities": {"tools": {"listChanged": true}}})` → `[{"listChanged": true}]`
- `resolve_wildcard_path("missing.path", {"other": 1})` → `[]`

SDKs SHOULD enforce a maximum traversal depth to prevent stack overflow on pathological inputs. A depth limit of 64 is RECOMMENDED.

**Limitation:** Dot-path syntax does not support escaping literal dots within field names. A JSON object key containing a dot (for example, `{"content.type": "text"}`) cannot be addressed because the path `content.type` is always interpreted as two segments. This is an intentional simplification; protocol messages in MCP, A2A, and AG-UI do not use dotted key names. Authors MUST use CEL expressions (format specification §6.3) to match fields with dots, brackets, or other special characters in their names.

### 5.2 parse_duration

```
parse_duration(input: String) → Result<Duration, ParseError>
```

Parses a duration string in either shorthand or ISO 8601 format.

**Accepted formats:**

| Format | Example | Meaning |
|---|---|---|
| `{N}s` | `30s` | 30 seconds |
| `{N}m` | `5m` | 5 minutes |
| `{N}h` | `1h` | 1 hour |
| `{N}d` | `2d` | 2 days |
| `PT{N}S` | `PT30S` | 30 seconds (ISO 8601) |
| `PT{N}M` | `PT5M` | 5 minutes (ISO 8601) |
| `PT{N}H` | `PT1H` | 1 hour (ISO 8601) |
| `P{N}D` | `P2D` | 2 days (ISO 8601) |
| `PT{N}M{N}S` | `PT5M30S` | 5 minutes 30 seconds (ISO 8601 composite) |
| `PT{N}H{N}M` | `PT1H30M` | 1 hour 30 minutes (ISO 8601 composite) |
| `PT{N}H{N}M{N}S` | `PT1H30M15S` | 1 hour 30 minutes 15 seconds (ISO 8601 composite) |
| `P{N}DT{...}` | `P1DT12H` | 1 day 12 hours (ISO 8601 composite) |

`N` is a non-negative integer (≥ 0); `0s` is a valid duration meaning zero elapsed time. Fractional values are not supported. Any ISO 8601 duration composed of integer D, H, M, and S components is accepted; the components must appear in descending order (days → hours → minutes → seconds) and the `T` separator is required before any time components.

### 5.3 evaluate_condition

```
evaluate_condition(condition: Condition, value: Value) → Boolean
```

Evaluates a condition against a resolved value. If `condition` is a bare value (string, number, boolean, array), performs deep equality comparison. If `condition` is a `MatchCondition` object, evaluates each present operator — when multiple operators are present, all must match (AND logic). Returns `true` only if every present operator is satisfied.

**Behavior by operator:**

| Operator | Value Type | Returns True When |
|---|---|---|
| `contains` | String | `value` contains `contains` as a substring. Case-sensitive. |
| `starts_with` | String | `value` starts with the specified prefix. Case-sensitive. |
| `ends_with` | String | `value` ends with the specified suffix. Case-sensitive. |
| `regex` | String | `value` matches the RE2 regular expression. |
| `any_of` | Any | `value` equals any element in the list (deep equality). |
| `gt` | Number | `value > operand`. |
| `lt` | Number | `value < operand`. |
| `gte` | Number | `value >= operand`. |
| `lte` | Number | `value <= operand`. |
| `exists` | Boolean | See §5.4 — `exists` is evaluated during predicate resolution, not by `evaluate_condition`. |
| *(equality)* | Any | `value` equals the operand (deep equality). Used when the MatchEntry is a scalar, not a MatchCondition. |

**Type mismatches:** If the operator requires a specific value type (string operators on non-string, numeric operators on non-number), the condition evaluates to `false`. Type mismatches are not errors.

**Deep equality:** The `any_of` and scalar equality operators use deep equality with the following rules: numeric values compare by mathematical value (integer `42` equals float `42.0`); object key order is irrelevant; NaN is not equal to any value including itself; null equals only null; arrays compare element-wise by position and length.

**Regex:** Patterns MUST be compiled with RE2 semantics (linear-time guarantee). SDKs MUST reject patterns with features outside the RE2 subset during `validate`. The regex is evaluated as a **partial match**: the pattern may match any substring of the value. To require a full-string match, the pattern MUST include `^` and `$` anchors. This matches the default behavior of RE2 libraries across languages (Go's `regexp.MatchString`, Rust's `regex::Regex::is_match`, Python's `re2.search`).

**The `exists` operator:** Unlike all other operators, `exists` does not inspect the resolved value — it inspects whether resolution succeeded. `exists` is evaluated during `evaluate_predicate` (§5.4) at the path-resolution step, before `evaluate_condition` is called. When `exists` is the only operator in a MatchCondition, `evaluate_condition` is not called at all (for `exists: true`, the path having resolved is sufficient; for `exists: false`, the path not having resolved is sufficient). When `exists` is combined with other operators, `exists: true` is redundant (all other operators already require a resolved value), and `exists: false` combined with any value-inspecting operator is always false (there is no value to inspect). These are natural consequences of AND logic, not special cases.

### 5.4 evaluate_predicate

```
evaluate_predicate(predicate: MatchPredicate, value: Value) → Boolean
```

Evaluates a match predicate (a set of dot-path → condition entries) against a value. All entries are combined with AND logic.

**Behavior:**

1. For each entry `(path, condition)` in the predicate map:
   a. Resolve the dot-path key against `value` using `resolve_simple_path` (§5.1.1).
   b. If the path does not resolve (returns nothing):
      - If `condition` is a `MatchCondition` with `exists: false` (and no other operators), the entry evaluates to `true`.
      - Otherwise, the entry evaluates to `false`.
   c. If the path resolves to a value:
      - If `condition` is a `MatchCondition` with `exists: false`, the entry evaluates to `false` (regardless of other operators, since AND with a false `exists` is false).
      - Otherwise, evaluate the remaining condition operators against the resolved value. The entry is `true` if the value satisfies the condition.
2. Return `true` if all entries are `true`. Return `false` if any entry is `false`.

### 5.5 interpolate_template

```
interpolate_template(
    template: String,
    extractors: Map<String, String>,
    request: Optional<Value>,
    response: Optional<Value>
) → (String, List<Diagnostic>)
```

Resolves template expressions in a string. Returns the interpolated string and any diagnostics (e.g., undefined references).

**Template syntax:**

- `{{extractor_name}}` → replaced with the value of the named extractor (current actor scope).
- `{{actor_name.extractor_name}}` → replaced with the value of a cross-actor extractor reference.
- `{{request.field.path}}` → replaced with the value at the dot-path in the current request.
- `{{response.field.path}}` → replaced with the value at the dot-path in the current response.
- `\{{` → replaced with a literal `{{` (escape sequence).

The `extractors` map is populated by the calling runtime with both local names (unqualified, from the current actor) and qualified names (`actor_name.extractor_name`, from all actors). The function itself performs simple key lookup — cross-actor resolution is a runtime responsibility.

**Behavior:**

1. Replace all `\{{` escape sequences with a placeholder.
2. Find all `{{...}}` expressions in `template`.
3. For each expression:
   a. If the name matches a key in `extractors`, replace with the extractor value.
   b. If the name starts with `request.` and `request` is present, resolve the remaining path against `request` using `resolve_simple_path`. Replace with the resolved value, serialized to string. If the path does not resolve, replace with empty string and emit a warning diagnostic (W-004).
   c. If the name starts with `response.` and `response` is present, resolve the remaining path against `response` using `resolve_simple_path`. Replace with the resolved value, serialized to string. If the path does not resolve, replace with empty string and emit a warning diagnostic (W-004).
   d. If neither matches, replace with empty string and emit a warning diagnostic (W-004).
4. Restore all placeholders to literal `{{`.
5. Return the interpolated string and accumulated diagnostics.

### 5.5a interpolate_value

```
interpolate_value(
    value: Value,
    extractors: Map<String, String>,
    request: Optional<Value>,
    response: Optional<Value>
) → (Value, List<Diagnostic>)
```

Recursively walks a `Value` tree and interpolates all template expressions found in string values. Non-string scalars are returned unchanged. This function is the entry point for interpolating structured values (e.g., action parameters, state objects) that may contain template expressions at any depth.

**Behavior:**

1. If `value` is a string containing `{{`, call `interpolate_template(value, extractors, request, response)`. Return the interpolated string and its diagnostics.
2. If `value` is a string without `{{`, return the string unchanged with no diagnostics.
3. If `value` is an object (map), recurse into each value (not keys). Return the object with interpolated values and the union of all diagnostics.
4. If `value` is an array, recurse into each element. Return the array with interpolated elements and the union of all diagnostics.
5. If `value` is any other scalar (null, boolean, number), return it unchanged with no diagnostics.

**No re-expansion:** Interpolation results are not re-scanned for template expressions. If an extractor value contains `{{`, it is treated as literal text in the output. This prevents injection of template expressions through extracted values.

### 5.6 evaluate_extractor

```
evaluate_extractor(
    extractor: Extractor,
    message: Value,
    direction: ExtractorSource
) → Optional<String>
```

Applies an extractor to a message, capturing a value. The `direction` parameter indicates whether `message` is a request or response, enabling the function to filter extractors by their declared source.

**Behavior:**

1. If `extractor.source` ≠ `direction`, return `None`. This extractor targets a different message direction and should not be applied.
2. Apply the extractor by type:

- `json_path`: Evaluate the JSONPath expression against `message`. If the expression matches one or more nodes, return the first match in document order (per RFC 9535 §2.6) serialized to its compact JSON string representation. If no match, return `None`.
- `regex`: Convert `message` to its string representation, evaluate the regular expression. If the regex matches and has at least one capture group, return the first capture group's value. If no match, return `None`.

`None` means "no match" (the extractor did not find the targeted content). `Some("")` is a valid result when the extractor matched but the captured value is genuinely an empty string. Downstream template interpolation treats `None` as an undefined extractor (triggering W-004 warnings), while `Some("")` substitutes the empty string silently.

When the extracted value is a non-scalar (object or array), it MUST be serialized to its compact JSON string representation.

### 5.7 select_response

```
select_response(
    entries: List<ResponseEntry>,
    request: Value
) → Optional<ResponseEntry>
```

Selects the first matching response entry from an ordered list, using `when` predicates for conditional dispatch.

**Behavior:**

1. Iterate `entries` in order.
2. For each entry that has a `when` predicate, evaluate the predicate against `request` using `evaluate_predicate` (§5.4). If the predicate matches, return that entry.
3. If no predicate-bearing entry matches and an entry without `when` exists (the default entry), return it.
4. If no entry matches, return `None`.

First-match-wins: the first entry whose `when` predicate matches is returned, regardless of subsequent entries. The default entry (no `when`) is only considered as a fallback after all predicate-bearing entries have been tried.

### 5.8 evaluate_trigger

```
evaluate_trigger(
    trigger: Trigger,
    event: Optional<ProtocolEvent>,
    elapsed: Duration,
    state: TriggerState,
    protocol: String
) → TriggerResult
```

Evaluates whether a trigger condition is satisfied for phase advancement. The function manages event counting internally via the mutable `state` parameter (§2.8c), which the caller persists across calls but does not inspect or modify. The `protocol` argument MUST be the normalized protocol identifier (the output of `extract_protocol(mode)`) corresponding to the registry keys defined in §2.25 (`mcp`, `a2a`, `ag_ui`); passing an unnormalized or free-form value will cause silent qualifier resolution failures.

**Behavior:**

1. If `trigger.after` is present and `elapsed` ≥ `trigger.after`, return `TriggerResult::Advanced { reason: timeout }`.
2. If `trigger.event` is present and `event` is present:
   a. Parse `trigger.event` via `parse_event_qualifier` (§5.9) to obtain `(trigger_base, trigger_qualifier)`.
   b. **Base match:** If `event.event_type` ≠ `trigger_base`, return `TriggerResult::NotAdvanced`.
   c. **Qualifier match:** If `trigger_qualifier` is present:
      i. Determine the event's qualifier: if `event.qualifier` is present, use that value. Otherwise, call `resolve_event_qualifier(protocol, event.event_type, event.content)` (§5.9a) and use its result (which may be `None`).
      ii. If the event's qualifier is `None` or does not equal `trigger_qualifier`, return `TriggerResult::NotAdvanced`.
   d. **Predicate check:** If `trigger.match` is present, evaluate the match predicate against `event.content` using `evaluate_predicate` (§5.4). If the predicate does not match, return `TriggerResult::NotAdvanced`.
   e. **Count increment:** Increment `state.event_count` by 1. This increment occurs only after base event, qualifier, and predicate have all passed.
   f. **Count check:** If `state.event_count` ≥ `trigger.count` (resolved, default `1`), return `TriggerResult::Advanced { reason: event_matched }`.
3. Return `TriggerResult::NotAdvanced`.

`TriggerResult` and `AdvanceReason` are defined in §2.8b. `TriggerState` is defined in §2.8c.

### 5.9 parse_event_qualifier

```
parse_event_qualifier(event_string: String) → (String, Optional<String>)
```

Splits an event type string on the first `:` separator, returning the base event type and an optional qualifier.

**Behavior:**

1. If `event_string` contains `:`, split on the first occurrence. Return `(base, Some(qualifier))`.
2. Otherwise, return `(event_string, None)`.

**Examples:**
- `"tools/call:calculator"` → `("tools/call", Some("calculator"))`
- `"tools/call"` → `("tools/call", None)`
- `"resources/read"` → `("resources/read", None)`

### 5.9a resolve_event_qualifier

```
resolve_event_qualifier(
    protocol: String,
    base_event: String,
    content: Value
) → Optional<String>
```

Resolves the qualifier value from a protocol event's content by looking up the content field path in the Qualifier Resolution Registry (§2.25).

**Behavior:**

1. Look up `(protocol, base_event)` in the Qualifier Resolution Registry (§2.25).
2. If no entry exists, return `None`. This event type does not support qualifier resolution.
3. Resolve the registered content field path against `content` using `resolve_simple_path` (§5.1.1).
4. If the path resolves to a value `v`, return a qualifier string: if `v` is a string, return it unchanged; if `v` is a number or boolean, return its canonical JSON encoding (e.g., `42`, `true`); for `null`, arrays, or objects, return `None` (these types are not valid qualifier values).
5. If the path does not resolve, return `None`.

**Examples:**
- `resolve_event_qualifier("mcp", "tools/call", {"params": {"name": "calculator"}})` → `Some("calculator")`
- `resolve_event_qualifier("mcp", "tools/call", {"params": {}})` → `None`
- `resolve_event_qualifier("mcp", "resources/read", {"uri": "file://x"})` → `None` (event not in registry)
- `resolve_event_qualifier("ag_ui", "custom", {"name": "my_event"})` → `Some("my_event")`

### 5.10 extract_protocol

```
extract_protocol(mode: String) → String
```

Extracts the protocol identifier from a mode string by stripping the `_server` or `_client` suffix.

**Behavior:**

1. If `mode` ends with `_server`, return the prefix before `_server`.
2. If `mode` ends with `_client`, return the prefix before `_client`.
3. Otherwise, return `mode` unchanged (this case should not occur for valid modes per V-036).

**Examples:**
- `"mcp_server"` → `"mcp"`
- `"a2a_client"` → `"a2a"`
- `"ag_ui_client"` → `"ag_ui"`

### 5.11 compute_effective_state

```
compute_effective_state(phases: List<Phase>, phase_index: Integer) → Value
```

Computes the effective state at a given phase by applying state inheritance.

**Behavior:**

1. Starting from phase 0, walk forward through phases up to `phase_index`.
2. If a phase defines `state`, that becomes the current effective state (full replacement).
3. If a phase omits `state`, the effective state carries forward from the preceding phase unchanged.
4. Return the effective state at `phase_index`.

This operation supports both adversarial tools (which need to know what state to present at each phase) and evaluation tools (which need to know what state to expect at each phase).

---

## 6. Extension Points

Extension points define interfaces that the SDK declares but does not necessarily implement. Language SDKs define these as traits, interfaces, protocols, or callback types according to language convention.

### 6.1 CelEvaluator

```
interface CelEvaluator {
    evaluate(
        expression: String,
        context: Map<String, Value>
    ) → Result<Value, EvaluationError>
}
```

Evaluates a CEL expression against a context of named variables. Returns the expression result (typically a boolean) or an evaluation error.

**Contract:**

- The evaluator MUST support the CEL standard functions: `size`, `contains`, `startsWith`, `endsWith`, `matches`, `exists`, `all`, `filter`, `map`.
- The evaluator MUST be side-effect-free. No I/O, no mutation, no network access.
- The evaluator SHOULD enforce a time limit. 100 milliseconds per expression is RECOMMENDED.
- The evaluator MUST return a type error (not crash) when the expression produces a non-boolean result in a boolean context.

SDKs SHOULD ship a default `CelEvaluator` implementation when a production-quality CEL library is available for the target language. SDKs that cannot ship a default implementation MUST clearly document this and MUST accept a user-provided implementation.

**Partial compliance:** When the underlying CEL library does not support the full set of standard functions listed above, the default implementation MAY ship with partial function coverage. In this case, the SDK MUST document which functions are supported, and the evaluator MUST return an `EvaluationError` with `kind: unsupported_method` when an expression calls an unsupported function (rather than failing silently or crashing). The CEL ecosystem maturity varies across languages: Go has Google's reference implementation, while Rust and Python have less complete alternatives. Partial compliance with a clear extension point is preferable to no default implementation.

### 6.2 SemanticEvaluator

```
interface SemanticEvaluator {
    evaluate(
        text: String,
        intent: String,
        intent_class: Optional<SemanticIntentClass>,
        threshold: Optional<Float>,
        examples: Optional<SemanticExamples>
    ) → Result<Float, EvaluationError>
}
```

Evaluates the semantic similarity or intent match between observed text and the indicator's intent description. Returns a confidence score between 0.0 and 1.0.

**Contract:**

- The evaluator is responsible for all inference logic (LLM calls, embedding similarity, classifier invocation). The SDK provides none of this.
- When `intent_class` is present, classification-based engines SHOULD use it as a hint. When absent, the evaluator MUST rely on the `intent` text and `examples` alone.
- When `threshold` is present, the indicator is considered matched if the returned score ≥ `threshold`.
- When `threshold` is absent, the SDK uses a default threshold of `0.7` (per format specification §6.4).
- The evaluator MAY use `examples.positive` and `examples.negative` to calibrate its scoring.
- Evaluation errors (model unavailable, timeout, malformed response) MUST be returned as `EvaluationError`, not thrown as unhandled exceptions.

SDKs MUST NOT ship a default `SemanticEvaluator`. Semantic evaluation is inherently model-dependent and deployment-specific.

> *Note:* Semantic evaluation involves I/O (LLM inference, embedding API calls). The trait interface is synchronous; implementations manage I/O internally. Language SDKs MAY provide async convenience wrappers. See §8.7.

### 6.3 GenerationProvider

```
interface GenerationProvider {
    generate(
        prompt: String,
        protocol: Protocol,
        response_context: Value
    ) → Result<Value, GenerationError>
}
```

Generates protocol-conformant content from a prompt. Used by adversarial tools to execute `synthesize` blocks (format specification §7.4). For server-mode actors (MCP, A2A), this generates response payloads. For client-mode actors (AG-UI), this generates input content (message histories).

**Contract:**

- The `prompt` has already been resolved (all `{{template}}` references interpolated). The provider receives the final prompt string.
- The `protocol` identifies which protocol binding the output must conform to (MCP, A2A, or AG-UI).
- The `response_context` provides protocol-specific metadata the provider needs to shape its output (for example, the tool's `inputSchema` for MCP, the task's expected `status` for A2A, or the `tools` and `state` from `run_agent_input` for AG-UI). The structure is defined by the consuming tool, not by this specification.
- The provider MUST return a `Value` that conforms to the protocol's expected structure. The consuming tool MUST validate this value against the protocol binding before injection (§7.4 of the format specification).
- The provider is responsible for all LLM interaction: model selection, API calls, structured output enforcement, caching, and retry.
- Generation errors (model unavailable, timeout, content policy rejection, validation failure) MUST be returned as `GenerationError`, not thrown as unhandled exceptions.

SDKs MUST NOT ship a default `GenerationProvider`. LLM generation is model-dependent, API-specific, and deployment-specific. The consuming tool (e.g., ThoughtJack) provides its own implementation.

> *Note:* LLM generation involves I/O. The trait interface is synchronous; implementations manage I/O internally. Language SDKs MAY provide async convenience wrappers. See §8.7.

---

## 7. Diagnostics and Error Types

### 7.0 Diagnostic

A structured diagnostic message produced during validation, normalization, or evaluation. SDKs MUST define this type.

| Field | Type | Description |
|---|---|---|
| `severity` | `DiagnosticSeverity` | One of: `error`, `warning`. |
| `code` | `String` | Machine-readable identifier (for example, `V-002`, `W-001`, `N-007`). |
| `path` | `Optional<String>` | Dot-path to the offending field (for example, `attack.indicators[0].surface`). |
| `message` | `String` | Human-readable description. |

**Usage:** `validate` returns a `ValidationResult` containing both errors and warnings:

```
ValidationResult {
    errors: List<ValidationError>   // conformance violations — document is non-conforming
    warnings: List<Diagnostic>      // severity: warning — document is valid but has issues
}
```

A document is valid if and only if `errors` is empty. Warnings are informational and do not block processing. SDKs MUST populate `errors` for all V-xxx rule failures.

SDKs MUST produce warnings for the following conditions:

| Code | Condition |
|---|---|
| W-001 | `oatf` is not the first key in the document (V-002). |
| W-002 | A mode passes pattern validation but is not in the known modes registry (§2.22). Likely typo. |
| W-003 | A protocol passes pattern validation but is not in the known protocols set. |
| W-004 | Template interpolation references an undefined extractor or an unresolvable message path. Two sub-cases: (a) "unknown extractor reference" — detectable at validate time by cross-referencing template expressions against declared extractor names; (b) "request/response path failed to resolve" — detectable only at runtime when the actual message is available. |
| W-005 | An indicator targets a protocol with no matching actor in the execution profile. |

SDKs MAY define additional warning codes for tool-specific diagnostics.

### 7.1 ParseError

Produced by `parse` when YAML deserialization fails.

| Field | Type | Description |
|---|---|---|
| `kind` | `ParseErrorKind` | One of: `syntax`, `type_mismatch`, `unknown_variant`. |
| `message` | `String` | Human-readable description. |
| `path` | `Optional<String>` | Dot-path to the offending field (when available). |
| `line` | `Optional<Integer>` | Line number in source YAML (when available). |
| `column` | `Optional<Integer>` | Column number in source YAML (when available). |

### 7.2 ValidationError

Produced by `validate` when a document violates a conformance rule.

| Field | Type | Description |
|---|---|---|
| `rule` | `String` | Rule identifier from §3.2 (for example, `V-001`). |
| `spec_ref` | `String` | Format specification section reference (for example, `§11.1.1`). |
| `message` | `String` | Human-readable description. |
| `path` | `String` | Dot-path to the offending field. |

### 7.3 EvaluationError

Produced during indicator evaluation when a runtime error occurs.

| Field | Type | Description |
|---|---|---|
| `kind` | `EvaluationErrorKind` | One of: `path_resolution`, `regex_timeout`, `cel_error`, `type_error`, `semantic_error`, `unsupported_method`. |
| `message` | `String` | Human-readable description. |
| `indicator_id` | `Optional<String>` | The indicator being evaluated when the error occurred. |

### 7.3a GenerationError

Produced by a `GenerationProvider` when LLM synthesis fails.

| Field | Type | Description |
|---|---|---|
| `kind` | `GenerationErrorKind` | One of: `provider_unavailable`, `model_error`, `validation_failure`, `timeout`, `content_policy`. |
| `message` | `String` | Human-readable description. |
| `phase_name` | `Optional<String>` | The phase during which generation was attempted. |
| `prompt_preview` | `Optional<String>` | First 200 characters of the resolved prompt, for diagnostics. |

The `GenerationProvider.generate` interface does not receive `phase_name` — the provider is intentionally unaware of execution context. The SDK is responsible for catching the error returned by the provider and populating `phase_name` from the current execution state before surfacing the `GenerationError` to the consuming tool.

`provider_unavailable` indicates no `GenerationProvider` is configured but a `synthesize` block was encountered. `validation_failure` indicates the LLM produced output that did not conform to the protocol binding's expected structure.

### 7.4 Error Aggregation

`validate` returns a `ValidationResult` containing both errors and warnings rather than stopping at the first failure. This enables IDE-style diagnostics where all problems are surfaced at once. `parse` MAY return a single error or multiple errors depending on the language deserialization framework's capabilities (see §3.1).

SDKs SHOULD order errors by their location in the source document (by line number for parse errors, by dot-path for validation errors). Diagnostics (warnings) SHOULD follow the same ordering.

The `load` convenience entry point (§3.5) returns the first applicable error list: if parsing fails, parse errors are returned and validation is not attempted. If parsing succeeds but validation finds errors, validation errors are returned. If both succeed, the normalized document and any warnings are returned together. A tool that needs fine-grained control over parse warnings and validation diagnostics should call the steps individually.

### 7.5 OATFError

Union type returned by `load` (§3.5). Represents any error that can occur during the combined parse-validate-normalize pipeline.

`OATFError` is one of:
- `ParseError` (§7.1) — YAML deserialization or structural typing failure.
- `ValidationError` (§7.2) — conformance rule violation.

SDKs MAY represent this as a tagged union, trait object, sum type, or language-appropriate equivalent.

---

## 8. Implementation Guidance

This section is non-normative. It offers practical advice for SDK implementors.

### 8.1 Language Adaptation

The types and function signatures in this specification are abstract. Language SDKs adapt them to idiomatic patterns:

| Concept | Rust | Python | Go | TypeScript |
|---|---|---|---|---|
| `Result<T, E>` | `Result<T, E>` | Raises exception | `(T, error)` | Throws or `Result<T, E>` |
| `Optional<T>` | `Option<T>` | `Optional[T]` / `None` | `*T` / zero value | `T \| undefined` |
| `List<T>` | `Vec<T>` | `list[T]` | `[]T` | `T[]` |
| `Map<K, V>` | `HashMap<K, V>` | `dict[K, V]` | `map[K]V` | `Map<K, V>` / `Record<K, V>` |
| `interface` | `trait` | `Protocol` / ABC | `interface` | `interface` |
| Enumerations | `enum` | `StrEnum` | `const` + type | `enum` / union type |
| `Value` | `serde_json::Value` | `Any` | `any` / `interface{}` | `unknown` / `JsonValue` |

### 8.2 Field Naming

SDKs SHOULD adapt field names to the target language's naming convention:

- Rust, Python: `snake_case` (matches YAML keys directly).
- Go: `PascalCase` for exported fields with `yaml:"snake_case"` struct tags.
- TypeScript/JavaScript: `camelCase` with consideration for YAML key mapping.

The canonical names in this specification use `snake_case` to match the YAML document format.

**Reserved keywords:** Several OATF field names collide with reserved keywords in common languages. In particular, `match` (§2.8 Trigger, §2.12 Indicator) is reserved in Rust, Scala, and PHP; `type` (§2.9 Extractor) is reserved in Python. SDKs MUST use the canonical YAML key for serialization/deserialization while renaming the struct field to a non-reserved alternative. For example, in Rust: `#[serde(rename = "match")] pub match_predicate: Option<MatchPredicate>`. The renamed field name is a language SDK decision; the YAML key is fixed by the format specification.

### 8.3 Immutability

SDKs SHOULD make the document model immutable after construction. `normalize` returns a new document; it does not mutate the input. This simplifies concurrent usage and prevents accidental modification of shared state.

### 8.4 Extension Fields

OATF documents may contain fields prefixed with `x-`. SDKs MUST preserve these through parse → normalize → serialize round-trips. The following core types include an `extensions: Optional<Map<String, Value>>` field for this purpose: `Attack` (§2.3), `Execution` (§2.6), `Actor` (§2.6a), `Phase` (§2.7), `Action` (§2.7a), `Indicator` (§2.12). During parsing, the SDK MUST collect any `x-` prefixed keys from each object and store them in the corresponding `extensions` map. During serialization, the SDK MUST emit these keys back into the output. Key names are preserved exactly (including the `x-` prefix); relative ordering of extension fields among themselves is preserved where the language's map type supports it. Ordering relative to standard fields is not guaranteed.

### 8.5 Performance Considerations

- Regex patterns SHOULD be compiled once during `validate` or `normalize` and cached for reuse during evaluation.
- CEL expressions SHOULD be parsed once during `validate` and the parsed AST cached for evaluation.
- The surface registry (§2.21) is static data. SDKs SHOULD represent it as a compile-time constant, not a runtime lookup.

### 8.6 Dependency Guidance

| Capability | Recommended Approach |
|---|---|
| YAML parsing | Use the language's standard or dominant YAML library. Require YAML 1.2 support. |
| Regular expressions | Use an RE2-compatible engine for linear-time guarantees. |
| CEL evaluation | Wrap an existing CEL library. Do not implement CEL from scratch. |
| JSONPath | Use a standard JSONPath library. Enforce traversal depth limits. |
| Duration parsing | Implement directly; the grammar is simple enough to avoid a dependency. See note below. |
| Dot-path resolution | Implement directly; no standard library exists for the OATF path syntax. |

**Duration parsing note:** OATF durations require accepting both shorthand (`30s`, `5m`) and ISO 8601 (`PT30S`, `PT5M`, `P1DT12H`) formats. Most language ecosystems have libraries that handle one format but not both (for example, Rust's `humantime` handles shorthand, `iso8601` handles ISO, but neither handles both). A hybrid parser is needed. The grammar is two branches: if the string starts with `P`, parse as ISO 8601; otherwise parse as shorthand. Both branches are simple enough to implement directly (shorthand is `\d+[smhd]`, ISO 8601 is `P(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?`), avoiding the need for two separate dependencies.

### 8.7 Async Evaluation

All entry points and evaluation functions defined in this specification have synchronous signatures. The SDK core MUST be synchronous:

- `parse`, `validate`, `normalize`, and `serialize` are CPU-bound operations on in-memory data. Synchronous signatures are appropriate.
- The core evaluation functions (`evaluate_indicator`, `compute_verdict`) MUST be synchronous. They invoke extension point trait implementations which present a synchronous interface to the SDK.
- Extension point implementations (`CelEvaluator`, `SemanticEvaluator`, `GenerationProvider`) MAY perform I/O internally (LLM inference, embedding API calls, network requests) but MUST present a synchronous interface to the SDK. How I/O is managed within the implementation (blocking calls, internal async runtimes, thread pools) is an implementation concern opaque to the SDK.
- Language SDKs MAY additionally provide async convenience wrappers that delegate to the synchronous core. These wrappers are SDK-specific sugar and not part of the abstract specification.
- Batch evaluation of multiple indicators against multiple messages is a common workflow. SDKs MAY offer batch evaluation functions that evaluate indicators concurrently where the language supports it.

This pattern — sync core, sync trait interface, optional async wrappers — ensures that the behavioral contracts are uniform across language ecosystems while allowing each SDK to integrate naturally with its language's concurrency model. SDKs SHOULD document whether they provide async convenience wrappers.

---

## 9. Versioning

### 9.1 SDK Specification Versioning

This specification follows Semantic Versioning independently of the OATF format specification:

- **Major** versions indicate breaking changes to the API contract (renamed entry points, changed function signatures, removed types).
- **Minor** versions add new entry points, new fields on existing types, or new evaluation capabilities.
- **Patch** versions clarify behavior without changing the API surface.

### 9.2 Format Compatibility

Each SDK specification version declares which OATF format specification version(s) it supports.

This version (SDK Spec 0.1) supports **OATF Format Spec 0.1**.

When the format specification adds a new protocol binding (for example, a hypothetical OATF 0.2 adding a new protocol), the SDK specification will be updated to include the new surfaces and event types. During the 0.x series, minor versions may introduce breaking changes (per format specification §10.1), so SDKs are not required to handle unknown format versions gracefully. Post-1.0, SDKs implementing a prior SDK specification version MUST still correctly parse documents using new minor-version bindings, ignoring unknown surfaces.

### 9.3 Language SDK Versioning

Individual language SDKs version independently of both specifications. A language SDK declares which SDK specification version it implements. For example:

- `oatf-rs 0.3.2` implements SDK Spec 0.1.
- `oatf-py 0.1.0` implements SDK Spec 0.1.

Patch versions of language SDKs (bug fixes, performance improvements) do not require SDK specification changes. Language SDKs SHOULD document their SDK specification version in their README and crate/package metadata.
