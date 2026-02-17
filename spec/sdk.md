# OATF SDK Specification

**Version:** 0.1.0-draft
**Status:** Draft
**Date:** 2026-02-16
**License:** Apache 2.0

## Abstract

This specification defines the language-agnostic API contract for OATF SDK implementations. An OATF SDK is a library that parses, validates, normalizes, evaluates, and serializes OATF documents. Any tool that consumes or produces OATF documents — adversarial simulation tools, evaluation scanners, CI pipeline integrations, IDE plugins — builds on an SDK rather than reimplementing the format's semantics.

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
3. MUST implement pattern and schema indicator evaluation (§4.2, §4.3).
4. MUST implement all verdict computation modes (§4.6).
5. MUST implement all execution primitives defined in §5.
6. MUST define extension point interfaces for CEL evaluation and semantic evaluation (§6).
7. MUST use the error taxonomy defined in §7.
8. SHOULD implement expression indicator evaluation via the CEL extension point (§4.4).
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
| `attack` | `Attack` | The attack definition. |

### 2.3 Attack

The attack envelope and all contained structures.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `String` | Yes | — | Unique identifier (for example, `OATF-003`). |
| `name` | `String` | Yes | — | Human-readable attack name. |
| `version` | `String` | No | `"1.0.0"` | Document version (SemVer). |
| `status` | `Status` | No | `draft` | Lifecycle status. |
| `created` | `Optional<Date>` | No | — | First published date. |
| `modified` | `Optional<Date>` | No | — | Last modified date. |
| `author` | `Optional<String>` | No | — | Author or organization. |
| `description` | `String` | Yes | — | Prose description of the attack. |
| `severity` | `Severity` | Yes | — | Always in object form after normalization. |
| `impact` | `Optional<List<Impact>>` | No | — | Categories of harm. |
| `classification` | `Optional<Classification>` | No | — | Framework mappings and taxonomy. |
| `references` | `Optional<List<Reference>>` | No | — | External references. |
| `execution` | `Execution` | Yes | — | Execution profile. |
| `indicators` | `List<Indicator>` | Yes | — | Detection patterns. At least one required. |
| `indicator_logic` | `IndicatorLogic` | No | `any` | How indicator verdicts combine. |
| `indicator_window` | `Optional<Duration>` | No | — | Time window for `ordered` logic. |
| `indicator_expression` | `Optional<String>` | No | — | CEL expression for `custom` logic. |

### 2.4 Severity

Always represented in object form. SDKs MUST expand scalar input during normalization.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `level` | `SeverityLevel` | Yes | — | One of: `informational`, `low`, `medium`, `high`, `critical`. |
| `confidence` | `Integer` | No | `50` | Author confidence, 0–100. |
| `cvss` | `Optional<String>` | No | — | CVSS 3.1 vector string. |

### 2.5 Classification

| Field | Type | Description |
|---|---|---|
| `category` | `Optional<Category>` | OATF taxonomy category. |
| `protocols` | `Optional<List<Protocol>>` | Targeted protocols. Inferred during normalization when absent. |
| `atlas` | `Optional<List<ATLASMapping>>` | MITRE ATLAS mappings. |
| `mitre_attack` | `Optional<List<ATTACKMapping>>` | MITRE ATT&CK mappings. |
| `owasp_mcp` | `Optional<List<String>>` | OWASP MCP Top 10 identifiers. |
| `owasp_agentic` | `Optional<List<String>>` | OWASP Agentic AI Top 10 identifiers. |
| `tags` | `Optional<List<String>>` | Free-form tags. |

### 2.6 Execution

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `protocol` | `Protocol` | Yes | — | Primary protocol: `mcp`, `a2a`, `ag_ui`. |
| `role` | `Role` | Yes | — | Default role: `server`, `client`, `peer`. |
| `setup` | `Optional<Setup>` | No | — | One-time initialization before first phase. |
| `phases` | `List<Phase>` | Yes | — | Ordered phase sequence. At least one required. |

### 2.7 Phase

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `String` | Yes | — | Unique phase label. |
| `description` | `Optional<String>` | No | — | Phase purpose. |
| `protocol` | `Optional<Protocol>` | No | Inherited from `execution.protocol` | Protocol for this phase. |
| `role` | `Optional<Role>` | No | Inherited from `execution.role` | Role for this phase. |
| `state` | `Optional<Value>` | No | Inherited from preceding phase | Protocol-specific state. Required on first phase. |
| `extractors` | `Optional<List<Extractor>>` | No | — | Value extractors for this phase. |
| `on_enter` | `Optional<List<Value>>` | No | — | Entry actions. Protocol-specific. |
| `advance` | `Optional<Trigger>` | No | — | Advancement condition. Absent on terminal phase. |

### 2.8 Trigger

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `event` | `Optional<String>` | No | — | Protocol event to match. |
| `count` | `Optional<Integer>` | No | `1` (when `event` present) | Number of matching events required. |
| `match` | `Optional<MatchPredicate>` | No | — | Content predicate on matching events. |
| `after` | `Optional<Duration>` | No | — | Unconditional time-based advancement. |
| `timeout` | `Optional<Duration>` | No | — | Maximum wait for matching event. |

### 2.9 Extractor

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `String` | Yes | Variable name for interpolation. |
| `source` | `ExtractorSource` | Yes | `request` or `response`. |
| `type` | `ExtractorType` | Yes | `json_path`, `regex`, or `header`. |
| `expression` | `String` | Yes | The extraction expression. |

### 2.10 MatchPredicate

A match predicate is a map from dot-path field references to conditions. All entries are combined with AND logic. Each entry maps a dot-path string to either a scalar value (equality check) or a `MatchCondition` object.

| Field | Type | Description |
|---|---|---|
| `entries` | `Map<String, MatchEntry>` | Dot-path → condition mappings. |

Where `MatchEntry` is either:
- A scalar `Value` (equality comparison), or
- A `MatchCondition` object.

### 2.11 MatchCondition

A single condition applied to a resolved field value. Exactly one operator MUST be present.

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

### 2.12 Indicator

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `String` | No | Auto-generated `{attack.id}-{NN}` | Unique indicator identifier. |
| `protocol` | `Protocol` | No | Inherited from `execution.protocol` | Protocol this indicator targets. |
| `surface` | `Surface` | Yes | — | Protocol surface being examined. |
| `description` | `Optional<String>` | No | — | What this indicator detects. |
| `method` | `IndicatorMethod` | No | Inferred from present key | Detection method used. |
| `pattern` | `Optional<PatternMatch>` | No | — | Pattern detection definition. |
| `schema` | `Optional<SchemaMatch>` | No | — | Schema detection definition. |
| `expression` | `Optional<ExpressionMatch>` | No | — | CEL detection definition. |
| `semantic` | `Optional<SemanticMatch>` | No | — | Semantic detection definition. |
| `confidence` | `Optional<Integer>` | No | — | Indicator-specific confidence override. |
| `severity` | `Optional<SeverityLevel>` | No | — | Indicator-specific severity override. |
| `false_positives` | `Optional<List<String>>` | No | — | Known false positive scenarios. |

### 2.13 PatternMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | Surface default target | Dot-path to field to inspect. |
| `condition` | `MatchCondition` | Yes | — | Always present after normalization. |
| `scope` | `PatternScope` | No | `value` | One of: `value`, `key`, `any`. |

Normalization: When a `PatternMatch` is parsed in shorthand form (condition operator as direct key without `condition` wrapper), the SDK MUST expand it to standard form with an explicit `condition` field and `target` defaulted from the surface.

### 2.14 SchemaMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | Surface default target | Dot-path to field to validate. |
| `checks` | `List<SchemaCheck>` | Yes | — | Structural checks. At least one required. |

### 2.15 SchemaCheck

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | `SchemaCheckType` | Yes | One of: `type_check`, `required_fields`, `max_length`, `max_depth`, `max_items`, `value_range`, `format`. |
| `expected_type` | `Optional<String>` | No | For `type_check`. |
| `fields` | `Optional<List<String>>` | No | For `required_fields`. |
| `max` | `Optional<Integer>` | No | For `max_length`, `max_depth`, `max_items`. |
| `min` | `Optional<Float>` | No | For `value_range`: minimum allowed value. |
| `max_value` | `Optional<Float>` | No | For `value_range`: maximum allowed value. |
| `format` | `Optional<String>` | No | For `format`. |

The `max` field (Integer) is used for count-based checks (`max_length`, `max_depth`, `max_items`). The `min` and `max_value` fields (Float) are used for `value_range` checks against numeric values that may be fractional. This distinction prevents type confusion between integer counts and float-valued numeric ranges.

### 2.16 ExpressionMatch

| Field | Type | Required | Description |
|---|---|---|---|
| `cel` | `String` | Yes | CEL expression evaluating to boolean. |
| `variables` | `Optional<Map<String, String>>` | No | Named variables as dot-paths into message. |

### 2.17 SemanticMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | Surface default target | Dot-path to field to analyze. |
| `intent` | `String` | Yes | — | Natural-language intent description. |
| `category` | `SemanticCategory` | Yes | — | Intent category. |
| `threshold` | `Optional<Float>` | No | — | Similarity/confidence threshold, 0.0–1.0. |
| `examples` | `Optional<SemanticExamples>` | No | — | Positive and negative examples. |

### 2.18 SemanticExamples

| Field | Type | Required | Description |
|---|---|---|---|
| `positive` | `Optional<List<String>>` | No | Strings that SHOULD trigger the indicator. |
| `negative` | `Optional<List<String>>` | No | Strings that SHOULD NOT trigger the indicator. |

Documents with `semantic` indicators SHOULD include at least two positive and two negative examples to enable cross-tool calibration (format specification §6.5).

### 2.19 Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | `String` | Yes | URL of the external reference. |
| `title` | `Optional<String>` | No | Human-readable title. |
| `description` | `Optional<String>` | No | Brief description of the reference. |

### 2.20 Setup

One-time initialization performed before the first phase begins. Declares static capabilities the adversarial tool exposes.

| Field | Type | Required | Description |
|---|---|---|---|
| `capabilities` | `Optional<SetupCapabilities>` | No | Protocol-specific capability declarations. |

#### SetupCapabilities

| Field | Type | Description |
|---|---|---|
| `mcp` | `Optional<Value>` | MCP capabilities. Structure defined in format specification §7.1. |
| `a2a` | `Optional<Value>` | A2A capabilities. Structure defined in format specification §7.2. |
| `ag_ui` | `Optional<Value>` | AG-UI capabilities. Structure defined in format specification §7.3. |

Capability structures are protocol-specific and vary as protocol bindings mature. The SDK represents them as `Value` to avoid coupling to a specific protocol binding version. Consuming tools that need typed access to capability fields use `resolve_path` against the `Value` tree.

### 2.21 ATLASMapping

| Field | Type | Required | Description |
|---|---|---|---|
| `technique` | `String` | Yes | MITRE ATLAS technique identifier (for example, `AML.T0051`). |
| `sub_technique` | `Optional<String>` | No | Sub-technique identifier (for example, `AML.T0051.001`). |
| `name` | `Optional<String>` | No | Human-readable technique name. |

### 2.22 ATTACKMapping

| Field | Type | Required | Description |
|---|---|---|---|
| `tactic` | `String` | Yes | MITRE ATT&CK tactic identifier (for example, `TA0001`). |
| `tactic_name` | `Optional<String>` | No | Human-readable tactic name. |
| `technique` | `String` | Yes | Technique identifier (for example, `T1195.002`). |
| `technique_name` | `Optional<String>` | No | Human-readable technique name. |

### 2.23 Verdict Types

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
| `attack_id` | `String` | Yes | The attack that was evaluated. |
| `result` | `AttackResult` | Yes | One of: `detected`, `not_detected`, `partial`, `error`. |
| `indicator_verdicts` | `List<IndicatorVerdict>` | Yes | All individual indicator results. |
| `timestamp` | `Optional<DateTime>` | No | When the verdict was produced. |
| `source` | `Optional<String>` | No | The tool that produced the verdict. |

### 2.24 Enumerations

SDKs MUST define named types for the following enumerations. The canonical string values listed here are the serialization form in YAML documents.

| Enumeration | Values |
|---|---|
| `SeverityLevel` | `informational`, `low`, `medium`, `high`, `critical` |
| `Impact` | `data_exfiltration`, `unauthorized_actions`, `service_disruption`, `privilege_escalation`, `information_disclosure`, `credential_theft` |
| `Category` | `capability_poisoning`, `response_fabrication`, `context_manipulation`, `discovery_exploitation`, `oversight_bypass`, `temporal_manipulation`, `availability_disruption`, `cross_protocol_chain` |
| `Protocol` | `mcp`, `a2a`, `ag_ui` |
| `Role` | `server`, `client`, `peer` |
| `Status` | `draft`, `experimental`, `stable`, `deprecated` |
| `IndicatorMethod` | `pattern`, `schema`, `expression`, `semantic` |
| `IndicatorLogic` | `any`, `all`, `ordered`, `custom` |
| `IndicatorResult` | `matched`, `not_matched`, `error`, `skipped` |
| `AttackResult` | `detected`, `not_detected`, `partial`, `error` |
| `ExtractorSource` | `request`, `response` |
| `ExtractorType` | `json_path`, `regex`, `header` |
| `PatternScope` | `value`, `key`, `any` |
| `SchemaCheckType` | `type_check`, `required_fields`, `max_length`, `max_depth`, `max_items`, `value_range`, `format` |
| `SemanticCategory` | `prompt_injection`, `data_exfiltration`, `privilege_escalation`, `social_engineering`, `instruction_override`, `benign` |

### 2.25 Surface Registry

SDKs MUST maintain a registry mapping each `Surface` value to its protocol and default target path. This registry is used during normalization to resolve omitted `target` fields and during validation to verify that surfaces match their indicator's protocol.

| Surface | Protocol | Default Target |
|---|---|---|
| `tool_description` | `mcp` | `tools[*].description` |
| `tool_input_schema` | `mcp` | `tools[*].inputSchema` |
| `tool_name` | `mcp` | `tools[*].name` |
| `tool_response` | `mcp` | `content[*]` |
| `tool_arguments` | `mcp` | `arguments` |
| `resource_content` | `mcp` | `contents[*]` |
| `resource_uri` | `mcp` | `resources[*].uri` |
| `resource_description` | `mcp` | `resources[*].description` |
| `prompt_template` | `mcp` | `messages[*].content` |
| `prompt_arguments` | `mcp` | `arguments` |
| `prompt_description` | `mcp` | `prompts[*].description` |
| `notification` | `mcp` | `params` |
| `capability` | `mcp` | `capabilities` |
| `server_info` | `mcp` | `serverInfo` |
| `sampling_request` | `mcp` | `params` |
| `roots_response` | `mcp` | `roots[*]` |
| `agent_card` | `a2a` | *(root)* |
| `agent_card_name` | `a2a` | `name` |
| `agent_card_description` | `a2a` | `description` |
| `skill_description` | `a2a` | `skills[*].description` |
| `skill_name` | `a2a` | `skills[*].name` |
| `task_message` | `a2a` | `messages[*]` |
| `task_artifact` | `a2a` | `artifacts[*]` |
| `task_status` | `a2a` | `status.state` |
| `message_history` | `ag_ui` | `messages[*]` |
| `tool_definitions` | `ag_ui` | `tools[*]` |
| `tool_result` | `ag_ui` | `result` |
| `state` | `ag_ui` | `state` |
| `forwarded_props` | `ag_ui` | `forwardedProps` |
| `agent_event` | `ag_ui` | `event` |
| `agent_tool_call` | `ag_ui` | `toolCall` |

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

`parse` MUST NOT reject documents based on semantic constraints (missing required fields, duplicate IDs, invalid cross-references). Those are `validate`'s responsibility. The separation allows tools to parse a partial document for editing or introspection without requiring full validity.

### 3.2 validate

```
validate(document: Document) → Result<void, List<ValidationError>>
```

Validates a parsed document against the conformance rules of OATF format specification §11.1. Returns success if the document is conforming. Returns a list of all violations found if not.

**Preconditions:** `document` is a value returned by `parse`.

**Behavior:**

The following rules are checked. Each rule references the normative requirement in the format specification. SDKs MUST check all rules and MUST return all violations found (not just the first).

| Rule | Spec Ref | Check |
|---|---|---|
| V-001 | §11.1.1 | `oatf` field is present and is a supported version string. |
| V-002 | §11.1.2 | `oatf` field is the first field in the document. This check requires access to YAML key ordering, which is lost after deserialization into typed structs. SDKs SHOULD check this during `parse` (before constructing the typed document model) or by pre-scanning the raw YAML input. SDKs that cannot preserve key ordering MAY skip this check, provided they document the omission. |
| V-003 | §11.1.3 | Exactly one `attack` object is present. |
| V-004 | §11.1.4 | Required fields present: `attack.id`, `attack.name`, `attack.description`, `attack.severity`, `execution`, `indicators`. |
| V-005 | §11.1.5 | All enumeration values are valid members of their respective types. |
| V-006 | §11.1.6 | `indicators` contains at least one entry. |
| V-007 | §11.1.7 | `execution.phases` contains at least one entry. |
| V-008 | §11.1.8 | At most one terminal phase (no `advance`), and it is the last phase. |
| V-009 | §11.1.9 | First phase includes `state`. |
| V-010 | §11.1.10 | All explicitly specified `indicator.id` values are unique. |
| V-011 | §11.1.11 | All `phase.name` values are unique. |
| V-012 | §11.1.12 | Each indicator has exactly one method key. When `method` is explicit, it matches the present key. |
| V-013 | §5.7 | All regular expressions are syntactically valid RE2. |
| V-014 | §5.7 | All CEL expressions are syntactically valid (parse without error). |
| V-015 | §5.7 | All JSONPath expressions are syntactically valid. |
| V-016 | §5.7 | All template references use valid syntax (no unclosed `{{`). Escaped sequences (`\{{`) are not template references and MUST NOT be flagged. |
| V-017 | §5.3 | `indicator_window` is present when `indicator_logic` is `ordered`. |
| V-018 | §8.3 | `indicator_expression` is present when `indicator_logic` is `custom`. |
| V-019 | §4.3 | `severity.confidence` is in range 0–100 when present. |
| V-020 | §6.3 | Each `SchemaMatch` has at least one check. |
| V-021 | §7 | Indicator `surface` is valid for the indicator's resolved protocol. |
| V-022 | §5.3 | Trigger `count` and `match` are only present when `event` is also present. |
| V-023 | §11.1.1 | Document does not contain YAML anchors, aliases, or merge keys. SDKs that parse via a YAML library exposing anchor/alias information SHOULD check this; SDKs whose parsers silently resolve aliases MAY skip this check. |

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
| N-001 | §11.2.1 | Apply default values: `version` → `"1.0.0"`, `status` → `draft`, `severity.confidence` → `50`, `indicator.protocol` → `execution.protocol`, `indicator_logic` → `any`. |
| N-002 | §11.2.2 | Expand severity scalar form to object form: `"high"` → `{level: "high", confidence: 50}`. |
| N-003 | §11.2.3 | Auto-generate `indicator.id` for indicators that omit it, as `{attack.id}-{NN}` where `NN` is the 1-based zero-padded indicator index. |
| N-004 | §11.2.4 | Infer `classification.protocols` as the union of `execution.protocol`, all `phase.protocol` values, and all `indicator.protocol` values. |
| N-005 | §11.2.5 | Resolve `pattern.target`, `schema.target`, and `semantic.target` from the surface registry (§2.25) when omitted. |
| N-006 | §11.2.6 | Expand pattern shorthand form to standard form: move condition operator into explicit `condition` field. |
| N-007 | §11.2.1 | Infer `indicator.method` from the present method key (`pattern` → `pattern`, etc.). |
| N-008 | §5.3 | Set `trigger.count` to `1` when `trigger.event` is present and `count` is omitted. |

`normalize` MUST be idempotent: `normalize(normalize(doc))` produces the same result as `normalize(doc)`.

The caller MUST receive a normalized document. The original document MUST NOT be observably mutated through any retained reference. SDKs MAY implement this in either of two ways:

- **Copy semantics**: accept a reference, return a new document (for example, `fn normalize(&Document) -> Document` in Rust, or returning a new object in Python/JS). The input remains usable after the call.
- **Consuming semantics**: accept ownership, return a transformed document (for example, `fn normalize(Document) -> Document` in Rust). The input is consumed and unavailable after the call. This avoids unnecessary allocation in languages with move semantics.

SDKs that offer consuming semantics SHOULD also offer a copy variant (or document that callers should clone before calling) for cases where the original document is needed after normalization.

After normalization, the following guarantees hold and consuming code MAY rely on them:

- `attack.severity` is always in object form with `level` and `confidence` present.
- Every indicator has an `id`.
- Every indicator has a `protocol`.
- Every indicator has a `method`.
- Every `PatternMatch` is in standard form with an explicit `condition` field.
- Every `PatternMatch`, `SchemaMatch`, and `SemanticMatch` has a resolved `target` (or validation would have rejected the document if the surface has no default and target was omitted).
- `classification.protocols` is present and non-empty.
- Every trigger with an `event` has a `count`.

### 3.4 serialize

```
serialize(document: Document) → String
```

Serializes a document to YAML. SDKs SHOULD emit the fully-expanded normalized form per §11.2.7.

**Preconditions:** `document` is a well-formed document model (typically the output of `normalize`).

**Behavior:**

1. Serialize all fields to YAML 1.2.
2. Preserve field ordering: `oatf` first, then `attack` fields in specification order.
3. Emit explicit values for all fields that have defaults (do not rely on consumer normalization).
4. Preserve `x-` extension fields in their original position.
5. Use block style for readability.

### 3.5 load

```
load(input: String) → Result<Document, List<OATFError>>
```

Convenience entry point that composes `parse`, `validate`, and `normalize` into a single operation. Returns a fully-normalized, valid document or the combined errors from parsing and validation.

**Behavior:** Equivalent to:
```
document = parse(input)?
validate(document)?
return normalize(document)
```

If `parse` fails, return parse errors. If `validate` fails, return validation errors. If both succeed, return the normalized document.

Most tool integrations will call `load` rather than the individual steps. The separate entry points exist for tools that need partial processing (IDE plugins that parse for syntax highlighting without requiring validity, linters that validate without normalizing).

---

## 4. Evaluation

The evaluation interface allows tools to assess whether observed protocol traffic matches the indicators defined in an OATF document. These operations are the foundation for evaluation tools, but adversarial tools MAY also use them for self-verification.

### 4.1 Message Abstraction

Indicator evaluation operates on protocol messages represented as `Value` — a dynamically-typed JSON-like tree. The SDK does not define message types for specific protocols. The consuming tool is responsible for constructing the `Value` from whatever wire format it captures.

The `Value` passed to indicator evaluation corresponds to the `result` (for responses) or `params` (for requests/notifications) field of the JSON-RPC message, not the full JSON-RPC envelope. This is the convention defined in the format specification §7.1.3.

SDKs MUST NOT require messages to conform to any particular protocol schema. Indicators evaluate against whatever structure is present. Missing fields produce `not_matched` verdicts, not errors.

### 4.2 evaluate_pattern

```
evaluate_pattern(pattern: PatternMatch, message: Value) → Boolean
```

Evaluates a pattern indicator against a protocol message.

**Preconditions:** `pattern` is in normalized standard form (explicit `condition`, resolved `target`).

**Behavior:**

1. Resolve `pattern.target` against `message` using dot-path resolution (§5.1). This may produce zero, one, or many values (when the path contains wildcards).
2. For each resolved value, apply the condition (§5.3) according to `pattern.scope`:
   - `value`: evaluate condition against the field's value.
   - `key`: evaluate condition against the field's key name.
   - `any`: evaluate condition against both; match if either matches.
3. Return `true` if any resolved value matches the condition. Return `false` if no values match or if the target path resolves to nothing.

### 4.3 evaluate_schema

```
evaluate_schema(schema: SchemaMatch, message: Value) → Boolean
```

Evaluates a schema indicator against a protocol message.

**Preconditions:** `schema` has a resolved `target` and at least one check.

**Behavior:**

1. Resolve `schema.target` against `message` using dot-path resolution (§5.1).
2. For each resolved value, evaluate all checks. All checks are combined with AND logic.
3. Return `true` if any resolved value passes all checks. Return `false` otherwise.

**Check evaluation:**

| Check Type | Evaluates To True When |
|---|---|
| `type_check` | The value's runtime type matches `expected_type` (one of: `string`, `number`, `integer`, `boolean`, `array`, `object`, `null`). |
| `required_fields` | The value is an object containing all fields listed in `fields`. |
| `max_length` | The value is a string with length ≤ `max`, or an array with item count ≤ `max`. |
| `max_depth` | The value's nesting depth ≤ `max`. Nesting depth of a scalar is 0; of an array or object, 1 + max depth of children. |
| `max_items` | The value is an array with item count ≤ `max`. |
| `value_range` | The value is a number ≥ `min` (when present) and ≤ `max_value` (when present). |
| `format` | The value is a string matching the named format (`uri`, `email`, `date`, `ipv4`, `ipv6`, `hostname`). Format validation uses the same semantics as JSON Schema format validation. |

### 4.4 evaluate_expression

```
evaluate_expression(
    expression: ExpressionMatch,
    message: Value,
    cel_evaluator: CelEvaluator
) → Boolean
```

Evaluates a CEL expression indicator against a protocol message using the provided CEL evaluator.

**Preconditions:** `expression.cel` is syntactically valid (verified during `validate`).

**Behavior:**

1. Construct the CEL evaluation context:
   - Bind `message` as the root variable `message`.
   - If `expression.variables` is present, for each entry `(name, path)`, resolve `path` against `message` using dot-path resolution (§5.1) and bind the result as variable `name`.
2. Pass the CEL string and context to `cel_evaluator.evaluate()` (§6.1).
3. If the evaluator returns a boolean, return that value.
4. If the evaluator returns an error or a non-boolean value, return `false`.

SDKs that do not bundle a CEL evaluator MUST still define this function. When called without a configured evaluator, it MUST return `false` and produce a diagnostic indicating that CEL evaluation is not available.

### 4.5 evaluate_indicator

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

1. Dispatch on `indicator.method`:
   - `pattern` → call `evaluate_pattern(indicator.pattern, message)`. Result is boolean.
   - `schema` → call `evaluate_schema(indicator.schema, message)`. Result is boolean.
   - `expression` → call `evaluate_expression(indicator.expression, message, cel_evaluator)`. If `cel_evaluator` is absent, return verdict with `result: skipped` and evidence indicating CEL support is unavailable. Result is boolean.
   - `semantic` → if `semantic_evaluator` is absent, return verdict with `result: skipped` and evidence indicating semantic evaluation is unavailable. Otherwise:
     a. Resolve `indicator.semantic.target` against `message` using dot-path resolution (§5.1). Serialize the first resolved value to string. If the path resolves to nothing, return verdict with `result: not_matched`.
     b. Call `semantic_evaluator.evaluate(text, indicator.semantic.intent, indicator.semantic.category, indicator.semantic.threshold, indicator.semantic.examples)`.
     c. Determine the effective threshold: use `indicator.semantic.threshold` if present, otherwise `0.7` (per format specification §6.5).
     d. If the returned score ≥ the effective threshold, the result is `true` (matched). Otherwise `false` (not matched).
2. Catch any runtime evaluation error. On error, return verdict with `result: error` and the diagnostic as `evidence`.
3. On successful evaluation, return verdict with `result: matched` (if true) or `result: not_matched` (if false).
4. Populate `indicator_id` from the indicator, `timestamp` from the current time.

### 4.6 compute_verdict

```
compute_verdict(
    attack: Attack,
    indicator_verdicts: Map<String, IndicatorVerdict>,
    cel_evaluator: Optional<CelEvaluator>
) → AttackVerdict
```

Computes the attack-level verdict from a set of indicator verdicts according to the attack's `indicator_logic`.

**Preconditions:** `indicator_verdicts` maps indicator IDs to their individual verdicts. All indicator IDs referenced in the attack SHOULD be present.

**Behavior by logic mode:**

**`any` (default):**
- If any indicator verdict is `error`, return `error`.
- If any indicator verdict is `matched`, return `detected`.
- Otherwise return `not_detected`.

**`all`:**
- If any indicator verdict is `error`, return `error`.
- If all indicator verdicts are `matched`, return `detected`.
- If at least one is `matched` and at least one is `not_matched`, return `partial`.
- If all are `not_matched` or `skipped`, return `not_detected`.

**`ordered`:**
- If any indicator verdict is `error`, return `error`.
- Collect all `matched` indicators with their timestamps.
- Check that matched indicators appear in the same order as they are listed in the attack's `indicators` array.
- Check that the time span between the first and last matched indicator is within `indicator_window`.
- If all indicators matched in order within the window, return `detected`.
- If some but not all matched, return `partial`.
- If none matched, return `not_detected`.
- If timestamps are missing on any `matched` verdict, return `error` with diagnostic indicating that ordered evaluation requires timestamps.

**`custom`:**
- If `cel_evaluator` is absent, return `error` with diagnostic indicating CEL support is required for custom logic.
- Construct CEL context with `indicators` as a map from indicator ID to an object with fields `matched` (boolean), `timestamp` (datetime or null), and `result` (string).
- Evaluate `attack.indicator_expression` against this context.
- If the expression returns `true`, return `detected`. If `false`, return `not_detected`. If error, return `error`.

**Treatment of `skipped` verdicts:** A `skipped` verdict means the indicator could not be evaluated (absent evaluator, unsupported method). For verdict computation purposes, `skipped` is treated equivalently to `not_matched`: the indicator did not produce evidence of the attack. This is semantically correct — the attack was not detected by that indicator, regardless of why. Consuming tools that need to distinguish between "evaluated and not matched" versus "not evaluated" SHOULD inspect the individual `IndicatorVerdict` results in the returned `AttackVerdict.indicator_verdicts`.

---

## 5. Execution Primitives

Shared utility operations used by both entry points and evaluation. SDKs MUST implement these and SHOULD expose them in the public API for use by consuming tools.

### 5.1 resolve_path

```
resolve_path(path: String, value: Value) → List<Value>
```

Resolves a dot-path expression against a dynamically-typed value tree. Returns all values that match the path. Returns an empty list if the path does not match.

**Path syntax:**

| Segment | Meaning | Example |
|---|---|---|
| `field_name` | Access named field on object | `capabilities` |
| `[N]` | Access array element by index | `tools[0]` |
| `[*]` | Wildcard: all elements of array | `tools[*]` |
| `.` | Segment separator | `tools[*].description` |

**Behavior:**

1. Split `path` on `.` segment boundaries (respecting `[*]` and `[N]` as atomic segments).
2. Starting from `value` as the root, traverse each segment:
   - For a field name: if the current value is an object, access the named field. If the field is absent or the current value is not an object, produce no results for this branch.
   - For `[N]`: if the current value is an array with index N in bounds, access element N. Otherwise, produce no results.
   - For `[*]`: if the current value is an array, fan out to all elements. Each element continues independently through remaining segments. If the current value is not an array, produce no results.
3. Collect all terminal values reached after processing all segments.

**Examples:**

- `resolve_path("tools[*].description", {"tools": [{"description": "A"}, {"description": "B"}]})` → `["A", "B"]`
- `resolve_path("capabilities.tools", {"capabilities": {"tools": {"listChanged": true}}})` → `[{"listChanged": true}]`
- `resolve_path("missing.path", {"other": 1})` → `[]`

SDKs SHOULD enforce a maximum traversal depth to prevent stack overflow on pathological inputs. A depth limit of 64 is RECOMMENDED.

**Limitation:** Dot-path syntax does not support escaping literal dots within field names. A JSON object key containing a dot (for example, `{"content.type": "text"}`) cannot be addressed because the path `content.type` is always interpreted as two segments. This is an intentional simplification — protocol messages in MCP, A2A, and AG-UI do not use dotted key names. If future protocol bindings introduce dotted keys, the path syntax will need an escape mechanism (for example, backtick quoting), introduced in a future SDK specification version.

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
| `P{N}DT{...}` | `P1DT12H` | 1 day 12 hours (ISO 8601 composite) |

`N` is a positive integer. Fractional values are not supported.

### 5.3 evaluate_condition

```
evaluate_condition(condition: MatchCondition, value: Value) → Boolean
```

Evaluates a single match condition against a resolved value.

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
| *(equality)* | Any | `value` equals the operand (deep equality). Used when the MatchEntry is a scalar, not a MatchCondition. |

**Type mismatches:** If the operator requires a specific value type (string operators on non-string, numeric operators on non-number), the condition evaluates to `false`. Type mismatches are not errors.

**Regex:** Patterns MUST be compiled with RE2 semantics (linear-time guarantee). SDKs MUST reject patterns with features outside the RE2 subset during `validate`. The regex is evaluated as a **partial match**: the pattern may match any substring of the value. To require a full-string match, the pattern MUST include `^` and `$` anchors. This matches the default behavior of RE2 libraries across languages (Go's `regexp.MatchString`, Rust's `regex::Regex::is_match`, Python's `re2.search`).

### 5.4 evaluate_predicate

```
evaluate_predicate(predicate: MatchPredicate, value: Value) → Boolean
```

Evaluates a match predicate (a set of dot-path → condition entries) against a value. All entries are combined with AND logic.

**Behavior:**

1. For each entry in `predicate.entries`:
   a. Resolve the dot-path key against `value` using `resolve_path`.
   b. If the path resolves to no values, the entry evaluates to `false`.
   c. If the path resolves to one or more values, evaluate the condition against each. The entry is `true` if any resolved value satisfies the condition.
2. Return `true` if all entries are `true`. Return `false` if any entry is `false`.

### 5.5 interpolate_template

```
interpolate_template(
    template: String,
    extractors: Map<String, String>,
    request: Optional<Value>
) → String
```

Resolves template expressions in a string.

**Template syntax:**

- `{{extractor_name}}` → replaced with the value of the named extractor.
- `{{request.field.path}}` → replaced with the value at the dot-path in the current request.
- `\{{` → replaced with a literal `{{` (escape sequence).

**Behavior:**

1. Replace all `\{{` escape sequences with a placeholder.
2. Find all `{{...}}` expressions in `template`.
3. For each expression:
   a. If the name matches a key in `extractors`, replace with the extractor value.
   b. If the name starts with `request.` and `request` is present, resolve the remaining path against `request` using `resolve_path`. Replace with the first resolved value, serialized to string. If the path resolves to no values, replace with empty string.
   c. If neither matches, replace with empty string and emit a warning diagnostic.
4. Restore all placeholders to literal `{{`.
5. Return the interpolated string.

### 5.6 evaluate_extractor

```
evaluate_extractor(
    extractor: Extractor,
    message: Value,
    headers: Optional<Map<String, String>>
) → Optional<String>
```

Applies an extractor to a message, capturing a value.

**Behavior by type:**

- `json_path`: Evaluate the JSONPath expression against `message`. If the expression matches one or more nodes, return the first match serialized to its compact JSON string representation. If no match, return empty.
- `regex`: Convert `message` to its string representation, evaluate the regular expression. If the regex matches and has at least one capture group, return the first capture group's value. If no match, return empty.
- `header`: Look up the extractor's `expression` as a key in `headers`. Return the header value as a string, or empty if the header is absent or `headers` is not provided. Header names SHOULD be compared case-insensitively per HTTP semantics. The `headers` parameter is transport-level data supplied by the consuming tool; the SDK does not perform HTTP I/O. When `headers` is absent and a `header` extractor is evaluated, the extractor returns empty and the SDK SHOULD emit a warning diagnostic.

When the extracted value is a non-scalar (object or array), it MUST be serialized to its compact JSON string representation.

### 5.7 compute_effective_state

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

**Partial compliance:** When the underlying CEL library does not support the full set of standard functions listed above, the default implementation MAY ship with partial function coverage. In this case, the SDK MUST document which functions are supported, and the evaluator MUST return an `EvaluationError` with `kind: unsupported_method` when an expression calls an unsupported function (rather than failing silently or crashing). The CEL ecosystem maturity varies across languages — Go has Google's reference implementation, while Rust and Python have less complete alternatives. Partial compliance with a clear extension point is preferable to no default implementation.

### 6.2 SemanticEvaluator

```
interface SemanticEvaluator {
    evaluate(
        text: String,
        intent: String,
        category: SemanticCategory,
        threshold: Optional<Float>,
        examples: Optional<SemanticExamples>
    ) → Result<Float, EvaluationError>
}
```

Evaluates the semantic similarity or intent match between observed text and the indicator's intent description. Returns a confidence score between 0.0 and 1.0.

**Contract:**

- The evaluator is responsible for all inference logic (LLM calls, embedding similarity, classifier invocation). The SDK provides none of this.
- When `threshold` is present, the indicator is considered matched if the returned score ≥ `threshold`.
- When `threshold` is absent, the SDK uses a default threshold of `0.7` (per format specification §6.5).
- The evaluator MAY use `examples.positive` and `examples.negative` to calibrate its scoring.
- Evaluation errors (model unavailable, timeout, malformed response) MUST be returned as `EvaluationError`, not thrown as unhandled exceptions.

SDKs MUST NOT ship a default `SemanticEvaluator`. Semantic evaluation is inherently model-dependent and deployment-specific.

---

## 7. Error Types

SDKs MUST define the following error types. Each error carries structured fields that enable programmatic handling and human-readable diagnostics.

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

### 7.4 Error Aggregation

`validate` returns lists of errors rather than stopping at the first failure. This enables IDE-style diagnostics where all problems are surfaced at once. `parse` MAY return a single error or multiple errors depending on the language deserialization framework's capabilities (see §3.1).

SDKs SHOULD order errors by their location in the source document (by line number for parse errors, by dot-path for validation errors).

The `load` convenience entry point (§3.5) returns the first applicable error list: if parsing fails, parse errors are returned and validation is not attempted. If parsing succeeds but validation fails, validation errors are returned. A tool that needs both parse warnings and validation errors should call the steps individually.

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

**Reserved keywords:** Several OATF field names collide with reserved keywords in common languages. Notably, `match` (§2.8 Trigger, §2.12 Indicator) is reserved in Rust, Scala, and PHP; `type` (§2.15 SchemaCheck, §2.9 Extractor) is reserved in Python. SDKs MUST use the canonical YAML key for serialization/deserialization while renaming the struct field to a non-reserved alternative. For example, in Rust: `#[serde(rename = "match")] pub match_predicate: Option<MatchPredicate>`. The renamed field name is a language SDK decision; the YAML key is fixed by the format specification.

### 8.3 Immutability

SDKs SHOULD make the document model immutable after construction. `normalize` returns a new document; it does not mutate the input. This simplifies concurrent usage and prevents accidental modification of shared state.

### 8.4 Extension Fields

OATF documents may contain fields prefixed with `x-`. SDKs MUST preserve these through parse → normalize → serialize round-trips. The RECOMMENDED approach is to store extension fields in a `Map<String, Value>` on each type that may contain them (`Attack`, `Phase`, `Indicator`).

### 8.5 Performance Considerations

- Regex patterns SHOULD be compiled once during `validate` or `normalize` and cached for reuse during evaluation.
- CEL expressions SHOULD be parsed once during `validate` and the parsed AST cached for evaluation.
- The surface registry (§2.25) is static data. SDKs SHOULD represent it as a compile-time constant, not a runtime lookup.

### 8.6 Dependency Guidance

| Capability | Recommended Approach |
|---|---|
| YAML parsing | Use the language's standard or dominant YAML library. Require YAML 1.2 support. |
| Regular expressions | Use an RE2-compatible engine for linear-time guarantees. |
| CEL evaluation | Wrap an existing CEL library. Do not implement CEL from scratch. |
| JSONPath | Use a standard JSONPath library. Enforce traversal depth limits. |
| Duration parsing | Implement directly — the grammar is simple enough to avoid a dependency. See note below. |
| Dot-path resolution | Implement directly — no standard library exists for the OATF path syntax. |

**Duration parsing note:** OATF durations require accepting both shorthand (`30s`, `5m`) and ISO 8601 (`PT30S`, `PT5M`, `P1DT12H`) formats. Most language ecosystems have libraries that handle one format but not both (for example, Rust's `humantime` handles shorthand, `iso8601` handles ISO, but neither handles both). A hybrid parser is needed. The grammar is two branches: if the string starts with `P`, parse as ISO 8601; otherwise parse as shorthand. Both branches are simple enough to implement directly (shorthand is `\d+[smhd]`, ISO 8601 is `P(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?`), avoiding the need for two separate dependencies.

### 8.7 Async Evaluation

The entry points and evaluation functions in this specification are defined with synchronous signatures. However, semantic evaluation (§6.2) involves I/O (LLM inference, embedding API calls) that may take seconds. CEL evaluation may also involve non-trivial computation. SDKs SHOULD consider the following:

- `parse`, `validate`, `normalize`, and `serialize` are CPU-bound operations on in-memory data. Synchronous signatures are appropriate.
- `evaluate_indicator` and `compute_verdict` may invoke extension points (`CelEvaluator`, `SemanticEvaluator`) that perform I/O. SDKs in languages with async ecosystems (Rust, Python, TypeScript, Go) SHOULD provide async variants of these functions or define the extension point interfaces as async.
- Batch evaluation of multiple indicators against multiple messages is a common workflow. SDKs MAY offer batch evaluation functions that evaluate indicators concurrently where the language supports it.

The decision between sync and async interfaces is a language SDK concern. This specification defines the behavioral contracts (inputs, outputs, error handling) — how those contracts are scheduled is an implementation detail. SDKs SHOULD document whether their evaluation APIs are sync, async, or both.

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

When the format specification adds a new protocol binding (for example, a hypothetical OATF 0.2 adding a new protocol), the SDK specification will be updated to include the new surfaces and event types. SDKs implementing the prior SDK specification version MUST still correctly parse documents using the new binding (ignoring unknown surfaces), per the forward-compatibility requirement of the format specification §10.1.

### 9.3 Language SDK Versioning

Individual language SDKs version independently of both specifications. A language SDK declares which SDK specification version it implements. For example:

- `oatf-rs 0.3.2` implements SDK Spec 0.1.
- `oatf-py 0.1.0` implements SDK Spec 0.1.

Patch versions of language SDKs (bug fixes, performance improvements) do not require SDK specification changes. Language SDKs SHOULD document their SDK specification version in their README and crate/package metadata.
