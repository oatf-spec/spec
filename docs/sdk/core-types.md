---
title: "Core Types"
description: "Abstract types that constitute the OATF document model: Document, Attack, Execution, Phase, Indicator, and all supporting types."
---

This section defines the abstract types that constitute the OATF document model. Each type is described as a set of named fields with specified types and constraints. SDKs MUST expose these types in their public API. Field names SHOULD match those listed here, adapted to the target language's naming conventions (for example, `snake_case` in Rust and Python, `camelCase` in JavaScript and Go).

## 2.1 Primitive Types

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

## 2.2 Document

The top-level container for a parsed OATF document.

| Field | Type | Description |
|---|---|---|
| `oatf` | `String` | Specification version declared by this document. |
| `schema` | `Optional<String>` | JSON Schema URL (`$schema` in YAML). Preserved through round-trips but ignored during processing. |
| `attack` | `Attack` | The attack definition. |

## 2.3 Attack

The attack envelope and all contained structures.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `Optional<String>` | No | — | Unique identifier (for example, `OATF-003`, `ACME-001`). Required for publication. |
| `name` | `Optional<String>` | No | `"Untitled"` | Human-readable attack name. |
| `version` | `Optional<Integer>` | No | `1` | Document version (positive integer, higher is newer). |
| `status` | `Optional<Status>` | No | `draft` | Lifecycle status. |
| `created` | `Optional<DateTime ∣ Date>` | No | — | First published date/time. Bare dates (`YYYY-MM-DD`) accepted and interpreted as midnight UTC. |
| `modified` | `Optional<DateTime ∣ Date>` | No | — | Last modified date/time. Bare dates accepted and interpreted as midnight UTC. |
| `author` | `Optional<String>` | No | — | Author or organization. |
| `description` | `Optional<String>` | No | — | Prose description of the attack. |
| `grace_period` | `Optional<Duration>` | No | — | Post-terminal-phase observation window. When present, tools observe for this duration after all terminal phases complete before computing the verdict. Parsed by `parse_duration` ([§5.2](/sdk/execution-primitives/#52-parse_duration)). |
| `severity` | `Optional<Severity>` | No | — | Absent when not assessed. Always in object form after normalization when present. |
| `impact` | `Optional<List<Impact>>` | No | — | Categories of harm. |
| `classification` | `Optional<Classification>` | No | — | Framework mappings and taxonomy. |
| `references` | `Optional<List<Reference>>` | No | — | External references. |
| `execution` | `Execution` | Yes | — | Execution profile. |
| `indicators` | `Optional<List<Indicator>>` | No | — | Patterns for determining agent compliance. When absent, document is simulation-only. |
| `correlation` | `Optional<Correlation>` | No | — | How indicator verdicts combine. See [§2.3a](/sdk/core-types/#23a-correlation). |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

**Post-normalization guarantee:** After `normalize` ([§3.3](/sdk/entry-points/#33-normalize)), `name`, `version`, and `status` are always present with their default values applied. Code that operates on normalized documents MAY assert their presence.

## 2.3a Correlation

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `logic` | `CorrelationLogic` | No | `any` | How indicator verdicts combine to produce the attack-level verdict. |

`correlation` MUST only be present when `indicators` is also present (the JSON Schema enforces this via `dependentRequired`). Correlation governs how indicator verdicts combine and is meaningless without indicators.

## 2.4 Severity

Always represented in object form. SDKs MUST expand scalar input during normalization.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `level` | `SeverityLevel` | Yes | — | One of: `informational`, `low`, `medium`, `high`, `critical`. |
| `confidence` | `Integer` | No | `50` | Author confidence in the assigned severity level, 0–100. |

## 2.5 Classification

| Field | Type | Description |
|---|---|---|
| `category` | `Optional<Category>` | OATF taxonomy category. |
| `mappings` | `Optional<List<FrameworkMapping>>` | External security framework mappings. |
| `tags` | `Optional<List<String>>` | Free-form tags. Lowercase, hyphenated. |

## 2.6 Execution

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `mode` | `Optional<String>` | No | — | Attacker posture. Must match `{protocol}_{role}` convention. Required when `state` is present. |
| `state` | `Optional<Value>` | No | — | Protocol-specific state (single-phase form only). |
| `phases` | `Optional<List<Phase>>` | No | — | Ordered phase sequence (multi-phase form only). |
| `actors` | `Optional<List<Actor>>` | No | — | Named concurrent actors (multi-actor form only). |

Three forms are mutually exclusive: `state`, `phases`, and `actors` MUST NOT coexist. The single-phase form (`state`) normalizes to multi-actor form via N-006. The multi-phase form (`phases`) normalizes to multi-actor form via N-007.

Extension fields (`x-` prefixed) on `Execution` are stored in an `extensions: Optional<Map<String, Value>>` and preserved through round-trips.

## 2.6a Actor

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `String` | Yes | — | Unique identifier. Must match `[a-z][a-z0-9_]*`. |
| `mode` | `String` | Yes | — | Attacker posture for this actor. Must match `{protocol}_{role}` convention. |
| `phases` | `List<Phase>` | Yes | — | Ordered phase sequence. At least one required. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

## 2.7 Phase

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | `Optional<String>` | No | `"phase-{N}"` (1-based index) | Human-readable phase label. Auto-generated when omitted. |
| `description` | `Optional<String>` | No | — | Phase purpose. |
| `mode` | `Optional<String>` | No | Inherited from `execution.mode` or `actor.mode` | Attacker posture for this phase. Required when `execution.mode` is absent and not in multi-actor form. |
| `state` | `Optional<Value>` | No | Inherited from preceding phase | Protocol-specific state. Required on first phase. |
| `extractors` | `Optional<List<Extractor>>` | No | — | Value extractors for this phase. |
| `on_enter` | `Optional<List<Action>>` | No | — | Entry actions executed when this phase begins. See [§2.7a](/sdk/core-types/#27a-action). |
| `trigger` | `Optional<Trigger>` | No | — | Trigger condition. Absent on terminal phase. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

> **Note on `state` type:** `state` uses `Value` to permit deserialization of structurally invalid documents for diagnostic reporting. The format specification and JSON Schema constrain `state` to an object; validation ([§3.2](/sdk/entry-points/#32-validate)) rejects non-object values.

## 2.7a Action

An entry action executed when a phase begins. Exactly one action key MUST be present per action object. The v0.1 specification defines three known actions; protocol bindings MAY define additional actions.

**Known actions (v0.1):**

| Key | Required Fields | Description |
|---|---|---|
| `send` | `method: String` | Send a protocol message (notification or request). `method` is the protocol method name; optional `params: Value` carries protocol-native message parameters (pass-through). Entry actions execute before client interaction, so notifications are the primary use case. |
| `log` | `message: String` | Emit a log message. `message` supports `{{template}}` interpolation. Optional `level: LogLevel`. |

**Associated enums:**

| Enumeration | Values |
|---|---|
| `LogLevel` | `info`, `warn`, `error` |

**Binding-specific actions:** Action objects MAY contain a single key not in the known set above (e.g., `delay_ms: 500`, `send_ui_event: {...}`). The value type is unconstrained: it may be an object, string, number, or any JSON value. SDKs MUST preserve unrecognized action keys through parse → normalize → serialize round-trips. When evaluating, SDKs SHOULD skip actions they do not recognize and emit a warning diagnostic.

**Extension fields:** Each action object MAY include `x-` prefixed keys alongside the action key. Extension fields are preserved but do not affect action execution.

## 2.8 Trigger

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `event` | `Optional<String>` | No | — | Protocol event to match. |
| `count` | `Optional<Integer>` | No | `1` (when `event` present) | Number of matching events required. |
| `match` | `Optional<MatchPredicate>` | No | — | Content predicate on matching events. |
| `after` | `Optional<Duration>` | No | — | Unconditional time-based advancement. |

## 2.8a ProtocolEvent

Represents a protocol-level event observed during execution. Used by `evaluate_trigger` ([§5.8](/sdk/execution-primitives/#58-evaluate_trigger)) to match against trigger conditions.

| Field | Type | Required | Description |
|---|---|---|---|
| `event_type` | `String` | Yes | The event type (e.g., `tools/call`, `message/send`, `run_started`). |
| `content` | `Value` | Yes | The event payload. Evaluated against `trigger.match` predicates via `evaluate_predicate`. |

## 2.8b TriggerResult

Returned by `evaluate_trigger` ([§5.8](/sdk/execution-primitives/#58-evaluate_trigger)) to indicate whether a phase should advance.

| Variant | Fields | Description |
|---|---|---|
| `Advanced` | `reason: AdvanceReason` | The trigger condition is satisfied; advance to the next phase. |
| `NotAdvanced` | — | The trigger condition is not yet satisfied; remain in the current phase. |

`AdvanceReason` is one of: `event_matched` (the required number of matching events was reached), `timeout` (the `after` duration elapsed).

## 2.8c TriggerState

Mutable state tracked per-actor-per-phase for trigger evaluation. The runtime creates a fresh `TriggerState` when an actor enters a phase and passes it to every `evaluate_trigger` call for that phase. The function updates the state internally; the caller persists it across calls but does not inspect or modify its fields.

| Field | Type | Default | Description |
|---|---|---|---|
| `event_count` | `Integer` | `0` | Number of fully-matched events observed so far in this phase. Initialized to `0` on phase entry; incremented by `evaluate_trigger` ([§5.8](/sdk/execution-primitives/#58-evaluate_trigger)) when base event and predicate match. |

## 2.9 Extractor

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | `String` | Yes | Variable name for interpolation. Must match `[a-z][a-z0-9_]*`. |
| `source` | `ExtractorSource` | Yes | `request` or `response`. |
| `type` | `ExtractorType` | Yes | `json_path` or `regex`. |
| `selector` | `String` | Yes | The extraction selector. |

## 2.10 MatchPredicate

A match predicate is a map from dot-path field references to conditions. All entries are combined with AND logic. Each entry maps a simple dot-path string ([§5.1.1](/sdk/execution-primitives/#511-simple-dot-path)) to either a scalar value (equality check) or a `MatchCondition` object.

```
type MatchPredicate = Map<String, MatchEntry>
```

Where `MatchEntry` is either:
- A scalar `Value` (equality comparison), or
- A `MatchCondition` object.

This is a type alias, not a struct. In YAML, predicates are written as flat mappings (e.g., `{arguments.command: "ls", headers.x-api-key: "secret"}`). The SDK MUST parse them directly as maps without introducing an intermediate `entries` key. Languages without algebraic types may represent `MatchEntry` as a tagged union or untyped `Value` with runtime type checking.

## 2.11 MatchCondition

A condition applied to a resolved field value. At least one operator MUST be present. When multiple operators are present, they are combined with AND logic, so the value must satisfy every operator for the condition to match. For example, `{contains: "secret", regex: "key_[0-9]+"}` matches only if both conditions are satisfied.

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

## 2.12 Indicator

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | `Optional<String>` | No | Auto-generated (see N-003) | Unique indicator identifier. Always present after normalization. |
| `protocol` | `Optional<String>` | No | Protocol component of `execution.mode` | Protocol this indicator targets. Required when `execution.mode` is absent. |
| `surface` | `Optional<Surface>` | No | — | Protocol operation name scoping this indicator. Optional. |
| `target` | `String` | Yes | — | Dot-path into the protocol message to examine. Supports wildcards. |
| `actor` | `Optional<String>` | No | — | References an actor by name. When present, evaluates only against that actor's traffic. |
| `direction` | `Optional<Direction>` | No | — | Restricts which side examined: `request` or `response`. When omitted, tool selects applicable messages; v0.1 does not define inference. |
| `method` | `Optional<IndicatorMethod>` | No | — | Explicit evaluation method: `pattern`, `expression`, or `semantic`. Inferred from which field is present when omitted. |
| `description` | `Optional<String>` | No | — | What this indicator evaluates. |
| `pattern` | `Optional<PatternMatch>` | No | — | Pattern evaluation definition. Exactly one of `pattern`, `expression`, `semantic` required. |
| `expression` | `Optional<ExpressionMatch>` | No | — | CEL evaluation definition. |
| `semantic` | `Optional<SemanticMatch>` | No | — | Semantic evaluation definition. |
| `confidence` | `Optional<Integer>` | No | — | Indicator-specific confidence override. |
| `severity` | `Optional<SeverityLevel>` | No | — | Indicator-specific severity override. |
| `false_positives` | `Optional<List<String>>` | No | — | Known false positive scenarios. |
| `extensions` | `Optional<Map<String, Value>>` | No | — | Extension fields (`x-` prefixed). Preserved through round-trips. |

## 2.13 PatternMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | — | Override for the indicator-level target. When present, takes precedence for this pattern evaluation. |
| `condition` | `Optional<Condition>` | No | — | Absent in shorthand form. Always present after normalization. |

A `Condition` is either:
- A bare `Value` (string, number, boolean, array, null) for equality matching, or
- A `MatchCondition` object containing one or more operator keys.

Languages without algebraic types may represent `Condition` as an untyped `Value` with runtime type checking: if it's an object with operator keys, treat as `MatchCondition`; otherwise treat as equality.

The YAML representation supports two forms:

- **Standard form:** `target` + `condition` (both explicit). `condition` may be a bare value (e.g., `condition: "ls"`) or an operator object (e.g., `condition: {contains: "ls"}`).
- **Shorthand form:** a single condition operator as a direct key (e.g., `contains: "foo"`). No `condition` wrapper.

Normalization (N-005): When a `PatternMatch` is parsed in shorthand form, the SDK MUST expand it to standard form with an explicit `condition` field (as a `MatchCondition` object). The indicator-level `target` provides the evaluation path; `pattern.target` overrides it when present. Bare-value conditions in standard form are preserved as-is (not wrapped in an operator object).

## 2.14 ExpressionMatch

| Field | Type | Required | Description |
|---|---|---|---|
| `cel` | `String` | Yes | CEL expression evaluating to boolean. |
| `variables` | `Optional<Map<String, String>>` | No | Named variables as dot-paths into message. Keys must be valid CEL identifiers (`[_a-zA-Z][_a-zA-Z0-9]*`). |

## 2.15 SemanticMatch

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `target` | `Optional<String>` | No | — | Override for the indicator-level target. When present, takes precedence for this semantic evaluation. |
| `intent` | `String` | Yes | — | Natural-language intent description. |
| `intent_class` | `Optional<SemanticIntentClass>` | No | — | Intent category hint for classification engines. |
| `threshold` | `Optional<Float>` | No | — | Similarity/confidence threshold, 0.0–1.0. |
| `examples` | `Optional<SemanticExamples>` | No | — | Positive and negative examples. |

## 2.16 SemanticExamples

| Field | Type | Required | Description |
|---|---|---|---|
| `positive` | `Optional<List<String>>` | No | Strings that SHOULD trigger the indicator. |
| `negative` | `Optional<List<String>>` | No | Strings that SHOULD NOT trigger the indicator. |

When `examples` is present, at least one of `positive` or `negative` MUST be provided (the JSON Schema enforces this via `minProperties: 1`). Documents with `semantic` indicators SHOULD include at least two positive and two negative examples to enable cross-tool calibration ([format specification §6.4](/specification/indicators/#64-semantic-analysis)).

## 2.17 Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `url` | `String` | Yes | URL of the external reference. |
| `title` | `Optional<String>` | No | Human-readable title. |
| `description` | `Optional<String>` | No | Brief description of the reference. |

## 2.18 FrameworkMapping

| Field | Type | Required | Description |
|---|---|---|---|
| `framework` | `Framework` | Yes | The external framework being referenced. |
| `id` | `String` | Yes | Identifier of the specific entry within the framework. |
| `name` | `Optional<String>` | No | Human-readable name of the referenced entry. |
| `url` | `Optional<String>` | No | Permalink to the referenced entry. |
| `relationship` | `Optional<Relationship>` | No | `primary` (default) or `related`. |

## 2.19 Verdict Types

### IndicatorVerdict

| Field | Type | Required | Description |
|---|---|---|---|
| `indicator_id` | `String` | Yes | The indicator that produced this verdict. |
| `result` | `IndicatorResult` | Yes | One of: `matched`, `not_matched`, `error`, `skipped`. |
| `timestamp` | `Optional<DateTime>` | No | When the verdict was produced. |
| `evidence` | `Optional<String>` | No | The matched content or error diagnostic. |
| `source` | `Optional<String>` | No | The tool or engine that produced the verdict. Populated by the consuming tool, not by SDK evaluation functions. |

### AttackVerdict

| Field | Type | Required | Description |
|---|---|---|---|
| `attack_id` | `Optional<String>` | No | The attack that was evaluated. Absent when the document has no `attack.id`. |
| `result` | `AttackResult` | Yes | One of: `exploited`, `not_exploited`, `partial`, `error`. |
| `indicator_verdicts` | `List<IndicatorVerdict>` | Yes | All individual indicator results. |
| `evaluation_summary` | `EvaluationSummary` | Yes | Counts of each indicator result. Prevents `skipped → not_matched` aggregation from masking evaluation gaps. |
| `timestamp` | `Optional<DateTime>` | No | When the verdict was produced. |
| `source` | `Optional<String>` | No | The tool or engine that produced the verdict. Populated by the consuming tool, not by SDK evaluation functions. |

### EvaluationSummary

| Field | Type | Required | Description |
|---|---|---|---|
| `matched` | `Integer` | Yes | Number of indicators that produced `matched`. |
| `not_matched` | `Integer` | Yes | Number of indicators that produced `not_matched`. |
| `error` | `Integer` | Yes | Number of indicators that produced `error`. |
| `skipped` | `Integer` | Yes | Number of indicators that produced `skipped`. |

## 2.20 Enumerations

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
| `Surface` | Open string. Values are protocol operation names (e.g., `tools/call`, `agent_card/get`). See [§2.21](/sdk/core-types/#221-surface-model). |
| `Direction` | `request`, `response` |
| `IndicatorMethod` | `pattern`, `expression`, `semantic` |
| `AdvanceReason` | `event_matched`, `timeout` |

**Open vs closed enums:** `Protocol`, `Mode`, `Surface` ([§2.21](/sdk/core-types/#221-surface-model)), and `Framework` are open strings: unknown values are accepted (with optional warnings for unrecognized bindings, per [§3.2](/sdk/entry-points/#32-validate)). All other enumerations in this table are closed: unknown values MUST be rejected during parsing (`ParseError` with `kind: unknown_variant`). This distinction ensures extensibility for protocol bindings and framework mappings while maintaining strict validation for lifecycle, verdict, and structural enums.

## 2.21 Surface Model

In the v0.1 binding model, `surface` is an optional indicator field that references a protocol operation name (e.g., `tools/call`, `agent_card/get`, `run_agent_input`). The `target` field (required on every indicator) provides the explicit dot-path into the protocol message.

SDKs do not need a compile-time surface registry for target resolution. Surface values, when present, are used for scoping (limiting which protocol traffic the indicator evaluates against) and for documentation. SDKs SHOULD validate surface values against the protocol's known operation names for recognized bindings and emit warnings for unrecognized values.

## 2.22 Event-Mode Validity

For recognized modes (v0.1: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`), SDKs SHOULD maintain awareness of which event types are defined by each binding's Events section. When a trigger references an event type not listed for the actor's mode, SDKs SHOULD emit a warning. SDKs MUST NOT reject documents based on event-mode validity; upstream protocols may define events beyond the subset covered by this OATF version. For unrecognized modes, SDKs MUST skip event validation entirely.

The complete event-mode mapping is defined in each binding's Events section (§7.1.2, §7.2.2, §7.3.2).

## 2.23 SynthesizeBlock (Reserved)

Reserved for a future version. The `SynthesizeBlock` type appears in binding state schemas as a placeholder for LLM-powered response generation. It has no normative semantics in v0.1. See [future-work §F.5](/reference/future-work/#f5-llm-synthesis) for the planned design.

| Field | Type | Required | Description |
|---|---|---|---|
| `prompt` | `String` | No | Free-text prompt for the LLM. Supports `{{template}}` interpolation. |

## 2.24 ResponseEntry

A conditional response entry used for binding-specific response dispatch. Appears in MCP tool/prompt `responses`, MCP client `sampling_responses`/`elicitation_responses`, A2A `task_responses`, and AG-UI `tool_responses`.

| Field | Type | Required | Description |
|---|---|---|---|
| `when` | `Optional<MatchPredicate>` | No | Predicate evaluated against the incoming request or binding-defined triggering event payload. Absent on the default (fallback) entry. |
| `content` | `Optional<Value>` | No | Protocol-native response content (pass-through). |
| `synthesize` | `Optional<SynthesizeBlock>` | No | Reserved for a future version. |

Static content fields are protocol-binding-specific: see the individual binding pages (§7.1–§7.3) for the complete structure of each binding's response entries.


