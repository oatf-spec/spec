---
title: "Execution Primitives"
description: "Shared utility operations: path resolution, duration parsing, condition evaluation, template interpolation, and trigger evaluation."
---

Shared utility operations used by both entry points and evaluation. SDKs MUST implement these and SHOULD expose them in the public API for use by consuming tools.

## 5.1 Path Resolution

OATF defines two path variants with different capabilities, matching the format specification ([§5.4](/specification/execution-profile/#54-match-predicates)):

### 5.1.1 Simple Dot-Path

Used for: `MatchPredicate` keys ([§2.10](/sdk/core-types/#210-matchpredicate)), `{{request.*}}` and `{{response.*}}` template references ([§5.5](/sdk/execution-primitives/#55-interpolate_template)), `expression.variables` values ([§2.14](/sdk/core-types/#214-expressionmatch)).

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

### 5.1.2 Wildcard Dot-Path

Used for: `pattern.target` ([§2.13](/sdk/core-types/#213-patternmatch)), `semantic.target` ([§2.15](/sdk/core-types/#215-semanticmatch)).

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

Segments consist of alphanumeric characters, underscores, and hyphens, with optional `[*]` suffix. Numeric indexing (`[0]`, `[1]`) is not supported; use CEL expressions for positional access.

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

**Limitation:** Dot-path syntax does not support escaping literal dots within field names. A JSON object key containing a dot (for example, `{"content.type": "text"}`) cannot be addressed because the path `content.type` is always interpreted as two segments. This is an intentional simplification; protocol messages in MCP, A2A, and AG-UI do not use dotted key names. Authors MUST use CEL expressions ([format specification §6.3](/specification/indicators/#63-expression-evaluation)) to match fields with dots, brackets, or other special characters in their names.

## 5.2 parse_duration

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

## 5.3 evaluate_condition

```
evaluate_condition(condition: Condition, value: Value) → Boolean
```

Evaluates a condition against a resolved value. If `condition` is a bare value (string, number, boolean, array), performs deep equality comparison. If `condition` is a `MatchCondition` object, evaluates each present operator. When multiple operators are present, all must match (AND logic). Returns `true` only if every present operator is satisfied.

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
| `exists` | Boolean | See [§5.4](/sdk/execution-primitives/#54-evaluate_predicate). `exists` is evaluated during predicate resolution, not by `evaluate_condition`. |
| *(equality)* | Any | `value` equals the operand (deep equality). Used when the MatchEntry is a scalar, not a MatchCondition. |

**Type mismatches:** If the operator requires a specific value type (string operators on non-string, numeric operators on non-number), the condition evaluates to `false`. Type mismatches are not errors.

**Deep equality:** The `any_of` and scalar equality operators use deep equality with the following rules: numeric values compare by mathematical value (integer `42` equals float `42.0`); object key order is irrelevant; NaN is not equal to any value including itself; null equals only null; arrays compare element-wise by position and length.

**Regex:** Patterns MUST be compiled with RE2 semantics (linear-time guarantee). SDKs MUST reject patterns with features outside the RE2 subset during `validate`. The regex is evaluated as a **partial match**: the pattern may match any substring of the value. To require a full-string match, the pattern MUST include `^` and `$` anchors. This matches the default behavior of RE2 libraries across languages (Go's `regexp.MatchString`, Rust's `regex::Regex::is_match`, Python's `re2.search`).

**The `exists` operator:** Unlike all other operators, `exists` does not inspect the resolved value; it inspects whether resolution succeeded. `exists` is evaluated during `evaluate_predicate` ([§5.4](/sdk/execution-primitives/#54-evaluate_predicate)) at the path-resolution step, before `evaluate_condition` is called. When `exists` is the only operator in a MatchCondition, `evaluate_condition` is not called at all (for `exists: true`, the path having resolved is sufficient; for `exists: false`, the path not having resolved is sufficient). When `exists` is combined with other operators, `exists: true` is redundant (all other operators already require a resolved value), and `exists: false` combined with any value-inspecting operator is always false (there is no value to inspect). These are natural consequences of AND logic, not special cases.

## 5.4 evaluate_predicate

```
evaluate_predicate(predicate: MatchPredicate, value: Value) → Boolean
```

Evaluates a match predicate (a set of dot-path → condition entries) against a value. All entries are combined with AND logic.

**Behavior:**

1. For each entry `(path, condition)` in the predicate map:
   a. Resolve the dot-path key against `value` using `resolve_simple_path` ([§5.1.1](/sdk/execution-primitives/#511-simple-dot-path)).
   b. If the path does not resolve (returns nothing):
      - If `condition` is a `MatchCondition` with `exists: false` (and no other operators), the entry evaluates to `true`.
      - Otherwise, the entry evaluates to `false`.
   c. If the path resolves to a value:
      - If `condition` is a `MatchCondition` with `exists: false`, the entry evaluates to `false` (regardless of other operators, since AND with a false `exists` is false).
      - Otherwise, evaluate the remaining condition operators against the resolved value. The entry is `true` if the value satisfies the condition.
2. Return `true` if all entries are `true`. Return `false` if any entry is `false`.

## 5.5 interpolate_template

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

The `extractors` map is populated by the calling runtime with both local names (unqualified, from the current actor) and qualified names (`actor_name.extractor_name`, from all actors). The function itself performs simple key lookup; cross-actor resolution is a runtime responsibility.

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

## 5.5a interpolate_value

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

## 5.6 evaluate_extractor

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

## 5.7 select_response

```
select_response(
    entries: List<ResponseEntry>,
    request: Value
) → Optional<ResponseEntry>
```

Selects the first matching response entry from an ordered list, using `when` predicates for conditional dispatch.

**Behavior:**

1. Iterate `entries` in order.
2. For each entry that has a `when` predicate, evaluate the predicate against `request` using `evaluate_predicate` ([§5.4](/sdk/execution-primitives/#54-evaluate_predicate)). If the predicate matches, return that entry.
3. If no predicate-bearing entry matches and an entry without `when` exists (the default entry), return it.
4. If no entry matches, return `None`.

First-match-wins: the first entry whose `when` predicate matches is returned, regardless of subsequent entries. The default entry (no `when`) is only considered as a fallback after all predicate-bearing entries have been tried.

## 5.8 evaluate_trigger

```
evaluate_trigger(
    trigger: Trigger,
    event: Optional<ProtocolEvent>,
    elapsed: Duration,
    state: TriggerState,
    protocol: String
) → TriggerResult
```

Evaluates whether a trigger condition is satisfied for phase advancement. The function manages event counting internally via the mutable `state` parameter ([§2.8c](/sdk/core-types/#28c-triggerstate)), which the caller persists across calls but does not inspect or modify. The `protocol` argument MUST be the normalized protocol identifier (the output of `extract_protocol(mode)`) corresponding to the registry keys defined in [§2.25](/sdk/core-types/#225-qualifier-resolution-registry) (`mcp`, `a2a`, `ag_ui`); passing an unnormalized or free-form value will cause silent qualifier resolution failures.

**Behavior:**

1. If `trigger.after` is present and `elapsed` ≥ `trigger.after`, return `TriggerResult::Advanced { reason: timeout }`.
2. If `trigger.event` is present and `event` is present:
   a. Parse `trigger.event` via `parse_event_qualifier` ([§5.9](/sdk/execution-primitives/#59-parse_event_qualifier)) to obtain `(trigger_base, trigger_qualifier)`.
   b. **Base match:** If `event.event_type` ≠ `trigger_base`, return `TriggerResult::NotAdvanced`.
   c. **Qualifier match:** If `trigger_qualifier` is present:
      i. Determine the event's qualifier: if `event.qualifier` is present, use that value. Otherwise, call `resolve_event_qualifier(protocol, event.event_type, event.content)` ([§5.9a](/sdk/execution-primitives/#59a-resolve_event_qualifier)) and use its result (which may be `None`).
      ii. If the event's qualifier is `None` or does not equal `trigger_qualifier`, return `TriggerResult::NotAdvanced`.
   d. **Predicate check:** If `trigger.match` is present, evaluate the match predicate against `event.content` using `evaluate_predicate` ([§5.4](/sdk/execution-primitives/#54-evaluate_predicate)). If the predicate does not match, return `TriggerResult::NotAdvanced`.
   e. **Count increment:** Increment `state.event_count` by 1. This increment occurs only after base event, qualifier, and predicate have all passed.
   f. **Count check:** If `state.event_count` ≥ `trigger.count` (resolved, default `1`), return `TriggerResult::Advanced { reason: event_matched }`.
3. Return `TriggerResult::NotAdvanced`.

`TriggerResult` and `AdvanceReason` are defined in [§2.8b](/sdk/core-types/#28b-triggerresult). `TriggerState` is defined in [§2.8c](/sdk/core-types/#28c-triggerstate).

## 5.9 parse_event_qualifier

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

## 5.9a resolve_event_qualifier

```
resolve_event_qualifier(
    protocol: String,
    base_event: String,
    content: Value
) → Optional<String>
```

Resolves the qualifier value from a protocol event's content by looking up the content field path in the Qualifier Resolution Registry ([§2.25](/sdk/core-types/#225-qualifier-resolution-registry)).

**Behavior:**

1. Look up `(protocol, base_event)` in the Qualifier Resolution Registry ([§2.25](/sdk/core-types/#225-qualifier-resolution-registry)).
2. If no entry exists, return `None`. This event type does not support qualifier resolution.
3. Resolve the registered content field path against `content` using `resolve_simple_path` ([§5.1.1](/sdk/execution-primitives/#511-simple-dot-path)).
4. If the path resolves to a value `v`, return a qualifier string: if `v` is a string, return it unchanged; if `v` is a number or boolean, return its canonical JSON encoding (e.g., `42`, `true`); for `null`, arrays, or objects, return `None` (these types are not valid qualifier values).
5. If the path does not resolve, return `None`.

**Examples:**
- `resolve_event_qualifier("mcp", "tools/call", {"params": {"name": "calculator"}})` → `Some("calculator")`
- `resolve_event_qualifier("mcp", "tools/call", {"params": {}})` → `None`
- `resolve_event_qualifier("mcp", "resources/read", {"uri": "file://x"})` → `None` (event not in registry)
- `resolve_event_qualifier("ag_ui", "custom", {"name": "my_event"})` → `Some("my_event")`

## 5.10 extract_protocol

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

## 5.11 compute_effective_state

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


