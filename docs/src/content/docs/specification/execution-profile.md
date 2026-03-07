---
title: "Execution Profile"
description: "Structure, phases, triggers, match predicates, extractors, response templates, and expression evaluation."
---

The execution profile specifies the protocol messages an adversarial tool MUST produce to simulate the attack. It supports three mutually exclusive forms, from simplest to most complex:

## 5.1 Structure

**Single-phase form** (simplest: one endpoint, one state):

```yaml
execution:
  mode: string                    # "{protocol}_{role}" convention
  state: <PhaseState>
```

**Multi-phase form** (one endpoint, multiple stages):

```yaml
execution:
  mode: string?                   # "{protocol}_{role}" convention
  phases: <Phase>[]
```

**Multi-actor form** (concurrent endpoints):

```yaml
execution:
  actors:
    - name: string
      mode: string               # "{protocol}_{role}" convention
      phases: <Phase>[]
```

The three forms are mutually exclusive. A document MUST NOT combine `execution.state` with `execution.phases` or `execution.actors`, nor `execution.phases` with `execution.actors`.

All forms are syntactic sugar over the multi-actor form. Conformant tools MUST normalize documents internally:

- **Single-phase form** normalizes to: `actors: [{ name: "default", mode: <mode>, phases: [{ name: "phase-1", state: <state> }] }]` (see [§11.2](/specification/conformance/#112-tool-conformance-general) item 6).
- **Multi-phase form** normalizes to: `actors: [{ name: "default", mode: <mode>, phases: <phases> }]` (see [§11.2](/specification/conformance/#112-tool-conformance-general) item 7).

### `execution.mode` (CONDITIONAL)

The attacker posture: which protocol the adversarial tool targets and which side of the connection it occupies. Mode values follow the `{protocol}_{role}` convention, where `{protocol}` identifies the agent communication protocol and `{role}` is either `server` or `client`. Mode values MUST match the pattern `[a-z][a-z0-9_]*_(server|client)`.

**Version 0.1 modes** (defined by included protocol bindings):

- `mcp_server`: The tool acts as a malicious MCP server, exposing poisoned tools, resources, or prompts to the agent.
- `mcp_client`: The tool acts as a malicious MCP client, sending crafted requests to an agent that exposes an MCP server interface.
- `a2a_server`: The tool acts as a malicious remote agent, serving a poisoned Agent Card or returning malicious task results.
- `a2a_client`: The tool acts as a malicious client agent, sending crafted tasks to the target agent.
- `ag_ui_client`: The tool acts as a malicious AG-UI client, sending fabricated messages or events to the agent.

Additional modes are defined by protocol bindings ([§7](/specification/protocol-bindings/)). Tools that encounter an unrecognized mode MUST parse the document without error but MAY skip execution for bindings they do not implement.

In single-phase and multi-phase forms, `mode` is REQUIRED when `execution.state` is present, and OPTIONAL when `execution.phases` is present. When present with `phases`, all phases inherit it as their default and all indicators inherit its protocol component (the substring before the last `_server` or `_client`). When omitted, every phase MUST specify its own `phase.mode` and every indicator MUST specify its own `indicator.protocol`. In multi-actor form, `execution.mode` is structurally absent, so indicators MUST always specify `indicator.protocol` explicitly.

### `execution.state` (OPTIONAL, single-phase form only)

The protocol state for a single-phase attack. This is shorthand for a single-element `phases` array with no trigger (a terminal phase). When present, `execution.mode` is REQUIRED and `execution.phases` and `execution.actors` MUST be absent.

### `execution.actors` (OPTIONAL, multi-actor form only)

An array of named actors, each representing a concurrent protocol endpoint. Every actor has its own mode and phase sequence. Actors operate simultaneously and independently; each advances through its own phases based on its own triggers.

#### `actor.name` (REQUIRED)

A unique identifier for this actor within the document. Used in cross-actor extractor references (`{{actor_name.extractor_name}}`). Must match the pattern `[a-z][a-z0-9_]*`.

#### `actor.mode` (REQUIRED)

The attacker posture for this actor. Same `{protocol}_{role}` convention as `execution.mode`. Every actor MUST declare its mode explicitly.

#### `actor.phases` (REQUIRED)

The phase sequence for this actor, structured identically to `execution.phases`. Phase names MUST be unique within the actor but MAY duplicate names in other actors.

### Readiness Semantics

When multiple actors are present, the runtime MUST ensure that all **server-role** actors (modes ending in `_server`) are accepting connections before any **client-role** actor (modes ending in `_client`) begins executing its first phase. This prevents race conditions where a client sends a message before the target server is bound.

An actor is considered ready when its protocol endpoint is bound and accepting connections. The document author does not need to express readiness; it is a runtime guarantee.

## 5.2 Phases

Each phase represents a distinct stage of the attack within an actor. Phases execute in order within their actor. The first phase begins when the actor becomes active (after readiness; see [§5.1](/specification/execution-profile/#51-structure)). Subsequent phases begin when their predecessor's trigger condition is met. In multi-actor documents, each actor advances through its own phases independently.

```yaml
phases:
  - name: string?
    description: string?
    mode: string?     # "{protocol}_{role}" convention. Required when execution.mode is absent
    
    state: <PhaseState>?
    
    extractors: <Extractor>[]?
    
    on_enter: <Action>[]?
    
    trigger: <Trigger>?
```

### `phase.name` (OPTIONAL)

A human-readable label for this phase (for example, `"trust_building"`, `"payload_delivery"`, `"exploit"`). When omitted, tools MUST auto-generate a positional name: `"phase-1"`, `"phase-2"`, etc. (1-based index within the actor's phase list). Explicit names are RECOMMENDED for multi-phase attacks to improve readability.

### `phase.description` (OPTIONAL)

Prose describing the purpose of this phase.

### `phase.mode` (CONDITIONAL)

The attacker posture for this phase. In single-phase and multi-phase forms: when `execution.mode` is present, this defaults to `execution.mode` and is optional; when `execution.mode` is absent, this field is REQUIRED on every phase. In multi-actor form: phases inherit their actor's `mode` and MAY be omitted. It MAY be specified for cross-protocol phases within an actor.

### `phase.state` (CONDITIONAL)

The protocol state the adversarial tool presents during this phase. The structure is protocol-specific and defined in the protocol binding sections ([§7](/specification/protocol-bindings/)). For MCP, this includes the tools, resources, and prompts to expose. For A2A, this includes the Agent Card to present. For AG-UI, this includes the messages or tool results to send.

If omitted, the phase inherits the entire state object from the immediately preceding phase in the same actor (deep copy). If present, it **completely replaces** the inherited state; no merging occurs at any level. Top-level keys (`tools`, `resources`, `prompts`, `capabilities`, etc.) are replaced wholesale. List fields (`tools[]`, `responses[]`, etc.) are replaced entirely. To carry forward part of the previous state while modifying it, authors must explicitly repeat the desired portions in the new `state` object. This full-replacement semantic enables clean rug-pull style attacks where a later phase completely swaps the state established by an earlier phase.

The first phase in the list MUST include `state`.

### `phase.extractors` (OPTIONAL)

Extractors that capture values from protocol messages during this phase. Extracted values are available in all subsequent phases via `{{name}}` template syntax. See §5.5.

### `phase.on_enter` (OPTIONAL)

Actions executed when this phase begins, before any client interaction is processed. Actions are protocol-specific and defined in the protocol binding sections ([§7](/specification/protocol-bindings/)). Common actions include sending notifications and emitting log events.

### `phase.trigger` (OPTIONAL)

The condition that triggers advancement to the next phase. If omitted, this is a **terminal phase** that persists indefinitely. A document MUST have at most one terminal phase, and it MUST be the last phase in the list.

A trigger object MUST specify at least one of `event` or `after`. An empty trigger object is invalid. To designate a terminal phase, omit `trigger` entirely. Tools SHOULD enforce a configurable maximum terminal phase duration (RECOMMENDED default: 5 minutes) to prevent indefinite resource consumption.

## 5.3 Triggers

Triggers define conditions for phase advancement. Trigger events are **per-actor scoped**: a trigger on an actor matches only events observed on that actor's own protocol connection. There is no global event bus and no cross-actor event observation.

An actor's mode determines event direction. Server-mode actors (`mcp_server`, `a2a_server`) observe incoming requests from the agent. Client-mode actors (`mcp_client`, `a2a_client`, `ag_ui_client`) observe incoming responses or streamed events from the agent. The same event name (e.g., `tools/call`) is unambiguous because the actor's mode determines perspective.

```yaml
trigger:
  event: string?
  count: integer?
  match: <MatchPredicate>?
  after: duration?
```

### `trigger.event` (OPTIONAL)

The protocol event type to match. Event names use the protocol's native naming convention: MCP and A2A use slash-separated JSON-RPC method names; AG-UI uses `snake_case` derived from its EventType enum. Non-RPC HTTP endpoints use an `entity/verb` pattern (e.g., `agent_card/get`). The full event vocabulary is defined per-mode in the protocol binding sections ([§7](/specification/protocol-bindings/)).

Event types MAY include a colon-separated **qualifier** for filtering: `tools/call:calculator` matches only `tools/call` events where the tool name is `calculator`. Qualifiers are restricted to simple identifier tokens (names, states). The event type is split at the first colon: everything before is the event name, everything after is the qualifier token. Values containing colons, slashes, or other structural characters (such as URIs) MUST use `trigger.match` instead. Qualifier resolution rules are defined per-protocol in §7.

A trigger's event type MUST be valid for the actor's resolved mode. An event type not listed in the validity matrix for the actor's mode is a validation error (see [§7](/specification/protocol-bindings/) Event-Mode Validity Matrix).

### `trigger.count` (OPTIONAL)

The number of matching events required before advancing. When omitted and `event` is specified, treated as `1` at evaluation time. The counter accumulates matching events for this actor within the current phase. The counter resets to zero when the actor transitions into a new phase. For the initial phase, the counter starts at zero when the actor becomes active.

### `trigger.match` (OPTIONAL)

A predicate evaluated against the **content root** of matching events. The content root depends on the actor's mode and event direction:

- **Server-mode request events**: the JSON-RPC `params` object (e.g., for `tools/call` on `mcp_server`, the root contains `name`, `arguments`).
- **Client-mode response events**: the JSON-RPC `result` object (e.g., for `tools/call` on `mcp_client`, the root contains `content[]`, `isError`).
- **Notification events**: the notification's `params` object.
- **AG-UI events**: the SSE event object (e.g., for `tool_call_start`, the root contains `toolCallName`, `toolCallId`).

This content root is the same object exposed to CEL context in indicator evaluation ([§7](/specification/protocol-bindings/)), ensuring field paths are consistent between trigger predicates and indicator expressions.

The phase advances only when an event matches both the event type (`event`) and the content predicate. See [§5.4](/specification/execution-profile/#54-match-predicates) for predicate syntax.

### `trigger.after` (OPTIONAL)

A duration after which the phase advances unconditionally, measured from phase entry. Format: ISO 8601 duration (e.g., `"PT30S"`, `"PT5M"`) or shorthand with units `s` (seconds), `m` (minutes), `h` (hours), `d` (days), for example, `"30s"`, `"5m"`, `"1h"`, `"2d"`.

When both `event` and `after` are specified, the phase advances when either the required number of matching events is reached or the `after` duration elapses, whichever comes first.

The `count` and `match` fields are only meaningful in combination with `event` and MUST NOT appear without it. A trigger with `count` or `match` but no `event` is invalid and MUST be rejected during validation.

## 5.4 Match Predicates

Match predicates evaluate structured conditions against protocol message content. A MatchPredicate is a mapping from field paths to conditions. It appears as the *value* of `trigger.match` and `when` fields; the key (`match:` or `when:`) is part of the parent object, not part of the predicate itself.

```yaml
# As it appears in a trigger:
trigger:
  event: tools/call
  match:                           # ← parent key
    arguments.command: "ls"        # ← MatchPredicate starts here

# As it appears in a response entry:
responses:
  - when:                          # ← parent key
      arguments.command: "ls"      # ← MatchPredicate starts here
    content: [...]
```

**Predicate grammar.** Each entry in the mapping is a field path paired with a condition:

```yaml
field.path: value                  # Equality
field.path:
  contains: string                 # Substring match
  starts_with: string              # Prefix match
  ends_with: string                # Suffix match
  regex: string                    # Regular expression
  any_of: value[]                  # Any of listed values
  gt: number                       # Greater than
  lt: number                       # Less than
  gte: number                      # Greater than or equal
  lte: number                      # Less than or equal
  exists: boolean                  # Field presence check
```

The `regex` operator performs a **partial match** (substring search): the pattern succeeds if it matches anywhere within the target string. To anchor a match to the full string, use `^` and `$` anchors explicitly. This is consistent with RE2's default behavior across languages (see Sandboxing and Resource Limits in [§5.7](/specification/execution-profile/#57-expression-evaluation) for RE2 constraints).

Field paths use dot notation for nested access (for example, `arguments.command`, `metadata.agent_id`). OATF defines two dot-path variants:

**Simple dot-path** (used in match predicates [§5.4](/specification/execution-profile/#54-match-predicates) and `{{request.*}}`/`{{response.*}}` templates [§5.6](/specification/execution-profile/#56-response-templates)):

```
simple-path  = segment *( "." segment )
segment      = 1*( ALPHA / DIGIT / "_" / "-" )
```

Simple paths resolve one field at a time through nested objects. No wildcard (`[*]`) or numeric index (`[0]`) support. Resolution of a simple path against a value proceeds left to right: if any segment encounters a non-object, a missing key, or an array, resolution fails and the path produces no value (evaluates to false in predicates, empty string in templates).

**Wildcard dot-path** (used in `pattern.target` [§6.2](/specification/indicators/#62-pattern-matching) and `semantic.target` [§6.4](/specification/indicators/#64-semantic-analysis)):

```
wildcard-path = wsegment *( "." wsegment )
wsegment      = segment / segment "[*]"
segment       = 1*( ALPHA / DIGIT / "_" / "-" )
```

Wildcard paths extend simple paths with `[*]` array traversal. When `[*]` is applied to an array, it expands to every element; the condition matches if **any** element satisfies it (OR semantics). When `[*]` is applied to a non-array value, it produces no match (not an error). Numeric indexing (`[0]`, `[1]`) is not supported; use CEL expressions ([§6.3](/specification/indicators/#63-expression-evaluation)) for positional access.

**Common rules for both variants:**

- JSON keys containing `.`, `[`, or `]` are not addressable via dot-path syntax. Authors MUST use CEL expressions ([§6.3](/specification/indicators/#63-expression-evaluation)) to match fields with these characters in their names.
- Missing intermediate keys produce no value (never an error).
- Type mismatches (e.g., traversing into a string or number) produce no value.
- The empty string `""` is a valid path that selects the root value (the entire message object). This is the canonical form for surfaces that target the root, such as A2A `agent_card`.

All conditions within a match predicate are combined with AND logic. Every condition must match for the predicate to succeed.

Missing fields never match, except when the condition is `exists: false`, which matches precisely when the field is absent. The `exists` operator checks field presence independent of value: `exists: true` matches if the dot-path resolves to any value (including `null`), `exists: false` matches if the dot-path does not resolve.

All string operators (`contains`, `starts_with`, `ends_with`, `any_of`, and equality) are case-sensitive. Case-insensitive matching is available via the `regex` operator with inline flags (e.g., `regex: "(?i)error"`).

**Comparison semantics.** Equality comparisons (bare-value matching and `any_of`) use deep equality: numeric values compare by mathematical value (integer `42` equals float `42.0`); object key order is irrelevant; arrays compare element-wise by position and length; `null` equals only `null`; NaN does not equal any value including itself.

**Type coercion for string operators.** When a string operator (`contains`, `starts_with`, `ends_with`, `regex`) encounters a non-string value (object, array, number, boolean, or null), the value is first serialized to its compact JSON representation (no extra whitespace, keys sorted lexicographically), and the operator is applied to the resulting string. For example, `regex: "account"` applied to the object `{"account": "attacker-123"}` matches because the compact JSON `{"account":"attacker-123"}` contains the substring `account`. This coercion ensures that string operators work intuitively on structured values such as tool arguments.

Numeric operators (`gt`, `lt`, `gte`, `lte`) applied to non-numeric values produce `false`. Equality comparison is strict and type-aware: integer `42` does not equal string `"42"`, but integer `42` equals float `42.0`.

## 5.5 Extractors

Extractors capture values from protocol messages for use in subsequent phases or in dynamic response content. Extractors are defined within a phase (see [§5.2](/specification/execution-profile/#52-phases)) and apply to messages observed during that phase.

```yaml
extractors:
  - name: string
    source: enum(request, response)
    type: enum(json_path, regex)
    selector: string
```

### `extractor.name` (REQUIRED)

The variable name. The name MUST match the pattern `[a-z][a-z0-9_]*`. Extracted values are referenced in subsequent phases and response templates as `{{variable_name}}`. In multi-actor documents, extractors are scoped per-actor by default, so `{{name}}` resolves to the current actor's extractor. To reference an extractor from a different actor, use the qualified syntax `{{actor_name.extractor_name}}`.

### `extractor.source` (REQUIRED)

Whether to extract from incoming requests or outgoing responses. The terms `request` and `response` refer to **protocol-level roles**, not network direction. A `tools/call` request is always a request regardless of whether the adversarial tool is the server receiving it or the client sending it. In server-mode actors, `request` is the message the agent sends to the tool (e.g., `tools/call` arguments) and `response` is what the tool sends back. In client-mode actors, `request` is the message the tool sends to the agent (e.g., `RunAgentInput`) and `response` is what the agent returns. The same convention applies to `{{request.field.path}}` templates ([§5.6](/specification/execution-profile/#56-response-templates)): the reference resolves to the protocol request message of the request-response pair currently being processed.

### `extractor.type` (REQUIRED)

The extraction method:

- `json_path`: A JSONPath expression conforming to [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535) evaluated against the message body. When the expression matches multiple nodes, the **first node** in document order is extracted. When the expression matches no nodes, the extractor produces no value (absent). An absent extractor resolves to empty string during template interpolation.
- `regex`: A regular expression with a capture group. The **first match** in the input string is used, and the first capture group's value from that match is extracted. When the regex does not match, the extractor produces no value (absent). An absent extractor resolves to empty string during template interpolation.

### `extractor.selector` (REQUIRED)

The extraction selector, interpreted according to `type`.

Extracted values are available in all subsequent phases via `{{name}}` template syntax in string fields within `state` and `on_enter`. Within the phase where the extractor is defined, the value becomes available immediately after the message that triggered the extraction, so subsequent messages processed in the same phase can use it. Values are strings; consuming fields are responsible for type coercion. When an extractor captures a non-scalar value (an object or array), the value MUST be serialized to its compact JSON string representation for template interpolation. If a later phase defines an extractor with the same name as an earlier phase, the new value overwrites the previous one for all subsequent phases (last-write-wins).

## 5.6 Response Templates

String fields within `phase.state` and `phase.on_enter` support template interpolation. Template expressions in `phase.state` are resolved lazily when the state is consumed to construct a protocol response, not at phase entry. This allows `{{request.*}}` and `{{response.*}}` references in tool descriptions and response content to resolve against the actual request/response being processed. Template expressions in `phase.on_enter` actions are resolved eagerly at phase entry time, before any protocol messages are processed. Cross-actor extractor references (`{{actor_name.extractor_name}}`) in both contexts resolve against the referenced actor's current extractor values at the time of resolution.

- `{{extractor_name}}`: Replaced with the value captured by the named extractor (current actor scope).
- `{{actor_name.extractor_name}}`: Replaced with the value captured by a named extractor from a different actor. The actor name MUST match an `actor.name` in the document.
- `{{request.field.path}}`: Replaced with a value from the current incoming request, using dot notation.
- `{{response.field.path}}`: Replaced with a value from the current outgoing response, using dot notation.

Template expressions that reference undefined extractors or missing request or response fields MUST be replaced with an empty string. Tools SHOULD emit a warning when this occurs. To include a literal `{{` in a payload without triggering interpolation, escape it as `\{{`. For example, `\{{name}}` produces the literal string `{{name}}`. The escape applies only to the opening `\{{`; no escape chaining is defined.

## 5.7 Expression Evaluation

OATF documents use five expression systems across execution profiles and indicators: template interpolation ([§5.6](/specification/execution-profile/#56-response-templates)), match predicates ([§5.4](/specification/execution-profile/#54-match-predicates)), CEL expressions ([§6.3](/specification/indicators/#63-expression-evaluation)), JSONPath ([RFC 9535](https://www.rfc-editor.org/rfc/rfc9535), in extractors, [§5.5](/specification/execution-profile/#55-extractors)), and regular expressions (in extractors and pattern conditions). This section defines how these systems interact, how errors are handled, and what execution constraints tools MUST enforce.

### Evaluation Order

Expression systems are evaluated in a fixed order within any single processing step:

1. **Template interpolation** resolves first. All `{{extractor_name}}`, `{{request.field.path}}`, and `{{response.field.path}}` references in string fields are replaced with their values (or empty strings for undefined references) before any further evaluation.
2. **JSONPath expressions** in extractors evaluate against the resolved message to capture values.
3. **Match predicates** evaluate against the resolved message content. Each field-path is resolved, then each condition operator is applied to the resolved value.
4. **CEL expressions** evaluate last. When `expression.variables` is present, the variable values are extracted from the message via dot-path resolution before the CEL expression is evaluated.

Regular expressions are not a separate evaluation phase. They are operators within match predicates (`condition.regex`) and extractors (`type: regex`), evaluated inline during steps 2 and 3.

### Error Handling

Expression errors fall into two categories:

**Document validation errors** are detected at parse time, before any execution or evaluation begins. A conforming tool MUST reject documents containing these errors:

- Syntactically invalid regular expressions.
- Syntactically invalid CEL expressions (parse failure).
- Syntactically invalid JSONPath expressions.
- Template references using invalid syntax (e.g., unclosed `{{`).

**Runtime evaluation errors** occur during execution or indicator evaluation when a structurally valid expression encounters unexpected data. These MUST NOT cause tool failure. Instead:

- A match predicate referencing a field path that does not exist in the message evaluates to `false` (as defined in [§5.4](/specification/execution-profile/#54-match-predicates)).
- A CEL expression that references a missing field, produces a type error, or divides by zero produces an indicator verdict of `error` (not `matched`) with a diagnostic message. The expression does not count as a match for correlation purposes.
- A JSONPath expression that matches no nodes produces an empty extraction (no value captured).
- A regular expression that does not match produces an empty extraction (no capture group value).

Tools SHOULD log runtime evaluation errors at a diagnostic level to aid debugging without disrupting operation.

### Sandboxing and Resource Limits

CEL expressions MUST be evaluated in a sandboxed environment. Specifically:

- CEL evaluation MUST NOT produce side effects (no I/O, no mutation of state, no network access).
- Tools SHOULD enforce an evaluation timeout on CEL expressions. The specific timeout value is a tool configuration concern, but 100 milliseconds per expression is a RECOMMENDED baseline for interactive use.
- Regular expressions MUST be evaluated with protections against catastrophic backtracking. Tools SHOULD use RE2-compatible engines or enforce match time limits. All regex patterns in OATF documents MUST conform to the RE2 syntax subset (no lookarounds, no backreferences, no possessive quantifiers) to guarantee linear-time evaluation and cross-language portability.
- JSONPath evaluation MUST NOT follow recursive descent unboundedly. Tools SHOULD enforce a maximum traversal depth.

These constraints ensure that OATF documents cannot be weaponized against the tools that consume them. A malicious OATF document with a pathological regex or an infinitely-recursive JSONPath expression must fail safely rather than deny service to the evaluating tool.

> *Note on RE2 and lookarounds:* The RE2 subset excludes lookaheads and lookbehinds. OATF evaluators process attacker-controlled content, so ReDoS is a direct risk. Lookaround use cases can be expressed as multiple `match` predicate entries or as CEL expressions.

