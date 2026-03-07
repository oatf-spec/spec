---
title: "Entry Points"
description: "Public SDK operations: parse, validate, normalize, serialize, and load."
---

These are the public operations every SDK MUST expose. Each entry point is described as a function signature with named parameters, return types, and behavioral contracts.

## 3.1 parse

```
parse(input: String) → Result<Document, List<ParseError>>
```

Parses a YAML string into an unvalidated document model. This operation performs YAML deserialization and type mapping only. It does NOT validate document conformance or apply normalization.

**Preconditions:** `input` is a UTF-8 string.

**Behavior:**

1. Deserialize `input` as YAML 1.2.
2. Map YAML nodes to the core types defined in [§2](/sdk/core-types/).
3. Preserve all fields, including unknown fields prefixed with `x-` (extensions).
4. Return the typed document on success.
5. On failure, return at least one `ParseError` value identifying the location and nature of a deserialization problem. SDKs SHOULD attempt to report multiple errors where feasible, but MAY stop at the first fatal error.

Most language deserialization frameworks (serde in Rust, Jackson in Java, encoding/json in Go) fail fast on the first type error or syntax violation. Requiring multiple error collection would prevent SDKs from using derive-based deserialization, which is the dominant approach in most ecosystems. Multi-error reporting is deferred to `validate`, which operates on the successfully parsed document model and can check all semantic rules independently.

**Error conditions:**

- Invalid YAML syntax → `ParseError` with `kind: syntax`.
- Type mismatch (for example, `severity.confidence` is a string instead of integer) → `ParseError` with `kind: type_mismatch`.
- Unknown enum value → `ParseError` with `kind: unknown_variant`.

`parse` MUST NOT reject documents based on semantic constraints (conditional field requirements, duplicate IDs, invalid cross-references). Those are `validate`'s responsibility. Fields marked `Required: Yes` in [§2](/sdk/core-types/) produce a `ParseError` with `kind: type_mismatch` when absent, since deserialization into the target type requires their presence. Constraints that depend on document context (e.g., `phase.mode` required only when `execution.mode` is absent, first phase must include `state`) are `validate`'s responsibility. The separation allows tools to parse a partial document for editing or introspection without requiring full validity.

## 3.2 validate

```
validate(document: Document) → ValidationResult
```

Validates a parsed document against the conformance rules of OATF [format specification §11.1](/specification/conformance/#111-document-conformance). Returns a `ValidationResult` containing all errors and warnings found.

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
| V-005 | §11.1.5 | All closed enumeration values are valid members of their respective types. Open enumerations ([§2.20](/sdk/core-types/#220-enumerations): Protocol, Mode, Surface, Framework) are validated by their pattern or format constraints only, not by membership in a fixed set. |
| V-006 | §11.1.6 | `indicators`, when present, contains at least one entry. |
| V-007 | §11.1.8, §11.1.9 | In multi-phase form: `execution.phases` contains at least one entry. In multi-actor form: each actor's `phases` contains at least one entry. (Single-phase form always has exactly one implicit phase.) |
| V-008 | §11.1.8 | At most one terminal phase per actor (no `trigger`), and it is the last phase in the actor's list. |
| V-009 | §11.1.8 | First phase in each actor includes `state`. In single-phase form, `execution.state` is present, which always satisfies this. In multi-phase and multi-actor forms, check `phases[0].state` directly. |
| V-010 | §11.1.10 | All explicitly specified `indicator.id` values are unique. |
| V-011 | §11.1.8 | In multi-phase form: all explicitly specified `phase.name` values are unique. In multi-actor form: explicitly specified phase names are unique within each actor (but MAY duplicate across actors). Omitted names (auto-generated) are guaranteed unique by their positional generation. |
| V-012 | §11.1.11 | Each indicator has exactly one detection key (`pattern`, `expression`, or `semantic`). |
| V-013 | [§6.2](/specification/indicators/#62-pattern-matching) | All regular expressions are syntactically valid RE2. |
| V-014 | [§6.3](/specification/indicators/#63-expression-evaluation) | All CEL expressions are syntactically valid (parse without error). |
| V-015 | [§5.5](/specification/execution-profile/#55-extractors) | All JSONPath expressions are syntactically valid. |
| V-016 | [§5.7](/specification/execution-profile/#57-expression-evaluation) | All template references use valid syntax (no unclosed `{{`). Escaped sequences (`\{{`) are not template references and MUST NOT be flagged. |
| V-017 | [§4.3](/specification/document-structure/#43-severity) | `severity.confidence` is in range 0–100 when present. |
| V-018 | [§7](/specification/protocol-bindings/) | Indicator `surface` is valid for the indicator's resolved protocol. |
| V-019 | [§5.3](/specification/execution-profile/#53-triggers) | Trigger `count` and `match` are only present when `event` is also present. |
| V-020 | §11.1.1 | Document does not contain YAML anchors, aliases, or merge keys. SDKs that parse via a YAML library exposing anchor/alias information SHOULD check this; SDKs whose parsers silently resolve aliases MAY skip this check. |
| V-021 | [§6.2](/specification/indicators/#62-pattern-matching), [§6.4](/specification/indicators/#64-semantic-analysis) | All explicit `target` fields on `PatternMatch` and `SemanticMatch` are syntactically valid wildcard dot-path expressions per the grammar in SDK spec [§5.1.2](/sdk/execution-primitives/#512-wildcard-dot-path). Valid paths consist of identifiers (alphanumeric, underscores, hyphens) separated by `.`, with optional `[*]` (wildcard) suffix on any segment. The empty string `""` is valid (targets root). Numeric indices (`[0]`, `[1]`) are not valid in target paths. Invalid examples: `tools[*.description` (unclosed bracket), `tools..name` (empty segment), `tools[0]` (numeric index). |
| V-022 | §6.4 | `semantic.threshold`, when explicitly present, is in range [0.0, 1.0] inclusive. The default threshold (0.7, applied at evaluation time per SDK spec [§4.4](/sdk/evaluation/#44-evaluate_indicator)) is not subject to this check. |
| V-023 | [§4.2](/specification/document-structure/#42-attack-object) | `attack.id`, when present, matches the pattern `^[A-Z][A-Z0-9-]*-[0-9]{3,}$`. |
| V-024 | [§6.1](/specification/indicators/#61-structure) | Each explicitly specified `indicator.id`, when `attack.id` is present, matches the pattern `^[A-Z][A-Z0-9-]*-[0-9]{3,}-[0-9]{2,}$` AND its prefix (the portion before the final `-NN` segment) equals `attack.id`. For example, indicator `ACME-003-02` is valid in attack `ACME-003` but invalid in attack `ACME-007`. When `attack.id` is absent, explicitly specified indicator IDs are accepted without pattern constraints but MUST still be unique (V-010). |
| V-025 | [§6.1](/specification/indicators/#61-structure) | `indicator.confidence`, when explicitly present, is in range 0–100 inclusive. |
| V-026 | [§6.3](/specification/indicators/#63-expression-evaluation) | All `expression.variables` values are syntactically valid simple dot-path expressions per the grammar in [§5.1.1](/sdk/execution-primitives/#511-simple-dot-path). No wildcards or indices. These values are resolved via `resolve_simple_path` at evaluation time ([§4.3](/sdk/evaluation/#43-evaluate_expression)) and malformed paths should be caught early. |
| V-027 | [§5.4](/sdk/execution-primitives/#54-evaluate_predicate) | All dot-path keys in `MatchPredicate` entries are syntactically valid simple dot-path expressions per the grammar in SDK spec [§5.1.1](/sdk/execution-primitives/#511-simple-dot-path). No wildcards or indices. This applies to match predicates in `trigger.match` (phase advancement conditions) and in response entry `when` predicates within execution state (MCP tool/prompt `responses`, A2A `task_responses`). A typo in a predicate key (e.g., `argumens.command` instead of `arguments.command`) causes the predicate to silently never match; this rule catches such errors at validation time. |
| V-028 | [§5.1](/sdk/execution-primitives/#51-path-resolution) | When `execution.mode` is absent and `execution.actors` is absent (mode-less multi-phase form), every phase MUST specify `phase.mode`. When `execution.mode` is absent, regardless of whether `execution.actors` is present, every indicator (when `indicators` is present) MUST specify `indicator.protocol`. In multi-actor form, `actor.mode` provides phase-level inheritance (so `phase.mode` is typically omitted), but indicators are document-level and `indicator.protocol` remains required. |
| V-029 | [§7](/specification/protocol-bindings/) | For recognized modes (v0.1: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`), all trigger event types (after stripping qualifier) MUST be valid per the Event-Mode Validity Registry ([§2.22](/sdk/core-types/#222-event-mode-validity-registry)). For unrecognized modes, skip event validation. |
| V-030 | [§5.1](/sdk/execution-primitives/#51-path-resolution) | Exactly one of `execution.state`, `execution.phases`, or `execution.actors` MUST be present. A document with more than one is invalid. When `execution.state` is present, `execution.mode` MUST also be present. |
| V-031 | [§5.1](/sdk/execution-primitives/#51-path-resolution) | In multi-actor form: all `actor.name` values MUST be unique. Each name MUST match `[a-z][a-z0-9_]*`. Each actor MUST declare `mode`. Each actor MUST have at least one phase. Phase names MUST be unique within each actor. |
| V-032 | [§5.5](/sdk/execution-primitives/#55-interpolate_template) | Cross-actor extractor references (`{{actor_name.extractor_name}}`) MUST reference an `actor.name` that exists in the document. |
| V-033 | §11.1.14 | In MCP tool and prompt `responses` entries: `content` (or `messages` for prompts) and `synthesize` are mutually exclusive, and each entry MUST specify at most one. In A2A `task_responses` entries: `messages`/`artifacts` and `synthesize` are mutually exclusive. In AG-UI `run_agent_input`: `messages` and `synthesize` are mutually exclusive. |
| V-034 | §11.1.15 | In any `responses` or `task_responses` list, at most one entry MAY omit `when`. An entry without `when` following another entry without `when` is invalid. |
| V-035 | §11.1.16 | `synthesize.prompt` MUST be a non-empty string when `synthesize` is present. |
| V-036 | [§5.1](/sdk/execution-primitives/#51-path-resolution) | All mode values (`execution.mode`, `actor.mode`, `phase.mode`) MUST match the pattern `[a-z][a-z0-9_]*_(server\|client)`. All `indicator.protocol` values MUST match `[a-z][a-z0-9_]*`. |
| V-037 | [§4.2](/sdk/evaluation/#42-evaluate_pattern) | `attack.version`, when present, MUST be a positive integer (≥ 1). |
| V-038 | [§5.3](/sdk/execution-primitives/#53-evaluate_condition) | `trigger.after`, when present, MUST be a valid duration (shorthand or ISO 8601). |
| V-039 | [§5.5](/sdk/execution-primitives/#55-interpolate_template) | Extractor names MUST match the pattern `[a-z][a-z0-9_]*`. |
| V-040 | §11.1.8 | `phase.extractors`, when present, MUST contain at least one entry. |
| V-041 | §11.1.17 | All `expression.variables` keys MUST be valid CEL identifiers, matching `^[_a-zA-Z][_a-zA-Z0-9]*$`. Names containing hyphens, dots, or other non-identifier characters are rejected because CEL would parse them as operators rather than variable references. |
| V-042 | [§5.3](/specification/execution-profile/#53-triggers) | Trigger MUST specify at least one of `event` or `after`. An empty trigger object is invalid. |
| V-043 | §11.1.17 | Binding-specific action objects (those containing no known action key) MUST contain exactly one non-`x-` key. |

**Unrecognized binding diagnostics:** SDKs SHOULD expose a `known_modes()` function returning the set of modes defined by included protocol bindings (v0.1: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`) and a `known_protocols()` function returning the corresponding protocols (v0.1: `mcp`, `a2a`, `ag_ui`). When a mode or protocol passes V-036 pattern validation but is not in the known set, `validate` SHOULD emit a warning (not an error) indicating the value is unrecognized. This catches typos like `mpc_server` while allowing intentional use of custom bindings. Tools MAY provide a mechanism to suppress these warnings.

**Error conditions:** Each failed rule produces a `ValidationError` ([§7.2](/sdk/diagnostics/#72-validationerror)).

## 3.3 normalize

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
| N-004 | §11.2.4 | Resolve `pattern.target` and `semantic.target` from the surface registry ([§2.21](/sdk/core-types/#221-surface-registry)) when omitted. |
| N-005 | §11.2.5 | Expand pattern shorthand form to standard form: move condition operator into explicit `condition` field. |
| N-006 | [§5.1](/sdk/execution-primitives/#51-path-resolution) | Normalize single-phase form to multi-actor form: when `execution.state` is present (and `execution.phases` and `execution.actors` are absent), wrap it in `actors: [{name: "default", mode: <execution.mode>, phases: [{name: "phase-1", state: <execution.state>}]}]`. Remove the top-level `mode` and `state` from `execution`. |
| N-007 | [§5.1](/sdk/execution-primitives/#51-path-resolution) | Normalize multi-phase form to multi-actor form: when `execution.phases` is present (and `execution.actors` is absent), wrap it in `actors: [{name: "default", mode: <execution.mode>, phases: <execution.phases>}]`. When `execution.mode` is absent (mode-less multi-phase form), set `actor.mode` from `phases[0].mode`. Remove the top-level `mode` and `phases` from `execution`. All subsequent normalization steps and all runtime processing operate on the `actors` array. |
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

## 3.4 serialize

```
serialize(document: Document) → String
```

Serializes a document to YAML. SDKs SHOULD emit the fully-expanded normalized form per [§11.2](/specification/conformance/#112-tool-conformance-general).

**Preconditions:** `document` is a well-formed document model (typically the output of `normalize`).

**Behavior:**

1. Serialize all fields to YAML 1.2.
2. Preserve field ordering: `oatf` first, then `attack` fields in specification order.
3. Emit explicit values for all fields that have defaults (do not rely on consumer normalization).
4. Preserve `x-` extension fields in their original position.
5. Use block style for readability.

## 3.5 load

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


