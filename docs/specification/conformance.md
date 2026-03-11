---
title: "Conformance"
description: "Document conformance rules, tool conformance requirements, and partial conformance."
---

## 11.1 Document Conformance

A conforming OATF document:

The [SDK specification](/sdk/) ([SDK specification, §3.2](/sdk/entry-points/)) assigns stable rule identifiers (V-001 through V-047) to conformance requirements across this specification. Conformance test suites reference these identifiers. The numbered rules below define the structural requirements; additional V-rules cover field-level validation constraints defined in their respective sections ([§4](/specification/document-structure/) through [§7](/specification/protocol-bindings/)).

**Core structure**

1. MUST be valid YAML (version 1.2). MUST NOT use YAML anchors (`&`), aliases (`*`), merge keys (`<<`), or custom YAML tags (e.g., `!include`, `!!python/object`). These constructs introduce parsing ambiguity, deserialization vulnerabilities, or conflict with OATF's own state inheritance model. Tools MUST parse OATF documents using a safe YAML loader that rejects language-specific type coercion.
2. MUST declare `oatf: "0.1"`. Documents SHOULD place it as the first key (see [§4.1](/specification/document-structure/#41-top-level-schema)).
3. MUST contain exactly one `attack` object.
4. MUST include `attack.execution`.
5. MUST use only valid values for closed enumerations defined in this specification: `severity.level`, `attack.status`, `impact`, `classification.category`, `correlation.logic`, `extractor.source`, `extractor.type`, and `mapping.relationship`. Mode values (`execution.mode`, `actor.mode`, `phase.mode`) are open: they MUST match the pattern `[a-z][a-z0-9_]*_(server|client)` but are not restricted to modes defined in this version. Protocol values (`indicator.protocol`) MUST match the pattern `[a-z][a-z0-9_]*`. Surface and event values for recognized protocol bindings SHOULD produce warnings for unrecognized values; for unrecognized bindings, tools MUST skip surface and event validation.

**Execution forms, phases, and actors**

6. MUST have at least one entry in `indicators` when `indicators` is present.
7. MUST specify exactly one of `execution.state` (single-phase form), `execution.phases` (multi-phase form), or `execution.actors` (multi-actor form); they are mutually exclusive. When `execution.state` is present, `execution.mode` MUST also be present.
8. In multi-phase form: MUST have at least one entry in `execution.phases`. MUST have at most one terminal phase, and it MUST be the last phase. MUST include `state` on the first phase. Explicitly specified `phase.name` values MUST be unique. When `phase.extractors` is present, it MUST contain at least one entry.
9. In multi-actor form: MUST have at least one entry in `execution.actors`. Each actor MUST declare `actor.name` (matching `[a-z][a-z0-9_]*`) and `actor.mode`. Actor names MUST be unique. Each actor MUST have at least one phase. Explicitly specified phase names MUST be unique within each actor. Terminal phase rules and first-phase `state` rules apply per-actor. When `phase.mode` is specified, it MUST match the actor's `actor.mode`; cross-protocol attacks use separate actors.

**Indicators and event validation**

10. MUST use unique `indicator.id` values within the document when IDs are specified explicitly.
11. Each indicator MUST contain exactly one detection key (`pattern`, `expression`, or `semantic`).
12. When `execution.mode` is absent and `execution.actors` is absent (the mode-less multi-phase form), every phase MUST specify `phase.mode`, and all phase modes MUST be identical. Attacks requiring different modes (including role changes within the same protocol, e.g., `mcp_server` → `mcp_client`) require the multi-actor form. When `execution.mode` is absent, regardless of whether `execution.actors` is present, every indicator (when present) MUST specify `indicator.protocol`. In multi-actor form, `actor.mode` provides phase-level mode inheritance (so `phase.mode` is typically omitted), but indicators are document-level and not scoped to any actor, so `indicator.protocol` remains required.
13. For modes defined by bindings included in this specification, trigger event types SHOULD produce a warning when not valid for the actor's mode. Event types not listed in the binding's event tables on a recognized mode SHOULD produce a warning but MUST NOT be rejected.

**Response entries and validation**

14. In any `responses`, `sampling_responses`, `elicitation_responses`, `task_responses`, or `tool_responses` list, at most one entry MAY omit `when`. When present, it SHOULD be the last entry in the list. An entry without `when` after another entry without `when` is a validation error.
15. All `expression.variables` keys MUST be valid CEL identifiers, matching `[_a-zA-Z][_a-zA-Z0-9]*`. Names containing hyphens, dots, or other non-identifier characters are rejected because CEL would parse them as operators rather than variable references.

**Actions**

16. Binding-specific action objects (those containing no known action key) MUST contain exactly one non-`x-` key.

## 11.2 Tool Conformance: General

All conforming tools (adversarial and evaluation):

**Defaults and shorthand expansion**

1. MUST apply default values for omitted optional fields as defined in this specification: `name` to `"Untitled"`, `version` to `1`, `status` to `"draft"`, `severity.confidence` to `50` (when `severity` is present), `phase.name` to `"phase-{N}"` (1-based index within actor), `phase.mode` to `execution.mode` (when present); in multi-actor form (including after normalization items 6-7) `phase.mode` to `actor.mode` (when `phase.mode` is still absent), `trigger.count` to `1` (when `trigger.event` is present and `trigger.count` is absent), `indicator.protocol` to protocol component of `execution.mode` (when both `indicators` and `execution.mode` are present), `correlation.logic` to `any` (when `indicators` is present), `mapping.relationship` to `"primary"`.
2. MUST expand severity scalar form (`severity: "high"`) to the object form (`{level: "high", confidence: 50}`) before processing, when `severity` is present.
3. MUST auto-generate `indicator.id` values for indicators that omit `id`. When `attack.id` is present, the format is `{attack.id}-{NN}`. When `attack.id` is absent, the format is `indicator-{NN}`. `NN` is the 1-based, zero-padded position of the indicator in the `indicators` array.
4. MUST resolve `pattern.target` and `semantic.target` from the indicator-level `target` when omitted on the pattern or semantic block. The indicator-level `target` is always required ([§6.1](/specification/indicators/#61-structure)).
5. MUST expand pattern shorthand form (condition operator as direct key) to the standard form before evaluation.

**Normalization**

6. MUST normalize single-phase form to multi-actor form internally (N-006): when `execution.state` is present (and `execution.phases` and `execution.actors` are absent), wrap it in `actors: [{name: "default", mode: <execution.mode>, phases: [{name: "phase-1", state: <execution.state>}]}]`. All subsequent processing operates on the normalized `actors` array.
7. MUST normalize multi-phase form to multi-actor form internally (N-007): when `execution.phases` is present (and `execution.actors` is absent), wrap it in `actors: [{name: "default", mode: <execution.mode>, phases: <execution.phases>}]`. When `execution.mode` is absent (the mode-less multi-phase form, where every phase declares its own mode), `actor.mode` is set from `phases[0].mode`. All subsequent processing operates on the normalized `actors` array.
**Validation and output**

8. MUST skip event type validation for unrecognized modes. For recognized modes, tools SHOULD emit warnings when trigger event types are not listed in the binding's Events section, and these warnings MUST NOT make the document non-conforming.
9. Tools that emit OATF documents MUST emit `oatf` as the first key and SHOULD emit the fully-expanded explicit form with all defaults materialized for maximum portability.

## 11.3 Tool Conformance: Adversarial

A conforming adversarial tool:

**Core requirements**

1. MUST parse valid OATF documents without error.
2. MUST support at least one protocol binding.
3. MUST execute phases in the declared order within each actor.
4. MUST evaluate triggers and progress between phases accordingly.
5. MUST support template interpolation for extractor values, including cross-actor references (`{{actor_name.extractor_name}}`).
6. MUST ensure all server-role actors (modes ending in `_server`) are accepting connections before any client-role actor (modes ending in `_client`) begins executing its first phase (readiness guarantee).
7. MUST evaluate binding-defined response-dispatch lists in order (first match wins): `responses`, `sampling_responses`, `elicitation_responses`, `task_responses`, and `tool_responses`.

**Recommended capabilities**

8. SHOULD support all four trigger types: event (`trigger.event`), count (`trigger.count`), match (`trigger.match`), and time (`trigger.after`).
9. SHOULD support the full set of response-dispatch lists and binding-specific entry actions for the bindings the tool claims to implement.
10. SHOULD execute each OATF document in an isolated protocol session to prevent state from one attack affecting subsequent attacks in a regression suite.

**Optional capabilities**

11. MAY support `synthesize` blocks (reserved for a future version; see §F.5). Tools that support `synthesize` MUST validate generated output against the protocol binding's message structure before injection. Tools that do not support `synthesize` SHOULD emit a warning when encountering `synthesize` blocks.
12. MAY ignore indicators (the detection side of the document).
13. MUST document which protocol bindings and features it supports.

## 11.4 Tool Conformance: Evaluation

A conforming evaluation tool:

**Core requirements**

1. MUST parse valid OATF documents without error.
2. MUST reject documents without indicators with a clear error rather than silently producing a pass verdict.
3. MUST support at least one protocol binding.
4. MUST evaluate indicators against observed protocol traffic.
5. MUST produce verdicts using the vocabulary defined in [§9](/specification/verdict-model/).

**Detection methods**

6. MUST support the `pattern` detection method.
7. SHOULD support the `expression` detection method.
8. MAY support the `semantic` detection method. Tools that implement `semantic` MUST document which inference engine is used (model name, version, and type) and MUST validate that provided `examples.positive` strings are classified as matches and `examples.negative` strings as non-matches under the configured threshold.

**Optional capabilities**

9. MAY ignore the execution profile (the attack side of the document).
10. MUST document which protocol bindings and detection methods it supports.

## 11.5 Partial Conformance

A tool MAY implement a subset of OATF capabilities. A tool that supports only MCP indicators with pattern matching is a valid partial implementation. The tool MUST clearly document its supported scope.

When a tool encounters an OATF document containing features it does not support, the expected behavior depends on whether the feature is structural or semantic:

- **Structural features** (unrecognized protocol bindings, unrecognized modes): MUST be skipped without error. The tool SHOULD emit a warning identifying the unsupported feature. Documents using unrecognized modes are structurally valid, as the core document model is protocol-agnostic.
- **Semantic features** (known features that alter output, such as `synthesize`): SHOULD emit a warning. The `synthesize` block is reserved for a future version; tools that do not support it SHOULD warn and fall back to static content when available.

This distinction ensures that tools fail loudly when they cannot produce correct results, but degrade gracefully when encountering extensions they were not designed to handle.
