---
title: "Implementation Guidance"
description: "Non-normative guidance for SDK implementors: language adaptation, naming, performance, async patterns, and versioning."
---

This section is non-normative. It offers practical advice for SDK implementors.

## 8.1 Language Adaptation

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

## 8.2 Field Naming

SDKs SHOULD adapt field names to the target language's naming convention:

- Rust, Python: `snake_case` (matches YAML keys directly).
- Go: `PascalCase` for exported fields with `yaml:"snake_case"` struct tags.
- TypeScript/JavaScript: `camelCase` with consideration for YAML key mapping.

The canonical names in this specification use `snake_case` to match the YAML document format.

**Reserved keywords:** Several OATF field names collide with reserved keywords in common languages. In particular, `match` ([§2.8](/sdk/core-types/#28-trigger) Trigger, [§2.12](/sdk/core-types/#212-indicator) Indicator) is reserved in Rust, Scala, and PHP; `type` ([§2.9](/sdk/core-types/#29-extractor) Extractor) is reserved in Python. SDKs MUST use the canonical YAML key for serialization/deserialization while renaming the struct field to a non-reserved alternative. For example, in Rust: `#[serde(rename = "match")] pub match_predicate: Option<MatchPredicate>`. The renamed field name is a language SDK decision; the YAML key is fixed by the format specification.

## 8.3 Immutability

SDKs SHOULD make the document model immutable after construction. `normalize` returns a new document; it does not mutate the input. This simplifies concurrent usage and prevents accidental modification of shared state.

## 8.4 Extension Fields

OATF documents may contain fields prefixed with `x-`. SDKs MUST preserve these through parse → normalize → serialize round-trips. The following core types include an `extensions: Optional<Map<String, Value>>` field for this purpose: `Attack` ([§2.3](/sdk/core-types/#23-attack)), `Execution` ([§2.6](/sdk/core-types/#26-execution)), `Actor` ([§2.6a](/sdk/core-types/#26a-actor)), `Phase` ([§2.7](/sdk/core-types/#27-phase)), `Action` ([§2.7a](/sdk/core-types/#27a-action)), `Indicator` ([§2.12](/sdk/core-types/#212-indicator)). During parsing, the SDK MUST collect any `x-` prefixed keys from each object and store them in the corresponding `extensions` map. During serialization, the SDK MUST emit these keys back into the output. Key names are preserved exactly (including the `x-` prefix); relative ordering of extension fields among themselves is preserved where the language's map type supports it. Ordering relative to standard fields is not guaranteed.

## 8.5 Performance Considerations

- Regex patterns SHOULD be compiled once during `validate` or `normalize` and cached for reuse during evaluation.
- CEL expressions SHOULD be parsed once during `validate` and the parsed AST cached for evaluation.
- The surface registry ([§2.21](/sdk/core-types/#221-surface-registry)) is static data. SDKs SHOULD represent it as a compile-time constant, not a runtime lookup.

## 8.6 Dependency Guidance

| Capability | Recommended Approach |
|---|---|
| YAML parsing | Use the language's standard or dominant YAML library. Require YAML 1.2 support. |
| Regular expressions | Use an RE2-compatible engine for linear-time guarantees. |
| CEL evaluation | Wrap an existing CEL library. Do not implement CEL from scratch. |
| JSONPath | Use a standard JSONPath library. Enforce traversal depth limits. |
| Duration parsing | Implement directly; the grammar is simple enough to avoid a dependency. See note below. |
| Dot-path resolution | Implement directly; no standard library exists for the OATF path syntax. |

**Duration parsing note:** OATF durations require accepting both shorthand (`30s`, `5m`) and ISO 8601 (`PT30S`, `PT5M`, `P1DT12H`) formats. Most language ecosystems have libraries that handle one format but not both (for example, Rust's `humantime` handles shorthand, `iso8601` handles ISO, but neither handles both). A hybrid parser is needed. The grammar is two branches: if the string starts with `P`, parse as ISO 8601; otherwise parse as shorthand. Both branches are simple enough to implement directly (shorthand is `\d+[smhd]`, ISO 8601 is `P(\d+D)?(T(\d+H)?(\d+M)?(\d+S)?)?`), avoiding the need for two separate dependencies.

## 8.7 Async Evaluation

All entry points and evaluation functions defined in this specification have synchronous signatures. The SDK core MUST be synchronous:

- `parse`, `validate`, `normalize`, and `serialize` are CPU-bound operations on in-memory data. Synchronous signatures are appropriate.
- The core evaluation functions (`evaluate_indicator`, `compute_verdict`) MUST be synchronous. They invoke extension point trait implementations which present a synchronous interface to the SDK.
- Extension point implementations (`CelEvaluator`, `SemanticEvaluator`, `GenerationProvider`) MAY perform I/O internally (LLM inference, embedding API calls, network requests) but MUST present a synchronous interface to the SDK. How I/O is managed within the implementation (blocking calls, internal async runtimes, thread pools) is an implementation concern opaque to the SDK.
- Language SDKs MAY additionally provide async convenience wrappers that delegate to the synchronous core. These wrappers are SDK-specific sugar and not part of the abstract specification.
- Batch evaluation of multiple indicators against multiple messages is a common workflow. SDKs MAY offer batch evaluation functions that evaluate indicators concurrently where the language supports it.

This pattern (sync core, sync trait interface, optional async wrappers) ensures that the behavioral contracts are uniform across language ecosystems while allowing each SDK to integrate naturally with its language's concurrency model. SDKs SHOULD document whether they provide async convenience wrappers.


## 9. Versioning

## 9.1 SDK Specification Versioning

This specification follows Semantic Versioning independently of the OATF format specification:

- **Major** versions indicate breaking changes to the API contract (renamed entry points, changed function signatures, removed types).
- **Minor** versions add new entry points, new fields on existing types, or new evaluation capabilities.
- **Patch** versions clarify behavior without changing the API surface.

## 9.2 Format Compatibility

Each SDK specification version declares which OATF format specification version(s) it supports.

This version (SDK Spec 0.1) supports **OATF Format Spec 0.1**.

When the format specification adds a new protocol binding (for example, a hypothetical OATF 0.2 adding a new protocol), the SDK specification will be updated to include the new surfaces and event types. During the 0.x series, minor versions may introduce breaking changes (per [format specification §10.1](/specification/versioning/#101-specification-versioning)), so SDKs are not required to handle unknown format versions gracefully. Post-1.0, SDKs implementing a prior SDK specification version MUST still correctly parse documents using new minor-version bindings, ignoring unknown surfaces.

## 9.3 Language SDK Versioning

Individual language SDKs version independently of both specifications. A language SDK declares which SDK specification version it implements. For example:

- `oatf-rs 0.3.2` implements SDK Spec 0.1.
- `oatf-py 0.1.0` implements SDK Spec 0.1.

Patch versions of language SDKs (bug fixes, performance improvements) do not require SDK specification changes. Language SDKs SHOULD document their SDK specification version in their README and crate/package metadata.

