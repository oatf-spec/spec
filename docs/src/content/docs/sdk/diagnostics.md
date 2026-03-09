---
title: "Diagnostics"
description: "Error types, diagnostic codes, and error aggregation for OATF SDK implementations."
---

## 7.0 Diagnostic

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
    errors: List<ValidationError>   // conformance violations; document is non-conforming
    warnings: List<Diagnostic>      // severity: warning; document is valid but has issues
}
```

A document is valid if and only if `errors` is empty. Warnings are informational and do not block processing. SDKs MUST populate `errors` for all V-xxx rule failures.

SDKs MUST produce warnings for the following conditions:

| Code | Condition |
|---|---|
| W-001 | `oatf` is not the first key in the document (V-002). |
| W-002 | A mode passes pattern validation but is not in the set of modes defined by included protocol bindings (v0.1: `mcp_server`, `mcp_client`, `a2a_server`, `a2a_client`, `ag_ui_client`). Derived from the Event-Mode Validity Registry ([§2.22](/sdk/core-types/#222-event-mode-validity-registry)). Likely typo. |
| W-003 | A protocol passes pattern validation but is not in the set of protocols defined by included protocol bindings (v0.1: `mcp`, `a2a`, `ag_ui`). Derived from the Surface Registry ([§2.21](/sdk/core-types/#221-surface-registry)). Likely typo. |
| W-004 | Template interpolation references an undefined extractor or an unresolvable message path. Two sub-cases: (a) "unknown extractor reference", detectable at validate time by cross-referencing template expressions against declared extractor names; (b) "request/response path failed to resolve", detectable only at runtime when the actual message is available. |
| W-005 | An indicator targets a protocol with no matching actor in the execution profile. |

SDKs MAY define additional warning codes for tool-specific diagnostics.

## 7.1 ParseError

Produced by `parse` when YAML deserialization fails.

| Field | Type | Description |
|---|---|---|
| `kind` | `ParseErrorKind` | One of: `syntax`, `type_mismatch`, `unknown_variant`. |
| `message` | `String` | Human-readable description. |
| `path` | `Optional<String>` | Dot-path to the offending field (when available). |
| `line` | `Optional<Integer>` | Line number in source YAML (when available). |
| `column` | `Optional<Integer>` | Column number in source YAML (when available). |

## 7.2 ValidationError

Produced by `validate` when a document violates a conformance rule.

| Field | Type | Description |
|---|---|---|
| `rule` | `String` | Rule identifier from [§3.2](/sdk/entry-points/#32-validate) (for example, `V-001`). |
| `spec_ref` | `String` | Format specification section reference (for example, `§11.1.1`). |
| `message` | `String` | Human-readable description. |
| `path` | `String` | Dot-path to the offending field. |

## 7.3 EvaluationError

Produced during indicator evaluation when a runtime error occurs.

| Field | Type | Description |
|---|---|---|
| `kind` | `EvaluationErrorKind` | One of: `path_resolution`, `regex_timeout`, `cel_error`, `type_error`, `semantic_error`, `unsupported_method`. |
| `message` | `String` | Human-readable description. |
| `indicator_id` | `Optional<String>` | The indicator being evaluated when the error occurred. |

## 7.3a GenerationError

Produced by a `GenerationProvider` when LLM synthesis fails.

| Field | Type | Description |
|---|---|---|
| `kind` | `GenerationErrorKind` | One of: `provider_unavailable`, `model_error`, `validation_failure`, `timeout`, `content_policy`. |
| `message` | `String` | Human-readable description. |
| `phase_name` | `Optional<String>` | The phase during which generation was attempted. |
| `prompt_preview` | `Optional<String>` | First 200 characters of the resolved prompt, for diagnostics. |

The `GenerationProvider.generate` interface does not receive `phase_name`; the provider is intentionally unaware of execution context. The SDK is responsible for catching the error returned by the provider and populating `phase_name` from the current execution state before surfacing the `GenerationError` to the consuming tool.

`provider_unavailable` indicates no `GenerationProvider` is configured but a `synthesize` block was encountered. `validation_failure` indicates the LLM produced output that did not conform to the protocol binding's expected structure.

## 7.4 Error Aggregation

`validate` returns a `ValidationResult` containing both errors and warnings rather than stopping at the first failure. This enables IDE-style diagnostics where all problems are surfaced at once. `parse` MAY return a single error or multiple errors depending on the language deserialization framework's capabilities (see [§3.1](/sdk/entry-points/#31-parse)).

SDKs SHOULD order errors by their location in the source document (by line number for parse errors, by dot-path for validation errors). Diagnostics (warnings) SHOULD follow the same ordering.

The `load` convenience entry point ([§3.5](/sdk/entry-points/#35-load)) returns the first applicable error list: if parsing fails, parse errors are returned and validation is not attempted. If parsing succeeds but validation finds errors, validation errors are returned. If both succeed, the normalized document and any warnings are returned together. A tool that needs fine-grained control over parse warnings and validation diagnostics should call the steps individually.

## 7.5 OATFError

Union type returned by `load` ([§3.5](/sdk/entry-points/#35-load)). Represents any error that can occur during the combined parse-validate-normalize pipeline.

`OATFError` is one of:
- `ParseError` ([§7.1](/sdk/diagnostics/#71-parseerror)): YAML deserialization or structural typing failure.
- `ValidationError` ([§7.2](/sdk/diagnostics/#72-validationerror)): conformance rule violation.

SDKs MAY represent this as a tagged union, trait object, sum type, or language-appropriate equivalent.


