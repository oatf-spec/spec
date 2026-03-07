---
title: "Extension Points"
description: "Interfaces for CEL evaluation, semantic evaluation, and LLM generation providers."
---

Extension points define interfaces that the SDK declares but does not necessarily implement. Language SDKs define these as traits, interfaces, protocols, or callback types according to language convention.

## 6.1 CelEvaluator

```
interface CelEvaluator {
    evaluate(
        expression: String,
        context: Map<String, Value>
    ) → Result<Value, EvaluationError>
}
```

Evaluates a CEL expression against a context of named variables. Returns a boolean or an evaluation error.

**Contract:**

- The evaluator MUST support the CEL standard functions: `size`, `contains`, `startsWith`, `endsWith`, `matches`, `exists`, `all`, `filter`, `map`.
- The evaluator MUST be side-effect-free. No I/O, no mutation, no network access.
- The evaluator SHOULD enforce a time limit. 100 milliseconds per expression is RECOMMENDED.
- The evaluator MUST return a type error (not crash) when the expression produces a non-boolean result in a boolean context.

SDKs SHOULD ship a default `CelEvaluator` implementation when a production-quality CEL library is available for the target language. SDKs that cannot ship a default implementation MUST clearly document this and MUST accept a user-provided implementation.

**Partial compliance:** When the underlying CEL library does not support the full set of standard functions listed above, the default implementation MAY ship with partial function coverage. In this case, the SDK MUST document which functions are supported, and the evaluator MUST return an `EvaluationError` with `kind: unsupported_method` when an expression calls an unsupported function (rather than failing silently or crashing). The CEL ecosystem maturity varies across languages: Go has Google's reference implementation, while Rust and Python have less complete alternatives. Partial compliance with a clear extension point is preferable to no default implementation.

## 6.2 SemanticEvaluator

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
- When `threshold` is absent, the SDK uses a default threshold of `0.7` (per [format specification §6.4](/specification/indicators/#64-semantic-analysis)).
- The evaluator MAY use `examples.positive` and `examples.negative` to calibrate its scoring.
- Evaluation errors (model unavailable, timeout, malformed response) MUST be returned as `EvaluationError`, not thrown as unhandled exceptions.

SDKs MUST NOT ship a default `SemanticEvaluator`. Semantic evaluation is inherently model-dependent and deployment-specific.

> *Note:* Semantic evaluation involves I/O (LLM inference, embedding API calls). The trait interface is synchronous; implementations manage I/O internally. Language SDKs MAY provide async convenience wrappers. See [§8.7](/sdk/implementation-guidance/#87-async-evaluation).

## 6.3 GenerationProvider

```
interface GenerationProvider {
    generate(
        prompt: String,
        protocol: Protocol,
        response_context: Value
    ) → Result<Value, GenerationError>
}
```

Generates protocol-conformant content from a prompt. Used by adversarial tools to execute `synthesize` blocks ([format specification §7.4](/specification/protocol-bindings/llm-synthesis/)). For server-mode actors (MCP, A2A), this generates response payloads. For client-mode actors (AG-UI), this generates input content (message histories).

**Contract:**

- The `prompt` has already been resolved (all `{{template}}` references interpolated). The provider receives the final prompt string.
- The `protocol` identifies which protocol binding the output must conform to (MCP, A2A, or AG-UI).
- The `response_context` provides protocol-specific metadata the provider needs to shape its output (for example, the tool's `inputSchema` for MCP, the task's expected `status` for A2A, or the `tools` and `state` from `run_agent_input` for AG-UI). The structure is defined by the consuming tool, not by this specification.
- The provider MUST return a `Value` that conforms to the protocol's expected structure. The consuming tool MUST validate this value against the protocol binding before injection ([format specification §7.4](/specification/protocol-bindings/llm-synthesis/)).
- The provider is responsible for all LLM interaction: model selection, API calls, structured output enforcement, caching, and retry.
- Generation errors (model unavailable, timeout, content policy rejection, validation failure) MUST be returned as `GenerationError`, not thrown as unhandled exceptions.

SDKs MUST NOT ship a default `GenerationProvider`. LLM generation is model-dependent, API-specific, and deployment-specific. The consuming tool (e.g., ThoughtJack) provides its own implementation.

> *Note:* LLM generation involves I/O. The trait interface is synchronous; implementations manage I/O internally. Language SDKs MAY provide async convenience wrappers. See [§8.7](/sdk/implementation-guidance/#87-async-evaluation).


