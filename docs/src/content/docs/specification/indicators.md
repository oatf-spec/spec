---
title: "Indicators"
description: "Pattern matching, expression evaluation, and semantic analysis for detecting attack outcomes."
---

The `indicators` field is OPTIONAL. When absent, the document is valid for simulation only: adversarial tools can execute the attack, but evaluation tools cannot produce verdicts. When present, indicators define patterns for determining whether the agent complied with the attack. Each indicator is independent: it targets a specific protocol and surface, examines the agent's behavior in response to the simulated attack, and produces a verdict.

Indicators SHOULD examine only the agent's *response* to the attack — not the attack payload itself. An indicator that checked whether a tool description contains suspicious text would always fire in a closed-loop simulation: the execution profile placed that text there. The valuable indicators are those that detect whether the agent *acted on* the malicious content — exfiltrating data, complying with injected instructions, or performing unauthorized actions.

Evaluation tools evaluate each indicator against protocol traffic observed during the entire execution of the attack profile (all phases of all actors). An indicator matches if **any** applicable message in the observed trace satisfies its condition — the tool does not require a specific message position (first, last, or otherwise). Tools MAY apply a configurable grace period after the terminal phase(s) complete, to capture delayed effects such as exfiltration or state changes that manifest after the attack simulation ends. When `attack.grace_period` is present, tools MUST use the specified duration as the post-terminal-phase observation window. When absent, tools MAY apply their own configurable default.

## 6.1 Structure

```yaml
indicators:
  - id: string?                          # Auto-generated if omitted
    protocol: string?                     # Required when execution.mode is absent
    surface: string
    description: string?
    
    # Exactly one of the following (determines evaluation method):
    pattern: <PatternMatch>?
    expression: <ExpressionMatch>?
    semantic: <SemanticMatch>?
    
    confidence: integer?   # 0–100, overrides attack-level confidence
    severity: enum(informational, low, medium, high, critical)?
    false_positives: string[]?
```

### `indicator.id` (OPTIONAL)

A unique identifier within this document. When specified and `attack.id` is present, MUST match the pattern `{attack.id}-{sequence}` where `{sequence}` is a zero-padded numeric sequence of at least two digits (for example, `OATF-027-01`, `ACME-003-02`). When omitted, tools MUST auto-generate an identifier: `{attack.id}-{NN}` when `attack.id` is present, or `indicator-{NN}` when `attack.id` is absent. `NN` is the 1-based, zero-padded position of the indicator in the `indicators` array.

### `indicator.protocol` (CONDITIONAL)

The protocol this indicator applies to. The value is the protocol component of a mode string (the substring before `_server` or `_client`; for example, `mcp` from `mcp_server`, `ag_ui` from `ag_ui_client`). When `execution.mode` is present, this defaults to its protocol component and is optional. When `execution.mode` is absent, this field is REQUIRED on every indicator.

### `indicator.surface` (REQUIRED)

The specific protocol construct being examined. Valid values are protocol-specific and defined in the protocol binding sections ([§7](/specification/protocol-bindings/)).

### `indicator.description` (OPTIONAL)

Prose describing what this indicator detects and why it is significant.

### `indicator.confidence` (OPTIONAL)

The confidence level for this specific indicator, overriding the attack-level confidence. Integer from 0 to 100.

### `indicator.severity` (OPTIONAL)

The severity level for this specific indicator, overriding the attack-level severity. Useful when an attack has indicators of varying significance.

### `indicator.false_positives` (OPTIONAL)

Known scenarios where this indicator may match benign traffic. Each entry is a prose description of a legitimate situation that would trigger this indicator. This field helps tool operators tune alerting thresholds and triage results.

## 6.2 Pattern Matching

The `pattern` field governs string and structural matching rules. Pattern matching operates on the parsed protocol message, not the raw wire representation. Attacks that exploit wire-level anomalies (duplicate JSON keys, non-canonical encoding) are outside the scope of pattern indicators. Two forms are supported:

**Standard form**: explicit target and condition:

```yaml
pattern:
  target: string?              # Dot-path to the field to inspect (defaults from surface)
  condition: <Condition>       # contains, regex, starts_with, etc.
```

**Shorthand form**: condition operator directly on pattern object, using the surface's default target:

```yaml
pattern:
  regex: "(id_rsa|passwd|\\.env)"
```

When a `pattern` object contains a recognized condition operator (`contains`, `starts_with`, `ends_with`, `regex`, `any_of`, `gt`, `lt`, `gte`, `lte`) as a direct key rather than inside a `condition` wrapper, it is treated as an implicit single condition on the surface's default target path. This form is equivalent to:

```yaml
pattern:
  target: <default_target_for_surface>
  condition:
    regex: "(id_rsa|passwd|\\.env)"
```

The shorthand form supports only a single condition. For multi-condition AND logic or explicit target override, use the standard form.

### `pattern.target` (OPTIONAL)

The dot-path to the field within the protocol message to inspect. Path semantics are protocol-specific. Wildcard segments are supported: `tools[*].description` matches the `description` field of every element in the `tools` array. When a wildcard path resolves to multiple nodes, the condition matches if **any** node satisfies it (OR semantics). For example, `tools[*].description` with `contains: "IMPORTANT"` matches if any tool's description contains the substring.

When omitted, defaults to the canonical target path for the indicator's `surface` value as defined in the protocol binding sections ([§7](/specification/protocol-bindings/)). Each surface table includes a **Default Target** column specifying this path.

> *Note:* Target paths use a simplified dot-path syntax (`tools[*].description`) rather than full JSONPath or XPath. The simplified syntax covers the majority of indicator use cases (field access, array wildcard, nested traversal) without requiring a JSONPath parser in every consuming tool. For cases requiring predicate filters or recursive descent, the `expression` method ([§6.3](/specification/indicators/#63-expression-evaluation)) provides full CEL evaluation against the complete message context.

### `pattern.condition` (CONDITIONAL)

The matching condition applied to the node(s) selected by `pattern.target`. A Condition is a single operator object — one of `contains`, `starts_with`, `ends_with`, `regex`, `any_of`, `gt`, `lt`, `gte`, `lte`, `exists` — or a bare value for equality matching. This is the same set of operators used within MatchPredicates ([§5.4](/specification/execution-profile/#54-match-predicates)), but here applied to an already-selected field rather than a field-path mapping. Required when using the standard form. Absent when using the shorthand form. Note that `exists` is available in the standard form but not in the shorthand form (shorthand omits `target`, so there is no explicit path for `exists` to check).

When the condition contains multiple operators, they are combined with AND logic (all must match). For example, `{contains: "secret", regex: "key_[0-9]+"}` matches only if both conditions are satisfied.

All pattern matching operates on the parsed protocol message, not the raw wire representation. Attacks that exploit wire-level anomalies (duplicate JSON keys, non-canonical encoding, whitespace manipulation) are outside the scope of pattern indicators and require tool-specific detection.

## 6.3 Expression Evaluation

The `expression` field contains a CEL expression. Expression indicators do not use a `target` field. The CEL expression has access to the entire message context as defined in the protocol binding's CEL Context section ([§7.1.3](/specification/protocol-bindings/mcp/#713-cel-context-mcp), [§7.2.3](/specification/protocol-bindings/a2a/#723-cel-context-a2a), [§7.3.3](/specification/protocol-bindings/ag-ui/#733-cel-context-ag-ui)). The expression itself is responsible for navigating to the relevant fields.

```yaml
expression:
  cel: string
  variables: map<string, string>?
```

### `expression.cel` (REQUIRED)

A [Common Expression Language](https://github.com/google/cel-spec) expression that evaluates to a boolean. The expression receives the protocol message as its root context.

> *Note:* CEL was selected over Rego (OPA) and Datalog for expression evaluation. Rego requires a policy engine runtime and uses a logic-programming model unfamiliar to most security practitioners. CEL is designed to be embedded, is side-effect-free by specification (simplifying sandboxing), and has production-quality implementations in Go, Rust, Java, and C++. The tradeoff is lower expressive power for policy-style rules, but OATF expressions evaluate individual messages rather than policy sets, so CEL's expression-oriented model is a better fit.

Examples:

```yaml
# Tool description exceeds 500 characters and contains suspicious keywords
expression:
  cel: >
    message.tools.exists(t,
      size(t.description) > 500 &&
      t.description.contains("IMPORTANT:"))

# Ratio of system messages to user messages exceeds threshold
expression:
  cel: >
    message.messages.filter(m, m.role == "system").size() >
    message.messages.filter(m, m.role == "user").size() * 3

# Tool response content exceeds safe size threshold
expression:
  cel: >
    message.content.exists(c, c.type == "text" && size(c.text) > 100000)
```

### `expression.variables` (OPTIONAL)

Named variables available to the CEL expression beyond the message context. Defined as a map from variable name to dot-path into the message, enabling pre-extraction of deeply nested values for cleaner expressions. Variable names MUST be valid CEL identifiers (`[_a-zA-Z][_a-zA-Z0-9]*`); names containing hyphens or other non-identifier characters will fail CEL compilation.

## 6.4 Semantic Analysis

The `semantic` field specifies intent-based detection that requires an inference engine.

```yaml
semantic:
  target: string?    # Defaults from surface
  intent: string
  intent_class: enum(prompt_injection, data_exfiltration, privilege_escalation,
                  social_engineering, instruction_override)?
  threshold: number?   # 0.0–1.0, similarity or confidence threshold
  examples:
    positive: string[]?
    negative: string[]?
```

### `semantic.target` (OPTIONAL)

The dot-path to the field to analyze. Defaults to the canonical target path for the indicator's `surface` value as defined in the protocol binding sections ([§7](/specification/protocol-bindings/)).

### `semantic.intent` (REQUIRED)

A natural-language description of the malicious intent to detect. Inference engines use this as the reference for similarity or classification.

### `semantic.intent_class` (OPTIONAL)

The class of malicious intent, used by classification-based inference engines. When present, engines that support classification SHOULD use this as a hint. When absent, engines MUST rely on the `intent` and `examples` fields alone.

### `semantic.threshold` (OPTIONAL)

The minimum confidence or similarity score for a positive match. When omitted, SDKs apply a default threshold of `0.7` at evaluation time. The threshold is not materialized during normalization, preserving the distinction between an author-specified threshold and the SDK default.

The threshold is a tool-relative calibration target, not an absolute or cross-tool-comparable score. A threshold of `0.75` means "this tool, using its own inference engine, should consider scores at or above 0.75 as matches." The same threshold value will produce different match boundaries across tools using different models, embedding spaces, or classification architectures. This is inherent to semantic analysis and is the reason `semantic` is a distinct method from `pattern` and `expression`, which are deterministic.

The interoperability mechanism for semantic indicators is the `examples` field, not the threshold. Two conforming tools using different inference engines SHOULD both classify `examples.positive` strings as matches and `examples.negative` strings as non-matches. If a tool's engine does not correctly classify the provided examples, the tool's calibration is incorrect, and the threshold should be adjusted by the tool operator, not the OATF document author.

### `semantic.examples` (RECOMMENDED)

Example strings that should (positive) and should not (negative) trigger this indicator. These serve as the ground truth for calibrating inference engines across implementations. While this field is not strictly required, OATF documents with `semantic` indicators SHOULD include at least two positive and two negative examples to enable cross-tool validation.

This specification does not prescribe the inference engine implementation. A conforming evaluation tool MAY implement semantic indicators using LLM-as-judge, embedding similarity, trained classifiers, or any other method that accepts the specified parameters.

