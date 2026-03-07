---
title: "SDK Introduction"
description: "Scope, purpose, and conformance requirements for OATF SDK implementations."
---

This specification defines the language-agnostic API contract for OATF SDK implementations. An OATF SDK is a library that parses, validates, normalizes, evaluates, and serializes OATF documents. Any tool that consumes or produces OATF documents (adversarial simulation tools, evaluation scanners, CI pipeline integrations, IDE plugins) builds on an SDK rather than reimplementing the format's semantics.

This specification defines the abstract types, entry points, evaluation interfaces, execution primitives, extension points, and error taxonomy that every conforming SDK MUST expose. Language-specific idioms (error signaling mechanisms, collection types, concurrency models, naming conventions) are left to individual SDK implementations. The behavioral contracts are language-agnostic and testable via the OATF conformance test suite.

This specification references the OATF Format Specification v0.1 throughout. Section references (§) refer to that document unless otherwise noted.

## 1. Scope

## 1.1 What the SDK Does

The SDK implements the portable logic defined by the OATF format specification:

- Parsing YAML into a typed document model.
- Validating documents against the structural and semantic rules of [§11.1](/specification/conformance/#111-document-conformance).
- Normalizing documents to canonical form per [§11.2](/specification/conformance/#112-tool-conformance-general).
- Resolving dot-paths, match predicates, and template expressions.
- Evaluating indicators against protocol messages.
- Computing attack-level verdicts from indicator results.
- Serializing documents back to YAML in fully-expanded form.

## 1.2 What the SDK Does Not Do

The SDK has no knowledge of:

- Protocol transports (stdio, HTTP, SSE, WebSocket).
- Protocol wire formats (JSON-RPC framing, HTTP headers).
- Attack execution (connecting to servers, sending messages, managing sessions).
- Traffic capture (proxying, recording, replaying).
- Reporting, visualization, or user interfaces.
- Configuration management, environment variables, or file inclusion.

These are concerns of the tools that consume the SDK.

## 1.3 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

A conforming OATF SDK:

1. MUST implement all entry points defined in [§3](/sdk/entry-points/).
2. MUST implement all core types defined in [§2](/sdk/core-types/).
3. MUST implement pattern indicator evaluation ([§4.2](/sdk/evaluation/#42-evaluate_pattern)).
4. MUST implement all verdict computation modes ([§4.5](/sdk/evaluation/#45-compute_verdict)).
5. MUST implement all execution primitives defined in [§5](/sdk/execution-primitives/).
6. MUST define extension point interfaces for CEL evaluation and semantic evaluation ([§6](/sdk/extension-points/)).
7. MUST use the error taxonomy defined in [§7](/sdk/diagnostics/).
8. SHOULD implement expression indicator evaluation via the CEL extension point ([§4.3](/sdk/evaluation/#43-evaluate_expression), [§6.1](/sdk/extension-points/#61-celevaluator)).
9. SHOULD pass the OATF conformance test suite without failure.
10. MUST document which optional capabilities it supports.


