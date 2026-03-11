---
title: "Future Work"
description: "Areas under investigation for OATF v0.2, including A2A and AG-UI binding extensions."
---

This appendix collects areas under investigation for the next minor version. These items are non-normative and do not affect v0.1 conformance.

## F.1 A2A Binding Extensions

- **Streaming task updates.** A2A supports server-sent events for long-running tasks (`message/stream`). The current binding defines `task/status` and `task/artifact` events for the client-mode side but does not model attacks that exploit the streaming channel (e.g., injecting malicious status updates mid-stream or exploiting race conditions between concurrent task updates). Behavioral modifiers for A2A streaming need to be defined.
- **Multi-agent delegation chains.** A2A permits agents to delegate tasks to other agents, forming chains of arbitrary depth. The current execution state models a single agent-to-agent interaction. Attacks that exploit transitive trust across three or more agents (e.g., a compromised intermediate agent modifying task artifacts before forwarding) require a delegation-aware execution model.
- **Authentication scheme manipulation.** The Agent Card's `authentication.schemes` field is surfaced in the execution state but not yet treated as an attack surface. Attacks that advertise false authentication capabilities to downgrade security or harvest credentials need dedicated surfaces and indicators.

## F.2 AG-UI Binding Extensions

- **State object schema.** AG-UI's `state` field accepts arbitrary JSON, making it a flexible but opaque attack surface. The current binding treats it as an unstructured blob. Future versions may define typed state schemas for common agent frameworks (e.g., LangGraph checkpoint state, CrewAI task state) to enable more precise indicators.
- **Event sequencing attacks.** The SSE response stream delivers events in order, but the current binding does not model attacks that depend on specific event sequences (e.g., emitting a `tool_call_start` event without a corresponding `tool_call_end`, or interleaving events from concurrent runs to confuse client-side state management). This requires behavioral modifiers for AG-UI.
- **ForwardedProps trust boundary.** `forwardedProps` passes client-side context to the agent without schema validation. Whether this constitutes an independent attack surface or a subset of the existing `forwarded_props` surface needs further analysis based on real-world AG-UI deployments.

## F.3 Behavioral Modifiers

Delivery delays, side effects, and notification scheduling for realistic protocol simulation. In v0.1, bindings define entry actions (e.g., `send_notification`) but do not include fine-grained timing or side-effect controls. Future versions may add:

- **Delivery delays**: Per-response or per-notification timing to simulate realistic network behavior.
- **Side effects**: Declarative specification of side-channel actions triggered by protocol events (e.g., `list_changed` notifications after tool mutation).
- **Notification scheduling**: Time-based or event-based scheduling for server-initiated notifications.

These were partially prototyped in the MCP binding during v0.1 development and deferred to reduce specification surface area.

## F.4 Deterministic Payload Generation

Protocol-conformant payload generation using `generate` blocks with deterministic seeding:

- **`kind`**: Generation strategy — `unicode` (random Unicode strings), `binary` (random byte sequences), `json` (schema-conformant JSON).
- **`seed`**: Deterministic seed for reproducible fuzzing across runs.
- **Parameters**: Strategy-specific controls (string length ranges, JSON schema constraints, character class restrictions).

Deterministic generation enables regression testing of protocol parsers and validators without requiring LLM infrastructure.

## F.5 LLM Synthesis

Adaptive payload generation using `synthesize` blocks. The `synthesize` field is present in v0.1 binding state schemas as a reserved placeholder. The planned design includes:

- **`prompt`**: Free-text prompt for LLM generation, supporting `{{template}}` interpolation from extractors and request context.
- **Cross-protocol response dispatch**: `when`/`content`/`synthesize` response entries where `synthesize` provides an LLM fallback when static `content` is insufficient.
- **Structured output validation**: Generated content validated against the protocol binding's message schema before injection.
- **Runtime concerns**: Model selection, temperature, caching, retry policy, and content policy enforcement are tool-level configuration, not document-level specification.

The `SynthesizeBlock` type definition is preserved in the v0.1 JSON Schema for forward compatibility.

## F.6 Indicator Trace Evaluation

v0.1 specifies single-message indicator evaluation (`evaluate_indicator`) but leaves trace-level scoping to tool implementers. Future versions will define:

- **Trace-filtering algorithm**: A normative procedure for selecting which observed protocol messages are fed to `evaluate_indicator` based on `indicator.protocol`, `indicator.surface`, `indicator.actor`, and `indicator.direction`.
- **Direction inference**: An algorithm for inferring `indicator.direction` from the target path and protocol binding context when the field is omitted. v0.1 recommends explicit specification; v0.2 will define deterministic inference.

