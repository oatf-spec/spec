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

