---
title: "Architecture"
description: "Document model, dual-purpose design, and versioning architecture of OATF."
---

## 3.1 Document Model

An OATF document describes a single attack. Every document has:

- An **attack envelope**: protocol-agnostic metadata, classification, and severity.
- An **execution profile**: the protocol messages required to simulate the attack.

The attack envelope is the same regardless of which protocols are involved. A capability poisoning attack has one identity, one severity, and one set of framework mappings whether it targets MCP, A2A, or both.

The execution profile describes the ordered steps an adversarial tool performs to simulate the attack. Each step targets a specific protocol and specifies the messages to produce. Single-protocol attacks have steps targeting one protocol. Cross-protocol attacks have steps targeting multiple protocols.

A document MAY also include:

- **Indicators**: observable patterns that determine whether the attack succeeded.

Indicators answer the question "did the agent comply with the attack?" Each indicator targets a specific protocol and surface, examining the agent's behavior in response to the simulated attack: tool calls with exfiltrated data, compliance with injected instructions, unauthorized actions. An attack MAY have indicators for protocols not covered by its execution profile. For example, an attack executed via MCP may include indicators examining the agent's subsequent tool calls or message content for evidence of exploitation.

Documents without indicators are valid for simulation: adversarial tools can reproduce the attack from the execution profile alone. Adding indicators closes the loop: tools can determine whether the agent was exploited and produce a verdict.

> Indicators SHOULD examine the agent's *response* to the attack, not the attack payload itself. An indicator on the payload would always fire: the execution profile placed that content there.

> One document per attack. Multi-attack bundles were considered and rejected: they couple the lifecycle of unrelated attacks.

## 3.2 Dual-Purpose Design

When indicators are present, a document co-locates the execution profile (how to perform the attack) and the indicators (how to determine if the agent was exploited). A single tool can execute the attack and automatically evaluate the outcome in a closed loop, producing a verdict without manual interpretation. A library of OATF documents functions as a regression suite that runs end-to-end after each change to an agent deployment.

The two halves of the document are deliberately independent of each other:

**Adversarial tools** (red team) read the execution profile. They simulate the attack by producing the specified protocol messages in the specified order, evaluating triggers to advance between phases, and using extractors to carry state between steps. An adversarial tool MUST be able to reproduce the attack from the execution profile alone without consulting the indicators.

**Evaluation tools** (blue team / purple team) read the indicators. They examine protocol traffic for evidence that the agent complied with the attack and produce verdicts. An evaluation tool MUST be able to assess indicators without consulting the execution profile. Evaluation tools MUST reject documents without indicators with a clear error rather than silently producing a pass verdict.

Both consumers read the attack envelope for classification and severity metadata.

This independence means a tool MAY implement only one side. A simulation tool may consume only execution profiles. A monitoring tool may consume only indicators. The format is designed for tools that consume both.

## 3.3 Versioning

The top-level `oatf` field declares the specification version the document conforms to. This specification defines version `0.1`.

Documents carry their own `attack.version` field (a positive integer) independent of the specification version. When an attack description is updated (for example, to add an indicator for a new protocol), the document version increments.

