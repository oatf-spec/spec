---
title: "What is OATF?"
description: "An introduction to the Open Agent Threat Format: what it is, who it's for, and what problems it solves."
---

The **Open Agent Threat Format (OATF)** is a YAML-based specification for describing security threats against AI agent communication protocols. Each OATF document captures everything needed to reproduce a specific attack and evaluate whether an agent is vulnerable to it: the attack scenario, the protocol messages involved, and the observable patterns that indicate success or failure.

## Scope

OATF defines a structured format for:

- Sharing attack definitions between tools and teams
- Reproducing attacks across environments (deterministic for pattern and expression indicators; model-dependent for optional semantic and synthesize extensions)
- Evaluating agent resilience with consistent success criteria
- Building regression suites that track fixes over time

## What a Document Contains

Every OATF document describes a single attack through three layers:

1. **Attack envelope**: protocol-agnostic metadata including name, severity, classification mappings (MITRE ATT&CK, OWASP), and lifecycle status
2. **Execution profile**: the protocol-specific state required to simulate the attack (tool definitions, server responses, agent cards, or UI events)
3. **Indicators** (optional): observable patterns that determine whether the attack succeeded (regex matches on tool arguments, CEL expressions over protocol messages, or semantic analysis of agent responses)

Documents with indicators enable **closed-loop testing**: a conforming tool can reproduce the attack and evaluate its outcome from the document alone, without external configuration.

## Protocol Support

OATF v0.1 includes bindings for three protocols:

| Protocol | Binding Status | Interaction Model |
|---|---|---|
| **MCP** (Model Context Protocol) | Provisional | Agent ↔ Tool |
| **A2A** (Agent-to-Agent) | Provisional | Agent ↔ Agent |
| **AG-UI** (Agent-to-UI) | Provisional | Agent ↔ User Interface |

Additional protocols can be supported by adding new [bindings](/specification/protocol-bindings/).

## Next Steps

- [Quick Start](/getting-started/quick-start/)
- [Core Concepts](/getting-started/concepts/)
- [Format Specification](/specification/)
