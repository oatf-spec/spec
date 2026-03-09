---
title: "What is OATF?"
description: "An introduction to the Open Agent Threat Format: what it is, who it's for, and what problems it solves."
---

AI agents are being deployed with tool access and cross-agent delegation, but there is no standard way to test whether they resist prompt injection, tool poisoning, or protocol-level attacks. The **Open Agent Threat Format (OATF)** fills that gap: a YAML-based specification where each document captures everything needed to reproduce a specific attack and evaluate whether an agent is vulnerable to it.

OATF serves both **red teams** (security researchers reproducing attacks) and **blue teams** (platform engineers evaluating defenses) from the same document. A library of OATF documents functions as a regression suite — run it after every deployment change to verify that known threats are still resisted.

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

Documents with indicators enable **closed-loop testing**: a conforming tool can reproduce the attack and evaluate its outcome from the document alone, without external configuration. The completeness of closed-loop support depends on the protocol binding's maturity; see [Protocol Support](#protocol-support) for current status.

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
