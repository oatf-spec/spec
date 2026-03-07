---
title: "What is OATF?"
description: "An introduction to the Open Agent Threat Format: what it is, who it's for, and what problems it solves."
---

The **Open Agent Threat Format (OATF)** is a YAML-based specification for describing security threats against AI agent communication protocols. Each OATF document captures everything needed to reproduce a specific attack and evaluate whether an agent is vulnerable to it: the attack scenario, the protocol messages involved, and the observable patterns that indicate success or failure.

## The Problem

AI agents communicate through protocols like MCP (Model Context Protocol), A2A (Agent-to-Agent), and AG-UI (Agent-to-UI). These protocols expose new attack surfaces. Tool descriptions can carry prompt injections, agent cards can contain poisoned skill definitions, and server instructions can manipulate agent behavior.

Today, security researchers describe these attacks in blog posts, proof-of-concept scripts, and ad-hoc tooling. There is no standard way to:

- **Share attack definitions** between tools and teams
- **Reproduce attacks deterministically** across different environments
- **Evaluate agent resilience** with consistent success criteria
- **Build regression suites** that track vulnerability fixes over time

OATF provides the missing standard format for all of these.

## Who It's For

- **Security researchers** documenting agent protocol vulnerabilities
- **Agent developers** building regression test suites for their agents
- **Red teamers** running structured adversarial evaluations
- **Tool builders** creating security scanners, CI integrations, and IDE plugins

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
| **MCP** (Model Context Protocol) | Stable | Agent ↔ Tool |
| **A2A** (Agent-to-Agent) | Provisional | Agent ↔ Agent |
| **AG-UI** (Agent-to-UI) | Provisional | Agent ↔ User Interface |

The binding architecture is extensible. New protocols can be added in future versions without changing the core format.

## Next Steps

- [Quick Start](/getting-started/quick-start/)
- [Core Concepts](/getting-started/concepts/)
- [Format Specification](/specification/)
