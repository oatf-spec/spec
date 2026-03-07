---
title: "Introduction"
description: "Abstract, purpose, scope, conformance requirements, and notation for the OATF specification."
---

This specification defines the Open Agent Threat Format (OATF), a YAML-based format for describing security threats against AI agent communication protocols. OATF is built around three core interaction models — user-to-agent, agent-to-agent, and agent-to-tool — and is designed to accommodate current and future protocols serving these models. Version 0.1 includes protocol bindings for MCP, A2A, and AG-UI.

Each OATF document describes a single attack through an attack envelope (protocol-agnostic metadata, classification, and severity), an execution profile (the protocol messages required to simulate the attack), and optionally a set of indicators (observable patterns that determine whether the attack succeeded). Documents with indicators enable closed-loop testing: conforming tools can reproduce the attack and evaluate its outcome from the document alone, without external configuration. Documents without indicators are valid for simulation only.

This specification defines the document structure, schema, protocol binding architecture, detection methods, and conformance requirements for OATF version 0.1.

## 1. Introduction

## 1.1 Purpose

OATF standardizes how threats against agent communication protocols are described, tested, and evaluated.

An OATF document specifies:

- **What the attack is**: classification, severity, and framework mappings.
- **How to execute it**: the protocol messages a simulation tool must produce to reproduce the attack.
- **How to evaluate it**: the observable patterns that determine whether the attack succeeded or was resisted.

Because execution and evaluation are co-located in a single document, the format supports closed-loop security testing. A library of OATF documents functions as a regression suite: after each change to an agent deployment, the suite validates that known threats are still resisted.

### Why testing, not runtime enforcement

Agent-protocol attacks differ fundamentally from traditional web attacks. Web payloads (SQL injection, XSS, path traversal) must be syntactically valid to exploit a deterministic parser, giving them stable structural signatures. Agent-protocol attacks use natural-language persuasion against a probabilistic LLM. The same malicious intent can be rephrased infinitely without shared syntactic features.

This makes signature-based inline blocking (the "WAF for agents" model) inherently brittle: an attacker who reads the published indicators can trivially rephrase to evade them.

OATF indicators are designed for testing (verifying that a specific known payload is caught) and for monitoring (flagging structural anomalies for human review) — never for live enforcement. Effective runtime defenses against agent-protocol threats operate at other layers: model-level guardrails, architectural controls (sandboxing, least privilege, human-in-the-loop approval), and protocol-level design constraints.

## 1.2 Scope

OATF describes protocol-level threats: attacks that manifest in the messages exchanged between agents, tools, and users over agent communication protocols. Version 0.1 includes bindings for MCP, A2A, and AG-UI; the binding architecture ([§7](/specification/protocol-bindings/)) supports additional protocols without changes to the core specification. OATF does not describe:

- Network-layer attacks (DNS rebinding, TLS stripping, packet injection).
- Infrastructure attacks (container escape, credential theft, supply chain compromise of dependencies).
- Model-layer attacks (training data poisoning, model extraction, membership inference) except where they manifest as observable protocol messages.

The format is a description language. It does not define how tools implement transport, logging, metrics, configuration management, or user interfaces.

## 1.3 Conformance

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

A conforming OATF document MUST validate against the schema defined in this specification. The normative JSON Schema is published at `https://oatf.io/schemas/v0.1.json` and distributed as a companion file (`v0.1.json`). The schema validates the protocol-agnostic document core (envelope, execution forms, phases, triggers, extractors, indicators, correlation). Binding-specific state validation — MCP tools/resources/prompts structure, A2A agent card, AG-UI run input — is the responsibility of binding-aware tools and is not enforced by the JSON Schema. The schema at a given `MAJOR.MINOR` URL is immutable: once published, it MUST NOT be modified. Patch releases clarify prose but do not change the schema; minor releases publish a new schema at a new URL (e.g., `v0.2.json`). A conforming tool MAY implement support for a subset of protocol bindings (for example, MCP only) but MUST correctly parse and ignore bindings it does not support.

Several MUST-level constraints defined in this specification are not enforced by the JSON Schema in this version, because they involve cross-field or cross-element semantics better validated with richer diagnostics at the SDK level (see the [SDK specification, §3.2](/sdk/entry-points/)):

- **Uniqueness of names and identifiers.** Indicator IDs (V-010), phase names (V-011), and actor names (V-031) MUST be unique within their respective scopes.
- **Terminal phase ordering.** A terminal phase (one without a trigger) MUST be the last phase in its actor's phase list (V-008).
- **YAML source constraints.** Documents MUST NOT use YAML anchors, aliases, or merge keys (V-020). The `oatf` key SHOULD appear first in the source mapping (V-002); tools that serialize MUST emit it first.
- **Event-mode and surface-protocol validity.** Trigger events MUST be valid for the actor's mode (V-029). Indicator surfaces MUST be valid for the indicator's protocol (V-018).
- **Conditional requiredness.** `phase.mode` is required when `execution.mode` is absent (V-028). `indicator.protocol` is required when `execution.mode` is absent (V-028).
- **Action key cardinality.** Binding-specific action objects MUST contain exactly one non-`x-` key (V-043).

## 1.4 Relationship to Other Standards

OATF complements existing security standards:

- **MITRE ATLAS**: Documents reference ATLAS technique identifiers (AML.T-series) for AI-specific threat classification.
- **MITRE ATT&CK**: Documents reference ATT&CK technique identifiers (T-series) for traditional cyber threat classification.
- **STIX 2.1**: Documents MAY be exported as STIX Attack Pattern objects for integration with threat intelligence platforms. The confidence scale follows STIX's 0–100 model.
- **Sigma**: The indicator structure borrows conventions from Sigma's detection rule format, including logsource abstraction, field-path matching, and value modifiers. Indicators MAY be compiled to Sigma rules for SIEM integration.
- **CEL**: Complex matching conditions use the Common Expression Language.
- **Nuclei**: The single-document model (metadata envelope, execution steps, extractors with template interpolation, detection matchers) draws from ProjectDiscovery's Nuclei template format. OATF adapts this model from network vulnerability scanning to agent protocol threat simulation, replacing HTTP/DNS/TCP protocol bindings with an extensible binding architecture for agent communication protocols and adding semantic detection for natural-language attack surfaces.
- **OWASP**: Documents reference OWASP MCP Top 10 and OWASP Agentic AI Top 10 risk identifiers where applicable.

## 1.5 Notation

Schema definitions in this specification use YAML syntax. Type annotations follow TypeScript conventions for clarity:

> *Note:* YAML was chosen over JSON because attack payloads frequently contain multiline strings with embedded quotes (injected instructions, social engineering text, fabricated system messages). JSON requires escaping every interior quote and represents multiline content as `\n`-delimited single-line strings, making payloads difficult to read and error-prone to edit. YAML's block scalar syntax (`|`, `>`) preserves payload readability without escaping.

- `string`: A UTF-8 string value.
- `integer`: A whole number.
- `number`: A floating-point number.
- `boolean`: `true` or `false`.
- `datetime`: An ISO 8601 date-time string (e.g., `2026-02-15T10:30:00Z`). Bare dates (`2026-02-15`) are accepted and interpreted as midnight UTC.
- `duration`: A time span. ISO 8601 format (`PT30S`, `PT5M`) or shorthand with units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days) — e.g., `30s`, `5m`, `1h`. Shorthand supports exactly one numeric-unit pair. For compound durations, use ISO 8601 form (e.g., `PT1H30M`). `0s` is a valid duration meaning zero elapsed time.
- `enum(a, b, c)`: One of the listed values.
- `T[]`: An ordered list of values of type T.
- `T?`: An optional value of type T. When absent, the field is omitted entirely.
- `map<K, V>`: A mapping from keys of type K to values of type V.

