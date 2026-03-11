---
title: "Terminology"
description: "Key terms and definitions used throughout the OATF specification."
---

**Agent**: A software system that uses a large language model (LLM) to make decisions and take actions. An agent may act as a client or server depending on the protocol.

**Agent Communication Protocol**: A structured protocol governing message exchange between agents, tools, or users. OATF's core specification is protocol-agnostic; specific protocols are supported through protocol bindings ([§7](/specification/protocol-bindings/)).

**Interaction Model**: One of three fundamental categories of agent communication, independent of any specific protocol:
- **User-to-Agent**: A human provides input and receives responses from an agent (e.g., AG-UI).
- **Agent-to-Agent**: Agents delegate to, collaborate with, or discover other agents (e.g., A2A, or MCP when used for agent-to-agent communication).
- **Agent-to-Tool**: An agent invokes external capabilities through a tool protocol (e.g., MCP).

**Protocol Binding**: A specification extension that defines the protocol-specific surfaces, event types, execution state structures, CEL context, and naming conventions for a particular agent communication protocol. Bindings are defined in [§7](/specification/protocol-bindings/) and may be added in future OATF versions or as external extensions.

**Attack**: A specific threat scenario targeting one or more agent communication protocols. An attack is the unit of description in OATF.

**Attack Envelope**: The protocol-agnostic portion of an OATF document: metadata, classification, severity, and framework mappings. The envelope describes *what* the attack is.

**Execution Profile**: The protocol-specific portion of an OATF document that specifies the messages required to simulate the attack. The execution profile describes *how to perform* the attack.

**Indicator**: A protocol-specific pattern describing observable evidence that the agent complied with the attack. Each indicator targets a specific protocol and attack surface, examining the agent's behavior in response to the simulated attack.

**Surface**: A protocol operation name used to scope indicators to a specific kind of traffic (for example, `tools/call` in MCP, `agent_card/get` in A2A, or `run_agent_input` in AG-UI). Surface values are defined by protocol bindings.

**Phase**: A distinct stage in a multi-step attack. Phases execute sequentially. Each phase defines protocol messages to produce and conditions that trigger advancement to the next phase.

**Verdict**: The outcome of evaluating indicators against observed protocol traffic. Indicator-level verdicts roll up into an attack-level verdict indicating whether the agent was exploited.
