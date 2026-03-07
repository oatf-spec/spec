---
title: "Document Structure"
description: "Top-level schema, attack envelope, severity, impact, classification, and references."
---

## 4.1 Top-Level Schema

Every OATF document MUST be a valid YAML file with the following top-level structure:

```yaml
oatf: "0.1"
$schema: string?               # JSON Schema URL for IDE validation

attack:
  id: string?                    # Optional; required for publication
  name: string?                  # Defaults to "Untitled"
  version: integer?             # Defaults to 1
  status: enum(...)?           # Defaults to "draft"
  created: datetime?
  modified: datetime?
  author: string?
  description: string?
  grace_period: duration?            # Post-terminal observation window

  severity: (<Severity> | string)?  # Optional; no default
  impact: enum(...)[]?
  classification: <Classification>?
  references: <Reference>[]?
  
  execution: <ExecutionProfile>    # One of: state, phases, or actors
  indicators: <Indicator>[]?
  correlation:                     # Optional; defaults logic to "any" when indicators present
    logic: enum(any, all)?
```

### `oatf` (REQUIRED)

The OATF specification version. For this specification, the value MUST be `"0.1"`. The `oatf` field uses `MAJOR.MINOR` format (not full SemVer). The human-readable spec header (`0.1.0-draft`) includes the patch version and pre-release label for editorial tracking; documents declare only `MAJOR.MINOR`.

YAML mappings are conceptually unordered, but the `oatf` field serves as a format identifier — the first thing a human or tool sees when opening a file. Documents SHOULD place `oatf` as the first key. Tools that serialize OATF documents MUST emit `oatf` as the first key in their output (canonical form). Validators MAY warn when `oatf` is not the first key but MUST NOT reject the document on that basis alone.

### `$schema` (OPTIONAL)

A URL pointing to the JSON Schema for this OATF version, enabling IDE validation, autocompletion, and inline documentation. Conforming tools MUST ignore this field during processing; it is tooling metadata, not document content. Example:

```yaml
$schema: "https://oatf.io/schemas/v0.1.json"
```

### `attack` (REQUIRED)

The attack definition. Exactly one attack per document.

> **Field path convention.** Within [§4](/specification/document-structure/), field headings use full dot-paths from the document root (for example, `attack.severity.level`) so their position in the YAML structure is unambiguous. From [§5](/specification/execution-profile/) onward, headings use paths relative to the section's parent object (for example, `phase.name` rather than `attack.execution.phases[].name`) because each section introduces its own scope.
>
> **YAML snippet convention.** Unless a snippet shows the full document (including `oatf:` and `attack:`), YAML code blocks throughout this specification show content **relative to `attack:`** — the outer `attack:` wrapper is omitted for brevity. For example, a snippet beginning with `execution:` represents `attack.execution:` in a complete document.

## 4.2 Attack Envelope

### `attack.id` (OPTIONAL)

A unique, stable identifier for this attack. When present, the identifier MUST match the pattern `{PREFIX}-{NUMBER}` where `PREFIX` is one or more uppercase alphanumeric characters or hyphens (`[A-Z][A-Z0-9-]*`) and `NUMBER` is a numeric sequence of at least three digits (`[0-9]{3,}`). For example: `OATF-001`, `OATF-027`, `ACME-001`, `INTERNAL-1042`.

The prefix `OATF-` is reserved for a future public registry of community-maintained attack documents. The registry's governance, ID assignment process, and hosting will be defined separately before its launch. Until the registry is established, authors MAY use `OATF-` prefixed IDs in documents they intend to contribute to the public registry. Organizations creating private threat scenarios SHOULD use their own prefix (for example, their organization name or an internal project identifier). Identifiers MUST NOT be reused once assigned, even if the attack is deprecated.

When omitted, the document has no stable identifier. This is appropriate for local development and iteration. Tools MUST still function without an `id`, but registries and shared repositories SHOULD require it.

### `attack.name` (OPTIONAL)

A human-readable name for the attack. SHOULD be concise (under 80 characters) and descriptive. Defaults to `"Untitled"` when omitted.

### `attack.version` (OPTIONAL)

The version of this attack document, expressed as a positive integer. Defaults to `1` when omitted. Increments by one each time the document is updated. Higher numbers are newer. Tools or registries that need to know what changed between versions should diff the documents or maintain a changelog externally.

### `attack.status` (OPTIONAL)

The lifecycle status of this attack document. Defaults to `"draft"` when omitted:

- `draft`: Under active development. Schema may change without notice.
- `experimental`: Complete and testable but not yet validated against multiple tools.
- `stable`: Validated against at least one adversarial and one evaluation tool. Changes increment `version`.
- `deprecated`: Superseded or no longer relevant. The `description` SHOULD indicate the replacement.

### `attack.created` (OPTIONAL)

The date and time this document was first published, in ISO 8601 datetime format (e.g., `2026-02-15T10:30:00Z`). Bare dates (`2026-02-15`) are also accepted and interpreted as midnight UTC. Tools MAY populate this from filesystem or version control metadata when absent.

### `attack.modified` (OPTIONAL)

The date and time this document was last modified, in ISO 8601 datetime format. Bare dates are also accepted. Tools MAY populate this from filesystem or version control metadata when absent.

### `attack.author` (OPTIONAL)

The author or organization that created this document.

### `attack.description` (OPTIONAL)

A prose description of the attack: what it does, why it matters, and what conditions enable it. SHOULD provide sufficient context for a security practitioner to understand the threat without reading the execution profile or indicators.

### `attack.grace_period` (OPTIONAL)

The duration to continue observing protocol traffic after all terminal phases complete, before computing the final verdict. Format: shorthand (`30s`, `5m`) or ISO 8601 (`PT30S`, `PT5M`), parsed by `parse_duration`. When absent, the tool uses its own default observation window.

This field enables attack authors to specify observation time for delayed effects — exfiltration, state changes, or unauthorized actions that manifest after the attack simulation ends. For example, a prompt injection that causes the agent to exfiltrate data on its next autonomous action may need a 60-second observation window.

## 4.3 Severity

The `severity` field quantifies the threat level of the attack. It is OPTIONAL; when omitted, severity is absent from the normalized document. This allows authors to defer severity assessment during early development. It accepts two forms:

**Scalar form**: a severity level string that expands to the full object with default confidence:

```yaml
severity: high
# Equivalent to: { level: high, confidence: 50 }
```

**Object form**: the full severity specification:

```yaml
severity:
  level: enum(informational, low, medium, high, critical)
  confidence: integer?  # 0–100, defaults to 50
```

When `severity` is a string, it MUST be one of the valid `level` values. Tools MUST expand the scalar form to the object form before processing.

### `attack.severity.level` (REQUIRED)

The severity classification. These levels align with the CVSS 3.1 qualitative severity ratings (`low`, `medium`, `high`, `critical`), with `informational` corresponding to the CVSS rating `none`. This alignment allows organizations already using CVSS-based triage workflows to adopt OATF severity levels without translation:

- `informational`: Observation only. No direct security impact.
- `low`: Limited impact. Unlikely to cause harm without additional exploitation.
- `medium`: Moderate impact. May cause data exposure, degraded service, or unauthorized actions under specific conditions.
- `high`: Significant impact. Likely to cause data exposure, unauthorized actions, or service disruption.
- `critical`: Severe impact. Enables arbitrary code execution, complete data exfiltration, or full compromise of the agent system.

### `attack.severity.confidence` (OPTIONAL)

How confident the author is in the assigned severity level, expressed as an integer from 0 (no confidence) to 100 (certain). This scale follows the STIX confidence model. Defaults to `50` (neutral) when omitted. A high-severity attack with confidence `30` means the author believes it could be high severity but has limited evidence. A high-severity attack with confidence `90` means the assessment is well-supported.

## 4.4 Impact

The `impact` field describes the categories of harm this attack can cause. While `severity.level` quantifies *how bad* the attack is, `impact` describes *what happens*, enabling appropriate response playbook selection.

The six traditional categories align with ATT&CK's Impact tactic. The two additions are `behavior_manipulation` for the dominant AI agent failure mode (reasoning corrupted through normal protocol inputs, identified by ATLAS AML.TA0011 and OWASP ASI-01) and `data_tampering` for persistent integrity violations against agent memory, context, and capability definitions. Confidentiality splits three ways (`data_exfiltration`, `information_disclosure`, `credential_theft`) because each triggers a different incident response playbook.

```yaml
impact:
  - enum(behavior_manipulation, data_exfiltration, data_tampering,
         unauthorized_actions, information_disclosure, credential_theft,
         service_disruption, privilege_escalation)
```

### `attack.impact` (OPTIONAL)

An array of impact categories. Impact values MUST be unique (duplicates are invalid). Multiple values indicate an attack with several consequence types:

- `behavior_manipulation`: The agent's reasoning or decisions are corrupted by attacker-controlled inputs without modifying persistent data. The agent processes normal protocol content (tool descriptions, task messages, conversation history) that has been crafted to alter its behaviour. This is the dominant impact category for prompt injection and capability poisoning attacks.
- `data_exfiltration`: Sensitive data is actively sent to an attacker-controlled destination such as a webhook URL, external email address, paste site, or remote tool endpoint.
- `data_tampering`: Persistent data is modified by the attacker: agent memory, configuration state, knowledge bases, tool definitions, or stored context. This covers integrity violations where the attack leaves lasting changes that affect future interactions.
- `unauthorized_actions`: The agent performs actions outside its intended scope using its existing permissions, such as modifying files, sending messages, or invoking tools it was not intended to use.
- `information_disclosure`: Sensitive information is revealed to an unauthorized party without active extraction. This includes leaks in agent outputs, tool responses, logs, or error messages (for example, system prompt contents exposed in a response).
- `credential_theft`: Authentication material is exposed in reusable form: API keys, tokens, session cookies, secrets, or cryptographic keys. This differs from `information_disclosure` in that the exposed material grants direct access to protected systems.
- `service_disruption`: The agent or its supporting infrastructure is rendered unavailable, degraded, or unreliable.
- `privilege_escalation`: The attacker gains capabilities beyond those intended for the compromised protocol role.

When an attack has multiple consequences, authors SHOULD include all applicable categories. In particular, when `behavior_manipulation` causes the agent to perform out-of-scope actions, authors SHOULD include both `behavior_manipulation` and `unauthorized_actions`. When `behavior_manipulation` is detected or attempted but blocked before any out-of-scope action occurs, `behavior_manipulation` alone is appropriate.

## 4.5 Classification

The `classification` object maps the attack to external security frameworks and establishes its category within the OATF taxonomy. The entire `classification` object is OPTIONAL.

```yaml
classification:
  category: enum(...)?
  mappings: <FrameworkMapping>[]?
  tags: string[]?
```

### `attack.classification.category` (OPTIONAL)

The attack category within the OATF taxonomy. Categories describe the *mechanism* of the attack (how it works), independent of which protocol it targets. This complements the `impact` field, which describes the *outcome* (what happens when it succeeds):

- `capability_poisoning`: Injecting malicious content into capability descriptions (tool descriptions, skill descriptions, agent card fields) or impersonating trusted capabilities during discovery to manipulate LLM behavior.
- `response_fabrication`: Returning fabricated, misleading, or malicious content in tool responses, task results, or agent outputs.
- `context_manipulation`: Altering the structural context an LLM reasons within: injecting false system messages, rewriting conversation history, reordering messages, or poisoning prompt templates. This covers attacks on the *frame* of reasoning, not malicious *content* within a legitimate response (which is `response_fabrication`).
- `oversight_bypass`: Circumventing human-in-the-loop controls, approval workflows, or confirmation mechanisms.
- `temporal_manipulation`: Exploiting timing, ordering, or state transitions to alter attack behavior over time (rug pulls, sleepers, time bombs).
- `availability_disruption`: Degrading or denying service through resource exhaustion, malformed payloads, or protocol abuse.
- `cross_protocol_chain`: Attacks that span multiple protocols, using one protocol as an entry point to exploit another.

### `attack.classification.mappings` (OPTIONAL)

An array of mappings to external security frameworks. Each mapping identifies a specific entry in a framework and describes its relationship to this attack:

```yaml
mappings:
  - framework: string    # Open; recommended: atlas, mitre_attack, owasp_llm, owasp_mcp, owasp_agentic, cwe, other
    id: string
    name: string?
    url: string?
    relationship: enum(primary, related)?
```

#### `mapping.framework` (REQUIRED)

The external framework being referenced:

- `atlas`: MITRE ATLAS (Adversarial Threat Landscape for AI Systems). IDs follow the `AML.T` prefix (for example, `AML.T0051`, `AML.T0051.001`).
- `mitre_attack`: MITRE ATT&CK. IDs use the `T` prefix for techniques and `TA` prefix for tactics (for example, `T1195.002`, `TA0001`).
- `owasp_llm`: OWASP Top 10 for LLM Applications. IDs follow the `LLM` prefix (for example, `LLM01`, `LLM05`).
- `owasp_mcp`: OWASP Top 10 for MCP Servers. IDs follow the `MCP-` prefix (for example, `MCP-03`, `MCP-06`).
- `owasp_agentic`: OWASP Top 10 for Agentic Applications. IDs follow the `ASI-` prefix (for example, `ASI-01`, `ASI-02`).
- `cwe`: Common Weakness Enumeration. IDs follow the `CWE-` prefix (for example, `CWE-74`, `CWE-918`).
- `other`: Any framework not listed above. Use `name` to identify the framework and `url` to link to the specific entry.

New framework values MAY be added in future OATF minor versions. Tools MUST accept mapping entries with unrecognized `framework` values and treat them as equivalent to `other`.

#### `mapping.id` (REQUIRED)

The identifier of the specific entry within the framework. The format is framework-specific (see examples above).

#### `mapping.name` (OPTIONAL)

A human-readable name for the referenced entry (for example, `"Indirect Prompt Injection"`, `"Supply Chain Compromise"`). Aids readability without requiring the reader to look up the ID.

#### `mapping.url` (OPTIONAL)

A permalink to the referenced entry in the framework's documentation. RECOMMENDED for `other` framework entries. Useful for any framework where identifiers alone may be ambiguous.

#### `mapping.relationship` (OPTIONAL)

How closely this attack maps to the referenced framework entry. Defaults to `primary` when omitted:

- `primary`: The attack directly implements or demonstrates the referenced technique.
- `related`: The attack is related to the referenced technique but does not directly implement it (for example, the attack uses a technique as a prerequisite, or the technique describes a broader class that includes this attack).

**Example:**

```yaml
mappings:
  - framework: atlas
    id: AML.T0051.002
    name: "Indirect Prompt Injection"
  - framework: mitre_attack
    id: T1195.002
    name: "Supply Chain Compromise: Software Supply Chain"
    relationship: related
  - framework: owasp_mcp
    id: MCP-03
  - framework: owasp_agentic
    id: ASI-01
    name: "Agent Goal Hijacking"
  - framework: cwe
    id: CWE-74
    name: "Improper Neutralization of Special Elements in Output"
    relationship: related
```

### `attack.classification.tags` (OPTIONAL)

Free-form tags for filtering and discovery. Tags SHOULD be lowercase and hyphenated. Multiple words use hyphens, not underscores or spaces (for example, `rug-pull`, not `rug_pull` or `Rug Pull`).

Recommended tags to seed consistency across documents:

- Attack pattern: `injection`, `rug-pull`, `poisoning`, `fabrication`, `fuzzing`
- Temporal: `multi-phase`, `sleeper`, `time-bomb`, `single-shot`
- Target: `tool-description`, `agent-card`, `message-history`, `system-prompt`
- Scope: `cross-protocol`, `single-protocol`

## 4.6 References

```yaml
references:
  - url: string
    title: string?
    description: string?
```

External references providing context for the attack: research papers, blog posts, CVE entries, or related OATF documents.

