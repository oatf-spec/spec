---
title: "Versioning & Lifecycle"
description: "Specification versioning, document lifecycle stages, and extension mechanism."
---

## 10.1 Specification Versioning

The OATF specification version follows Semantic Versioning:

- **Major** versions indicate breaking changes to the document schema.
- **Minor** versions add new included protocol bindings, surfaces, or optional fields. External protocol bindings (defined outside this specification) do not require a new OATF version.
- **Patch** versions clarify existing definitions without changing the schema.

The `oatf` field in each document declares the specification version it conforms to. Version compatibility rules depend on whether the specification has reached 1.0 (see below).

**Pre-1.0 stability:** During the 0.x series, minor versions MAY introduce breaking changes to the document schema. Tools MUST reject documents declaring an unsupported 0.x version. Authors SHOULD expect that documents written for 0.1 may require migration when 0.2 is released.

**Post-1.0 compatibility:** Once OATF reaches 1.0, the following forward-compatibility guarantee applies: tools MUST accept documents declaring a higher minor version within the same major version, ignoring unknown fields. For example, a tool supporting 1.0 MUST accept a document declaring 1.2, skipping any fields or surfaces it does not recognize.

This forward-compatibility guarantee applies to unknown *fields*, not unknown *values* in closed enumerations. When a tool encounters an unrecognized value for a closed enumeration (e.g., a new `impact` category added in a higher minor version), the tool MUST reject the document with a validation error. Open enumerations (Protocol, Mode, Surface, Framework) accept any value matching their pattern constraints, regardless of version.

## 10.2 Document Lifecycle

Documents progress through four lifecycle stages:

```
draft → experimental → stable → deprecated
```

- **draft**: Under active development. May change without notice. Not suitable for production use.
- **experimental**: Complete and testable. At least one tool can consume the document. Changes increment `version`.
- **stable**: Validated against at least one adversarial tool and one evaluation tool. The execution profile reproduces the attack. At least one indicator detects it.
- **deprecated**: The attack is superseded, patched, or no longer relevant. The `description` SHOULD reference the replacement.

## 10.3 Extension Mechanism

The following object types support extension fields prefixed with `x-`: `attack`, `execution`, `actor`, `phase`, `action`, and `indicator`. Conforming tools MUST ignore `x-` prefixed fields they do not understand. Extension fields MUST NOT alter the semantics of standard fields. To avoid collisions between independent extension authors, organizations SHOULD use a unique prefix after `x-`, such as their organization name (e.g., `x-acme-scan-profile`, `x-thoughtgate-alert-severity`). Other object types (triggers, extractors, match conditions, pattern/expression/semantic definitions, severity, correlation, synthesis blocks, references, classifications, framework mappings) do not support extension fields.

```yaml
attack:
  id: OATF-027
  x-thoughtjack:
    scenario_file: "scenarios/injection/tool-response-injection.yaml"
    primitives: [rug_pull]
  x-thoughtgate:
    alert_severity: high
    scan_profile: regression
```

