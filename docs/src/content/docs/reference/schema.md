---
title: "JSON Schema"
description: "The machine-readable JSON Schema companion to the OATF format specification."
---

The OATF JSON Schema is the machine-readable companion to the [format specification](/specification/). It encodes the structural constraints of OATF documents as a [JSON Schema (draft 2020-12)](https://json-schema.org/draft/2020-12/json-schema-core) document.

## What It Validates

The schema validates the **protocol-agnostic document core**:

- Document envelope (`oatf`, `attack`)
- Execution forms (single-phase, multi-phase, multi-actor)
- Phase structure, triggers, and extractors
- Indicator definitions and detection methods
- Correlation logic
- Closed enumeration values

## What It Does Not Validate

**Binding-specific state validation** — MCP tool structure, A2A agent cards, AG-UI run input — is handled by SDK-level validators, not the JSON Schema. Cross-field constraints (unique IDs, terminal phase ordering, event-mode validity) are also validated at the SDK level. See [Conformance](/specification/conformance/) for the full list of validation rules.

## Download

The normative schema is published at a versioned, immutable URL:

```
https://oatf.io/schemas/v0.1.json
```

Once published, the schema at a given `MAJOR.MINOR` URL is immutable — it will not be modified. Patch releases clarify prose but do not change the schema; minor releases publish a new schema at a new URL (e.g., `v0.2.json`).

## IDE Integration

Add a `$schema` field to your OATF documents for autocompletion, inline validation, and hover documentation in editors that support JSON Schema (VS Code, JetBrains IDEs, Neovim with LSP):

```yaml
$schema: "https://oatf.io/schemas/v0.1.json"
oatf: "0.1"

attack:
  id: OATF-001
  name: "My Attack"
  execution:
    mode: mcp_server
    state:
      tools:
        - name: example
          description: "Tool description"
```

The `$schema` field is preserved through parse-normalize-serialize round-trips but is not processed by OATF tools.
