# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **Open Agent Threat Format (OATF)** specification repository — the normative definition of a YAML-based format for describing security threats against AI agent communication protocols (MCP, A2A, AG-UI). It contains **no executable code** — only specifications, a JSON Schema, and conformance test fixtures.

Current version: **0.1.0-draft**

## Repository Structure

- `spec/format.md` — Normative format specification (§11.1 document conformance rules, §11.2 normalization rules)
- `spec/sdk.md` — Language-agnostic SDK API contract (entry points, types, evaluation functions, primitives)
- `schemas/v0.1.json` — Normative JSON Schema (draft 2020-12), published at `https://oatf.io/schemas/v0.1.json`
- `conformance/` — Data-driven YAML test fixtures (no test code) organized by SDK entry point:
  - `parse/` — corpus format (valid/invalid raw documents with `.meta.yaml` sidecars)
  - `validate/` — suite format (V-001 through V-039 test cases per §11.1)
  - `normalize/` — suite format (N-001 through N-008 test cases per §11.2)
  - `evaluate/` — suite format (pattern, expression, semantic indicator tests)
  - `verdict/` — suite format (any, all correlation logic modes)
  - `roundtrip/` — suite format (parse→normalize→serialize→parse stability)
  - `primitives/` — function-specific inputs/outputs (resolve_path, parse_duration, etc.)

## No Build System

There is no Makefile, package.json, or any build/test tooling. Validation during editing is done ad-hoc with permitted commands: `python3` and `ruby -ryaml -e`.

To validate YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('path/to/file.yaml'))"`

To validate against the JSON Schema: `python3 -c "import json, yaml, jsonschema; jsonschema.validate(yaml.safe_load(open('file.yaml')), json.load(open('schemas/v0.1.json')))"`

## Key Design Constraints

- **One attack per document** — multi-attack bundles are deliberately rejected
- **`oatf` must be the first key** in canonical serialized form
- **YAML anchors, aliases, and merge keys are prohibited** (V-023)
- **RE2 regex semantics** — linear-time guarantee, partial match
- **Normalization is idempotent** — `normalize(normalize(doc)) == normalize(doc)`
- **Three execution forms** (single-phase `state`, multi-phase `phases`, multi-actor `actors`) are mutually exclusive; all normalize to multi-actor form
- **Protocol and Mode are open enums**; most others are closed
- **Schema is immutable** once published at a versioned URL

## Conformance Test Conventions

- Test case IDs are globally unique: `VAL-NNNx`, `NORM-NNNx`, `RT-NNN`, `EVAL-PAT-NN`, `VERDICT-ANY-NN`, `PATH-NNN`, `DUR-NNN`, etc.
- Test case names are human-readable sentences
- Each fixture tests one specific behavior; keep inputs minimal
- For validation fixtures, reference the rule ID (V-NNN) in the test name
- A failing case must not prevent other cases from running

## Editing Guidelines

- When modifying `spec/format.md` or `spec/sdk.md`, keep validation/normalization rule IDs stable — they are referenced by conformance fixtures
- When adding conformance fixtures, follow the format in `conformance/FIXTURE-SCHEMA.md`
- The JSON Schema (`schemas/v0.1.json`) must stay consistent with `spec/format.md` — changes to one usually require changes to the other
- Cross-reference changes: spec rules → schema constraints → conformance tests should all agree
