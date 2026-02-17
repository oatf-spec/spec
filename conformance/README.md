# OATF Conformance Test Suite

Data-driven, language-agnostic test fixtures for validating OATF SDK implementations.

## Overview

This directory contains **YAML fixtures only** — no test code. Each SDK implementation writes its own test runner that loads these fixtures and asserts the expected results. This keeps the fixtures portable across Rust, Python, Go, TypeScript, and any future SDK.

Fixtures are organized by SDK entry point, matching the operations defined in the [SDK Specification](../spec/sdk.md):

| Directory | SDK Entry Point | What It Tests |
|---|---|---|
| `parse/` | `parse()` | YAML deserialization into typed document model |
| `validate/` | `validate()` | Conformance rule checking (V-001 through V-023) |
| `normalize/` | `normalize()` | Default materialization and shorthand expansion |
| `evaluate/` | `evaluate_indicator()` | Indicator evaluation against protocol messages |
| `verdict/` | `compute_verdict()` | Attack-level verdict computation from indicator results |
| `roundtrip/` | `parse()` → `normalize()` → `serialize()` → `parse()` | Serialization round-trip stability |
| `primitives/` | `resolve_path()`, `evaluate_condition()`, etc. | Individual execution primitives |

## Fixture Formats

Three formats are used, documented in [FIXTURE-SCHEMA.md](FIXTURE-SCHEMA.md):

- **Corpus format** (`parse/`) — Raw OATF documents with companion metadata sidecars for invalid cases.
- **Suite format** (`validate/`, `normalize/`, `evaluate/`, `verdict/`, `roundtrip/`) — YAML files containing lists of test cases with `name`, `id`, `input`, and `expected` fields.
- **Primitive format** (`primitives/`) — YAML files containing lists of test cases with function-specific inputs and expected outputs.

## How to Write a Test Runner

A minimal test runner:

1. Discovers all fixture files under `conformance/`.
2. Loads each YAML file and iterates over test cases.
3. Calls the corresponding SDK function with the test case `input`.
4. Asserts the result matches `expected`.

For `parse/valid/`, the runner calls `parse()` on each `.yaml` file and asserts no error is returned. For `parse/invalid/`, it calls `parse()` and asserts a `ParseError` is returned.

For suite-format directories, the runner loads each `.yaml` file as a list, iterates the cases, and asserts each one independently. A single failing case MUST NOT prevent other cases in the same file from running.

## How to Add New Fixtures

1. Determine which entry point the fixture tests.
2. Find or create an appropriately named `.yaml` file in the corresponding directory.
3. Follow the format defined in [FIXTURE-SCHEMA.md](FIXTURE-SCHEMA.md).
4. Use a descriptive `name` and a unique `id` (convention: `{directory}-{NNN}`, e.g., `validate-042`).
5. Run your SDK's test runner to verify the fixture works.

### Naming Conventions

- **File names** describe the area being tested: `severity-defaults.yaml`, `pattern-shorthand.yaml`, `ordered-logic.yaml`.
- **Test case IDs** are globally unique within the suite. Use the directory prefix and a zero-padded number.
- **Test case names** are human-readable sentences: `"severity scalar expands to object form"`.

### Guidelines

- Each fixture should test one specific behavior. Combine related cases in a single file, but keep each case independent.
- Include both positive (expected to succeed) and negative (expected to fail) cases.
- For validation fixtures, reference the rule ID (`V-001`, etc.) in the test case name or description.
- Keep OATF document inputs minimal — include only the fields relevant to what is being tested.
