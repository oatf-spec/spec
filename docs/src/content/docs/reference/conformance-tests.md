---
title: "Conformance Tests"
description: "Data-driven, language-agnostic test fixtures for validating OATF SDK implementations."
---

The [conformance test suite](https://github.com/oatf-spec/spec/tree/main/conformance) is a collection of **YAML fixtures**, containing no test code, that validate SDK implementations against the specification. Each SDK writes its own test runner that loads these fixtures and asserts the expected results. This keeps the fixtures portable across Rust, Python, Go, TypeScript, and any future SDK.

## Structure

Fixtures are organized by [SDK entry point](/sdk/entry-points/):

| Directory | SDK Function | What It Tests |
|---|---|---|
| `parse/valid/` | `parse()` | Valid documents that must parse without error |
| `parse/invalid/` | `parse()` | Malformed documents that must produce `ParseError` |
| `validate/` | `validate()` | Conformance rule checking (V-001 through V-045) |
| `normalize/` | `normalize()` | Default materialization and shorthand expansion |
| `evaluate/` | `evaluate_indicator()` | Indicator evaluation (pattern, expression, semantic) |
| `verdict/` | `compute_verdict()` | Attack-level verdict computation |
| `roundtrip/` | `parse` → `normalize` → `serialize` → `parse` | Serialization stability |
| `primitives/` | Individual functions | Execution primitives (path resolution, conditions, triggers, etc.) |

## Fixture Formats

### Corpus Format (`parse/`)

Raw OATF documents fed directly to `parse()`. Valid documents are standalone `.yaml` files. Invalid documents have a companion `.meta.yaml` sidecar:

```
parse/valid/
  minimal.yaml              # Must parse without error
  all-optional-fields.yaml  # Every optional field populated

parse/invalid/
  not-yaml.yaml             # Garbage input
  not-yaml.meta.yaml        # expected_error: "not valid YAML"
  yaml-with-anchors.yaml    # Uses prohibited YAML features
  yaml-with-anchors.meta.yaml
```

### Suite Format (`validate/`, `normalize/`, `evaluate/`, `verdict/`, `roundtrip/`)

YAML files containing lists of test cases. Every case has four fields:

```yaml
- name: "severity scalar expands to object form"
  id: NORM-001
  input: |
    oatf: "0.1"
    attack:
      severity: high
      execution:
        mode: mcp_server
        state:
          tools:
            - name: test
              description: "test"
  expected: |
    oatf: "0.1"
    attack:
      severity:
        level: high
        confidence: 50
      # ... normalized form
```

For validation tests, `expected` contains the rule IDs and field paths that must appear in the error output:

```yaml
- name: "missing oatf key fails V-001"
  id: VAL-001
  input: |
    attack:
      execution:
        mode: mcp_server
        state:
          tools: [{ name: test, description: test }]
  expected:
    errors:
      - rule: "V-001"
        path: "oatf"
```

### Primitive Format (`primitives/`)

Each file tests a single [execution primitive](/sdk/execution-primitives/) with function-specific inputs:

| File | Function |
|---|---|
| `resolve-simple-path.yaml` | `resolve_simple_path()` |
| `resolve-wildcard-path.yaml` | `resolve_wildcard_path()` |
| `parse-duration.yaml` | `parse_duration()` |
| `evaluate-condition.yaml` | `evaluate_condition()` |
| `evaluate-predicate.yaml` | `evaluate_predicate()` |
| `evaluate-trigger.yaml` | `evaluate_trigger()` |
| `evaluate-extractor.yaml` | `evaluate_extractor()` |
| `interpolate-template.yaml` | `interpolate_template()` |
| `interpolate-value.yaml` | `interpolate_value()` |
| `resolve-event-qualifier.yaml` | `resolve_event_qualifier()` |
| `parse-event-qualifier.yaml` | `parse_event_qualifier()` |
| `select-response.yaml` | `select_response()` |
| `extract-protocol.yaml` | `extract_protocol()` |
| `compute-effective-state.yaml` | `compute_effective_state()` |

## Writing a Test Runner

A minimal test runner:

1. Discovers all fixture files under `conformance/`.
2. Loads each YAML file and iterates over test cases.
3. Calls the corresponding SDK function with the test case `input`.
4. Asserts the result matches `expected`.

A single failing case MUST NOT prevent other cases in the same file from running.

For normalization and roundtrip tests, compare document models structurally (not string equality) to avoid false failures from whitespace, key ordering, or quoting differences.

## Adding Fixtures

1. Find or create an appropriately named `.yaml` file in the corresponding directory.
2. Follow the format documented above.
3. Use a descriptive `name` and a unique `id` (e.g., `VAL-044`, `NORM-025`, `EVAL-PAT-23`).
4. Keep inputs minimal. Include only the fields relevant to the behavior being tested.
5. For validation fixtures, reference the rule ID (V-NNN) in the test case name.

The full fixture schema is documented in [`FIXTURE-SCHEMA.md`](https://github.com/oatf-spec/spec/blob/main/conformance/FIXTURE-SCHEMA.md).
