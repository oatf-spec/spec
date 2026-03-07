---
title: "SDKs"
description: "Available SDK implementations for working with OATF documents."
---

OATF SDKs are libraries that parse, validate, normalize, evaluate, and serialize OATF documents. They implement the [SDK specification](/sdk/) so that tools can work with OATF documents without reimplementing the format's semantics.

## Available SDKs

### Rust: `oatf`

The reference implementation of the OATF SDK specification.

- **Repository:** [github.com/oatf-spec/oatf-rs](https://github.com/oatf-spec/oatf-rs)
- **Crate:** [crates.io/crates/oatf](https://crates.io/crates/oatf)
- **API Docs:** [docs.rs/oatf](https://docs.rs/oatf)

```toml
[dependencies]
oatf = "0.1"
```

## Building an SDK

The [SDK specification](/sdk/) defines the language-agnostic API contract: entry points, types, evaluation interfaces, and error taxonomy. The [conformance test suite](/reference/conformance-tests/) provides ~374 data-driven YAML fixtures for validating implementations.

Key resources:

- [Entry Points](/sdk/entry-points/): `parse`, `validate`, `normalize`, `serialize`, `load`
- [Core Types](/sdk/core-types/): the abstract document model
- [Evaluation](/sdk/evaluation/): indicator evaluation and verdict computation
- [Execution Primitives](/sdk/execution-primitives/): path resolution, conditions, triggers
- [Implementation Guidance](/sdk/implementation-guidance/): language adaptation, naming, async patterns
