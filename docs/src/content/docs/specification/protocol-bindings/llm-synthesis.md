---
title: "LLM Synthesis"
description: "LLM-powered adaptive payload generation across protocol bindings."
---

The `synthesize` block enables LLM-powered adaptive generation across all protocol bindings. For server-mode actors (MCP, A2A), it appears within response entries (`responses`, `task_responses`) as a mutually exclusive alternative to static content. For client-mode actors (AG-UI), it appears within `run_agent_input` as a mutually exclusive alternative to static `messages`.

## Structure

```yaml
synthesize:
  prompt: string    # Required. Supports {{template}} interpolation.
```

## Semantics

When a `synthesize` block is selected (its `when` predicate matched, it is a catch-all, or in AG-UI where it replaces the `messages` array), the adversarial tool MUST:

1. Resolve all `{{template}}` references in the prompt (extractors, request fields, cross-actor references).
2. Send the resolved prompt to the configured LLM.
3. Validate the LLM's output against the protocol binding's expected structure (MCP tool call result, MCP prompt get result, A2A task response, or AG-UI messages array).
4. Inject the validated output into the protocol stream.
5. On validation failure, retry or report an error. Generation failures MUST NOT be sent to the target agent.

## Runtime Concerns

This specification deliberately excludes model configuration from the document. The following are runtime concerns defined by the consuming tool's configuration:

- **Model selection**: Which LLM to use (model name, provider, API endpoint).
- **Temperature and sampling**: How creative or deterministic the generation should be.
- **Caching**: Whether to cache generated responses for reproducibility (record/replay/live modes).
- **Structured output**: Whether to use JSON mode, function calling, or constrained generation to enforce protocol structure.
- **Retry policy**: How to handle validation failures or API errors.

This separation ensures documents are portable across tools and environments: the document specifies the intent, not the model or configuration.

## Distinction from Content-Item Generate

OATF has two generation mechanisms that serve different purposes:

- **Content-item `generate`** ([§7.1.7](/specification/protocol-bindings/mcp/#717-payload-generation-mcp)): Deterministic, seeded, algorithmic. Produces raw payloads (nested JSON, random bytes, unicode stress) for fuzzing attacks. Defined by `kind`, `seed`, and `parameters`. Reproducible across runs with the same seed.
- **`synthesize`** (this section): Non-deterministic, LLM-powered, prompt-driven. Produces protocol-conformant content for adaptive attacks. For server-mode actors, generates response payloads. For client-mode actors (AG-UI), generates fabricated input content (message histories). Defined by a `prompt`. Reproducible only through caching.

