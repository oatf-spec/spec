---
title: "LLM Synthesis"
description: "Reserved for a future version."
---

## 7.4 LLM Synthesis (Reserved)

The `synthesize` field appears in binding state schemas as a reserved placeholder. It has no normative semantics in v0.1.

LLM-powered response generation — including adaptive payload synthesis, cross-protocol response dispatch with LLM fallback, and structured output validation — is planned for a future version. See [Future Work §F.5](/reference/future-work/#f5-llm-synthesis) for the design direction.

Tools encountering `synthesize` blocks in v0.1 documents SHOULD emit a warning indicating the feature is not yet supported.
