---
title: "Diagnostic Codes"
description: "Non-normative diagnostic warning codes for OATF SDK implementations."
---

SDKs that implement the validation and evaluation pipeline (see the [SDK specification](/sdk/)) produce structured diagnostics. The following warning codes are defined for v0.1. These are non-normative summaries — the [SDK specification](/sdk/) is authoritative.

| Code  | Condition |
|-------|-----------|
| W-001 | `oatf` is not the first key in the document. |
| W-002 | A mode passes pattern validation but is not in the known modes registry. Likely typo. |
| W-003 | A protocol passes pattern validation but is not in the known protocols set. Likely typo. |
| W-004 | Template interpolation references an undefined extractor or an unresolvable message path. |
| W-005 | An indicator targets a protocol with no matching actor in the execution profile. |

Authors encountering these warnings should review the flagged fields. W-002 and W-003 in particular catch common typos in mode and protocol strings (e.g., `mpc_server` instead of `mcp_server`).

