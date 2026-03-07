---
title: "Security & Privacy"
description: "Safe parsing, trace data handling, and responsible use considerations."
---

## 12.1 Safe Parsing

OATF documents are untrusted input. Tools MUST parse them defensively:

- YAML parsing MUST use a safe loader that rejects language-specific type coercion and custom tags (see [§11.1](/specification/conformance/#111-document-conformance) rule 1). Anchors, aliases, and merge keys are banned to eliminate alias-based denial-of-service and parsing ambiguity.
- Regular expressions within documents MUST be evaluated with RE2-compatible engines or enforced time limits (see [§5.7](/specification/execution-profile/#57-expression-evaluation)). A malicious OATF document MUST NOT be able to deny service to the tool consuming it.
- JSONPath evaluation MUST enforce traversal depth limits (see [§5.7](/specification/execution-profile/#57-expression-evaluation)).
- Template interpolation MUST NOT permit recursive expansion — a template that resolves to another `{{...}}` reference MUST NOT be re-evaluated.

## 12.2 Trace Data Handling

Execution of OATF documents produces protocol traces that may contain sensitive information: API keys, credentials, personally identifiable information, or proprietary business data extracted from the target agent's environment. Tools that capture, store, or transmit trace data SHOULD:

- Treat traces as sensitive by default and apply appropriate access controls.
- Provide mechanisms to redact or mask sensitive values in stored traces and verdict evidence.
- Document their data retention and sharing policies.
- Avoid logging full trace content at default verbosity levels.

## 12.3 Responsible Use

OATF documents describe attack techniques against AI agent systems. The same document that enables defensive regression testing can be used to attack production systems. Authors and distributors of OATF documents SHOULD:

- Clearly label documents with their intended use context (research, internal testing, public registry).
- Apply the `attack.status` field (`draft`, `experimental`, `stable`, `deprecated`) to communicate lifecycle state.
- Consider the severity and exploitability of described attacks when deciding publication scope.
- Follow coordinated disclosure practices when publishing documents that describe novel attack techniques against specific agent frameworks or deployments.

This specification does not define access control, distribution restrictions, or classification markings for OATF documents. Organizations adopting OATF SHOULD establish their own policies for document handling consistent with their security practices.

