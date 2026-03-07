#!/usr/bin/env python3
"""Split spec/sdk.md into individual Starlight pages."""

import re

SDK_PATH = "../spec/sdk.md"
OUT_DIR = "src/content/docs/sdk"

# Cross-references within SDK spec (§N → /sdk/page/#anchor)
SDK_XREF_MAP = {
    "§2": "/sdk/core-types/",
    "§2.1": "/sdk/core-types/#21-primitive-types",
    "§2.2": "/sdk/core-types/#22-document",
    "§2.3": "/sdk/core-types/#23-attack",
    "§2.3a": "/sdk/core-types/#23a-correlation",
    "§2.4": "/sdk/core-types/#24-severity",
    "§2.5": "/sdk/core-types/#25-classification",
    "§2.6": "/sdk/core-types/#26-execution",
    "§2.6a": "/sdk/core-types/#26a-actor",
    "§2.7": "/sdk/core-types/#27-phase",
    "§2.7a": "/sdk/core-types/#27a-action",
    "§2.8": "/sdk/core-types/#28-trigger",
    "§2.8a": "/sdk/core-types/#28a-protocolevent",
    "§2.8b": "/sdk/core-types/#28b-triggerresult",
    "§2.8c": "/sdk/core-types/#28c-triggerstate",
    "§2.9": "/sdk/core-types/#29-extractor",
    "§2.10": "/sdk/core-types/#210-matchpredicate",
    "§2.11": "/sdk/core-types/#211-matchcondition",
    "§2.12": "/sdk/core-types/#212-indicator",
    "§2.13": "/sdk/core-types/#213-patternmatch",
    "§2.14": "/sdk/core-types/#214-expressionmatch",
    "§2.15": "/sdk/core-types/#215-semanticmatch",
    "§2.16": "/sdk/core-types/#216-semanticexamples",
    "§2.17": "/sdk/core-types/#217-reference",
    "§2.18": "/sdk/core-types/#218-frameworkmapping",
    "§2.19": "/sdk/core-types/#219-verdict-types",
    "§2.20": "/sdk/core-types/#220-enumerations",
    "§2.21": "/sdk/core-types/#221-surface-registry",
    "§2.22": "/sdk/core-types/#222-event-mode-validity-registry",
    "§2.23": "/sdk/core-types/#223-synthesizeblock",
    "§2.24": "/sdk/core-types/#224-responseentry",
    "§2.25": "/sdk/core-types/#225-qualifier-resolution-registry",
    "§3": "/sdk/entry-points/",
    "§3.1": "/sdk/entry-points/#31-parse",
    "§3.2": "/sdk/entry-points/#32-validate",
    "§3.3": "/sdk/entry-points/#33-normalize",
    "§3.4": "/sdk/entry-points/#34-serialize",
    "§3.5": "/sdk/entry-points/#35-load",
    "§4": "/sdk/evaluation/",
    "§4.1": "/sdk/evaluation/#41-message-abstraction",
    "§4.2": "/sdk/evaluation/#42-evaluate_pattern",
    "§4.3": "/sdk/evaluation/#43-evaluate_expression",
    "§4.4": "/sdk/evaluation/#44-evaluate_indicator",
    "§4.5": "/sdk/evaluation/#45-compute_verdict",
    "§5": "/sdk/execution-primitives/",
    "§5.1": "/sdk/execution-primitives/#51-path-resolution",
    "§5.1.1": "/sdk/execution-primitives/#511-simple-dot-path",
    "§5.1.2": "/sdk/execution-primitives/#512-wildcard-dot-path",
    "§5.2": "/sdk/execution-primitives/#52-parse_duration",
    "§5.3": "/sdk/execution-primitives/#53-evaluate_condition",
    "§5.4": "/sdk/execution-primitives/#54-evaluate_predicate",
    "§5.5": "/sdk/execution-primitives/#55-interpolate_template",
    "§5.5a": "/sdk/execution-primitives/#55a-interpolate_value",
    "§5.6": "/sdk/execution-primitives/#56-evaluate_extractor",
    "§5.7": "/sdk/execution-primitives/#57-select_response",
    "§5.8": "/sdk/execution-primitives/#58-evaluate_trigger",
    "§5.9": "/sdk/execution-primitives/#59-parse_event_qualifier",
    "§5.9a": "/sdk/execution-primitives/#59a-resolve_event_qualifier",
    "§5.10": "/sdk/execution-primitives/#510-extract_protocol",
    "§5.11": "/sdk/execution-primitives/#511-compute_effective_state",
    "§6": "/sdk/extension-points/",
    "§6.1": "/sdk/extension-points/#61-celevaluator",
    "§6.2": "/sdk/extension-points/#62-semanticevaluator",
    "§6.3": "/sdk/extension-points/#63-generationprovider",
    "§7": "/sdk/diagnostics/",
    "§7.0": "/sdk/diagnostics/#70-diagnostic",
    "§7.1": "/sdk/diagnostics/#71-parseerror",
    "§7.2": "/sdk/diagnostics/#72-validationerror",
    "§7.3": "/sdk/diagnostics/#73-evaluationerror",
    "§7.3a": "/sdk/diagnostics/#73a-generationerror",
    "§7.4": "/sdk/diagnostics/#74-error-aggregation",
    "§7.5": "/sdk/diagnostics/#75-oatferror",
    "§8": "/sdk/implementation-guidance/",
    "§8.1": "/sdk/implementation-guidance/#81-language-adaptation",
    "§8.2": "/sdk/implementation-guidance/#82-field-naming",
    "§8.3": "/sdk/implementation-guidance/#83-immutability",
    "§8.4": "/sdk/implementation-guidance/#84-extension-fields",
    "§8.5": "/sdk/implementation-guidance/#85-performance-considerations",
    "§8.6": "/sdk/implementation-guidance/#86-dependency-guidance",
    "§8.7": "/sdk/implementation-guidance/#87-async-evaluation",
    "§9": "/sdk/implementation-guidance/#9-versioning",
    "§9.1": "/sdk/implementation-guidance/#91-sdk-specification-versioning",
    "§9.2": "/sdk/implementation-guidance/#92-format-compatibility",
    "§9.3": "/sdk/implementation-guidance/#93-language-sdk-versioning",
}

# References to the format spec (§N.N from "format specification §X")
FORMAT_XREF_MAP = {
    "§4.1": "/specification/document-structure/#41-top-level-schema",
    "§4.2": "/specification/document-structure/#42-attack-envelope",
    "§4.3": "/specification/document-structure/#43-severity",
    "§5.1": "/specification/execution-profile/#51-execution-forms",
    "§5.2": "/specification/execution-profile/#52-phase-model",
    "§5.3": "/specification/execution-profile/#53-triggers-and-phase-advancement",
    "§5.4": "/specification/execution-profile/#54-dot-path-syntax",
    "§5.5": "/specification/execution-profile/#55-extractors-and-template-interpolation",
    "§6.1": "/specification/indicators/#61-indicator-definition",
    "§6.2": "/specification/indicators/#62-pattern-matching",
    "§6.3": "/specification/indicators/#63-cel-expressions",
    "§6.4": "/specification/indicators/#64-semantic-matching",
    "§7": "/specification/protocol-bindings/",
    "§7.1": "/specification/protocol-bindings/mcp/",
    "§7.1.2": "/specification/protocol-bindings/mcp/#712-events",
    "§7.1.3": "/specification/protocol-bindings/mcp/#713-indicator-evaluation-context",
    "§7.1.4": "/specification/protocol-bindings/mcp/#714-normalization",
    "§7.2": "/specification/protocol-bindings/a2a/",
    "§7.2.2": "/specification/protocol-bindings/a2a/#722-events",
    "§7.3": "/specification/protocol-bindings/a2a/",
    "§7.3.2": "/specification/protocol-bindings/ag-ui/#732-events",
    "§7.4": "/specification/protocol-bindings/llm-synthesis/",
    "§9": "/specification/verdict-model/",
    "§10.1": "/specification/versioning/#101-version-evolution",
    "§11.1": "/specification/conformance/#111-document-conformance",
    "§11.2": "/specification/conformance/#112-tool-conformance-general",
    "§11.2.1": "/specification/conformance/#112-tool-conformance-general",
    "§11.2.10": "/specification/conformance/#112-tool-conformance-general",
}

# Pages to generate
PAGES = [
    {
        "title": "SDK Introduction",
        "description": "Scope, purpose, and conformance requirements for OATF SDK implementations.",
        "output": "index.md",
        "start_heading": "## Abstract",
        "end_heading": "## 2. Core Types",
        "heading_offset": 1,  # ## → ##, ### → ##
    },
    {
        "title": "Core Types",
        "description": "Abstract types that constitute the OATF document model: Document, Attack, Execution, Phase, Indicator, and all supporting types.",
        "output": "core-types.md",
        "start_heading": "## 2. Core Types",
        "end_heading": "## 3. Entry Points",
        "heading_offset": 1,
    },
    {
        "title": "Entry Points",
        "description": "Public SDK operations: parse, validate, normalize, serialize, and load.",
        "output": "entry-points.md",
        "start_heading": "## 3. Entry Points",
        "end_heading": "## 4. Evaluation",
        "heading_offset": 1,
    },
    {
        "title": "Evaluation",
        "description": "Indicator evaluation interface: pattern, expression, semantic evaluation, and verdict computation.",
        "output": "evaluation.md",
        "start_heading": "## 4. Evaluation",
        "end_heading": "## 5. Execution Primitives",
        "heading_offset": 1,
    },
    {
        "title": "Execution Primitives",
        "description": "Shared utility operations: path resolution, duration parsing, condition evaluation, template interpolation, and trigger evaluation.",
        "output": "execution-primitives.md",
        "start_heading": "## 5. Execution Primitives",
        "end_heading": "## 6. Extension Points",
        "heading_offset": 1,
    },
    {
        "title": "Extension Points",
        "description": "Interfaces for CEL evaluation, semantic evaluation, and LLM generation providers.",
        "output": "extension-points.md",
        "start_heading": "## 6. Extension Points",
        "end_heading": "## 7. Diagnostics and Error Types",
        "heading_offset": 1,
    },
    {
        "title": "Diagnostics",
        "description": "Error types, diagnostic codes, and error aggregation for OATF SDK implementations.",
        "output": "diagnostics.md",
        "start_heading": "## 7. Diagnostics and Error Types",
        "end_heading": "## 8. Implementation Guidance",
        "heading_offset": 1,
    },
    {
        "title": "Implementation Guidance",
        "description": "Non-normative guidance for SDK implementors: language adaptation, naming, performance, async patterns, and versioning.",
        "output": "implementation-guidance.md",
        "start_heading": "## 8. Implementation Guidance",
        "end_heading": None,  # to end of file
        "heading_offset": 1,
    },
]


def read_sdk():
    with open(SDK_PATH) as f:
        return f.readlines()


def find_line(lines, heading):
    """Find the line number of a heading."""
    for i, line in enumerate(lines):
        if line.strip() == heading.strip():
            return i
    # Try prefix match for headings with trailing content
    for i, line in enumerate(lines):
        if line.strip().startswith(heading.strip()):
            return i
    raise ValueError(f"Heading not found: {heading}")


def extract_section(lines, start_heading, end_heading):
    """Extract lines between start (inclusive of content after heading) and end heading."""
    start = find_line(lines, start_heading)

    if start_heading == "Abstract":
        # Special case: Abstract is a ## heading, include from next line
        start_content = start + 1
    else:
        # Skip the section heading itself (it becomes the frontmatter title)
        start_content = start + 1

    if end_heading is None:
        end = len(lines)
    else:
        end = find_line(lines, end_heading)

    # Trim leading/trailing blank lines
    content_lines = lines[start_content:end]
    while content_lines and content_lines[0].strip() == "":
        content_lines = content_lines[1:]
    while content_lines and content_lines[-1].strip() == "":
        content_lines = content_lines[:-1]

    return content_lines


def demote_headings(lines, offset):
    """Adjust heading levels: ### → ## (remove one # level)."""
    result = []
    for line in lines:
        m = re.match(r"^(#{2,6})\s", line)
        if m:
            hashes = m.group(1)
            new_level = len(hashes) - offset
            if new_level < 2:
                new_level = 2
            line = "#" * new_level + line[len(hashes):]
        result.append(line)
    return result


def convert_xrefs(text):
    """Convert §N.N references to Markdown links.

    Handles two types:
    1. "format specification §X.Y" → link to format spec page
    2. Plain "§X.Y" → link to SDK page (internal)

    Must avoid double-replacing already-linked references.
    """
    # First, handle "format specification §X.Y.Z" references
    def replace_format_ref(m):
        prefix = m.group(1)  # "format specification " or "format spec "
        section = m.group(2)  # e.g., "§7.1.3"
        url = FORMAT_XREF_MAP.get(section)
        if url:
            return f"[format specification {section}]({url})"
        return m.group(0)

    text = re.sub(
        r"(format specification\s+)(§\d+(?:\.\d+)*(?:[a-z])?)",
        replace_format_ref,
        text
    )

    # Skip already-linked refs: don't match § inside [...](...)
    # Replace standalone §X.Y references with SDK internal links
    def replace_sdk_ref(m):
        # Don't replace if inside a markdown link
        section = m.group(0)
        url = SDK_XREF_MAP.get(section)
        if url:
            return f"[{section}]({url})"
        return section

    # Match §N.N.N that are NOT already inside []() markdown links
    # Use negative lookbehind for [ and negative lookahead for ](
    text = re.sub(
        r"(?<!\[)§\d+(?:\.\d+)*(?:[a-z])?(?!\]\()",
        replace_sdk_ref,
        text
    )

    return text


def strip_hr(lines):
    """Remove horizontal rule lines (---)."""
    return [l for l in lines if l.strip() != "---"]


def write_page(page, lines):
    content_lines = extract_section(lines, page["start_heading"], page["end_heading"])
    content_lines = strip_hr(content_lines)
    content_lines = demote_headings(content_lines, page["heading_offset"])

    content = "".join(content_lines)
    content = convert_xrefs(content)

    # Build frontmatter
    frontmatter = f'---\ntitle: "{page["title"]}"\ndescription: "{page["description"]}"\n---\n\n'

    outpath = f"{OUT_DIR}/{page['output']}"
    with open(outpath, "w") as f:
        f.write(frontmatter + content + "\n")

    print(f"  wrote {outpath}")


def main():
    import os
    os.makedirs(OUT_DIR, exist_ok=True)

    lines = read_sdk()
    print(f"Read {len(lines)} lines from {SDK_PATH}")

    for page in PAGES:
        write_page(page, lines)

    print(f"\nDone: {len(PAGES)} pages written")


if __name__ == "__main__":
    main()
