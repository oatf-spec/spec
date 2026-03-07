#!/usr/bin/env python3
"""Split format.md into Starlight pages with cross-reference conversion."""
import re
import os

SPEC_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'spec', 'format.md')
DOCS_BASE = os.path.join(os.path.dirname(__file__), '..', 'src', 'content', 'docs')

with open(SPEC_PATH) as f:
    lines = f.readlines()

# Find section boundaries by line number
def find_sections(lines):
    """Return list of (line_idx, heading_text) for ## headings."""
    result = []
    for i, line in enumerate(lines):
        if line.startswith('## '):
            result.append((i, line.strip()))
    return result

sections = find_sections(lines)

def get_section_content(start_idx, end_idx):
    """Get lines between start and end, stripping leading/trailing blank lines and trailing ---."""
    content = lines[start_idx:end_idx]
    # Remove the section heading itself
    content = content[1:]
    # Strip trailing ---
    while content and content[-1].strip() in ('---', ''):
        content.pop()
    # Strip leading blank lines
    while content and content[0].strip() == '':
        content.pop(0)
    return ''.join(content)

def section_range(heading_prefix):
    """Find start/end indices for a section by heading prefix."""
    start = None
    for i, (idx, text) in enumerate(sections):
        if heading_prefix in text:
            start = idx
            end = sections[i+1][0] if i+1 < len(sections) else len(lines)
            return start, end
    raise ValueError(f"Section not found: {heading_prefix}")

def demote_headings(text):
    """Shift ### -> ##, #### -> ###, etc."""
    result = []
    for line in text.split('\n'):
        if line.startswith('#### '):
            result.append('### ' + line[5:])
        elif line.startswith('### '):
            result.append('## ' + line[4:])
        elif line.startswith('##### '):
            result.append('#### ' + line[6:])
        else:
            result.append(line)
    return '\n'.join(result)

# Cross-reference mapping
XREF_MAP = {
    '§12': '[§12](/specification/security/)',
    '§11.5': '[§11.5](/specification/conformance/#115-partial-conformance)',
    '§11.4': '[§11.4](/specification/conformance/#114-tool-conformance-evaluation)',
    '§11.3': '[§11.3](/specification/conformance/#113-tool-conformance-adversarial)',
    '§11.2': '[§11.2](/specification/conformance/#112-tool-conformance-general)',
    '§11.1': '[§11.1](/specification/conformance/#111-document-conformance)',
    '§11': '[§11](/specification/conformance/)',
    '§10': '[§10](/specification/versioning/)',
    '§9.2': '[§9.2](/specification/verdict-model/#92-attack-level-verdicts)',
    '§9': '[§9](/specification/verdict-model/)',
    '§8': '[§8](/specification/cross-protocol-chains/)',
    '§7.4': '[§7.4](/specification/protocol-bindings/llm-synthesis/)',
    '§7.3.5': '[§7.3.5](/specification/protocol-bindings/ag-ui/#735-ag-ui-specific-attack-considerations)',
    '§7.3.4': '[§7.3.4](/specification/protocol-bindings/ag-ui/#734-execution-state-ag-ui)',
    '§7.3.3': '[§7.3.3](/specification/protocol-bindings/ag-ui/#733-cel-context-ag-ui)',
    '§7.3': '[§7.3](/specification/protocol-bindings/ag-ui/)',
    '§7.2.5': '[§7.2.5](/specification/protocol-bindings/a2a/#725-a2a-specific-attack-considerations)',
    '§7.2.4': '[§7.2.4](/specification/protocol-bindings/a2a/#724-execution-state-a2a)',
    '§7.2.3': '[§7.2.3](/specification/protocol-bindings/a2a/#723-cel-context-a2a)',
    '§7.2': '[§7.2](/specification/protocol-bindings/a2a/)',
    '§7.1.7': '[§7.1.7](/specification/protocol-bindings/mcp/#717-payload-generation-mcp)',
    '§7.1.6': '[§7.1.6](/specification/protocol-bindings/mcp/#716-behavioral-modifiers-mcp)',
    '§7.1.5': '[§7.1.5](/specification/protocol-bindings/mcp/#715-entry-actions-mcp)',
    '§7.1.4a': '[§7.1.4a](/specification/protocol-bindings/mcp/#714a-execution-state-mcp-client)',
    '§7.1.4': '[§7.1.4](/specification/protocol-bindings/mcp/#714-execution-state-mcp)',
    '§7.1.3': '[§7.1.3](/specification/protocol-bindings/mcp/#713-cel-context-mcp)',
    '§7.1.2': '[§7.1.2](/specification/protocol-bindings/mcp/#712-event-types)',
    '§7.1.1': '[§7.1.1](/specification/protocol-bindings/mcp/#711-surfaces)',
    '§7.1': '[§7.1](/specification/protocol-bindings/mcp/)',
    '§7.0.1': '[§7.0.1](/specification/protocol-bindings/#701-included-bindings-summary)',
    '§7.0': '[§7.0](/specification/protocol-bindings/)',
    '§7': '[§7](/specification/protocol-bindings/)',
    '§6.4': '[§6.4](/specification/indicators/#64-semantic-analysis)',
    '§6.3': '[§6.3](/specification/indicators/#63-expression-evaluation)',
    '§6.2': '[§6.2](/specification/indicators/#62-pattern-matching)',
    '§6.1': '[§6.1](/specification/indicators/#61-structure)',
    '§6': '[§6](/specification/indicators/)',
    '§5.7': '[§5.7](/specification/execution-profile/#57-expression-evaluation)',
    '§5.6': '[§5.6](/specification/execution-profile/#56-response-templates)',
    '§5.5': '[§5.5](/specification/execution-profile/#55-extractors)',
    '§5.4': '[§5.4](/specification/execution-profile/#54-match-predicates)',
    '§5.3': '[§5.3](/specification/execution-profile/#53-triggers)',
    '§5.2': '[§5.2](/specification/execution-profile/#52-phases)',
    '§5.1': '[§5.1](/specification/execution-profile/#51-structure)',
    '§5': '[§5](/specification/execution-profile/)',
    '§4.6': '[§4.6](/specification/document-structure/#46-references)',
    '§4.5': '[§4.5](/specification/document-structure/#45-classification)',
    '§4.4': '[§4.4](/specification/document-structure/#44-impact)',
    '§4.3': '[§4.3](/specification/document-structure/#43-severity)',
    '§4.2': '[§4.2](/specification/document-structure/#42-attack-envelope)',
    '§4.1': '[§4.1](/specification/document-structure/#41-top-level-schema)',
    '§4': '[§4](/specification/document-structure/)',
    '§3.3': '[§3.3](/specification/architecture/#33-versioning)',
    '§3.2': '[§3.2](/specification/architecture/#32-dual-purpose-design)',
    '§3.1': '[§3.1](/specification/architecture/#31-document-model)',
    '§3': '[§3](/specification/architecture/)',
    '§2': '[§2](/specification/terminology/)',
    '§1': '[§1](/specification/)',
}

# Also handle "SDK specification, §3.2" → link to SDK
SDK_XREFS = {
    'SDK specification, §3.2': '[SDK specification, §3.2](/sdk/entry-points/)',
    'sdk.md §3.2': '[SDK specification §3.2](/sdk/entry-points/)',
    'SDK specification': '[SDK specification](/sdk/)',
    'the SDK specification': 'the [SDK specification](/sdk/)',
}

def convert_xrefs(text, current_page=None):
    """Convert §X references to Starlight links."""
    # First handle SDK references
    for pattern, replacement in SDK_XREFS.items():
        text = text.replace(pattern, replacement)

    # Handle section references - sort by length descending to match longest first
    sorted_refs = sorted(XREF_MAP.keys(), key=len, reverse=True)
    for ref in sorted_refs:
        link = XREF_MAP[ref]
        # Match §X.Y when not already inside a link and not followed by more digits
        # Use word boundary after the number
        pattern = re.escape(ref) + r'(?![0-9.])'
        # Don't replace if already inside a markdown link
        text = re.sub(r'(?<!\[)' + pattern, link, text)

    return text

# Page definitions: (heading_match, output_path, title, description)
PAGES = [
    # specification/index.md = Abstract + §1
    {
        'sections': ['## Abstract', '## 1. Introduction'],
        'path': 'specification/index.md',
        'title': 'Introduction',
        'description': 'Abstract, purpose, scope, conformance requirements, and notation for the OATF specification.',
    },
    {
        'sections': ['## 2. Terminology'],
        'path': 'specification/terminology.md',
        'title': 'Terminology',
        'description': 'Key terms and definitions used throughout the OATF specification.',
    },
    {
        'sections': ['## 3. Architecture'],
        'path': 'specification/architecture.md',
        'title': 'Architecture',
        'description': 'Document model, dual-purpose design, and versioning architecture of OATF.',
    },
    {
        'sections': ['## 4. Document Structure'],
        'path': 'specification/document-structure.md',
        'title': 'Document Structure',
        'description': 'Top-level schema, attack envelope, severity, impact, classification, and references.',
    },
    {
        'sections': ['## 5. Execution Profile'],
        'path': 'specification/execution-profile.md',
        'title': 'Execution Profile',
        'description': 'Structure, phases, triggers, match predicates, extractors, response templates, and expression evaluation.',
    },
    {
        'sections': ['## 6. Indicators'],
        'path': 'specification/indicators.md',
        'title': 'Indicators',
        'description': 'Pattern matching, expression evaluation, and semantic analysis for detecting attack outcomes.',
    },
    {
        'sections': ['## 7. Protocol Bindings'],
        'path': 'specification/protocol-bindings/index.md',
        'title': 'Binding Architecture',
        'description': 'Protocol binding architecture, extensibility model, and included bindings summary.',
        'end_before': '### 7.1 MCP Binding',
    },
    {
        'sections': ['### 7.1 MCP Binding'],
        'path': 'specification/protocol-bindings/mcp.md',
        'title': 'MCP Binding',
        'description': 'Model Context Protocol binding — surfaces, events, CEL context, execution state, and behavioral modifiers.',
        'end_before': '### 7.2 A2A Binding',
        'heading_offset': -1,  # ### -> ##
    },
    {
        'sections': ['### 7.2 A2A Binding'],
        'path': 'specification/protocol-bindings/a2a.md',
        'title': 'A2A Binding',
        'description': 'Agent-to-Agent protocol binding — surfaces, events, CEL context, and execution state.',
        'end_before': '### 7.3 AG-UI Binding',
        'heading_offset': -1,
    },
    {
        'sections': ['### 7.3 AG-UI Binding'],
        'path': 'specification/protocol-bindings/ag-ui.md',
        'title': 'AG-UI Binding',
        'description': 'Agent-User Interface protocol binding — surfaces, events, CEL context, and execution state.',
        'end_before': '### 7.4 LLM Synthesis',
        'heading_offset': -1,
    },
    {
        'sections': ['### 7.4 LLM Synthesis'],
        'path': 'specification/protocol-bindings/llm-synthesis.md',
        'title': 'LLM Synthesis',
        'description': 'LLM-powered adaptive payload generation across protocol bindings.',
        'end_before': '## 8. Cross-Protocol',
        'heading_offset': -1,
    },
    {
        'sections': ['## 8. Cross-Protocol Chains'],
        'path': 'specification/cross-protocol-chains.md',
        'title': 'Cross-Protocol Chains',
        'description': 'Modeling multi-protocol attacks with multi-actor execution profiles and indicator correlation.',
    },
    {
        'sections': ['## 9. Verdict Model'],
        'path': 'specification/verdict-model.md',
        'title': 'Verdict Model',
        'description': 'Indicator-level and attack-level verdicts, aggregation algorithm, and verdict metadata.',
    },
    {
        'sections': ['## 10. Versioning and Lifecycle'],
        'path': 'specification/versioning.md',
        'title': 'Versioning & Lifecycle',
        'description': 'Specification versioning, document lifecycle stages, and extension mechanism.',
    },
    {
        'sections': ['## 11. Conformance'],
        'path': 'specification/conformance.md',
        'title': 'Conformance',
        'description': 'Document conformance rules, tool conformance requirements, and partial conformance.',
    },
    {
        'sections': ['## 12. Security and Privacy'],
        'path': 'specification/security.md',
        'title': 'Security & Privacy',
        'description': 'Safe parsing, trace data handling, and responsible use considerations.',
    },
    {
        'sections': ['## Appendix A:'],
        'path': 'examples/prompt-injection.md',
        'title': 'Simple Prompt Injection',
        'description': 'Minimal OATF document demonstrating prompt injection via MCP tool descriptions.',
    },
    {
        'sections': ['## Appendix B:'],
        'path': 'examples/mcp-rug-pull.md',
        'title': 'MCP Rug Pull Attack',
        'description': 'Multi-phase MCP attack that swaps tool definitions after building trust.',
    },
    {
        'sections': ['## Appendix C:'],
        'path': 'examples/a2a-skill-poisoning.md',
        'title': 'A2A Skill Poisoning',
        'description': 'A2A Agent Card with poisoned skill descriptions targeting delegation decisions.',
    },
    {
        'sections': ['## Appendix D:'],
        'path': 'examples/server-instructions.md',
        'title': 'Server Instructions Injection',
        'description': 'MCP server instructions prompt injection with content annotations and identity spoofing.',
    },
    {
        'sections': ['## Appendix E:'],
        'path': 'examples/../reference/diagnostics.md',
        'title': 'Diagnostic Codes',
        'description': 'Non-normative diagnostic warning codes for OATF SDK implementations.',
    },
    {
        'sections': ['## Appendix F:'],
        'path': 'examples/../reference/future-work.md',
        'title': 'Future Work',
        'description': 'Areas under investigation for OATF v0.2, including A2A and AG-UI binding extensions.',
    },
]

def find_line(prefix):
    for i, line in enumerate(lines):
        if line.strip().startswith(prefix):
            return i
    raise ValueError(f"Line not found: {prefix}")

def find_next_section(after_idx, level='## '):
    """Find the next heading at the given level after the given index."""
    for i in range(after_idx + 1, len(lines)):
        if lines[i].startswith(level):
            return i
    return len(lines)

for page in PAGES:
    # Determine start and end indices
    first_section = page['sections'][0]
    start_idx = find_line(first_section)

    if 'end_before' in page:
        end_idx = find_line(page['end_before'])
    elif len(page['sections']) > 1:
        # Multiple sections: find end of last section
        last_start = find_line(page['sections'][-1])
        # Find next ## heading after the last section
        end_idx = find_next_section(last_start)
    else:
        # Single section: find next section at same level
        level = '## ' if first_section.startswith('## ') else '### '
        end_idx = find_next_section(start_idx, level)

    # Extract content (skip the first heading line)
    raw_lines = lines[start_idx:end_idx]

    # For multi-section pages (like Abstract + §1), keep all headings
    # but remove the first one (it becomes the page title)
    content_lines = raw_lines[1:]  # skip first heading

    # Strip trailing --- and blank lines
    while content_lines and content_lines[-1].strip() in ('---', ''):
        content_lines.pop()

    # Strip leading blank lines
    while content_lines and content_lines[0].strip() == '':
        content_lines.pop(0)

    content = ''.join(content_lines)

    # Adjust heading levels
    heading_offset = page.get('heading_offset', 0)

    # For ## sections: ### -> ##, #### -> ###
    # For ### sections (protocol bindings): #### -> ##, ##### -> ###
    if first_section.startswith('### '):
        # Sub-sections of §7: #### -> ##, ##### -> ###
        new_lines = []
        for line in content.split('\n'):
            if line.startswith('##### '):
                new_lines.append('### ' + line[6:])
            elif line.startswith('#### '):
                new_lines.append('## ' + line[5:])
            elif line.startswith('### '):
                # This shouldn't normally happen within a ### section
                new_lines.append(line)
            else:
                new_lines.append(line)
        content = '\n'.join(new_lines)
    else:
        content = demote_headings(content)

    # Convert cross-references
    content = convert_xrefs(content)

    # Build output
    frontmatter = f"""---
title: "{page['title']}"
description: "{page['description']}"
---

"""

    output = frontmatter + content + '\n'

    # Write file
    out_path = os.path.normpath(os.path.join(DOCS_BASE, page['path']))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        f.write(output)
    print(f"  wrote {page['path']}")

print("Done!")
