import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://oatf.io',
  vite: {
    resolve: {
      // Content lives in ../docs via symlink; tell Vite to resolve
      // bare imports (e.g. @astrojs/starlight/components) from website/
      preserveSymlinks: true,
    },
  },
  integrations: [
    starlight({
      title: 'OATF',
      tagline: 'Open Agent Threat Format',
      logo: {
        src: './src/assets/logo.svg',
        replacesTitle: false,
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/oatf-spec/spec' },
      ],
      editLink: {
        baseUrl: 'https://github.com/oatf-spec/spec/edit/main/docs/',
      },
      lastUpdated: true,
      customCss: ['./src/styles/custom.css'],
      head: [
        {
          tag: 'meta',
          attrs: {
            property: 'og:type',
            content: 'website',
          },
        },
        {
          tag: 'meta',
          attrs: {
            property: 'og:description',
            content: 'A specification for describing, simulating, and evaluating security threats against AI agents communicating over MCP, A2A, and AG-UI.',
          },
        },
        {
          tag: 'script',
          attrs: {
            src: 'https://www.googletagmanager.com/gtag/js?id=G-L2KCK6M13F',
            async: true,
          },
        },
        {
          tag: 'script',
          content: "window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-L2KCK6M13F');",
        },
      ],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Overview', slug: 'getting-started/overview' },
            { label: 'Quick Start', slug: 'getting-started/quick-start' },
            { label: 'Concepts', slug: 'getting-started/concepts' },
          ],
        },
        {
          label: 'Specification',
          badge: { text: 'v0.1', variant: 'note' },
          items: [
            { label: 'Introduction', slug: 'specification' },
            { label: 'Terminology', slug: 'specification/terminology' },
            { label: 'Architecture', slug: 'specification/architecture' },
            { label: 'Document Structure', slug: 'specification/document-structure' },
            { label: 'Execution Profile', slug: 'specification/execution-profile' },
            { label: 'Indicators', slug: 'specification/indicators' },
            {
              label: 'Protocol Bindings',
              items: [
                { label: 'Architecture', slug: 'specification/protocol-bindings' },
                { label: 'MCP', slug: 'specification/protocol-bindings/mcp', badge: { text: 'Provisional', variant: 'caution' } },
                { label: 'A2A', slug: 'specification/protocol-bindings/a2a', badge: { text: 'Provisional', variant: 'caution' } },
                { label: 'AG-UI', slug: 'specification/protocol-bindings/ag-ui', badge: { text: 'Provisional', variant: 'caution' } },
                { label: 'LLM Synthesis', slug: 'specification/protocol-bindings/llm-synthesis' },
              ],
            },
            { label: 'Cross-Protocol Chains', slug: 'specification/cross-protocol-chains' },
            { label: 'Verdict Model', slug: 'specification/verdict-model' },
            { label: 'Versioning & Lifecycle', slug: 'specification/versioning' },
            { label: 'Conformance', slug: 'specification/conformance' },
            { label: 'Security & Privacy', slug: 'specification/security' },
          ],
        },
        {
          label: 'SDK Specification',
          items: [
            { label: 'Introduction', slug: 'sdk' },
            { label: 'Core Types', slug: 'sdk/core-types' },
            { label: 'Entry Points', slug: 'sdk/entry-points' },
            { label: 'Evaluation', slug: 'sdk/evaluation' },
            { label: 'Execution Primitives', slug: 'sdk/execution-primitives' },
            { label: 'Extension Points', slug: 'sdk/extension-points' },
            { label: 'Diagnostics', slug: 'sdk/diagnostics' },
            { label: 'Implementation Guidance', slug: 'sdk/implementation-guidance' },
          ],
        },
        {
          label: 'SDKs',
          items: [
            { label: 'Available SDKs', slug: 'sdks' },
          ],
        },
        {
          label: 'Examples',
          items: [
            { label: 'Simple Prompt Injection', slug: 'examples/prompt-injection' },
            { label: 'MCP Rug Pull', slug: 'examples/mcp-rug-pull' },
            { label: 'A2A Skill Poisoning', slug: 'examples/a2a-skill-poisoning' },
            { label: 'Server Instructions Injection', slug: 'examples/server-instructions' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'JSON Schema', slug: 'reference/schema' },
            { label: 'Conformance Tests', slug: 'reference/conformance-tests' },
            { label: 'Diagnostic Codes', slug: 'reference/diagnostics' },
            { label: 'Future Work', slug: 'reference/future-work' },
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
