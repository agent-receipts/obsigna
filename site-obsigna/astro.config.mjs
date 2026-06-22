import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import sitemap from "@astrojs/sitemap";
import starlightThemeFlexoki from "starlight-theme-flexoki";
import rehypeMermaid from "rehype-mermaid";

export default defineConfig({
  site: "https://obsigna.dev",
  markdown: {
    // See site/astro.config.mjs for explanation of why this is set explicitly.
    gfm: true,
    syntaxHighlight: {
      type: "shiki",
      excludeLangs: ["mermaid"],
    },
    rehypePlugins: [[rehypeMermaid, { strategy: "inline-svg" }]],
  },
  integrations: [
    starlight({
      title: "Obsigna",
      tagline: "Tooling for the Agent Receipts protocol",
      favicon: "/favicon.svg",
      plugins: [starlightThemeFlexoki({ accentColor: "orange" })],
      head: [
        // Go vanity import path — resolves obsigna.dev/{sdk/go,daemon,...} for `go get`.
        // Must be present on every page (including 404) so the Go toolchain can fetch
        // any subpath with ?go-get=1 and find the redirect. Starlight's head config
        // injects into all generated pages including the 404 route.
        {
          tag: "meta",
          attrs: {
            name: "go-import",
            content:
              "obsigna.dev git https://github.com/agent-receipts/obsigna",
          },
        },
        {
          tag: "meta",
          attrs: {
            name: "go-source",
            content:
              "obsigna.dev https://github.com/agent-receipts/obsigna https://github.com/agent-receipts/obsigna/tree/main{/dir} https://github.com/agent-receipts/obsigna/blob/main{/dir}/{file}#L{line}",
          },
        },
        {
          tag: "link",
          attrs: { rel: "apple-touch-icon", href: "/apple-touch-icon.png" },
        },
        {
          tag: "link",
          attrs: {
            rel: "me",
            href: "https://github.com/agent-receipts",
          },
        },
        {
          tag: "script",
          attrs: { type: "application/ld+json" },
          content: JSON.stringify({
            "@context": "https://schema.org",
            "@type": "WebSite",
            name: "Obsigna",
            url: "https://obsigna.dev",
            publisher: {
              "@type": "Organization",
              name: "Agent Receipts",
              url: "https://agentreceipts.ai",
              sameAs: ["https://github.com/agent-receipts"],
            },
          }),
        },
        // Default social-share image (per-page frontmatter can override).
        {
          tag: "meta",
          attrs: {
            property: "og:image",
            content: "https://obsigna.dev/og.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "twitter:image",
            content: "https://obsigna.dev/og.png",
          },
        },
        {
          tag: "meta",
          attrs: { name: "twitter:card", content: "summary_large_image" },
        },
        // Privacy-friendly, cookieless analytics (Plausible per-site script).
        {
          tag: "script",
          attrs: {
            async: true,
            src: "https://plausible.io/js/pa-hqsQgQA7hN9-7bMthXXP8.js",
          },
        },
        {
          tag: "script",
          content:
            "window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init()",
        },
      ],
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/agent-receipts/obsigna",
        },
      ],
      components: {
        SocialIcons: "./src/components/SocialIcons.astro",
      },
      customCss: ["./src/styles/custom.css"],
      sidebar: [
        // Standalone client-side verifier in public/verify/ (not a Starlight
        // content page), linked here so it is discoverable from every doc page.
        { label: "Verify a chain", link: "/verify/", badge: { text: "Tool" } },
        {
          label: "Getting Started",
          items: [
            { label: "Introduction", slug: "" },
            { label: "Quick Start", slug: "getting-started/quick-start" },
            { label: "Daemon Setup", slug: "getting-started/daemon-setup" },
            { label: "End-to-End Walkthrough", slug: "getting-started/end-to-end" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "CLI Commands", slug: "reference/cli-commands" },
            { label: "Configuration", slug: "reference/configuration" },
          ],
        },
        {
          label: "Hook",
          items: [
            { label: "Overview", slug: "hook/overview" },
            { label: "Installation", slug: "hook/installation" },
            { label: "Claude Code", slug: "hook/claude-code" },
          ],
        },
        {
          label: "OpenCode",
          items: [
            { label: "Overview", slug: "opencode/overview" },
            { label: "Plugin Installation", slug: "opencode/installation" },
            { label: "MCP Proxy (Tier A)", slug: "opencode/mcp-proxy" },
          ],
        },
        {
          label: "MCP Proxy",
          items: [
            { label: "Overview", slug: "mcp-proxy/overview" },
            { label: "Installation", slug: "mcp-proxy/installation" },
            { label: "Configuration", slug: "mcp-proxy/configuration" },
            { label: "Remote MCP Servers", slug: "mcp-proxy/remote-servers" },
            { label: "Approval Server", slug: "mcp-proxy/approval-ui" },
            { label: "Claude Desktop", slug: "mcp-proxy/claude-desktop" },
            { label: "Claude Code", slug: "mcp-proxy/claude-code" },
            { label: "Codex", slug: "mcp-proxy/codex" },
            { label: "Cursor", slug: "mcp-proxy/cursor" },
            { label: "Windsurf", slug: "mcp-proxy/windsurf" },
            { label: "VS Code Copilot", slug: "mcp-proxy/vscode-copilot" },
            {
              label: "JetBrains AI Assistant",
              slug: "mcp-proxy/jetbrains",
            },
            { label: "Cline", slug: "mcp-proxy/cline" },
          ],
        },
        {
          label: "Dashboard",
          items: [
            { label: "Overview", slug: "dashboard/overview" },
            { label: "Installation", slug: "dashboard/installation" },
          ],
        },
        {
          label: "Go SDK",
          items: [
            { label: "Overview", slug: "sdk-go/overview" },
            { label: "Installation", slug: "sdk-go/installation" },
            { label: "API Reference", slug: "sdk-go/api-reference" },
          ],
        },
        {
          label: "TypeScript SDK",
          items: [
            { label: "Overview", slug: "sdk-ts/overview" },
            { label: "Installation", slug: "sdk-ts/installation" },
            { label: "API Reference", slug: "sdk-ts/api-reference" },
          ],
        },
        {
          label: "Python SDK",
          items: [
            { label: "Overview", slug: "sdk-py/overview" },
            { label: "Installation", slug: "sdk-py/installation" },
            { label: "API Reference", slug: "sdk-py/api-reference" },
          ],
        },
        {
          label: "Deployment",
          items: [
            {
              label: "Ephemeral Compute",
              slug: "deployment/ephemeral-compute",
            },
            {
              label: "Collector Operations",
              slug: "deployment/collector-operations",
            },
          ],
        },
        {
          label: "OpenClaw",
          items: [
            { label: "Overview", slug: "openclaw/overview" },
            { label: "Installation", slug: "openclaw/installation" },
            { label: "CLI Reference", slug: "openclaw/cli-reference" },
            { label: "Agent Tools", slug: "openclaw/agent-tools" },
          ],
        },
        {
          label: "Blog",
          items: [
            { label: "All Posts", slug: "blog" },
            {
              label: "Your agents are isolated. Your shared state isn't.",
              slug: "blog/attribution-over-undo",
            },
            {
              label: "Agent Security Tooling Landscape — May 2026",
              slug: "blog/agent-security-tooling-landscape-may-2026",
            },
            {
              label: "The audit boundary belongs outside the agent",
              slug: "blog/daemon-process-separation",
            },
            {
              label: "OpenClaw Plugin: How It Works",
              slug: "blog/openclaw-plugin-deep-dive",
            },
            {
              label: "Agent Security Tooling Landscape — April 2026",
              slug: "blog/agent-security-tooling-landscape-april-2026",
            },
          ],
        },
        {
          label: "Protocol Spec →",
          link: "https://agentreceipts.ai",
          attrs: { target: "_blank" },
        },
      ],
    }),
    sitemap(),
  ],
});
