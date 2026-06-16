import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import sitemap from "@astrojs/sitemap";
import starlightThemeFlexoki from "starlight-theme-flexoki";
import rehypeMermaid from "rehype-mermaid";

export default defineConfig({
  site: "https://agentreceipts.ai",
  markdown: {
    // Astro 6 dropped the implicit `markdown.gfm` default, expecting the new
    // `unified()` processor to supply it. @astrojs/mdx (5.x) is not yet
    // processor-aware — it reads `markdown.gfm` directly — so without this it
    // sees `undefined` and silently drops remark-gfm, breaking every table
    // (and strikethrough/autolinks) in .mdx files. Set it explicitly until the
    // MDX integration adopts the processor model.
    gfm: true,
    syntaxHighlight: {
      type: "shiki",
      excludeLangs: ["mermaid"],
    },
    rehypePlugins: [[rehypeMermaid, { strategy: "inline-svg" }]],
  },
  integrations: [
    starlight({
      title: "Agent Receipts",
      tagline: "Cryptographically signed audit trails for AI agent actions",
      favicon: "/favicon.svg",
      plugins: [starlightThemeFlexoki({ accentColor: "green" })],
      head: [
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
            name: "Agent Receipts",
            url: "https://agentreceipts.ai",
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
            content: "https://agentreceipts.ai/og.png",
          },
        },
        {
          tag: "meta",
          attrs: {
            property: "twitter:image",
            content: "https://agentreceipts.ai/og.png",
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
            src: "https://plausible.io/js/pa-wNWKLsZ7QhfgLp3YwwaYB.js",
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
        {
          label: "Overview",
          slug: "",
        },
        {
          label: "Specification",
          items: [
            { label: "Overview", slug: "specification/overview" },
            {
              label: "How It Works",
              slug: "specification/how-it-works",
            },
            {
              label: "Trust Model",
              slug: "specification/trust-model",
            },
            {
              label: "Agent Receipt Schema",
              slug: "specification/agent-receipt-schema",
            },
            {
              label: "Action Taxonomy",
              slug: "specification/action-taxonomy",
            },
            { label: "Risk Levels", slug: "specification/risk-levels" },
            {
              label: "Receipt Chain Verification",
              slug: "specification/receipt-chain-verification",
            },
            {
              label: "Parameter Disclosure",
              slug: "specification/parameter-disclosure",
            },
          ],
        },
        {
          label: "Spec (full text)",
          link: "/spec/",
        },
        {
          label: "Ecosystem",
          items: [
            { label: "Overview", slug: "ecosystem" },
            {
              label: "Landscape (living)",
              slug: "ecosystem/landscape",
            },
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
          label: "SDKs & Tooling →",
          link: "https://obsigna.dev",
          attrs: { target: "_blank" },
        },
      ],
    }),
    sitemap(),
  ],
});
