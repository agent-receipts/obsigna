import { docsLoader } from "@astrojs/starlight/loaders";
import { docsSchema } from "@astrojs/starlight/schema";
import { defineCollection, z } from "astro:content";

export const collections = {
  docs: defineCollection({
    loader: docsLoader(),
    // `ogImage` lets a high-value page override the default social card with a
    // bespoke one (absolute URL or site-root-relative path). Read by the custom
    // Head override (src/components/Head.astro).
    schema: docsSchema({
      extend: z.object({
        ogImage: z.string().optional(),
      }),
    }),
  }),
};
