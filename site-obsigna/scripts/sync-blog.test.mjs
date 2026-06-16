import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalUrl, withCanonical, syncImages } from "./sync-blog.mjs";

test("canonicalUrl maps a post slug to its agentreceipts.ai URL", () => {
  assert.equal(
    canonicalUrl("daemon-process-separation.mdx"),
    "https://agentreceipts.ai/blog/daemon-process-separation/",
  );
  assert.equal(canonicalUrl("post.md"), "https://agentreceipts.ai/blog/post/");
});

test("canonicalUrl maps the index to the blog root", () => {
  assert.equal(canonicalUrl("index.mdx"), "https://agentreceipts.ai/blog/");
});

test("withCanonical injects a canonical link into frontmatter head", () => {
  const input = `---\ntitle: A Post\ndescription: Hi\n---\n\nBody.\n`;
  const out = withCanonical(input, "a-post.mdx");
  assert.match(out, /^---\ntitle: A Post\ndescription: Hi\nhead:\n/);
  assert.match(
    out,
    /rel: canonical\n {6}href: https:\/\/agentreceipts\.ai\/blog\/a-post\/\n---/,
  );
  assert.ok(out.endsWith("Body.\n"), "body is preserved");
});

test("withCanonical leaves a self-canonicalizing post untouched", () => {
  const input = `---\ntitle: A Post\nhead:\n  - tag: link\n    attrs:\n      rel: canonical\n      href: https://agentreceipts.ai/blog/a-post/\n---\n\nBody.\n`;
  assert.equal(withCanonical(input, "a-post.mdx"), input);
});

test("withCanonical leaves content without frontmatter untouched", () => {
  const input = "no frontmatter here\n";
  assert.equal(withCanonical(input, "x.mdx"), input);
});

test("syncImages mirrors flat image files into the output dir", () => {
  const base = mkdtempSync(join(tmpdir(), "syncblog-img-"));
  try {
    const src = join(base, "src");
    const out = join(base, "out");
    mkdirSync(src, { recursive: true });
    writeFileSync(join(src, "hero.png"), "PNGDATA");
    mkdirSync(join(src, "nested")); // directories are skipped

    const n = syncImages(src, out);

    assert.equal(n, 1);
    assert.ok(existsSync(join(out, "hero.png")), "image copied");
    assert.equal(readFileSync(join(out, "hero.png"), "utf8"), "PNGDATA");
    assert.ok(!existsSync(join(out, "nested")), "subdirs not copied");
  } finally {
    rmSync(base, { recursive: true });
  }
});

test("syncImages returns 0 and creates no output when the source dir is absent", () => {
  const base = mkdtempSync(join(tmpdir(), "syncblog-noimg-"));
  try {
    const out = join(base, "out");
    assert.equal(syncImages(join(base, "missing-src"), out), 0);
    assert.ok(!existsSync(out), "no output dir created for an absent source");
  } finally {
    rmSync(base, { recursive: true });
  }
});

test("syncImages clears stale images when the source dir is absent", () => {
  const base = mkdtempSync(join(tmpdir(), "syncblog-stale-"));
  try {
    const out = join(base, "out");
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, "old.png"), "STALE");
    assert.equal(syncImages(join(base, "missing-src"), out), 0);
    assert.ok(!existsSync(join(out, "old.png")), "stale image removed from the mirror");
  } finally {
    rmSync(base, { recursive: true });
  }
});
