"""Extract fenced code blocks from READMEs and assemble them into compilable units.

This module is pure (no IO beyond the markdown text passed in) so it can be unit
tested without a toolchain. The companion ``check.py`` writes the units to disk
and drives the per-language compiler / type-checker.

Selection rules:

* Only fenced blocks whose language is one we test (Go, TypeScript, Python) and
  that import the SDK are checked. Everything else (``bash`` install lines,
  illustrative output, etc.) is ignored.
* A block is checked in isolation by default — "would this compile if a reader
  pasted it into a fresh file against the published SDK?".
* An HTML-comment directive on the line(s) before a fence overrides this:
    ``<!-- snippet-check: continues -->`` concatenates the block onto the
    previous checked block in the same README so snippets that build on earlier
    state (store/verify follow-ons) resolve their references.
    ``<!-- snippet-check: skip -->`` opts a block out entirely (intentionally
    partial pseudo-code).
    ``<!-- snippet-check: no-run -->`` keeps the block under the type-check gate
    but opts it out of the execute gate — for snippets that can't run in a
    hermetic clean tmpdir (they need a daemon, the network, AWS, a writable
    system path, …). The block is still extracted and compiled / type-checked;
    only execution is skipped (``Unit.run`` is ``False``).
  Directives are invisible in rendered markdown. Unmarked blocks are checked by
  default, so a newly added quick-start snippet is covered without anyone
  remembering to annotate it — which is the drift this gate exists to catch.

Directive syntax is the HTML comment ``<!-- snippet-check: ... -->`` in ``.md``
and the JSX comment ``{/* snippet-check: ... */}`` in ``.mdx`` (HTML comments
aren't valid MDX). Both forms are recognised identically.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass, field

# Normalised language -> the info-strings that map to it.
_INFO_TO_LANG = {
    "go": "go",
    "typescript": "ts",
    "ts": "ts",
    "python": "py",
    "py": "py",
}

# A block counts as "documents the SDK" only if its body matches one of these.
# The Go pattern deliberately matches the *wrong* module path too
# (``agent-receipts/sdk-go`` vs the real ``agent-receipts/ar/sdk/go``) so that a
# snippet importing a non-existent module is still selected and then fails to
# build — that drift is exactly what we want to surface.
_SDK_IMPORT_PATTERN = {
    "go": re.compile(r"github\.com/agent-receipts/(?:ar/sdk/go|sdk-go)"),
    "ts": re.compile(r"""['"]@obsigna/sdk-ts(?:/[\w-]+)?['"]"""),
    "py": re.compile(r"\b(?:from|import)\s+obsigna\b"),
}

# The opener fixes the closer: an HTML comment (``<!--``) must close with
# ``-->`` and a JSX comment (``{/*``) with ``*/}``. The conditional ``(?(html)…)``
# enforces the matching pair so a mismatched directive (``<!-- … */}``) isn't
# silently accepted, which would quietly skip or no-run a snippet on invalid syntax.
_DIRECTIVE_RE = re.compile(
    r"(?:(?P<html><!--)|\{/\*)\s*snippet-check:\s*(?P<directive>[\w-]+)\s*(?(html)-->|\*/\})"
)
_FENCE_RE = re.compile(r"^(?P<indent>\s*)(?P<ticks>`{3,})(?P<info>.*)$")

_VALID_DIRECTIVES = {"continues", "skip", "no-run"}


@dataclass
class Block:
    """A single fenced code block."""

    lang: str  # normalised: "go" | "ts" | "py" | raw info-string otherwise
    code: str
    line: int  # 1-based line number of the opening fence
    directive: str | None = None


@dataclass
class Unit:
    """A compilation unit: one or more blocks rendered into a single source file."""

    lang: str  # "go" | "ts" | "py"
    name: str
    code: str
    sources: list[str] = field(default_factory=list)
    # False when any block in the unit carries the ``no-run`` directive: the
    # snippet still type-checks but can't be executed hermetically (it needs a
    # daemon, the network, a writable system path, …). The execute gate skips
    # these; the type-check gate still covers them.
    run: bool = True


def parse_blocks(text: str) -> list[Block]:
    """Return every fenced code block in ``text`` with any attached directive.

    The directive is taken from the most recent ``<!-- snippet-check: ... -->``
    comment that appears before the fence with only blank lines in between.
    """

    blocks: list[Block] = []
    lines = text.splitlines()
    pending_directive: str | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        directive_match = _DIRECTIVE_RE.search(line)
        if directive_match:
            value = directive_match.group("directive").lower()
            # An unrecognised snippet-check comment breaks any pending directive
            # rather than letting it leak onto the next fence.
            pending_directive = value if value in _VALID_DIRECTIVES else None
            i += 1
            continue

        fence = _FENCE_RE.match(line)
        if not fence:
            # A non-blank, non-directive line breaks the association between a
            # pending directive and a later fence.
            if line.strip():
                pending_directive = None
            i += 1
            continue

        ticks = fence.group("ticks")
        info = fence.group("info").strip()
        raw_lang = info.split()[0].lower() if info else ""
        lang = _INFO_TO_LANG.get(raw_lang, raw_lang)
        start_line = i + 1

        body: list[str] = []
        i += 1
        while i < len(lines):
            close = _FENCE_RE.match(lines[i])
            if close and close.group("ticks") == ticks and not close.group("info").strip():
                break
            body.append(lines[i])
            i += 1

        # Fences nested in list items are indented; strip the common leading
        # whitespace so the snippet parses (Python especially) without changing
        # relative indentation.
        blocks.append(
            Block(
                lang=lang,
                code=textwrap.dedent("\n".join(body)),
                line=start_line,
                directive=pending_directive,
            )
        )
        pending_directive = None
        i += 1

    return blocks


def _imports_sdk(lang: str, code: str) -> bool:
    pattern = _SDK_IMPORT_PATTERN.get(lang)
    return bool(pattern and pattern.search(code))


def build_units(readme_label: str, text: str, lang: str, mode: str = "typecheck") -> list[Unit]:
    """Assemble compilation units for a single README and target language.

    ``readme_label`` is a human-readable source reference (e.g. the README path),
    used both for diagnostics and to derive stable unit names. ``mode`` selects
    how units are rendered: ``"typecheck"`` (the default) renders Go as a library
    package so a block without ``func main`` still compiles; ``"run"`` renders Go
    as an executable ``package main`` so the snippet can be run end-to-end.
    """

    blocks = [b for b in parse_blocks(text) if b.lang == lang]

    units: list[Unit] = []
    chain: list[Block] = []

    def flush() -> None:
        if not chain:
            return
        idx = len(units) + 1
        sources = [f"{readme_label}:{b.line}" for b in chain]
        code = _render(lang, chain, mode)
        run = not any(b.directive == "no-run" for b in chain)
        units.append(
            Unit(
                lang=lang,
                name=f"{_safe_label(readme_label)}-{lang}-{idx}",
                code=code,
                sources=sources,
                run=run,
            )
        )
        chain.clear()

    for block in blocks:
        if block.directive == "skip":
            flush()
            continue
        if not _imports_sdk(lang, block.code):
            # Non-SDK block (or a "continues" block that doesn't itself import
            # the SDK but builds on one) — only keep it if it continues a chain.
            if block.directive == "continues" and chain:
                chain.append(block)
            else:
                flush()
            continue
        if block.directive == "continues" and chain:
            chain.append(block)
        else:
            flush()
            chain.append(block)

    flush()
    return units


def _safe_label(label: str) -> str:
    return re.sub(r"[^\w]+", "_", label).strip("_") or "readme"


def _render(lang: str, chain: list[Block], mode: str = "typecheck") -> str:
    if lang == "go":
        # Go blocks are standalone (a full program or a bare statement snippet);
        # concatenating two would not compile. Fail loudly rather than silently
        # drop the tail of a chain, which would leave a snippet unchecked.
        if len(chain) > 1:
            srcs = ", ".join(f"line {b.line}" for b in chain)
            raise ValueError(
                f"Go snippets cannot use 'continues' ({srcs}); each must be standalone"
            )
        return _render_go(chain[0].code, mode)
    return "\n\n".join(b.code for b in chain)


# Matches a top-level (column 0) short variable declaration or `var` declaration
# so the wrapper can suppress "declared and not used" for bare Go snippets.
_GO_SHORT_DECL_RE = re.compile(r"^(?P<names>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:=")
_GO_VAR_DECL_RE = re.compile(r"^var\s+(?P<name>[A-Za-z_]\w*)")
# A single-line import: captures the whole spec after `import ` (the optional
# alias / blank identifier plus the quoted path), so it round-trips verbatim.
_GO_SINGLE_IMPORT_RE = re.compile(r'^import\s+(?P<spec>(?:[\w.]+\s+|_\s+)?"[^"]+")\s*$')
_GO_IMPORT_BLOCK_OPEN_RE = re.compile(r"^import\s*\(\s*$")


GO_SNIPPET_PACKAGE = "snippet"


def _render_go(code: str, mode: str = "typecheck") -> str:
    """Render a Go snippet as a buildable unit.

    In ``typecheck`` mode every unit is compiled as ``package snippet`` rather
    than ``package main``: that way a snippet that defines helper funcs but no
    ``main`` (e.g. the collector-delivery example) still builds, and an unused
    ``func main`` is not an error. Unused *imports* and unused *locals* remain
    errors, so genuine drift is still caught.

    In ``run`` mode the unit is rendered as an executable ``package main`` with a
    ``func main`` entry point, so ``go run`` actually executes the snippet. (Only
    runnable snippets reach this mode — library-style blocks with no entry point
    carry the ``no-run`` directive and are filtered out before execution.)

    Blocks that already declare a package have that line rewritten. Bare
    statement snippets (root README quick-start) have their ``import`` lines
    hoisted into a package shim, the remaining statements placed in a function,
    and blank-identifier assignments appended so locally-declared values don't
    trip Go's unused-variable error.
    """

    package = "main" if mode == "run" else GO_SNIPPET_PACKAGE
    entry_func = "main" if mode == "run" else "run"

    if re.search(r"^package\s+\w+", code, re.MULTILINE):
        rewritten = re.sub(
            r"^package\s+\w+", f"package {package}", code.strip(), count=1, flags=re.MULTILINE
        )
        return rewritten + "\n"

    # Each entry is a full import spec, kept verbatim so aliases (`foo "pkg"`),
    # blank imports (`_ "pkg"`), and inline comments survive the rewrite.
    imports: list[str] = []
    body: list[str] = []
    lines = code.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        single = _GO_SINGLE_IMPORT_RE.match(stripped)
        if single:
            imports.append(single.group("spec").strip())
            i += 1
            continue
        if _GO_IMPORT_BLOCK_OPEN_RE.match(stripped):
            i += 1
            while i < len(lines) and lines[i].strip() != ")":
                spec = lines[i].strip()
                if spec:
                    imports.append(spec)
                i += 1
            i += 1  # skip the closing ")"
            continue
        body.append(lines[i])
        i += 1

    declared: list[str] = []
    for line in body:
        stripped = line.strip()
        short = _GO_SHORT_DECL_RE.match(stripped)
        if short:
            for name in short.group("names").split(","):
                name = name.strip()
                if name and name != "_":
                    declared.append(name)
            continue
        var = _GO_VAR_DECL_RE.match(stripped)
        if var:
            declared.append(var.group("name"))

    out: list[str] = [f"package {package}", ""]
    if imports:
        out.append("import (")
        for spec in imports:
            out.append(f"\t{spec}")
        out.append(")")
        out.append("")
    out.append(f"func {entry_func}() {{")
    for line in _trim_blank_edges(body):
        out.append("\t" + line if line.strip() else "")
    for name in declared:
        out.append(f"\t_ = {name}")
    out.append("}")
    return "\n".join(out) + "\n"


_GO_AR_IMPORT_RE = re.compile(r'"(github\.com/agent-receipts/[^"]+)"')
_GO_CANONICAL_PREFIX = "github.com/agent-receipts/ar/sdk/go"


def go_noncanonical_imports(code: str) -> list[str]:
    """Return any ``agent-receipts`` Go import paths that aren't the canonical SDK.

    A stale module (``github.com/agent-receipts/sdk-go``) is still resolvable on
    the proxy, so a wrong import path can silently *build*. This static guard
    fails the check anyway — a documented module path must be the one users get
    from ``go get github.com/agent-receipts/ar/sdk/go``.
    """

    bad: list[str] = []
    for path in _GO_AR_IMPORT_RE.findall(code):
        if path != _GO_CANONICAL_PREFIX and not path.startswith(_GO_CANONICAL_PREFIX + "/"):
            bad.append(path)
    return bad


def _trim_blank_edges(lines: list[str]) -> list[str]:
    start, end = 0, len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]
