# readme_snippets

Gate that the SDK code snippets in the user-facing READMEs hold up against the
SDK. Two complementary modes (see `--mode` below):

- **typecheck** — compile (Go) / type-check (TS, Py) every SDK snippet. Catches
  the recurring papercut (#593, #594) where a quick-start snippet calls a
  non-existent API, imports a wrong module path, or drifts behind a rename.
- **run** — *execute* every runnable snippet in an isolated tmpdir and assert it
  exits 0 (verification-gate #1 / ADR-0024). Catches snippets that type-check
  but don't actually work.

## Layout

| File | Role |
|------|------|
| `extract.py` | Pure fence extraction + per-language assembly. Unit tested. |
| `check.py` | IO + subprocess driver: scaffolds a throwaway project and runs the compiler/type-checker, or executes the snippet. |
| `test_extract.py` | Unit tests for `extract.py`. |
| `test_check.py` | Unit tests for `check.py`'s run-mode pass/fail + no-run filtering logic. |

## Run locally

```sh
python3 scripts/readme_snippets/test_extract.py          # unit tests
python3 scripts/readme_snippets/test_check.py            # unit tests
# TypeScript local mode needs the in-tree dist built first:
( cd sdk/ts && pnpm install && pnpm run build )
# typecheck mode (default):
python3 scripts/readme_snippets/check.py --lang go --source local README.md sdk/go/README.md
python3 scripts/readme_snippets/check.py --lang ts --source local README.md sdk/ts/README.md
python3 scripts/readme_snippets/check.py --lang py --source local README.md sdk/py/README.md
# run mode (execute the snippets):
python3 scripts/readme_snippets/check.py --lang go --source local --mode run README.md sdk/go/README.md
python3 scripts/readme_snippets/check.py --lang ts --source local --mode run README.md sdk/ts/README.md
python3 scripts/readme_snippets/check.py --lang py --source local --mode run README.md sdk/py/README.md
```

`--source local` builds against the in-tree SDK (used on PRs). `--source
published [--version X.Y.Z]` builds against the released artifact (used by the
publish-* workflows at release time). `--mode run` executes snippets instead of
only type-checking them; `--mode typecheck` (the default) is the compile-only
gate.

## Per-language tooling

- **Go** — every snippet compiles as a non-main `package snippet` via `go build`
  (so a block with no `func main` still builds; unused funcs are allowed, unused
  imports/locals are not). Bare statement snippets are wrapped automatically.
- **TypeScript** — `tsc --noEmit --strict` against the installed package.
- **Python** — `mypy` against the installed package (`obsigna` ships
  `py.typed`). Type-check only; snippets are never executed.

## Authoring snippets

Every fenced `go` / `typescript` / `python` block that imports the SDK is
checked **by default** — that default is what catches drift on a newly added
snippet without anyone remembering to annotate it. Invisible HTML-comment
directives override this when a block isn't standalone:

```md
<!-- snippet-check: continues -->   <!-- concatenate onto the previous checked block -->
<!-- snippet-check: skip -->        <!-- exclude entirely (intentionally partial pseudo-code) -->
<!-- snippet-check: no-run -->      <!-- type-check only; don't execute (run mode) -->
```

Place the directive on its own line immediately above the opening fence. In
`.mdx` site sources, use the JSX comment form instead (HTML comments are invalid
MDX): `{/* snippet-check: skip */}`.

`no-run` is the opt-out for snippets that can't run in a hermetic clean tmpdir —
they need a daemon, the network, AWS, or a writable system path (e.g. the
daemon-emitter, collector-delivery, WAL, and KMS examples). Such a block is
still extracted and compiled / type-checked; only execution is skipped. Prefer
making a snippet self-contained over `no-run`; reach for `no-run` only when the
snippet documents a path that inherently needs external state.

## Adding a README to the gate

1. Add its path to the `check.py` invocations in
   `.github/workflows/readme-snippets.yml` (and the relevant publish-* workflow
   for the release gate).
2. Run the local commands above and resolve any failures — prefer fixing the
   snippet over adding a `skip`.
