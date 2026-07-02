# conformance_matrix

Emits the conformance-vector counts for the [Conformance page](https://agentreceipts.ai/conformance/)
(`site/src/content/docs/conformance.mdx`).

The page carries a results matrix whose vector counts are citeable, so they must
not be hand-typed. `count.py` reads the frozen vector files directly and reports
the count per set, letting the page be regenerated and letting a reviewer
reproduce every figure from source.

## Layout

| File | Role |
|------|------|
| `count.py` | Reads the committed vector files and emits per-set counts as a table, Markdown, or JSON. Read-only — never writes or regenerates a vector file. |
| `test_count.py` | Unit tests over the real committed vectors (no network, no SDK install). |

## Run locally

```sh
python3 scripts/conformance_matrix/count.py             # human-readable table
python3 scripts/conformance_matrix/count.py --format md  # Markdown for the page
python3 scripts/conformance_matrix/count.py --format json

python3 -m unittest discover -s scripts/conformance_matrix -p 'test_*.py'
```

## What it counts

The vector sets are frozen (see `cross-sdk-tests/README.md` and each
`spec/test-vectors/*/README.md`). This script only measures them; it is not a
generator. Counting rules are declared per set in `VECTOR_SETS` — combined
list lengths for the shared corpora, top-level vector entries (excluding file
metadata) for the version-pinned files, and a single document for the rotation
example — so every number is transparent and reproducible.
