"""Unit tests for the README snippet extractor.

Run with: python3 -m pytest scripts/readme_snippets/test_extract.py
(or plain `python3 scripts/readme_snippets/test_extract.py` for a quick check).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import extract  # noqa: E402


def test_parse_blocks_normalises_language() -> None:
    text = """
```bash
echo hi
```

```typescript
const x = 1;
```

```py
x = 1
```
"""
    blocks = extract.parse_blocks(text)
    langs = [b.lang for b in blocks]
    assert langs == ["bash", "ts", "py"]


def test_parse_blocks_records_line_numbers() -> None:
    text = "line1\nline2\n```go\nfoo\n```\n"
    (block,) = extract.parse_blocks(text)
    assert block.line == 3
    assert block.code == "foo"


def test_directive_attaches_to_next_block() -> None:
    text = """
<!-- snippet-check: skip -->
```python
from obsigna import x
```
"""
    (block,) = extract.parse_blocks(text)
    assert block.directive == "skip"


def test_directive_broken_by_intervening_prose() -> None:
    text = """
<!-- snippet-check: continues -->
some prose here
```python
from obsigna import x
```
"""
    (block,) = extract.parse_blocks(text)
    assert block.directive is None


def test_unknown_directive_ignored() -> None:
    text = "<!-- snippet-check: bogus -->\n```go\nx\n```\n"
    (block,) = extract.parse_blocks(text)
    assert block.directive is None


def test_unknown_directive_clears_pending_directive() -> None:
    # A valid directive followed by an invalid snippet-check comment must not
    # leak the valid one onto the next fence.
    text = """
<!-- snippet-check: continues -->
<!-- snippet-check: bogus -->
```python
from obsigna import x
```
"""
    (block,) = extract.parse_blocks(text)
    assert block.directive is None


def test_only_sdk_importing_blocks_selected() -> None:
    text = """
```python
print("no sdk here")
```

```python
from obsigna import create_receipt
create_receipt()
```
"""
    units = extract.build_units("R.md", text, "py")
    assert len(units) == 1
    assert "create_receipt" in units[0].code


def test_continues_concatenates_onto_previous() -> None:
    text = """
```python
from obsigna import create_receipt
receipt = create_receipt()
```

<!-- snippet-check: continues -->
```python
from obsigna import verify_receipt
verify_receipt(receipt)
```
"""
    units = extract.build_units("R.md", text, "py")
    assert len(units) == 1
    code = units[0].code
    assert "create_receipt" in code and "verify_receipt" in code
    assert len(units[0].sources) == 2


def test_skip_excludes_block_and_breaks_chain() -> None:
    text = """
```python
from obsigna import create_receipt
receipt = create_receipt()
```

<!-- snippet-check: skip -->
```python
from obsigna import verify_chain
verify_chain(receipts, key)
```
"""
    units = extract.build_units("R.md", text, "py")
    assert len(units) == 1
    assert "verify_chain" not in units[0].code


def test_wrong_go_module_path_is_still_selected() -> None:
    # The buggy `sdk-go` path must be selected so the build catches it.
    text = """
```go
package main

import "github.com/agent-receipts/sdk-go/receipt"

func main() { _ = receipt.GenerateKeyPair }
```
"""
    units = extract.build_units("R.md", text, "go")
    assert len(units) == 1
    assert "sdk-go" in units[0].code


def test_full_go_program_repackaged_as_library() -> None:
    # `package main` is rewritten so a block without `func main` still builds.
    code = 'package main\n\nimport "github.com/agent-receipts/ar/sdk/go/receipt"\n\nfunc deliver() { _ = receipt.GenerateKeyPair }'
    text = f"```go\n{code}\n```\n"
    (unit,) = extract.build_units("R.md", text, "go")
    assert unit.code.startswith("package snippet")
    assert "func deliver()" in unit.code
    assert "package main" not in unit.code


def test_bare_go_snippet_is_wrapped_and_suppresses_unused() -> None:
    text = """
```go
import "github.com/agent-receipts/ar/sdk/go/receipt"

keys, _ := receipt.GenerateKeyPair()
unsigned := receipt.Create(receipt.CreateInput{})
signed, _ := receipt.Sign(unsigned, keys.PrivateKey, "k")
```
"""
    (unit,) = extract.build_units("R.md", text, "go")
    code = unit.code
    assert code.startswith("package snippet")
    assert "func run() {" in code
    assert 'import (\n\t"github.com/agent-receipts/ar/sdk/go/receipt"\n)' in code
    # Every locally declared value is referenced so Go won't reject it.
    assert "_ = keys" in code
    assert "_ = unsigned" in code
    assert "_ = signed" in code


def test_bare_go_snippet_with_import_block() -> None:
    text = """
```go
import (
	"fmt"
	"github.com/agent-receipts/ar/sdk/go/receipt"
)

fmt.Println(receipt.GenerateKeyPair())
```
"""
    (unit,) = extract.build_units("R.md", text, "go")
    assert '"fmt"' in unit.code
    assert '"github.com/agent-receipts/ar/sdk/go/receipt"' in unit.code


def test_go_noncanonical_imports_flags_stale_module() -> None:
    code = (
        'import "github.com/agent-receipts/sdk-go/receipt"\n'
        'import "github.com/agent-receipts/ar/sdk/go/store"\n'
    )
    assert extract.go_noncanonical_imports(code) == ["github.com/agent-receipts/sdk-go/receipt"]


def test_go_noncanonical_imports_accepts_canonical() -> None:
    code = (
        'import "github.com/agent-receipts/ar/sdk/go"\n'
        'import "github.com/agent-receipts/ar/sdk/go/emitter"\n'
    )
    assert extract.go_noncanonical_imports(code) == []


def test_single_aliased_import_preserved() -> None:
    text = '```go\nimport rcpt "github.com/agent-receipts/ar/sdk/go/receipt"\n\nrcpt.GenerateKeyPair()\n```\n'
    (unit,) = extract.build_units("R.md", text, "go")
    assert 'rcpt "github.com/agent-receipts/ar/sdk/go/receipt"' in unit.code


def test_import_block_preserves_alias_and_blank() -> None:
    text = """
```go
import (
	_ "github.com/agent-receipts/ar/sdk/go/receipt"
	st "github.com/agent-receipts/ar/sdk/go/store"
)

st.Open("x")
```
"""
    (unit,) = extract.build_units("R.md", text, "go")
    assert '_ "github.com/agent-receipts/ar/sdk/go/receipt"' in unit.code
    assert 'st "github.com/agent-receipts/ar/sdk/go/store"' in unit.code


def test_mdx_jsx_comment_directive() -> None:
    # MDX can't use HTML comments; the JSX comment form must be recognised.
    text = """
{/* snippet-check: skip */}
```python
from obsigna import x
```
"""
    (block,) = extract.parse_blocks(text)
    assert block.directive == "skip"


def test_mdx_jsx_comment_no_run() -> None:
    text = """
{/* snippet-check: no-run */}
```typescript
import { KMSSigner } from "@obsigna/sdk-ts";
```
"""
    (unit,) = extract.build_units("page.mdx", text, "ts")
    assert unit.run is False


def test_mismatched_comment_delimiters_are_not_directives() -> None:
    # The opener fixes the closer: a mismatched pair is invalid directive syntax
    # and must not silently skip/no-run the snippet. An unrecognised "directive"
    # leaves the block at its default (checked, runnable).
    for opener, closer in (("<!--", "*/}"), ("{/*", "-->")):
        text = f"""
{opener} snippet-check: skip {closer}
```python
from obsigna import create_receipt
create_receipt()
```
"""
        (unit,) = extract.build_units("page.mdx", text, "py")
        assert unit.run is True, f"{opener} … {closer} should not be a directive"


def test_default_unit_is_runnable() -> None:
    text = "```python\nfrom obsigna import create_receipt\ncreate_receipt()\n```\n"
    (unit,) = extract.build_units("R.md", text, "py")
    assert unit.run is True


def test_no_run_directive_marks_unit_not_runnable() -> None:
    # `no-run` keeps the block (still type-checked) but flags it as not
    # executable — the opt-out for snippets that can't run hermetically.
    text = """
<!-- snippet-check: no-run -->
```python
from obsigna.aws import KMSSigner

signer = KMSSigner("arn:aws:kms:...")
```
"""
    (unit,) = extract.build_units("R.md", text, "py")
    assert unit.run is False
    assert "KMSSigner" in unit.code  # still present for the type-check gate


def test_no_run_block_is_not_excluded_like_skip() -> None:
    # A `skip` block disappears; a `no-run` block survives (just isn't run).
    text = """
```python
from obsigna import create_receipt
receipt = create_receipt()
```

<!-- snippet-check: no-run -->
```python
from obsigna import KMSSigner
KMSSigner("x")
```
"""
    units = extract.build_units("R.md", text, "py")
    assert len(units) == 2
    assert [u.run for u in units] == [True, False]


def test_no_run_in_chain_taints_whole_unit() -> None:
    text = """
```python
from obsigna import create_receipt
receipt = create_receipt()
```

<!-- snippet-check: no-run -->
```python
from obsigna import verify_receipt
verify_receipt(receipt)
```
"""
    # The `no-run` block here is a standalone unit (it doesn't say `continues`),
    # so we get two units; only the second is non-runnable.
    units = extract.build_units("R.md", text, "py")
    assert [u.run for u in units] == [True, False]


def test_continues_chain_inherits_no_run() -> None:
    text = """
<!-- snippet-check: no-run -->
```python
from obsigna import HttpEmitter
http = HttpEmitter()
```

<!-- snippet-check: continues -->
```python
http.emit(receipt)
```
"""
    (unit,) = extract.build_units("R.md", text, "py")
    assert unit.run is False


def test_go_run_mode_wraps_bare_snippet_as_main() -> None:
    text = """
```go
import "github.com/agent-receipts/ar/sdk/go/receipt"

keys, _ := receipt.GenerateKeyPair()
```
"""
    (unit,) = extract.build_units("R.md", text, "go", mode="run")
    assert unit.code.startswith("package main")
    assert "func main() {" in unit.code
    assert "_ = keys" in unit.code


def test_go_run_mode_keeps_full_program_as_main() -> None:
    code = (
        "package main\n\n"
        'import "github.com/agent-receipts/ar/sdk/go/receipt"\n\n'
        "func main() { _, _ = receipt.GenerateKeyPair() }"
    )
    text = f"```go\n{code}\n```\n"
    (unit,) = extract.build_units("R.md", text, "go", mode="run")
    assert unit.code.startswith("package main")
    assert "func main()" in unit.code
    assert "package snippet" not in unit.code


def test_go_typecheck_mode_still_library_package() -> None:
    # Default mode is unchanged: a bare snippet becomes a library package.
    text = """
```go
import "github.com/agent-receipts/ar/sdk/go/receipt"

keys, _ := receipt.GenerateKeyPair()
```
"""
    (unit,) = extract.build_units("R.md", text, "go")
    assert unit.code.startswith("package snippet")
    assert "func run() {" in unit.code


def test_go_continues_is_rejected_loudly() -> None:
    text = """
```go
package main
import "github.com/agent-receipts/ar/sdk/go/receipt"
func main() { _ = receipt.GenerateKeyPair }
```

<!-- snippet-check: continues -->
```go
import "github.com/agent-receipts/ar/sdk/go/store"
_ = store.Open
```
"""
    try:
        extract.build_units("R.md", text, "go")
    except ValueError as exc:
        assert "continues" in str(exc)
    else:
        raise AssertionError("expected ValueError for chained Go snippets")


def _run_all() -> int:
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok   {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL {name}: {exc}")
    return failures


if __name__ == "__main__":
    sys.exit(1 if _run_all() else 0)
