#!/usr/bin/env python3
"""Gate #7: cross-SDK byte-identity at release time.

After a release is published, run the shared canonicalisation vectors
(``cross-sdk-tests/canonicalization_vectors.json``) through the *published* SDK
artifact's public canonicalisation/hashing API and assert the output is
byte-identical to the committed expected bytes (and the committed SHA-256
hashes). A release whose canonicalisation diverges from the vectors — and
therefore from the other SDKs, which are pinned to the same vectors — turns red
here, before the version is treated as good.

This is the release-time enforcement of the property ADR-0024 D1 records and
ADR-0002 / ADR-0005 commit to: all three SDKs produce byte-identical canonical
JSON (RFC 8785) for the same input. The in-tree per-SDK suites
(``sdk/{go,ts,py}`` canonicalisation-vectors tests) check the same property at
PR time against the in-tree source; this gate closes the gap at release time
against the artifact consumers actually install.

How the gate works:

1. The published SDK is installed into a throwaway project.
2. A tiny driver program (one per language) loads the committed vectors and
   feeds each one through the SDK's *public* API — ``canonicalize`` for the
   ``canonicalization_vectors`` array and the receipt-hash path for the
   ``receipt_hash_vectors`` array — then prints the SDK's actual output as a
   JSON object on stdout.
3. The comparison core in this module (``compare_actuals``) loads the same
   committed vectors and asserts the driver's output matches byte-for-byte,
   resolving ``SAME_AS_`` invariants and skipping the placeholders the in-tree
   suites also skip (``COMPUTE_AT_COMMIT_TIME``, ``receiptsFrom``-only
   signature-preservation vectors).

The comparison core takes no SDK and no network, so the unit tests exercise it
directly with controlled inputs; the install/emit drivers are exercised
end-to-end by CI at release time.

Usage:
    check.py --lang {go,ts,py} --version X.Y.Z [--vectors PATH] [--workdir DIR]

Exit codes:
    0  every vector's canonicalisation/hash is byte-identical to the committed
       expected value
    1  the driver failed, or at least one output diverged
    2  usage error (missing args, unknown lang)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GO_MODULE = "github.com/agent-receipts/ar/sdk/go"
TS_PACKAGE = "@obsigna/sdk-ts"
PY_PACKAGE = "obsigna"

# Default vectors location relative to the repo root (three levels up from here).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_VECTORS = os.path.join(
    _REPO_ROOT, "cross-sdk-tests", "canonicalization_vectors.json"
)

# Placeholders the in-tree per-SDK suites also skip. COMPUTE_AT_COMMIT_TIME is a
# not-yet-pinned hash; SAME_AS_<name> is an equality invariant resolved against
# the named vector's hash rather than a literal.
_COMPUTE_AT_COMMIT_TIME = "COMPUTE_AT_COMMIT_TIME"
_SAME_AS_PREFIX = "SAME_AS_"

# How many times to retry a registry fetch before failing. The public
# registries have occasional propagation lag after a new version is pushed;
# retries cover the window between "tag pushed" and "version installable".
REGISTRY_RETRIES = 4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    cwd: str,
    env: dict[str, str] | None = None,
    retries: int = 0,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    full_env = {**os.environ, **(env or {})}
    for attempt in range(retries + 1):
        print(f"  $ {' '.join(cmd)}  (cwd={cwd})", flush=True)
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=full_env,
            text=True,
            capture_output=capture_output,
        )
        if proc.returncode == 0 or attempt == retries:
            return proc
        wait = 2 ** (attempt + 1)
        print(f"  command failed (rc={proc.returncode}); retrying in {wait}s", flush=True)
        time.sleep(wait)
    return proc


def _sha256(data: str) -> str:
    """Return ``sha256:<hex>`` of the UTF-8 bytes of *data* — the receipt-hash
    prefix every SDK's ``sha256`` helper emits."""
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Comparison core (shared, unit-tested)
# ---------------------------------------------------------------------------


def _resolve_receipt_hashes(receipt_vectors: list[dict]) -> dict[str, str]:
    """Map each ``receipt_hash_vectors`` name to its concrete expected hash.

    A first pass collects literal hashes; a second pass resolves ``SAME_AS_``
    invariants against them. ``COMPUTE_AT_COMMIT_TIME`` placeholders and
    ``receiptsFrom``-only vectors (which carry no ``receipt`` to hash) are
    omitted — they have no byte to compare here.
    """
    literal: dict[str, str] = {}
    for v in receipt_vectors:
        eh = v.get("expectedHash")
        if eh and eh != _COMPUTE_AT_COMMIT_TIME and not eh.startswith(_SAME_AS_PREFIX):
            literal[v["name"]] = eh

    resolved: dict[str, str] = {}
    for v in receipt_vectors:
        if "receipt" not in v:
            continue  # e.g. receiptsFrom signature-preservation vectors
        eh = v.get("expectedHash", _COMPUTE_AT_COMMIT_TIME)
        if eh == _COMPUTE_AT_COMMIT_TIME:
            continue
        if eh.startswith(_SAME_AS_PREFIX):
            ref = eh[len(_SAME_AS_PREFIX) :]
            if ref not in literal:
                # Reference hash not pinned yet — nothing to assert.
                continue
            eh = literal[ref]
        resolved[v["name"]] = eh
    return resolved


def compare_actuals(vectors: dict, actuals: dict) -> list[str]:
    """Compare an SDK's driver output against the committed vectors.

    *vectors* is the parsed ``canonicalization_vectors.json``. *actuals* is the
    driver's emitted object: ``{"canonical": {name: str}, "receipt_hash":
    {name: str}}``. Returns a list of human-readable divergence messages; an
    empty list means every committed expectation was reproduced byte-for-byte.

    This is the core of the gate and is exercised by the unit tests with
    controlled inputs (no install, no network). For each
    ``canonicalization_vectors`` entry it asserts the SDK's ``canonicalize``
    output equals the committed ``canonical`` byte-for-byte, and — where the
    vector pins an ``expectedHash`` — that ``sha256:hex(canonical)`` equals it.
    For each ``receipt_hash_vectors`` entry with a pinned hash it asserts the
    SDK's receipt-hash output equals it.
    """
    diffs: list[str] = []

    actual_canon = actuals.get("canonical", {})
    actual_hash = actuals.get("receipt_hash", {})

    for v in vectors.get("canonicalization_vectors", []):
        name = v["name"]
        want = v["canonical"]
        got = actual_canon.get(name)
        if got is None:
            diffs.append(f"canonicalization_vectors[{name}]: SDK produced no output")
            continue
        if got != want:
            diffs.append(
                f"canonicalization_vectors[{name}]: canonical bytes diverge\n"
                f"      got:  {got!r}\n"
                f"      want: {want!r}"
            )
            continue
        # Where the vector pins a hash, the SHA-256 of the canonical bytes must
        # match it too — guarding against a hash-encoding regression even when
        # the canonical bytes are right.
        eh = v.get("expectedHash")
        if eh and eh != _COMPUTE_AT_COMMIT_TIME:
            got_hash = _sha256(got)
            if got_hash != eh:
                diffs.append(
                    f"canonicalization_vectors[{name}]: SHA-256 diverges\n"
                    f"      got:  {got_hash}\n"
                    f"      want: {eh}"
                )

    expected_hashes = _resolve_receipt_hashes(
        vectors.get("receipt_hash_vectors", [])
    )
    for name, want in expected_hashes.items():
        got = actual_hash.get(name)
        if got is None:
            diffs.append(f"receipt_hash_vectors[{name}]: SDK produced no output")
            continue
        if got != want:
            diffs.append(
                f"receipt_hash_vectors[{name}]: receipt hash diverges\n"
                f"      got:  {got}\n"
                f"      want: {want}"
            )

    return diffs


def _load_vectors(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _assert_identical(lang: str, vectors: dict, actuals: dict) -> int:
    """Compare driver output to the vectors and report. 0 if byte-identical."""
    diffs = compare_actuals(vectors, actuals)
    if diffs:
        print(
            f"ERROR: the published {lang} SDK's canonicalisation diverges from "
            "cross-sdk-tests/canonicalization_vectors.json:"
        )
        for d in diffs:
            print(f"  - {d}")
        return 1
    n_canon = len(vectors.get("canonicalization_vectors", []))
    print(
        f"OK: the published {lang} SDK reproduces all {n_canon} canonicalisation "
        "vectors (and every pinned receipt hash) byte-for-byte"
    )
    return 0


# ---------------------------------------------------------------------------
# Drivers — install the published artifact and emit its actual output
# ---------------------------------------------------------------------------

# Each driver loads the committed vectors, runs every vector through the SDK's
# public canonicalisation/hash API, and prints exactly one JSON object on
# stdout: {"canonical": {name: str}, "receipt_hash": {name: str}}. The
# comparison core then asserts byte-identity. The vectors path is passed as the
# program's first argument so the driver reads the same committed file the
# comparison core does.

_PY_DRIVER = """\
import json
import sys

from obsigna import canonicalize, hash_receipt

with open(sys.argv[1], encoding="utf-8") as fh:
    vectors = json.load(fh)

canon = {}
for v in vectors["canonicalization_vectors"]:
    canon[v["name"]] = canonicalize(v["input"])

receipt_hash = {}
for v in vectors["receipt_hash_vectors"]:
    if "receipt" not in v:
        continue
    receipt_hash[v["name"]] = hash_receipt(v["receipt"])

print(json.dumps({"canonical": canon, "receipt_hash": receipt_hash}))
"""

_TS_DRIVER = """\
import { readFileSync } from "node:fs";
import { canonicalize, hashReceipt } from "@obsigna/sdk-ts";

const vectors = JSON.parse(readFileSync(process.argv[2], "utf-8"));

const canonical = {};
for (const v of vectors.canonicalization_vectors) {
  canonical[v.name] = canonicalize(v.input);
}

const receipt_hash = {};
for (const v of vectors.receipt_hash_vectors) {
  if (!("receipt" in v)) continue;
  receipt_hash[v.name] = hashReceipt(v.receipt);
}

console.log(JSON.stringify({ canonical, receipt_hash }));
"""

# Go's public HashReceipt takes a typed receipt.AgentReceipt, which (since the
# v0.3.0 envelope migration, ADR-0012) can no longer round-trip the legacy
# flat-map parameters_disclosure shape some receipt_hash_vectors pin. The Go
# driver therefore reproduces the receipt hash via the SDK's public
# Canonicalize + SHA256Hash on a map[string]any after the documented Rule 2
# null-strip — exactly as the in-tree Go vectors test does — so the unit under
# test stays the public canonicaliser, not the typed struct.
_GO_DRIVER = """\
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

type vectorFile struct {
	CanonVectors []struct {
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"canonicalization_vectors"`
	ReceiptVectors []struct {
		Name    string          `json:"name"`
		Receipt json.RawMessage `json:"receipt"`
	} `json:"receipt_hash_vectors"`
}

// requiredNullable reports whether path is the sole required-nullable field the
// spec keeps as literal null (ADR-0009); every other null is dropped.
func requiredNullable(path []string) bool {
	return len(path) == 3 &&
		path[0] == "credentialSubject" &&
		path[1] == "chain" &&
		path[2] == "previous_receipt_hash"
}

func stripOptionalNulls(node map[string]any, path []string) {
	for k, v := range node {
		child := append(append([]string{}, path...), k)
		if v == nil {
			if !requiredNullable(child) {
				delete(node, k)
			}
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			stripOptionalNulls(sub, child)
		}
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		fail(err)
	}

	canonical := map[string]string{}
	for _, v := range vf.CanonVectors {
		var input any
		if err := json.Unmarshal(v.Input, &input); err != nil {
			fail(fmt.Errorf("vector %s: %w", v.Name, err))
		}
		c, err := receipt.Canonicalize(input)
		if err != nil {
			fail(fmt.Errorf("vector %s: %w", v.Name, err))
		}
		canonical[v.Name] = c
	}

	receiptHash := map[string]string{}
	for _, v := range vf.ReceiptVectors {
		if len(v.Receipt) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(v.Receipt, &m); err != nil {
			fail(fmt.Errorf("vector %s: %w", v.Name, err))
		}
		stripOptionalNulls(m, nil)
		delete(m, "proof")
		cs, _ := m["credentialSubject"].(map[string]any)
		if cs != nil {
			if chain, ok := cs["chain"].(map[string]any); ok {
				if _, present := chain["previous_receipt_hash"]; !present {
					chain["previous_receipt_hash"] = nil
				}
			}
		}
		c, err := receipt.Canonicalize(m)
		if err != nil {
			fail(fmt.Errorf("vector %s: %w", v.Name, err))
		}
		receiptHash[v.Name] = receipt.SHA256Hash(c)
	}

	out, err := json.Marshal(map[string]any{
		"canonical":    canonical,
		"receipt_hash": receiptHash,
	})
	if err != nil {
		fail(err)
	}
	fmt.Println(string(out))
}
"""


def _parse_emitted(lang: str, stdout: str) -> dict | None:
    """Pull the single JSON output object out of a driver's stdout."""
    for line in reversed(stdout.split("\n")):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"ERROR: {lang} driver produced a non-JSON output line: {exc}\n"
                    f"  offending line: {line}"
                )
                return None
    print(f"ERROR: {lang} driver produced no JSON output on stdout")
    return None


def emit_py(version: str, vectors_path: str, workdir: str) -> dict | None:
    venv = os.path.join(workdir, "venv")
    if _run([sys.executable, "-m", "venv", venv], cwd=workdir).returncode != 0:
        return None
    py = os.path.join(venv, "bin", "python")
    spec = f"{PY_PACKAGE}=={version}"
    print(f"\n--- Installing {spec} from PyPI")
    if (
        _run([py, "-m", "pip", "install", "--quiet", spec], cwd=workdir, retries=REGISTRY_RETRIES).returncode
        != 0
    ):
        print(f"ERROR: failed to install {spec} from PyPI")
        return None
    prog = os.path.join(workdir, "driver.py")
    with open(prog, "w", encoding="utf-8") as fh:
        fh.write(_PY_DRIVER)
    print("\n--- Running the vectors through the published Python SDK")
    result = _run([py, prog, vectors_path], cwd=workdir, capture_output=True)
    if result.returncode != 0:
        print(f"ERROR: Python driver failed\n{result.stderr}")
        return None
    return _parse_emitted("py", result.stdout)


def emit_ts(version: str, vectors_path: str, workdir: str) -> dict | None:
    package_json = {
        "name": "byte-identity",
        "private": True,
        "type": "module",
        "dependencies": {TS_PACKAGE: version},
    }
    with open(os.path.join(workdir, "package.json"), "w", encoding="utf-8") as fh:
        json.dump(package_json, fh, indent=2)
    print(f"\n--- Installing {TS_PACKAGE}@{version} from npm")
    if (
        _run(["npm", "install", "--no-audit", "--no-fund"], cwd=workdir, retries=REGISTRY_RETRIES).returncode
        != 0
    ):
        print(f"ERROR: npm install {TS_PACKAGE}@{version} failed")
        return None
    prog = os.path.join(workdir, "driver.ts")
    with open(prog, "w", encoding="utf-8") as fh:
        fh.write(_TS_DRIVER)
    print("\n--- Running the vectors through the published TypeScript SDK")
    # Node strips types directly (Node 22.18+ / 24); no separate compile step.
    result = _run(
        ["node", "--experimental-strip-types", "driver.ts", vectors_path],
        cwd=workdir,
        env={"NODE_NO_WARNINGS": "1"},
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"ERROR: TypeScript driver failed\n{result.stderr}")
        return None
    return _parse_emitted("ts", result.stdout)


def emit_go(version: str, vectors_path: str, workdir: str) -> dict | None:
    go_mod = [
        "module example.com/byte-identity\n",
        "go 1.26.1\n",
        f"require {GO_MODULE} v{version}\n",
    ]
    with open(os.path.join(workdir, "go.mod"), "w", encoding="utf-8") as fh:
        fh.writelines(go_mod)
    with open(os.path.join(workdir, "main.go"), "w", encoding="utf-8") as fh:
        fh.write(_GO_DRIVER)
    # Pin GOPROXY to the public proxy with no `direct` fallback so the driver
    # exercises the module consumers actually resolve, not a VCS checkout.
    env = {
        "GOFLAGS": "-mod=mod",
        "GOWORK": "off",
        "GOPROXY": "https://proxy.golang.org",
    }
    print(f"\n--- Fetching {GO_MODULE}@v{version} and running the vectors")
    if _run(["go", "mod", "tidy"], cwd=workdir, env=env, retries=REGISTRY_RETRIES).returncode != 0:
        print(f"ERROR: go mod tidy for {GO_MODULE}@v{version} failed")
        return None
    result = _run(["go", "run", ".", vectors_path], cwd=workdir, env=env, capture_output=True)
    if result.returncode != 0:
        print(f"ERROR: Go driver failed\n{result.stderr}")
        return None
    return _parse_emitted("go", result.stdout)


_EMITTERS = {"go": emit_go, "ts": emit_ts, "py": emit_py}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--lang", required=True, choices=["go", "ts", "py"])
    parser.add_argument(
        "--version",
        required=True,
        help="Released version string (no leading 'v'), e.g. 0.12.0 or 0.12.0-alpha.1",
    )
    parser.add_argument(
        "--vectors",
        default=DEFAULT_VECTORS,
        help=f"Path to the canonicalisation vectors (default: {DEFAULT_VECTORS})",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="Working directory for the temporary project (default: auto-created tmpdir)",
    )
    args = parser.parse_args(argv)

    if args.version.startswith("v"):
        parser.error(f"--version must not have a leading 'v' (got {args.version!r})")

    vectors = _load_vectors(args.vectors)

    cleanup = False
    if args.workdir:
        workdir = os.path.abspath(args.workdir)
        os.makedirs(workdir, exist_ok=True)
    else:
        workdir = tempfile.mkdtemp(prefix="byte-identity-")
        cleanup = True

    print("Gate #7 — cross-SDK byte-identity")
    print(f"  lang    : {args.lang}")
    print(f"  version : {args.version}")
    print(f"  vectors : {args.vectors}")
    print(f"  workdir : {workdir}")

    try:
        actuals = _EMITTERS[args.lang](args.version, os.path.abspath(args.vectors), workdir)
        if actuals is None:
            rc = 1
        else:
            rc = _assert_identical(args.lang, vectors, actuals)
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)

    if rc == 0:
        print(f"\nGate #7 PASSED for {args.lang} {args.version}")
    else:
        print(f"\nGate #7 FAILED for {args.lang} {args.version} (see errors above)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
