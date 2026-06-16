#!/usr/bin/env python3
"""Gate #6: SDK output schema-conformance at release time.

After a release is published, emit a representative signed receipt using the
*published* SDK artifact and validate it against the repo's published JSON
Schema (``spec/schema/agent-receipt.schema.json``). A release whose SDK emits
output that drifts from the schema turns red here, before the version is
treated as good.

This is the release-time enforcement of the property ADR-0024 D1 records:
"each SDK emits receipts conforming to the published schema." The in-tree
cross-SDK suite (``cross-sdk-tests/spec_schema_test.go``) checks the same
property at PR time against committed vectors; this gate closes the gap at
release time against the artifact consumers actually install.

What "the targeted spec version" means here: the schema validates every
protocol ``version`` it lists in its ``version`` enum (v0.1 .. v0.4 today), and
the receipt under test carries its own ``version`` field, which the schema
keys its per-version constraints off. The single repo-tracked schema file is
the source of truth — it ships from this same commit, so the schema validated
against is the one released alongside the SDK (ADR-0021 coordination).

Validation uses the ``jsonschema`` library (already a dev dependency of the
Python SDK) configured for Draft 2020-12 with format assertion enabled — the
same draft and the same format-checking posture as the Go validator in
``cross-sdk-tests/spec_schema_test.go`` (``Draft2020`` + ``AssertFormat``), so
a regression to a non-RFC3339 timestamp fails here too.

Usage:
    check.py --lang {go,ts,py} --version X.Y.Z [--schema PATH] [--workdir DIR]

Exit codes:
    0  emitted receipt validates against the schema
    1  emit failed, or the emitted receipt violates the schema
    2  usage error (missing args, unknown lang)
"""

from __future__ import annotations

import argparse
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

# Default schema location relative to the repo root (two levels up from here).
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_SCHEMA = os.path.join(_REPO_ROOT, "spec", "schema", "agent-receipt.schema.json")

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


# ---------------------------------------------------------------------------
# Schema validation (shared, unit-tested)
# ---------------------------------------------------------------------------


def validate_receipt(receipt: object, schema: dict) -> list[str]:
    """Validate *receipt* against *schema*; return a list of violation messages.

    An empty list means the receipt conforms. This is the core of the gate and
    is exercised by the unit tests with controlled inputs (no emit, no network).

    Uses Draft 2020-12 with a FormatChecker so ``"format": "date-time"``
    constraints (issuanceDate, proof.created) are asserted, not annotation-only
    — matching ``AssertFormat`` in the Go validator. A regression to a
    non-RFC3339 timestamp is therefore caught here.
    """
    # Imported lazily so the unit tests can import this module without the
    # jsonschema dependency present unless they actually validate.
    from jsonschema import Draft202012Validator, FormatChecker

    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(receipt), key=lambda e: list(e.absolute_path))
    messages = []
    for err in errors:
        location = "/".join(str(p) for p in err.absolute_path) or "<root>"
        messages.append(f"{location}: {err.message}")
    return messages


def _load_schema(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _assert_conforms(lang: str, receipt: object, schema: dict) -> int:
    """Validate an emitted receipt and report. Returns 0 on conformance, 1 otherwise."""
    violations = validate_receipt(receipt, schema)
    if violations:
        print(
            f"ERROR: receipt emitted by the published {lang} SDK does not validate "
            "against spec/schema/agent-receipt.schema.json:"
        )
        for v in violations:
            print(f"  - {v}")
        return 1
    print(f"OK: receipt emitted by the published {lang} SDK validates against the schema")
    return 0


# ---------------------------------------------------------------------------
# Emit drivers — install the published artifact and emit one receipt as JSON
# ---------------------------------------------------------------------------

# Each driver writes a tiny program that uses only the SDK's public emit API
# (mirroring the README quick-start, which Gate #1 keeps in sync with the
# released surface) and prints exactly one signed receipt as JSON to stdout.

_PY_EMIT = """\
import json
from obsigna import (
    ActionInput,
    CreateReceiptInput,
    Chain,
    Issuer,
    Outcome,
    Principal,
    create_receipt,
    generate_key_pair,
    sign_receipt,
)

keys = generate_key_pair()
unsigned = create_receipt(
    CreateReceiptInput(
        issuer=Issuer(id="did:agent:schema-conformance"),
        principal=Principal(id="did:user:release-gate"),
        action=ActionInput(type="filesystem.file.read", risk_level="low"),
        outcome=Outcome(status="success"),
        chain=Chain(
            sequence=1,
            previous_receipt_hash=None,
            chain_id="schema-conformance-1",
        ),
    )
)
receipt = sign_receipt(unsigned, keys.private_key, "did:agent:schema-conformance#key-1")
wire = receipt.model_dump(by_alias=True, exclude_none=True)
# previous_receipt_hash is required-nullable per spec; exclude_none strips it,
# but the wire form (what the SDK signs and consumers receive) keeps it as null.
# Mirror the SDK's own serialization (see sdk/py .../receipt/signing.py).
chain = wire["credentialSubject"]["chain"]
chain.setdefault("previous_receipt_hash", None)
print(json.dumps(wire))
"""

_TS_EMIT = """\
import {
  type CreateReceiptInput,
  createReceipt,
  generateKeyPair,
  signReceipt,
} from "@obsigna/sdk-ts";

const keys = generateKeyPair();
const input: CreateReceiptInput = {
  issuer: { id: "did:agent:schema-conformance" },
  principal: { id: "did:user:release-gate" },
  action: { type: "filesystem.file.read", risk_level: "low" },
  outcome: { status: "success" },
  chain: { sequence: 1, previous_receipt_hash: null, chain_id: "schema-conformance-1" },
};
const unsigned = createReceipt(input);
const receipt = signReceipt(unsigned, keys.privateKey, "did:agent:schema-conformance#key-1");
console.log(JSON.stringify(receipt));
"""

_GO_EMIT = """\
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/agent-receipts/ar/sdk/go/receipt"
)

func main() {
	kp, err := receipt.GenerateKeyPair()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	unsigned := receipt.Create(receipt.CreateInput{
		Issuer:    receipt.Issuer{ID: "did:agent:schema-conformance"},
		Principal: receipt.Principal{ID: "did:user:release-gate"},
		Action:    receipt.Action{Type: "filesystem.file.read", RiskLevel: receipt.RiskLow},
		Outcome:   receipt.Outcome{Status: receipt.StatusSuccess},
		Chain:     receipt.Chain{Sequence: 1, ChainID: "schema-conformance-1"},
	})
	signed, err := receipt.Sign(unsigned, kp.PrivateKey, "did:agent:schema-conformance#key-1")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, err := json.Marshal(signed)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
"""


def _parse_emitted(lang: str, stdout: str) -> object | None:
    """Pull the single JSON receipt object out of an emit program's stdout."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"ERROR: {lang} emit program produced a non-JSON receipt line: {exc}\n"
                    f"  offending line: {line}"
                )
                return None
    print(f"ERROR: {lang} emit program produced no JSON receipt on stdout")
    return None


def emit_py(version: str, workdir: str) -> object | None:
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
    prog = os.path.join(workdir, "emit.py")
    with open(prog, "w", encoding="utf-8") as fh:
        fh.write(_PY_EMIT)
    print("\n--- Emitting a receipt with the published Python SDK")
    result = _run([py, prog], cwd=workdir, capture_output=True)
    if result.returncode != 0:
        print(f"ERROR: Python emit program failed\n{result.stderr}")
        return None
    return _parse_emitted("py", result.stdout)


def emit_ts(version: str, workdir: str) -> object | None:
    package_json = {
        "name": "schema-conformance",
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
    prog = os.path.join(workdir, "emit.ts")
    with open(prog, "w", encoding="utf-8") as fh:
        fh.write(_TS_EMIT)
    print("\n--- Emitting a receipt with the published TypeScript SDK")
    # Node strips types directly (Node 22.18+ / 24); no separate compile step.
    result = _run(
        ["node", "--experimental-strip-types", "emit.ts"],
        cwd=workdir,
        env={"NODE_NO_WARNINGS": "1"},
        capture_output=True,
    )
    if result.returncode != 0:
        print(f"ERROR: TypeScript emit program failed\n{result.stderr}")
        return None
    return _parse_emitted("ts", result.stdout)


def emit_go(version: str, workdir: str) -> object | None:
    go_mod = [
        "module example.com/schema-conformance\n",
        "go 1.26.1\n",
        f"require {GO_MODULE} v{version}\n",
    ]
    with open(os.path.join(workdir, "go.mod"), "w", encoding="utf-8") as fh:
        fh.writelines(go_mod)
    with open(os.path.join(workdir, "main.go"), "w", encoding="utf-8") as fh:
        fh.write(_GO_EMIT)
    # Pin GOPROXY to the public proxy with no `direct` fallback so the emit
    # exercises the module consumers actually resolve, not a VCS checkout.
    env = {
        "GOFLAGS": "-mod=mod",
        "GOWORK": "off",
        "GOPROXY": "https://proxy.golang.org",
    }
    print(f"\n--- Fetching {GO_MODULE}@v{version} and emitting a receipt")
    if _run(["go", "mod", "tidy"], cwd=workdir, env=env, retries=REGISTRY_RETRIES).returncode != 0:
        print(f"ERROR: go mod tidy for {GO_MODULE}@v{version} failed")
        return None
    result = _run(["go", "run", "."], cwd=workdir, env=env, capture_output=True)
    if result.returncode != 0:
        print(f"ERROR: Go emit program failed\n{result.stderr}")
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
        "--schema",
        default=DEFAULT_SCHEMA,
        help=f"Path to the JSON Schema to validate against (default: {DEFAULT_SCHEMA})",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="Working directory for the temporary project (default: auto-created tmpdir)",
    )
    args = parser.parse_args(argv)

    if args.version.startswith("v"):
        parser.error(f"--version must not have a leading 'v' (got {args.version!r})")

    schema = _load_schema(args.schema)

    cleanup = False
    if args.workdir:
        workdir = os.path.abspath(args.workdir)
        os.makedirs(workdir, exist_ok=True)
    else:
        workdir = tempfile.mkdtemp(prefix="schema-conformance-")
        cleanup = True

    print("Gate #6 — SDK output schema-conformance")
    print(f"  lang    : {args.lang}")
    print(f"  version : {args.version}")
    print(f"  schema  : {args.schema}")
    print(f"  workdir : {workdir}")

    try:
        receipt = _EMITTERS[args.lang](args.version, workdir)
        if receipt is None:
            rc = 1
        else:
            rc = _assert_conforms(args.lang, receipt, schema)
    finally:
        if cleanup:
            shutil.rmtree(workdir, ignore_errors=True)

    if rc == 0:
        print(f"\nGate #6 PASSED for {args.lang} {args.version}")
    else:
        print(f"\nGate #6 FAILED for {args.lang} {args.version} (see errors above)")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
