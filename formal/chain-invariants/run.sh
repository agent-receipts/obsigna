#!/usr/bin/env bash
#
# Run the Agent Receipt Protocol chain tamper-evidence Alloy model headless, using
# Alloy's own built-in `exec` command. It runs every `check`/`run` in the model,
# enforces each command's `expect` annotation, prints a one-line-per-command
# summary, and exits non-zero if any result contradicts its `expect` — a `check`
# that finds a counterexample, or a non-vacuity `run` that comes back UNSAT.
#
# (This uses Alloy's supported command-line entry point rather than a bespoke Java
# driver on its internal API — same result, nothing custom to compile or maintain.)
#
# Requirements:
#   - Java 17+ (tested with OpenJDK 21)
#   - The Alloy 6 distribution jar (org.alloytools.alloy.dist). This script
#     fetches Alloy 6.2.0 from Maven Central on first run if ALLOY_JAR is unset
#     and ./alloy.jar is absent, and verifies it against a pinned SHA-256.
#   - Only for that auto-fetch path: `curl`, plus a SHA-256 tool (`sha256sum`,
#     `shasum`, or `openssl`). Neither is needed when ALLOY_JAR points at a jar
#     that already exists.
#
# Usage:
#   ./run.sh                       # fetch+verify jar if needed, run the model
#   ALLOY_JAR=/path/to/alloy.jar ./run.sh
#
# Exit code: 0 if every command matched its `expect`; non-zero (from `alloy exec`)
# if any did not, or on a solver/parse error. Full solutions and a machine-readable
# receipt.json are written under ./out/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")"

ALLOY_VERSION="6.2.0"
# SHA-256 of org.alloytools.alloy.dist-6.2.0.jar on Maven Central (cross-checked
# against Maven's published .sha1/.md5 for the same artifact). Pinning this makes
# the fetched binary tamper-evident — a swapped mirror/proxy artifact fails here
# rather than being compiled and executed unverified.
ALLOY_SHA256="6037cbeee0e8423c1c468447ed10f5fcf2f2743a2ffc39cb1c81f2905c0fdb9d"
JAR="${ALLOY_JAR:-./alloy.jar}"

verify_sha256() {
  # $1 = file. Returns 0 iff its SHA-256 equals the pin. If NO checksum tool is
  # available, fail (return non-zero) rather than pass: a security pin that
  # silently no-ops is worse than none — we refuse to run an unverified binary.
  local f="$1" got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$f" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "$f" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    got="$(openssl dgst -sha256 "$f" | awk '{print $NF}')"
  else
    echo ">> ERROR: no sha256sum/shasum/openssl available to verify the Alloy jar;" >&2
    echo "   refusing to run unverified. Install one, or vet a jar and pass ALLOY_JAR=." >&2
    return 2
  fi
  [[ "$got" == "$ALLOY_SHA256" ]]
}

if [[ -n "${ALLOY_JAR:-}" ]]; then
  # Caller supplied an explicit jar path: honour it verbatim and do NOT auto-fetch.
  # A missing path is a configuration error (e.g. a typo), not a signal to silently
  # download something else. The pinned checksum is not enforced here — an explicit
  # ALLOY_JAR is the caller's own vetted artifact, possibly a different Alloy build.
  if [[ ! -f "$JAR" ]]; then
    echo ">> ERROR: ALLOY_JAR=$JAR does not exist. Unset ALLOY_JAR to auto-fetch Alloy" >&2
    echo "   ${ALLOY_VERSION} from Maven Central, or point ALLOY_JAR at a real jar." >&2
    exit 4
  fi
elif [[ ! -f "$JAR" ]]; then
  # Default path, no cached jar: fetch from Maven Central atomically and verify the
  # pinned SHA-256 before trusting it. Download to a temp path and move into place
  # only on success, so an interrupted download can never leave a truncated
  # ./alloy.jar that a later run treats as valid.
  echo ">> Alloy jar not found; fetching Alloy ${ALLOY_VERSION} from Maven Central ..."
  URL="https://repo1.maven.org/maven2/org/alloytools/org.alloytools.alloy.dist/${ALLOY_VERSION}/org.alloytools.alloy.dist-${ALLOY_VERSION}.jar"
  tmp="$(mktemp ./alloy.jar.XXXXXX)"
  trap 'rm -f "$tmp"' EXIT
  curl -fSL "$URL" -o "$tmp"
  if ! verify_sha256 "$tmp"; then
    echo ">> ERROR: downloaded Alloy jar failed SHA-256 verification (expected $ALLOY_SHA256)." >&2
    exit 4
  fi
  mv "$tmp" ./alloy.jar
  trap - EXIT
  JAR="./alloy.jar"
else
  # Default path, cached ./alloy.jar we fetched previously — re-verify before trusting
  # it, so a corrupted cache surfaces as a clear checksum error, not a javac failure.
  if ! verify_sha256 "$JAR"; then
    echo ">> ERROR: cached ./alloy.jar failed SHA-256 verification; delete it and re-run." >&2
    exit 4
  fi
fi

echo ">> Running model via 'alloy exec' (SAT4J, pure Java; a few minutes at the top scopes) ..."
# `exec -c '*'` runs every check and run in the model, enforces each command's
# `expect` annotation, and returns non-zero on any mismatch. `-s sat4j` pins the
# pure-Java solver (no native libraries). Solutions + receipt.json go to ./out/;
# the concise per-command summary goes to stdout. The `sed` only strips the JVM's
# JAVA_TOOL_OPTIONS banner; unlike `grep -v` it always exits 0 (it can't be the
# pipe's failing member), so `pipefail` (set above) faithfully surfaces exec's own
# exit code.
java -jar "$JAR" exec --command '*' --solver sat4j --force --output out chain-tamper-evidence.als \
  2>&1 | sed '/^Picked up JAVA_TOOL/d'
