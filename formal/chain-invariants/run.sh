#!/usr/bin/env bash
#
# Run the AARP chain tamper-evidence Alloy model headless and print, for every
# `check` and `run` command, whether the result matched its `expect` annotation.
#
# Requirements:
#   - Java 17+ (tested with OpenJDK 21)
#   - The Alloy 6 distribution jar (org.alloytools.alloy.dist). This script
#     fetches Alloy 6.2.0 from Maven Central on first run if ALLOY_JAR is unset
#     and ./alloy.jar is absent, and verifies it against a pinned SHA-256.
#
# Usage:
#   ./run.sh                       # fetch+verify jar if needed, compile runner, run model
#   ALLOY_JAR=/path/to/alloy.jar ./run.sh
#   DUMP=1 ./run.sh                # also print the instance for any unexpected result
#
# Exit code (from RunAlloy): 0 all commands matched their `expect`;
#   2 a result contradicted its `expect` (counterexample, or a non-vacuity run
#   went UNSAT); 3 a command threw during solving.
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
  # $1 = file. Returns 0 iff its SHA-256 equals the pin. Uses whichever tool exists.
  local f="$1" got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$f" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    got="$(shasum -a 256 "$f" | awk '{print $1}')"
  else
    echo ">> WARNING: no sha256sum/shasum available; skipping integrity check" >&2
    return 0
  fi
  [[ "$got" == "$ALLOY_SHA256" ]]
}

if [[ ! -f "$JAR" ]]; then
  echo ">> Alloy jar not found; fetching Alloy ${ALLOY_VERSION} from Maven Central ..."
  URL="https://repo1.maven.org/maven2/org/alloytools/org.alloytools.alloy.dist/${ALLOY_VERSION}/org.alloytools.alloy.dist-${ALLOY_VERSION}.jar"
  # Download to a temp path and move into place only on success, so an interrupted
  # download can never leave a truncated ./alloy.jar that a later run treats as valid.
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
elif [[ -z "${ALLOY_JAR:-}" ]]; then
  # A cached ./alloy.jar we fetched previously — re-verify before trusting it, so a
  # corrupted cache surfaces as a clear checksum error instead of a javac failure.
  if ! verify_sha256 "$JAR"; then
    echo ">> ERROR: cached ./alloy.jar failed SHA-256 verification; delete it and re-run." >&2
    exit 4
  fi
fi

echo ">> Compiling headless runner ..."
javac -cp "$JAR" RunAlloy.java

echo ">> Running model (SAT4J, pure Java; this takes a few minutes at the top scopes) ..."
# Quiet Kodkod's INFO logging; keep only the per-command verdicts. `pipefail` (set
# above) preserves RunAlloy's exit code through the grep, and RunAlloy always prints
# a non-filtered header line so grep exits 0 and never masks/inverts that code.
java -Dorg.slf4j.simpleLogger.defaultLogLevel=warn -cp "$JAR:." RunAlloy chain-tamper-evidence.als \
  2>&1 | grep -vE "INFO kodkod|^Picked up JAVA_TOOL"
