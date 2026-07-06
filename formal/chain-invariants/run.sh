#!/usr/bin/env bash
#
# Run the AARP chain tamper-evidence Alloy model headless and print, for every
# `check` and `run` command, whether Alloy found a counterexample/instance or
# exhausted the scope cleanly.
#
# Requirements:
#   - Java 17+ (tested with OpenJDK 21)
#   - The Alloy 6 distribution jar (org.alloytools.alloy.dist). This script
#     fetches Alloy 6.2.0 from Maven Central on first run if ALLOY_JAR is unset
#     and ./alloy.jar is absent.
#
# Usage:
#   ./run.sh                       # fetch jar if needed, compile runner, run model
#   ALLOY_JAR=/path/to/alloy.jar ./run.sh
#   DUMP=1 ./run.sh                # also print any counterexample instance
#
# Exit code: 0 if no `check` produced a counterexample; 2 if any did.
set -euo pipefail
cd "$(dirname "$0")"

ALLOY_VERSION="6.2.0"
JAR="${ALLOY_JAR:-./alloy.jar}"

if [[ ! -f "$JAR" ]]; then
  echo ">> Alloy jar not found; fetching Alloy ${ALLOY_VERSION} from Maven Central ..."
  URL="https://repo1.maven.org/maven2/org/alloytools/org.alloytools.alloy.dist/${ALLOY_VERSION}/org.alloytools.alloy.dist-${ALLOY_VERSION}.jar"
  curl -fSL "$URL" -o ./alloy.jar
  JAR="./alloy.jar"
fi

echo ">> Compiling headless runner ..."
javac -cp "$JAR" RunAlloy.java

echo ">> Running model (SAT4J, pure Java; this takes a few minutes at the top scopes) ..."
# Quiet Kodkod's INFO logging; keep only the per-command verdicts.
java -Dorg.slf4j.simpleLogger.defaultLogLevel=warn -cp "$JAR:." RunAlloy chain-tamper-evidence.als \
  2>&1 | grep -vE "INFO kodkod|^Picked up JAVA_TOOL"
