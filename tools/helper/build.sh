#!/usr/bin/env bash
# Rebuilds public/ezlarp-helper-v1.jar (the CheerpJ driver for Vineflower + CFR).
# Bump the -vN suffix (here and in public/app.js CLASSPATH) when Run.java changes,
# so browsers never run a stale cached copy.
# Needs a JDK 17+ on PATH. Run from the repo root: bash tools/helper/build.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
out=$(mktemp -d)
javac --release 17 -encoding UTF-8 \
  -cp public/vineflower-1.12.0.jar:public/cfr-0.152.jar \
  -d "$out" tools/helper/src/ezlarp/Run.java
jar --create --file public/ezlarp-helper-v1.jar -C "$out" .
rm -rf "$out"
echo "built public/ezlarp-helper-v1.jar"
