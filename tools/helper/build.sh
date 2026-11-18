#!/usr/bin/env bash
# Rebuilds public/ezlarp-helper-v4.jar: the CheerpJ drivers for Vineflower/CFR
# (ezlarp.Run), Procyon (ezlarp.RunProcyon), JD-Core (ezlarp.RunJd), JADX
# (ezlarp.RunJadx), dex2jar (ezlarp.Dex) and the ASM bytecode view (ezlarp.Asm).
# jadx-core-1.5.1.jar is a trimmed build of jadx-1.5.1-all.jar: jadx/{core,api,commons},
# the dex + java input plugins, gson, slf4j and the clst/ + android/ data files.
# Bump the -vN suffix (here and in public/app.js) when the sources change,
# so browsers never run a stale cached copy.
# Needs a JDK 17+ on PATH. Run from the repo root: bash tools/helper/build.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
out=$(mktemp -d)
javac --release 17 -encoding UTF-8 -Xlint:-options \
  -cp public/vineflower-1.12.0.jar:public/cfr-0.152.jar:public/d2j-bundle-2.4.jar:public/procyon-decompiler-0.6.0.jar:public/jd-core-1.1.3.jar:public/jadx-core-1.5.1.jar \
  -d "$out" tools/helper/src/ezlarp/*.java
jar --create --file public/ezlarp-helper-v4.jar -C "$out" .
echo "built public/ezlarp-helper-v4.jar"
