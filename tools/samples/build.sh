#!/usr/bin/env bash
# Rebuilds public/samples/. Needs JDK 17+, python3 and the dx jar from dex2jar's
# dex-tools release (DX_JAR=/path/to/dx-30.0.2.jar) for the dex in the apk.
set -euo pipefail
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
javac --release 17 -Xlint:-options -d "$tmp/stubs" tools/samples/stubs/net/minecraft/client/session/Session.java
javac --release 17 -Xlint:-options -cp "$tmp/stubs" -d "$tmp/cls" $(find tools/samples/src -name "*.java")
cp tools/samples/res/*.json "$tmp/cls/"
jar --create --file public/samples/sample.jar -C "$tmp/cls" .
# android sample: plain Java 8 classes -> dex
mkdir -p "$tmp/asrc/demo" "$tmp/acls"
cp tools/samples/android/App.java "$tmp/asrc/demo/"
javac --release 8 -Xlint:-options -d "$tmp/acls" "$tmp/asrc/demo/App.java"
java -cp "${DX_JAR:?set DX_JAR}" com.android.dx.command.Main --dex --output="$tmp/classes.dex" "$tmp/acls"
python3 tools/samples/make.py public/samples/sample.jar "$tmp/classes.dex" public/samples
ls -l public/samples
