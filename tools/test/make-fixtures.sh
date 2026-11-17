#!/usr/bin/env bash
# Builds the e2e fixtures into $1 (default /tmp/fx) from public/samples and a few
# tool binaries. Needs: JDK, zip, python3; DX_JAR (dex2jar's dx jar) for app.dex;
# a large jar to use as big.jar (BIG_JAR, default public/cfr-0.152.jar);
# any small Windows exe as native.exe (NATIVE_EXE).
set -euo pipefail
cd "$(dirname "$0")/../.."
P=$PWD/public
FX=${1:-/tmp/fx}
mkdir -p "$FX" && cd "$FX"
rm -rf cls oldv nest mr && mkdir -p cls

unzip -q -o "$P/samples/sample.jar" 'demo/mod/*.class' -d cls
cp cls/demo/mod/ExampleMod.class one.class
cp "$P/samples/sample.jar" mods-a.jar
cp "$P/samples/sample-wrapped.exe" .
cp "${BIG_JAR:-$P/cfr-0.152.jar}" big.jar
cp "${NATIVE_EXE:?set NATIVE_EXE to a small Windows .exe}" native.exe
head -c 5000 /dev/urandom > junk.bin

# clean "previous version" of the sample mod for the compare test
mkdir oldv && (cd oldv && unzip -q "$P/samples/sample.jar" && rm demo/mod/ScanDemo.class \
  && sed -i 's/"version": "1.0.0"/"version": "0.9.0"/' fabric.mod.json && jar --create --file ../sample-old.jar .)

# clean library jar (no indicators)
mkdir -p clean/demo && cat > clean/demo/Lib.java <<'J'
package demo;
public class Lib { public static int add(int a, int b) { return a + b; } static String hi() { return "hello"; } }
J
javac --release 8 -Xlint:-options -d clean/out clean/demo/Lib.java && jar --create --file clean-lib.jar -C clean/out . && rm -rf clean

# jar-in-jar + bundled native binary
mkdir -p nest/META-INF/jars && cp "$P/samples/sample.jar" nest/META-INF/jars/inner-mod.jar && cp native.exe nest/lib-native.dll \
  && echo hello > nest/readme.txt && (cd nest && jar --create --file ../nested.jar .)

# dex (from the apk sample)
unzip -p "$P/samples/sample.apk" classes.dex > app.dex

# Modrinth modpack pointing at the local test server
SHA=$(sha1sum "$P/samples/sample.jar" | cut -d' ' -f1); SZ=$(stat -c%s "$P/samples/sample.jar")
mkdir mr && cat > mr/modrinth.index.json <<J
{"formatVersion":1,"game":"minecraft","versionId":"1.0","name":"EZLARP Test Pack","files":[
 {"path":"mods/sample.jar","hashes":{"sha1":"$SHA"},"downloads":["http://127.0.0.1:8799/samples/sample.jar"],"fileSize":$SZ},
 {"path":"mods/bad-hash.jar","hashes":{"sha1":"0000000000000000000000000000000000000000"},"downloads":["http://127.0.0.1:8799/samples/sample.jar"],"fileSize":$SZ}],
 "dependencies":{"minecraft":"1.21.1","fabric-loader":"0.16.5"}}
J
rm -f pack.mrpack && (cd mr && zip -q ../pack.mrpack modrinth.index.json)
rm -rf oldv nest mr
ls -l "$FX"
