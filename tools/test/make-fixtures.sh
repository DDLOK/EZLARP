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

# mixin into the session class + webhook (stub annotation: same name and retention as Mixin's)
rm -rf mx && mkdir -p mx/src/org/spongepowered/asm/mixin mx/src/net/minecraft/client/session mx/src/evil/mixin
cat > mx/src/org/spongepowered/asm/mixin/Mixin.java <<'J'
package org.spongepowered.asm.mixin;
import java.lang.annotation.*;
@Retention(RetentionPolicy.CLASS) @Target(ElementType.TYPE)
public @interface Mixin { Class<?>[] value() default {}; String[] targets() default {}; int priority() default 1000; }
J
cat > mx/src/net/minecraft/client/session/Session.java <<'J'
package net.minecraft.client.session;
public class Session { public String getAccessToken() { return ""; } }
J
cat > mx/src/evil/mixin/SessionMixin.java <<'J'
package evil.mixin;
import org.spongepowered.asm.mixin.Mixin;
@Mixin(net.minecraft.client.session.Session.class)
public class SessionMixin { static final String HOOK = "https://discord.com/api/webhooks/000000000000000000/EZLARP-TEST-NOT-REAL"; }
J
cat > mx/src/evil/mixin/TitleMixin.java <<'J'
package evil.mixin;
import org.spongepowered.asm.mixin.Mixin;
@Mixin(targets = "net.minecraft.client.gui.screen.TitleScreen", priority = 900)
public class TitleMixin { }
J
javac --release 8 -Xlint:-options -d mx/out $(find mx/src -name '*.java') && rm -rf mx/out/net mx/out/org \
  && jar --create --file mixin-session.jar -C mx/out . && rm -rf mx

# encrypted payload + runtime class loading
rm -rf pl && mkdir -p pl/src/demo pl/out/assets
cat > pl/src/demo/Loader.java <<'J'
package demo;
public class Loader extends ClassLoader {
  Class<?> load(byte[] b) { return defineClass("x", b, 0, b.length); }
  java.io.InputStream blob() { return getClass().getResourceAsStream("/assets/tbfpkodt.cache"); }
}
J
javac --release 8 -Xlint:-options -d pl/out pl/src/demo/Loader.java && head -c 20000 /dev/urandom > pl/out/assets/tbfpkodt.cache \
  && jar --create --file payload.jar -C pl/out . && rm -rf pl

# strings hidden with Base64 / reversal / byte arrays
rm -rf hs && mkdir -p hs/demo && cat > hs/demo/Hide.java <<'J'
package demo;
import java.util.Base64;
public class Hide {
  static String a() { return new String(Base64.getDecoder().decode("aHR0cHM6Ly9leGFtcGxlLmNvbS9ob29r")); }
  static String b() { return new StringBuilder("txt.yek/moc.elpmaxe//:sptth").reverse().toString(); }
  static String c() { return new String(new byte[]{104,116,116,112,115,58,47,47,120,46,121}); }
}
J
javac --release 8 -Xlint:-options -d hs/out hs/demo/Hide.java && jar --create --file hide.jar -C hs/out . && rm -rf hs

# jar-in-jar + bundled native binary
mkdir -p nest/META-INF/jars && cp "$P/samples/sample.jar" nest/META-INF/jars/inner-mod.jar && cp native.exe nest/lib-native.dll \
  && echo hello > nest/readme.txt && (cd nest && jar --create --file ../nested.jar .)

# two versions of a mod that keeps its code in a nested jar (compare must look inside)
for v in old new; do
  mkdir -p nv/META-INF/jars && rm -f nv/META-INF/jars/*
  if [ $v = old ]; then cp sample-old.jar nv/META-INF/jars/inner-mod-0.9.0+abc123.jar; else cp "$P/samples/sample.jar" nv/META-INF/jars/inner-mod-1.0.0+def456.jar; fi
  echo '{"schemaVersion":1,"id":"wrapper","version":"1"}' > nv/fabric.mod.json
  rm -f nested-$v.jar && (cd nv && jar --create --file ../nested-$v.jar .)
done
rm -rf nv

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
