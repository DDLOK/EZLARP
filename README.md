# EZLARP

jar / class / exe decompiler &middot; Vineflower + CFR &middot; slim black UI
**100% in-browser &middot; no backend &middot; nothing leaves your machine**

Live: https://ezlarp.pages.dev

## What it does

- **.jar / .zip / .war**: decompiles every class to Java. Big jars (over 150 classes) open instantly and decompile each class when you click it, with a "decompile all" button.
- **.apk / .dex / .aar / .xapk**: dex2jar converts Dalvik bytecode in the browser, then the normal decompiler runs. Decoded `AndroidManifest.xml`, permissions (sensitive ones flagged), SDK levels and components.
- **.class**: one or many; they're packed into a jar at their package paths.
- **.exe / .dll**: Java apps wrapped as exe (Launch4j, exe4j, JSmooth...) get their jar extracted and decompiled. Everything else gets a VirusTotal-style report: version info, icon, UAC level, compile time, sections + entropy, imports/exports, .NET and packer detection, PyInstaller contents (with extraction), and a searchable strings list.
- **Threat scan**: 27 static indicator rules over every class's constant pool (Discord/Telegram exfil, Minecraft session-token access, browser/Discord/wallet/launcher credential paths, persistence, shell commands, runtime class loading, payload URLs, IP lookups...), plus URL/IP extraction and an obfuscation heuristic. Findings link to the exact class. Heuristics, not an antivirus.
- **Batch scan**: drop a whole mods folder (or any mix of jars/exes) and get a sorted verdict table. Also works on nested archives inside a jar.
- **Viewer**: file tree with risk dots and entrypoint stars, editor tabs, outline, syntax highlighting, line numbers (click to copy `path:line`), double-click or ctrl+click a class name to jump to it, "usages" (who references this class), bytecode view, image preview, pretty JSON, decoded binary XML.
- **Search**: file names, decompiled code (plain or `/regex/`), and string constants across every class without decompiling.
- **Mod metadata**: Fabric / Quilt / Forge / NeoForge / Bukkit / Paper / Bungee / Velocity descriptors, entrypoints, dependencies, mixin classes.
- **Engines**: Vineflower 1.12.0 (default) or CFR 0.152, auto-fallback, optional renaming of obfuscated names.
- **Export**: source .zip, single files, JSON report. MD5 / SHA-1 / SHA-256 with a VirusTotal lookup link (only the hash, only when clicked).
- **Python exes (PyInstaller)**: every bundled module is listed with its functions, classes, names and string constants; all of them go through the threat scan; download any module as a real `.pyc` (correct header) for pycdc / decompyle3.
- **Jar-in-jar**: nested jars (e.g. Fabric `META-INF/jars/`) and bundled `.dll/.so/.exe` files are scanned too, with a per-file table; findings link straight into the inner jar.
- **Hidden strings**: base64, hex and reversed strings are decoded and scanned; decoded URLs/paths are listed.
- **Compare two versions**: classes / resources added, removed and changed, indicators the new version adds, new URLs, and a line diff of the decompiled source of any changed class.
- **Open from a link**: Modrinth mod/plugin pages (latest or a specific version, hash-checked), Modrinth modpacks (`.mrpack`: list every mod, then download and batch-scan them, hash-checked), raw GitHub files and any other URL that allows cross-site downloads. `#url=...` in the address works too.
- **Copy summary**: short Discord-ready text of the verdict, top findings and defanged URLs.
- Nested archives open in place with a breadcrumb back. Recent scans (names and verdicts only) are listed on the start page.

## How it works

```
browser
  +-- static files from public/ (Cloudflare Pages)
  +-- CheerpJ 5 runtime (OpenJDK 17 compiled to WebAssembly, cached after first visit)
  +-- cheerpjRunMain("ezlarp.Run", helper + vineflower + cfr jars, engine, in.jar, out.zip)
  |      ezlarp.Run drives the engine through its Java API and writes all sources to one zip
  |      ezlarp.Dex converts .dex to a jar (dex2jar), ezlarp.Asm prints bytecode (ASM)
  +-- JSZip reads the zip, the UI renders it
```

`public/inspect.js` does .class / PE parsing and string extraction in plain JS.

### Files

| file | what |
|---|---|
| `public/index.html`, `style.css`, `app.js` | UI and flow |
| `public/ui.js` | rendering: tree, viewer, search, scan / details views |
| `public/inspect.js` | sniffing, .class / PE / PyInstaller / dex / binary-XML parsers, strings, MD5 |
| `public/scan.js` | threat-indicator rules, encoded-string decoding |
| `public/compare.js` | compare two versions, line diff |
| `public/vendor/jszip.min.js` | JSZip 3.10.1 |
| `public/vineflower-1.12.0.jar`, `cfr-0.152.jar` | decompiler engines (unmodified upstream releases) |
| `public/d2j-bundle-2.4.jar` | dex2jar 2.4 + ASM 9.5 (unmodified classes, merged into one jar) |
| `public/ezlarp-helper-v2.jar` | drivers built from `tools/helper/src/ezlarp/*.java` (Run, Dex, Asm) |
| `public/samples/` | sample files for the "try" buttons, built by `tools/samples/build.sh` |
| `public/_headers` | long cache for the (versioned) jars |

Rebuild the driver after editing `Run.java` (needs JDK 17+):

```
bash tools/helper/build.sh
```

Bump the `-vN` suffix in `build.sh` and in `CLASSPATH` in `app.js` when it changes, so browsers never use a stale cached copy.

## Deploy

Cloudflare Pages is git-connected to `main`: build command blank, output directory `public`. Every push redeploys in about 30 seconds.

`.github/workflows/deploy.yml` is an alternative GitHub Actions deploy (needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets). Use one or the other, not both.

## Tests

See `tools/test/README.md`: unit tests for the parsers and scanner, and a headless-Chrome
end-to-end test that runs the real driver classes on a local JVM.

## Local dev

```
npm install
npm run dev
```

Opens on http://localhost:8788.

## Notes

- First visit downloads the CheerpJ runtime (tens of MB); it's cached after that.
- The first decompile per page load includes JVM startup; later ones are faster.
- Big jars (thousands of classes) work but take a while. Browser memory is the ceiling.
- Not supported: decompiling .NET or native machine code to source (the exe report covers what can be learned statically).
