# EZLARP

jar / class / exe decompiler &middot; Vineflower + CFR &middot; slim black UI
**100% in-browser &middot; no backend &middot; nothing leaves your machine**

Live: https://ezlarp.pages.dev

## What it does

- **.jar / .zip / .war**: decompiles every class to Java source. Resources (plugin.yml, fabric.mod.json, configs, manifest) are browsable too.
- **.class**: drop one or many; they're packed into a jar at their real package paths and decompiled.
- **.exe / .dll**:
  - Java apps wrapped as exe (Launch4j, exe4j, JSmooth, ...): the embedded jar is found and decompiled.
  - Anything else: VirusTotal-style report: PE headers, compile time, sections with entropy, imports and exports, .NET detection, packer and installer detection (UPX, PyInstaller, Inno, NSIS, ...), and a searchable strings list (URLs, IPs, paths, registry keys).
- Viewer: file tree with filter, full-text search across all decompiled code, syntax highlighting, line numbers, copy, per-file download, and download everything as a .zip.
- Engines: **Vineflower 1.12.0** (default) or **CFR 0.152**, with automatic fallback to the other one if a decompile fails.

## How it works

```
browser
  +-- static files from public/ (Cloudflare Pages)
  +-- CheerpJ 5 runtime (OpenJDK 17 compiled to WebAssembly, cached after first visit)
  +-- cheerpjRunMain("ezlarp.Run", helper + vineflower + cfr jars, engine, in.jar, out.zip)
  |      ezlarp.Run drives the engine through its Java API and writes all sources to one zip
  +-- JSZip reads the zip, the UI renders it
```

`public/inspect.js` does .class / PE parsing and string extraction in plain JS.

### Files

| file | what |
|---|---|
| `public/index.html`, `style.css`, `app.js` | UI and flow |
| `public/inspect.js` | file sniffing, .class parser, PE parser, strings |
| `public/vineflower-1.12.0.jar`, `cfr-0.152.jar` | decompiler engines (unmodified upstream releases) |
| `public/ezlarp-helper-v1.jar` | driver built from `tools/helper/src/ezlarp/Run.java` |
| `public/_headers` | long cache for the (versioned) jars |

Rebuild the driver after editing `Run.java` (needs JDK 17+):

```
bash tools/helper/build.sh
```

Bump the `-vN` suffix in `build.sh` and in `CLASSPATH` in `app.js` when it changes, so browsers never use a stale cached copy.

## Deploy

Cloudflare Pages is git-connected to `main`: build command blank, output directory `public`. Every push redeploys in about 30 seconds.

`.github/workflows/deploy.yml` is an alternative GitHub Actions deploy (needs `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets). Use one or the other, not both.

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
- Not supported yet: Android `.apk` / `.dex`, decompiling .NET or native code to source.
