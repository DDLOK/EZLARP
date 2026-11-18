# EZLARP

malware scanner + decompiler for jar / apk / exe &middot; Vineflower + CFR &middot; slim black UI
**files are scanned in your browser and never uploaded** &middot; one small server function downloads links

Live: https://ezlarp.pages.dev

## What it does

- **Report first (like jarscanner.org)**: drop a file or paste a link and you get a verdict in seconds: **MALICIOUS** (named detection), **SUSPICIOUS** (high-risk indicators), **NEEDS REVIEW** or **CLEAN**. The scan is plain JavaScript; the Java engine (CheerpJ) is only downloaded when you open the CODE tab, so the report works on phones and when the CDN is blocked.
- **Built-in quick decompiler** (`public/jview.js`): turns bytecode into readable Java-like code in plain JavaScript (calls, strings, fields, byte arrays decoded to text, string concatenation, lambdas, imports; if/else, while, do-while, &&/||, ternaries and try/catch are rebuilt, anything unusual stays a labelled goto). Opening a class shows it instantly; on computers Vineflower's full source replaces it when ready. On iPhone / iPad, where the in-browser JVM doesn't start, it is the default ("full source" still tries Vineflower). The bytecode view is also pure JS now. The JVM gets a 60 s start timeout instead of hanging.
- **Phones**: code first with the file list in a drawer ("☰ Files"), long lines wrap at word boundaries, a one-row scrollable toolbar, and classes open scrolled to their declaration. Installable to the home screen (web app manifest) and the page shell works offline (`public/sw.js`, network first, files you scan are never cached).
- **PC**: drag the divider to resize the file list (remembered), keyboard shortcuts (`?` lists them: `1`-`4` tabs, `q` quick/full, `b` bytecode, `u` usages, `w` wrap), and paste a link anywhere on the page to scan it.
- **Mixins**: `@Mixin` annotations are read from the class files (including mods nested inside jars); DETAILS lists each mixin and the Minecraft class it rewrites, and mixins into the session/login class are flagged.
- **Hidden payloads**: files with no known format and random-looking bytes (entropy ≥ 7.5) are reported as "Encrypted file inside"; together with runtime class loading (also via a `ClassLoader` subclass) that is the "Hidden payload loader" detection.
- **Hidden strings in code**: the quick view adds the plain text next to `Base64...decode("...")`, `new StringBuilder("...").reverse()`, hex decoders and byte arrays.
- **Share links**: "share" packs the report summary into a compressed `#r=` link (Discord-sized, nothing uploaded); opening it shows a read-only report with a warning that links can be edited.
- **Five decompilers** (settings → engine): Vineflower 1.12 (best for Java), JADX 1.5 (best for Android: reads dex directly, no dex2jar), CFR 0.152, Procyon 0.6 and JD-Core 1.1.3 (JD-GUI's engine). "Auto" (default) picks JADX for APK/dex and Vineflower for everything else; auto-fallback tries the next engines when one fails; the code toolbar has a per-class engine switch to compare outputs. Third-party licenses: [THIRD_PARTY.md](THIRD_PARTY.md).
- **Named detections**: signatures for known Minecraft malware (fractureiser, Skyrage) and behaviour detections that need "steals X" and "sends it out" together: Minecraft session stealer (same class), Discord token grabber, browser password stealer, crypto wallet stealer, launcher account stealer, dropper.
- **Scan with URL**: Discord attachments, MediaFire pages, Gofile, GitHub release files, CurseForge CDN, Modrinth, Dropbox and Google Drive. Hosts that block in-browser downloads go through `functions/api/fetch.js` (a Cloudflare Pages Function with a host allowlist and a 150 MB cap; files stream through and are not stored).

- **.jar / .zip / .war**: every class decompiles to Java when you open it, or all at once with "decompile all". `#lazy=N` in the address decompiles files with up to N classes up front.
- **.apk / .dex / .aar / .xapk**: dex files are parsed in JS (tree, scan, search, usages in seconds even for 100 MB APKs); each class goes through dex2jar only when opened, and "decompile all" works in chunks. Decoded `AndroidManifest.xml`, permissions (sensitive ones flagged), SDK levels and components.
- **.class**: one or many; they're packed into a jar at their package paths.
- **.NET .exe / .dll → C#** (`public/cil.js`): a built-in .NET decompiler reads the metadata tables, signatures and IL and rebuilds C#: classes, fields, constants, properties, events, P/Invoke, attributes, generics, if/else, while, do-while, break, ternaries, try/catch/finally, `x++`/`+=`, indexers, string concatenation, array initializers (embedded byte arrays are printed), and an IL view per type. Calls into .NET APIs (Process.Start, WebClient, Assembly.Load, registry Run keys, DPAPI...) feed the threat scan. Tested on 2,800+ types of real assemblies (ILSpy, Mono.Cecil, Iced, System.Reflection.Metadata) without a failure. Try the "C# .exe" sample.
- **Native .exe / .dll → x86/x64 assembly** (`public/x86.js`, `public/native.js`): a built-in disassembler (general-purpose, x87, MMX, SSE–SSE4.2, AVX lengths) walks the program from its entry point, TLS callbacks and exports, follows calls, and labels Windows API calls and referenced strings. Matches objdump's instruction boundaries on 100% of 700k+ instructions of real binaries. Imported Windows APIs (process injection, URLDownloadToFile, keyboard hooks, registry autostart, DPAPI...) feed the threat scan.
- **Windows app** (`desktop/`): `EZLARP-Setup.exe` installs per user (no admin), adds "Scan with EZLARP" to the right-click menu of .jar/.exe/.dll/.apk files and a one-click scan of your Minecraft mods folders, and updates itself (checksum-verified). Needs a Discord login. See [desktop/README.md](desktop/README.md).
- **VS Code layout** (`public/ide.js`, `public/ide.css`): menus, activity bar, Explorer with file icons + Outline, editor tabs, breadcrumbs, minimap, Problems/Output panel, status bar (verdict, problem counts, Ln/Col, language), Ctrl+P quick open, Ctrl+Shift+P command palette, Ctrl+Shift+O symbols, Ctrl+G line, zoom, settings. Default in the Windows app; on PC browsers use the "VS Code layout" link in the footer (or `#ide`).
- **.exe / .dll**: Java apps wrapped as exe (Launch4j, exe4j, JSmooth...) get their jar extracted and decompiled. Everything else gets a VirusTotal-style report: version info, icon, UAC level, compile time, sections + entropy, imports/exports, .NET and packer detection, PyInstaller contents (with extraction), and a searchable strings list.
- **Threat scan**: 27 static indicator rules over every class's constant pool (Discord/Telegram exfil, Minecraft session-token access, browser/Discord/wallet/launcher credential paths, persistence, shell commands, runtime class loading, payload URLs, IP lookups...), plus URL/IP extraction and an obfuscation heuristic. Findings link to the exact class. Session-token reads that only talk to Mojang/Microsoft servers are reported separately from token theft. Heuristics, not an antivirus.
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
| `public/ezlarp-helper-v4.jar` | drivers built from `tools/helper/src/ezlarp/*.java` (Run, RunProcyon, RunJd, RunJadx, Dex, Asm) |
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

## Accounts, free scans and VPN block

Logged-out visitors get a few free scans (default 2 per 24 h per IP, IPv6 counted per /64).
Logging in with Discord removes the limit. Login is done by the EZLARP Discord bot, which also
adds the user to the Discord server. VPNs, proxies, hosting/datacenter IPs and Tor are blocked
(iCloud Private Relay is allowed).

Nothing is enforced until login is set up: with no secrets the site stays open, no limit, no login button.

### Cloudflare Pages settings (Settings → Variables and Secrets, Production)

Login works one of two ways. Pick one.

**A. Built-in (easiest, no extra hosting).** The site does Discord login itself and uses the
bot's token to add the user to the server.

| Name | What |
|---|---|
| `SESSION_SECRET` | Signs the session cookie. 32+ random chars. |
| `DISCORD_CLIENT_ID` | The bot's Application ID. |
| `DISCORD_CLIENT_SECRET` | OAuth2 client secret from the Discord developer portal. |
| `DISCORD_BOT_TOKEN` | The bot's token (secret). |
| `DISCORD_GUILD_ID` | The server to add people to. |
| `DISCORD_ROLE_ID` | Optional role to give them. |

In the Discord developer portal, OAuth2 → Redirects: `https://ezlarp.pages.dev/auth/callback`.
The bot must be in the server with the Create Invite permission (and above `DISCORD_ROLE_ID`).

**B. Through the bot's own web server.** Set these; they win over A if both are set.

| Name | What |
|---|---|
| `SESSION_SECRET` | As above. |
| `AUTH_SECRET` | Shared with the bot. Signs the login handoff token. |
| `BOT_LOGIN_URL` | The bot's login page, e.g. `https://bot.example.com/login`. |
| `AUTH_AUDIENCE` | Optional. Expected `aud` in the bot token. Default `ezlarp`. |

**Either way, optional:**

| Name | What |
|---|---|
| `PUBLIC_ORIGIN` | Defaults to the request origin, e.g. `https://ezlarp.pages.dev`. |
| `ANON_SCAN_LIMIT` | Free scans before login. Default `2`. |
| `ANON_WINDOW_HOURS` | Window for the free scans. Default `24`. |
| `VPN_BLOCK` | Set to `off` to turn the VPN block off. |
| `PROXYCHECK_KEY` | proxycheck.io key for better VPN detection. |
| `IP_SALT` | Extra salt for the hashed IPs kept in KV. |

KV: create a namespace and bind it as `EZLARP_KV` (Settings → Bindings → KV namespace).
Redeploy after changing settings.

### Bot handoff contract (option B)

1. The site sends the user to `BOT_LOGIN_URL?return=https://ezlarp.pages.dev/auth/done`.
2. The bot runs Discord OAuth2 (`identify guilds.join`) and adds the user to the server with
   `PUT /guilds/{guild}/members/{user}` using the bot token.
3. The bot redirects to `<return>?token=<JWT>`, or `<return>?error=<message>` on failure.

The JWT is HS256, signed with `AUTH_SECRET`:

```json
{ "sub": "<discord user id>", "name": "<display name>", "avatar": "<avatar hash or null>",
  "joined": true, "aud": "ezlarp", "iat": 1700000000, "exp": 1700000120, "jti": "<random id>" }
```

`exp - iat` must be 600 s or less (use 120). Each `jti` works once.

### Limits

- Scans of local files run in the browser, so their limit is a speed bump, not a lock.
  Scans by link go through `/api/fetch`, which checks the limit on the server.
- VPN detection is by network (ASN), Tor exit list and optionally proxycheck.io. A few home ISPs
  that also rent servers can be misjudged; add `VPN_BLOCK=off` if that bites.

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
