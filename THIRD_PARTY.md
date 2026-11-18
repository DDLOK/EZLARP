# Third-party components

EZLARP serves these unmodified (except where noted) jars from `public/` and runs them
in the visitor's browser through CheerpJ. Each keeps its own license.

| Component | Version | License | Source |
|---|---|---|---|
| Vineflower | 1.12.0 | Apache-2.0 | https://github.com/Vineflower/vineflower |
| CFR | 0.152 | MIT | https://github.com/leibnitz27/cfr |
| Procyon | 0.6.0 | Apache-2.0 | https://github.com/mstrobel/procyon |
| JD-Core | 1.1.3 | GPL-3.0 | https://github.com/java-decompiler/jd-core (classes `org/jd/core/**` taken unmodified from the JD-GUI 1.6.6 release jar) |
| JADX | 1.5.1 | Apache-2.0 | https://github.com/skylot/jadx (trimmed from `jadx-1.5.1-all.jar`: `jadx/{core,api,commons}`, the dex and java input plugins, gson (Apache-2.0), slf4j (MIT) and the `clst/` + `android/` data files; nothing modified) |
| dex2jar | 2.4 | Apache-2.0 | https://github.com/ThexXTurBoXx/dex2jar |
| JSZip | 3.x | MIT / GPL-3.0 (dual) | https://github.com/Stuk/jszip |
| highlight.js | 11.9.0 (CDN) | BSD-3-Clause | https://github.com/highlightjs/highlight.js |
| CheerpJ | 5.0 (CDN) | Leaning Technologies terms | https://cheerpj.com |

The EZLARP drivers that call these engines are in `tools/helper/src/ezlarp/`.
