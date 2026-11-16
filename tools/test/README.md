# Tests

```
node tools/test/unit.js                    # inspect.js + scan.js on the sample fixtures
python3 tools/test/server.py 8799 &        # serves public/ + a real JVM behind a fake CheerpJ
node tools/test/e2e.js http://127.0.0.1:8799 /path/to/fixtures
```

`e2e.js` drives headless Chrome (Playwright). The CheerpJ CDN script is replaced by
`cheerpj-stub.js`, which forwards `cheerpjRunMain` to `server.py`; that runs the exact
same driver classes (`ezlarp.Run`, `ezlarp.Dex`, `ezlarp.Asm`) on a local JDK. Everything
else in the page runs unmodified. Fixtures it expects in the fixtures dir: `app.dex`,
`one.class`, `cls/demo/mod/Config.class`, `nested.jar` (contains `inner-mod.jar`),
`native.exe`, `junk.bin`, `big.jar` (>150 classes), `mods-a.jar`, `clean-lib.jar`,
`sample-wrapped.exe`.
