# Tests

```
node tools/test/unit.js                    # inspect.js + scan.js on the sample fixtures
python3 tools/test/server.py 8799 &        # serves public/ + a real JVM behind a fake CheerpJ
node tools/test/e2e.js http://127.0.0.1:8799 /path/to/fixtures
```

`e2e.js` drives headless Chrome (Playwright). The CheerpJ CDN script is replaced by
`cheerpj-stub.js`, which forwards `cheerpjRunMain` to `server.py`; that runs the exact
same driver classes (`ezlarp.Run`, `ezlarp.Dex`, `ezlarp.Asm`) on a local JDK. Everything
else in the page runs unmodified. Fixtures are built by `tools/test/make-fixtures.sh /tmp/fx` (see the script header for what it needs).
- `NODE_NO_WARNINGS=1 node tools/test/functions.test.mjs` tests the Pages Functions (login, free scans, VPN block).
