// End-to-end test in headless Chrome against tools/test/server.py.
// usage: node tools/test/e2e.js [baseUrl] [fixturesDir]
'use strict';
const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
const fs = require('fs'), path = require('path');
const BASE = process.argv[2] || 'http://127.0.0.1:8799';
const FX = process.argv[3] || '/tmp/fx';
const SHOTS = process.env.SHOTS || '/tmp/shots';
fs.mkdirSync(SHOTS, { recursive: true });
const stub = fs.readFileSync(path.join(__dirname, 'cheerpj-stub.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, name, extra) => { if (c) { pass++; console.log('  ok', name); } else { fail++; console.log('  FAIL', name, extra === undefined ? '' : extra); } };

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || '/usr/bin/google-chrome', args: ['--no-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });
  await ctx.route(/cjrtnc\.leaningtech\.com/, r => r.fulfill({ contentType: 'text/javascript', body: stub }));
  await ctx.route(/cdnjs\.cloudflare\.com/, r => r.abort());
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const EXPECTED = /unsupported file type/;
  page.on('console', m => { if (m.type() === 'error' && !/ERR_FAILED|Failed to load resource/.test(m.text()) && !EXPECTED.test(m.text())) errors.push(m.text()); });
  page.on('dialog', d => d.dismiss());

  const state = () => page.textContent('#fstate');
  const waitState = async (re, ms = 120000) => {
    await page.waitForFunction(r => new RegExp(r).test(document.getElementById('fstate').textContent) || !document.getElementById('err').hidden, re.source, { timeout: ms });
    const err = await page.$eval('#err', e => e.hidden ? '' : e.textContent);
    if (err) console.log('  page error box:', err.slice(0, 400));
    return err;
  };
  const reset = () => page.evaluate(() => { document.getElementById('fstate').textContent = '…'; document.getElementById('err').hidden = true; });
  const sample = async n => { await reset(); await page.evaluate(n => loadSample(n), n); };
  const drop = async file => { await reset(); await page.setInputFiles('#file', Array.isArray(file) ? file.map(f => path.join(FX, f)) : path.join(FX, file)); };
  const code = () => page.textContent('#code');
  const waitCode = (re, ms = 60000) => page.waitForFunction(r => new RegExp(r).test(document.getElementById('code').textContent), re.source, { timeout: ms }).then(() => true, () => false);
  const waitFull = (ms = 120000) => page.waitForFunction(() => { const f = S.files.get(S.current); return f && f.text != null && !/Quick view/.test(el.code.textContent); }, null, { timeout: ms }).then(() => true, () => false);
  const shot = n => page.screenshot({ path: `${SHOTS}/${n}.png` });

  // classic mode: small files decompile fully up front (#lazy=150), so the source-view tests below apply
  await page.goto(BASE + '/#lazy=150');
  ok(await page.title() === 'EZLARP — jar / apk / exe decompiler & scanner', 'title');

  // ---------------- sample mod jar
  console.log('sample jar');
  await sample('sample.jar');
  ok(!(await waitState(/^done/)), 'decompiled', await state());
  ok(/ExampleMod\.java/.test(await page.textContent('#tree')), 'tree lists ExampleMod.java');
  ok(await waitCode(/class ExampleMod/), 'first file is the entrypoint');
  ok(await page.$eval('#verdict', e => !e.hidden && e.classList.contains('malicious')), 'verdict malicious');
  ok(/Minecraft session stealer/.test(await page.textContent('#verdict')), 'detection name in verdict', await page.textContent('#verdict'));
  ok(/high-risk/.test(await page.textContent('#ftags')), 'risk tag');
  ok(/Fabric mod/.test(await page.textContent('#ftags')), 'fabric tag');
  ok(/[0-9a-f]{64}/.test(await page.textContent('#fhash')) && /[0-9a-f]{32}/.test(await page.textContent('#fmd5')), 'hashes');
  ok(/virustotal\.com\/gui\/file\/[0-9a-f]{64}/.test(await page.getAttribute('#vt', 'href')), 'virustotal link');
  ok(await page.$$eval('#ftabs .ftab', t => t.length) === 1, 'one tab open');
  ok(/^5 classes$/.test(await page.$$eval('#ftags .tagx', t => t.map(x => x.textContent).find(x => /class/.test(x)))), 'plural classes');
  ok(/^MALICIOUS/.test(await page.textContent('#verdict')), 'verdict word', await page.textContent('#verdict'));
  ok(await page.$eval('.rtab.active', e => e.dataset.view) === 'scan', 'report tab shown first');
  await page.click('.rtab[data-view=source]');
  await page.waitForTimeout(500);
  ok(await page.$eval('#fill', e => e.style.width) === '100%', 'progress full when done');
  ok(!(await page.$eval('#outline', e => e.hidden)) && /onInitialize/.test(await page.textContent('#outline')), 'outline has methods');
  await shot('01-jar-source');

  await page.click('.rtab[data-view=scan]');
  const scanText = await page.textContent('#scan');
  ok(/Discord webhook URL/.test(scanText) && /Reads the Minecraft session token/.test(scanText) && /Runs system commands/.test(scanText), 'scan findings');
  ok(/api\.ipify\.org/.test(scanText), 'url list');
  ok(/DECODED HIDDEN STRINGS/.test(scanText) && /example\.org\/ezlarp-demo\/hidden-url-not-real/.test(scanText), 'base64 decoded');
  await page.click('#copysum');
  await page.waitForTimeout(200);
  const summ = await page.evaluate(() => navigator.clipboard.readText());
  ok(/^\*\*sample\.jar\*\*/.test(summ) && /hxxps:\/\/discord\[\.\]com/.test(summ), 'copy summary', summ.slice(0, 200));
  await shot('02-scan');
  await page.click('#scan .finding.high a[data-cls]');
  ok(await waitCode(/FAKE_WEBHOOK/), 'finding location opens ScanDemo');
  ok(/ScanDemo\.java/.test(await page.textContent('#cpath')), 'path ScanDemo');
  ok(await page.$$eval('#ftabs .ftab', t => t.length) === 2, 'two tabs');

  await page.click('.rtab[data-view=details]');
  const det = await page.textContent('#details');
  ok(/EZLARP Sample Mod/.test(det) && /demo\.mod\.ExampleMod/.test(det) && /fabricloader/.test(det), 'fabric metadata');
  ok(/PACKAGES|JAVA ARCHIVE/.test(det), 'jar details');
  ok(/demo\.mod\.mixin\.TitleScreenMixin/.test(det), 'mixin classes listed');
  await page.click('#details a[data-cls="demo/mod/mixin/TitleScreenMixin"]');
  ok(await waitCode(/class TitleScreenMixin/), 'mixin link opens class');
  await page.click('.rtab[data-view=details]');
  await shot('03-details');

  await page.click('.rtab[data-view=source]');
  await page.click('#qmode [data-m=code]');
  await page.fill('#q', 'onInitialize');
  await page.waitForSelector('#tree .hit');
  ok(/ExampleMod\.java:\d+/.test(await page.textContent('#tree')), 'code search');
  await page.fill('#q', '/unknown\\s+feature/');
  await page.waitForTimeout(400);
  ok(/unknown feature/.test(await page.textContent('#tree')), 'regex code search', await page.textContent('#tree'));
  await page.click('#qmode [data-m=strings]');
  await page.fill('#q', 'webhooks');
  await page.waitForSelector('#tree .hit');
  ok(/demo\.mod\.ScanDemo/.test(await page.textContent('#tree')), 'string-constant search');
  await page.click('#qmode [data-m=files]');
  await page.fill('#q', 'config');
  await page.waitForTimeout(200);
  ok(await page.$$eval('#tree .node', n => n.length) === 1, 'file filter');
  await page.press('#q', 'Enter');
  ok(await waitCode(/class Config/), 'enter opens first match');
  await page.fill('#q', '');
  await page.press('#q', 'Escape');

  // jump to class
  await page.evaluate(() => openFile('demo/mod/ScanDemo.java'));
  await waitCode(/class ScanDemo/);
  const jumped = await page.evaluate(() => { const f = S.files.get(S.current); return resolveClass('ExampleMod', f.text) ? 'yes' : 'no'; });
  ok(jumped === 'yes', 'resolveClass same package');

  // usages (cross references)
  await page.evaluate(() => openFile('demo/mod/Config.java'));
  await waitCode(/class Config/);
  await page.click('#usages');
  ok(/usages of Config/.test(await page.textContent('#tree')) && /demo\.mod\.ExampleMod/.test(await page.textContent('#tree')), 'usages list', await page.textContent('#tree'));
  await page.click('#tree .hit');
  ok(await waitCode(/class ExampleMod/), 'usage opens referencing class');
  await page.click('.usage-head a');

  // line number click copies path:line
  await page.$eval('#codebox', c => { c.scrollTop = 0; });
  await page.mouse.click(...await page.$eval('#gutter', g => { const r = g.getBoundingClientRect(); return [r.left + r.width / 2, r.top + 14 + 19 * 2 + 5]; }));
  await page.waitForTimeout(200);
  ok(/^demo\/mod\/ExampleMod\.java:3$/.test(await page.evaluate(() => navigator.clipboard.readText())), 'gutter copies path:line', await page.evaluate(() => navigator.clipboard.readText()));

  // bytecode
  await page.evaluate(() => openFile('demo/mod/ScanDemo.java'));
  await waitCode(/class ScanDemo/);
  await page.click('#bc');
  ok(await waitCode(/invokevirtual|invokestatic|getstatic/i), 'bytecode view');
  ok(!(await page.$eval('#codebox', e => e.classList.contains('loading'))), 'bytecode not dimmed');
  await page.click('#bc');
  ok(await waitCode(/class ScanDemo/), 'back to source');

  // tabs: close
  await page.keyboard.press('Alt+w');
  await page.waitForTimeout(200);
  ok(await page.$$eval('#ftabs .ftab', t => t.length) >= 1 && !/ScanDemo/.test(await page.textContent('#cpath')), 'alt+w closes tab');

  // resource view + json pretty
  await page.evaluate(() => openFile('fabric.mod.json'));
  ok(await waitCode(/"schemaVersion": 1/), 'json resource');

  // downloads
  const [dz] = await Promise.all([page.waitForEvent('download'), page.click('#dl')]);
  const zpath = path.join(SHOTS, dz.suggestedFilename()); await dz.saveAs(zpath);
  ok(dz.suggestedFilename() === 'sample-src.zip' && fs.statSync(zpath).size > 1000, 'zip download');
  const [dr] = await Promise.all([page.waitForEvent('download'), page.click('#report')]);
  const rp = path.join(SHOTS, dr.suggestedFilename()); await dr.saveAs(rp);
  const rep = JSON.parse(fs.readFileSync(rp, 'utf8'));
  ok(rep.scan.level === 'high' && rep.java.classes === 5 && rep.file.sha256, 'report json');

  // retry with CFR
  await reset();
  await page.click('#retry');
  ok(!(await waitState(/^done · CFR/)), 'retry with CFR', await state());
  ok(await waitCode(/Decompiled with CFR|class|\{/), 'cfr output shown');

  // ---------------- wrapped exe
  console.log('wrapped exe');
  await sample('sample-wrapped.exe');
  ok(!(await waitState(/^done/)), 'exe decompiled', await state());
  ok(/embedded Java jar/.test(await page.textContent('#ftags')) && /Launch4j/.test(await page.textContent('#ftags')), 'exe tags');
  await page.click('.rtab[data-view=details]');
  ok(/PORTABLE EXECUTABLE/.test(await page.textContent('#details')) && /Found a jar inside/.test(await page.textContent('#details')), 'pe + embedded details');
  ok(!(await page.$eval('.rtab[data-view=strings]', e => e.hidden)), 'strings tab visible');
  await shot('04-exe');

  // ---------------- apk
  console.log('apk');
  await sample('sample.apk');
  ok(!(await waitState(/^done/)), 'apk decompiled', await state());
  ok(/Android package/.test(await page.textContent('#ftype')), 'apk type');
  ok(/dev\.ezlarp\.sample/.test(await page.textContent('#ftags')), 'apk package tag');
  ok(/App\.java/.test(await page.textContent('#tree')) && /AndroidManifest\.xml/.test(await page.textContent('#tree')), 'apk tree');
  await page.click('.rtab[data-view=details]');
  const ad = await page.textContent('#details');
  ok(/READ_CONTACTS/.test(ad) && /24 \/ 34/.test(ad) && /1\.2\.0/.test(ad), 'apk details', ad.slice(0, 300));
  ok(/Sensitive Android permissions/.test(await page.textContent('#scan')), 'apk permission finding');
  await page.click('.rtab[data-view=source]');
  await page.evaluate(() => openFile('AndroidManifest.xml'));
  ok(await waitCode(/<manifest[\s\S]*uses-permission/), 'manifest decoded in viewer');
  await page.evaluate(() => openFile('demo/App.java'));
  ok(await waitCode(/HELLO/), 'apk source');
  await shot('05-apk');

  // ---------------- dex, single class, multi-class
  console.log('dex / class');
  await drop('app.dex');
  ok(!(await waitState(/^done/)), 'dex', await state());
  ok(/Android DEX/.test(await page.textContent('#ftype')), 'dex type');
  await drop('one.class');
  ok(!(await waitState(/^done/)), 'single class', await state());
  ok(await waitCode(/class ExampleMod/), 'single class source');
  await drop(['one.class', 'cls/demo/mod/Config.class']);
  ok(!(await waitState(/^done/)), 'multi class', await state());
  ok(/2 class files/.test(await page.textContent('#fname')), 'multi class name');

  // ---------------- nested
  console.log('nested');
  await drop('nested.jar');
  ok(!(await waitState(/^done/)), 'nested outer', await state());
  ok(await page.$eval('#verdict', e => /malicious|suspicious/.test(e.className)), 'nested: inner jar findings reach the verdict');
  await page.click('.rtab[data-view=scan]');
  const nscan = await page.textContent('#scan');
  ok(/INSIDE THIS ARCHIVE/.test(nscan) && /inner-mod\.jar/.test(nscan) && /lib-native\.dll/.test(nscan) && /NATIVE/.test(nscan), 'nested table', nscan.slice(0, 300));
  ok(/Bundled native binaries/.test(nscan), 'native rule');
  await reset();
  await page.click('#scan a[data-cls="META-INF/jars/inner-mod.jar!demo/mod/ScanDemo"]');
  ok(!(await waitState(/^done/)), 'nested finding opens inner jar', await state());
  ok(await waitCode(/FAKE_WEBHOOK/), 'nested finding opens the class');
  await page.click('#banner [data-up]');
  await page.waitForTimeout(300);
  await page.click('.rtab[data-view=source]');
  await page.evaluate(() => openFile('META-INF/jars/inner-mod.jar'));
  await page.waitForSelector('#openjar:not([hidden])');
  await reset();
  await page.click('#openjar');
  ok(!(await waitState(/^done/)), 'nested inner opened', await state());
  ok(/nested\.jar/.test(await page.textContent('#banner')) && /inner-mod\.jar/.test(await page.textContent('#fname')), 'breadcrumb');
  await page.click('#banner [data-up]');
  await page.waitForTimeout(300);
  ok(/nested\.jar/.test(await page.textContent('#fname')) && /readme\.txt/.test(await page.textContent('#tree')), 'back to parent');

  // ---------------- python (PyInstaller)
  console.log('python');
  await sample('sample-python.exe');
  ok(!(await waitState(/analysis done/)), 'python exe', await state());
  ok(/PyInstaller/.test(await page.textContent('#ftags')) && /2 Python modules/.test(await page.textContent('#ftags')), 'python tags', await page.textContent('#ftags'));
  ok(/demo_main\.py/.test(await page.textContent('#tree')) && /helper\.py/.test(await page.textContent('#tree')), 'python tree');
  ok(await waitCode(/def candidate_paths/), 'entry script opened first');
  ok(/discord\.com\/api\/webhooks/.test(await code()), 'python strings listed');
  ok(await page.$eval('#verdict', e => /malicious|suspicious/.test(e.className)), 'python webhook flagged');
  await page.click('.rtab[data-view=source]');
  const [dpyc] = await Promise.all([page.waitForEvent('download'), page.click('#dlone')]);
  const pycPath = path.join(SHOTS, dpyc.suggestedFilename()); await dpyc.saveAs(pycPath);
  const pyc = fs.readFileSync(pycPath);
  ok(dpyc.suggestedFilename() === 'demo_main.pyc' && pyc[2] === 0x0d && pyc[3] === 0x0a && pyc.length > 100, 'pyc download with header', [dpyc.suggestedFilename(), pyc.subarray(0, 4)]);
  await page.evaluate(() => openFile('helper.py'));
  ok(await waitCode(/class Banner:[\s\S]*def Banner\.render/), 'helper module outline');
  ok(!/Launch4j/.test(await page.textContent('#ftags')), 'python sample not tagged launch4j');
  await shot('11-python');

  // ---------------- native exe
  console.log('native exe');
  await drop('native.exe');
  ok(!(await waitState(/analysis done/)), 'native exe', await state());
  ok(await page.$eval('#ficon', e => !e.hidden), 'exe icon shown');
  await page.click('.rtab[data-view=strings]');
  await page.fill('#sq', 'kernel32');
  await page.waitForTimeout(300);
  ok(/kernel32/i.test(await page.textContent('#strings')), 'strings filter');
  await page.click('.rtab[data-view=details]');
  ok(/IMPORTS/.test(await page.textContent('#details')) && /asInvoker/.test(await page.textContent('#details')), 'imports + UAC level');
  await shot('06-native');

  // ---------------- junk
  console.log('junk');
  await drop('junk.bin');
  const jerr = await waitState(/error/);
  ok(/unsupported file type/.test(jerr), 'junk rejected');

  // ---------------- open from a link (same-origin path)
  console.log('url');
  await reset();
  await page.click('.mode[data-mode=url]');
  await page.fill('#url', '/samples/sample.apk');
  await page.press('#url', 'Enter');
  ok(!(await waitState(/^done/)), 'url load', await state());
  ok(/from 127\.0\.0\.1/.test(await page.textContent('#ftags')), 'url source tag');
  await reset();
  await page.fill('#url', 'http://127.0.0.1:1/nothing.jar');
  await page.press('#url', 'Enter');
  ok(/unsupported|download/.test(await waitState(/error/)), 'url failure explained');
  // blocked hosts go through /api/fetch (test server serves public/samples/ for Discord links)
  await reset();
  await page.fill('#url', 'https://cdn.discordapp.com/attachments/1/2/sample.jar?ex=abc');
  await page.press('#url', 'Enter');
  ok(!(await waitState(/^done/)), 'discord link via server', await state());
  ok(/sample\.jar/.test(await page.textContent('#fname')) && /from Discord/.test(await page.textContent('#ftags')), 'discord name + source tag', await page.textContent('#ftags'));
  await page.click('.mode[data-mode=file]');

  // ---------------- modrinth modpack
  console.log('mrpack');
  await drop('pack.mrpack');
  ok(!(await waitState(/^done/)), 'mrpack', await state());
  ok(/EZLARP Test Pack/.test(await page.textContent('#details')) && /mods\/bad-hash\.jar/.test(await page.textContent('#details')), 'mrpack details');
  await reset();
  await page.click('#mrscan');
  ok(!(await waitState(/^batch done/)), 'mrpack batch', await state());
  const mrows = await page.$$eval('#scan table.batch tr.brow', r => r.map(x => x.textContent));
  ok(mrows.length === 2 && /^(MALICIOUS|SUSPICIOUS).*sample\.jar/.test(mrows[0]) && /SKIPPED.*hash does not match/.test(mrows[1]), 'mrpack rows (hash check)', mrows);

  // ---------------- compare
  console.log('compare');
  await drop('sample-old.jar');
  ok(!(await waitState(/^done/)), 'old version', await state());
  ok(!(await page.$eval('#cmp', e => e.hidden)), 'compare button');
  await page.setInputFiles('#cmpfile', path.join(FX, 'mods-a.jar'));
  await page.waitForSelector('#cmpview .scan-sum', { timeout: 60000 });
  const cmpText = await page.textContent('#cmpview');
  ok(/NEW INDICATORS/.test(cmpText) && /Discord webhook URL/.test(cmpText) && /not in the old version at all/.test(cmpText), 'compare new indicators', cmpText.slice(0, 400));
  ok(/\+1\s*classes added/.test(cmpText) && /ADDED CLASSES/.test(cmpText), 'compare added class', cmpText.slice(0, 600));
  await shot('12-compare');
  await page.click('#cmpview a[data-cdiff="demo/mod/ScanDemo"]');
  ok(await waitCode(/\+\s*static final String FAKE_WEBHOOK/), 'diff of added class');
  ok(/^diff · \+\d+ −0$/.test(await page.textContent('#cmeta')), 'diff stats', await page.textContent('#cmeta'));
  await page.click('.rtab[data-view=compare]');
  await page.click('#cmpview a[data-rdiff="fabric.mod.json"]');
  ok(await waitCode(/-\s*"version": "0\.9\.0"[\s\S]*\+\s*"version": "1\.0\.0"/), 'resource diff');
  ok(await page.$$eval('#code .hljs-deletion', x => x.length) === 1 && await page.$$eval('#code .hljs-addition', x => x.length) === 1, 'diff colored');
  await shot('13-diff');

  // reverse compare (what "compare with previous release" does): open file is the NEW one
  await drop('mods-a.jar');
  await waitState(/^done/);
  const oldBytes = [...fs.readFileSync(path.join(FX, 'sample-old.jar'))];
  await page.evaluate(b => compareWith('sample-old.jar', new Uint8Array(b), true), oldBytes);
  await page.waitForSelector('#cmpview .scan-sum', { timeout: 60000 });
  const rc = await page.textContent('#cmpview');
  ok(/sample-old\.jar\s*→\s*mods-a\.jar/.test(rc) && /Discord webhook URL/.test(rc) && /\+1\s*classes added/.test(rc), 'reverse compare', rc.slice(0, 300));
  await page.click('#cmpview a[data-cdiff="demo/mod/ScanDemo"]');
  ok(await waitCode(/^--- sample-old\.jar[\s\S]*\+\s*static final String FAKE_WEBHOOK/), 'reverse diff direction');
  await page.click('.rtab[data-view=compare]');
  await page.click('#cmpview a[data-rdiff="fabric.mod.json"]');
  ok(await waitCode(/-\s*"version": "0\.9\.0"[\s\S]*\+\s*"version": "1\.0\.0"/), 'reverse resource diff');

  // compare looks inside nested jars and pairs them across versions
  await drop('nested-old.jar');
  await waitState(/^done/);
  await page.setInputFiles('#cmpfile', path.join(FX, 'nested-new.jar'));
  await page.waitForSelector('#cmpview .scan-sum', { timeout: 60000 });
  const nc = await page.textContent('#cmpview');
  ok(/\+1\s*classes added/.test(nc) && /Discord webhook URL/.test(nc) && /inner-mod › demo\.mod\.ScanDemo/.test(nc), 'nested compare', nc.slice(0, 500));
  await page.click('#cmpview a[data-cdiff="META-INF/jars/inner-mod.jar!demo/mod/ScanDemo"]');
  ok(await waitCode(/\+\s*static final String FAKE_WEBHOOK/), 'nested class diff');
  await page.click('.rtab[data-view=compare]');
  await page.click('#cmpview a[data-rdiff="META-INF/jars/inner-mod.jar!fabric.mod.json"]');
  ok(await waitCode(/-\s*"version": "0\.9\.0"/), 'nested resource diff');

  // ---------------- batch
  console.log('batch');
  await drop(['mods-a.jar', 'clean-lib.jar', 'native.exe', 'sample-wrapped.exe', 'junk.bin']);
  ok(!(await waitState(/^batch done/)), 'batch done', await state());
  const rows = await page.$$eval('#scan table.batch tr.brow', r => r.map(x => x.textContent));
  ok(rows.length === 5, 'batch rows', rows.length);
  ok(/^(MALICIOUS|SUSPICIOUS)/.test(rows[0]) && /SKIPPED/.test(rows[rows.length - 1]), 'batch sorted by risk', rows.map(r => r.slice(0, 40)));
  ok(rows.some(r => /^CLEAN.*clean-lib\.jar/.test(r)), 'clean jar clean');
  ok(rows.some(r => /EZLARP Sample Mod/.test(r)), 'batch shows mod name');
  ok(/MALICIOUS|SUSPICIOUS|of 5 files/.test(await page.textContent('#verdict')), 'batch verdict', await page.textContent('#verdict'));
  await shot('09-batch');
  await reset();
  await page.click('#scan table.batch tr.brow');
  ok(!(await waitState(/^done/)), 'open batch item', await state());
  ok(/5 files/.test(await page.textContent('#banner')), 'batch breadcrumb');
  await page.click('#banner [data-up]');
  await page.waitForTimeout(300);
  ok(await page.$$eval('#scan table.batch tr.brow', r => r.length) === 5, 'back to batch');

  // ---------------- recent scans survive a reload
  await page.reload();
  ok(!(await page.$eval('#recent', e => e.hidden)) && /sample\.jar|mods-a\.jar/.test(await page.textContent('#recentlist')), 'recent scans listed');
  await shot('10-recent');

  // ---------------- big jar: on-demand mode
  console.log('big jar (lazy)');
  await drop('big.jar');
  ok(!(await waitState(/^scan done/, 180000)), 'lazy ready', await state());
  ok(!(await page.$eval('#decall', e => e.hidden)), 'decompile-all button', await page.evaluate(() => JSON.stringify({ st: el.fstate.textContent, lazy: S.lazy, name: S.name, pend: pendingCount(), err: el.err.hidden ? '' : el.err.textContent })));
  ok(/full source replaces it/.test(await page.textContent('#banner')), 'lazy banner');
  ok(await waitCode(/class Main|public class/, 120000), 'entry class decompiled on demand');
  await page.click('.rtab[data-view=source]');
  await page.click('#qmode [data-m=files]');
  await page.fill('#q', 'CfrDriver.java');
  await page.waitForTimeout(200);
  await page.press('#q', 'Enter');
  ok(await waitCode(/interface CfrDriver/, 120000) && await waitFull(), 'clicked class decompiles on demand');
  await page.fill('#q', '');
  await page.press('#q', 'Escape');
  ok(/\(2 decompiled\)/.test(await page.textContent('#sidefoot')), 'footer counts decompiled', await page.textContent('#sidefoot'));
  await shot('07-lazy');

  // ---------------- mobile
  await page.setViewportSize({ width: 390, height: 844 });
  await sample('sample.jar');
  await waitState(/^done/);
  await shot('08-mobile');

  // ---------------- default mode: report first, Java engine only when CODE is opened
  console.log('report-first (default)');
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(BASE + '/?fresh#noprewarm');
  ok(await page.isVisible('.hero') && await page.isVisible('.mode[data-mode=url]'), 'landing hero + url tab');
  await sample('sample.jar');
  ok(!(await waitState(/^scan done/)), 'scan done without decompiling', await state());
  ok(await page.$eval('#verdict', e => e.classList.contains('malicious')), 'verdict shown right away');
  ok(await page.$eval('.rtab.active', e => e.dataset.view) === 'scan' && /DETECTIONS/.test(await page.textContent('#scan')), 'report with detections first');
  ok(await page.evaluate(() => !document.querySelector('script[src*="cjrtnc"]') && !S.current), 'Java engine not loaded yet');
  ok(!(await page.isVisible('.hero')), 'hero hidden once a file is open');
  await page.click('.rtab[data-view=source]');
  ok(await waitCode(/class ExampleMod/), 'CODE tab decompiles the entry class');
  ok(await page.evaluate(() => !!document.querySelector('script[src*="cjrtnc"]')), 'Java engine loaded on demand');
  await shot('12-report-first');

  // ---------------- iPhone: built-in quick view, Java engine never loaded
  console.log('iphone quick view');
  {
    const { devices } = require(process.env.PLAYWRIGHT || 'playwright');
    const ictx = await browser.newContext({ ...devices['iPhone 13'] });
    let cjLoads = 0;
    await ictx.route(/cjrtnc\.leaningtech\.com/, r => { cjLoads++; r.fulfill({ contentType: 'text/javascript', body: stub }); });
    await ictx.route(/cdnjs\.cloudflare\.com/, r => r.abort());
    const ip = await ictx.newPage();
    ip.on('pageerror', e => errors.push('iphone: ' + e.message));
    await ip.goto(BASE + '/');
    await ip.evaluate(() => loadSample('sample.jar'));
    await ip.waitForFunction(() => /^scan done/.test(el.fstate.textContent), null, { timeout: 60000 });
    await ip.click('.rtab[data-view=source]');
    const t0 = Date.now();
    await ip.waitForFunction(() => /class ExampleMod/.test(el.code.textContent), null, { timeout: 5000 }).catch(() => {});
    ok(/Quick view/.test(await ip.textContent('#code')) && /class ExampleMod/.test(await ip.textContent('#code')), 'iphone: quick view shows code', (await ip.textContent('#code')).slice(0, 200));
    ok(Date.now() - t0 < 3000, 'iphone: code in under 3 s', Date.now() - t0);
    ok(/quick view/.test(await ip.textContent('#cmeta')) && (await ip.textContent('#qv')) === 'full source', 'iphone: quick meta + full-source button');
    await ip.evaluate(() => openFile('demo/mod/ScanDemo.java'));
    await ip.waitForFunction(() => /getAccessToken/.test(el.code.textContent), null, { timeout: 5000 }).catch(() => {});
    ok(/discord\.com\/api\/webhooks/.test(await ip.textContent('#code')) && /getAccessToken\(\)/.test(await ip.textContent('#code')), 'iphone: strings + calls visible');
    await ip.click('#bc');
    await ip.waitForFunction(() => /invokevirtual/.test(el.code.textContent), null, { timeout: 5000 }).catch(() => {});
    ok(/invokevirtual/.test(await ip.textContent('#code')), 'iphone: bytecode without Java');
    ok(cjLoads === 0, 'iphone: Java engine never downloaded', cjLoads);
    await ip.click('#decall');
    await ip.waitForFunction(() => /quick view of every class/.test(el.fstate.textContent), null, { timeout: 20000 }).catch(() => {});
    ok(/quick view of every class/.test(await ip.textContent('#fstate')), 'iphone: decompile all = quick view of everything', await ip.textContent('#fstate'));
    await ip.screenshot({ path: `${SHOTS}/13-iphone-quick.png` });
    await ictx.close();
  }

  // ---------------- desktop with a Java engine that never starts: timeout, quick view stays
  console.log('hanging jvm');
  {
    const hctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
    await hctx.route(/cjrtnc\.leaningtech\.com/, r => r.fulfill({ contentType: 'text/javascript', body: 'window.cheerpjInit = () => new Promise(() => {});' }));
    await hctx.route(/cdnjs\.cloudflare\.com/, r => r.abort());
    const hp = await hctx.newPage();
    hp.on('pageerror', e => errors.push('hang: ' + e.message));
    await hp.goto(BASE + '/#jvmtimeout=3');
    await hp.evaluate(() => loadSample('sample.jar'));
    await hp.waitForFunction(() => /^scan done/.test(el.fstate.textContent), null, { timeout: 60000 });
    await hp.click('.rtab[data-view=source]');
    await hp.waitForFunction(() => /class ExampleMod/.test(el.code.textContent), null, { timeout: 5000 }).catch(() => {});
    ok(/Quick view/.test(await hp.textContent('#code')), 'hang: quick view while the engine loads');
    await hp.waitForFunction(() => /did not start within 3 seconds/.test(el.code.textContent), null, { timeout: 15000 }).catch(() => {});
    ok(/did not start within 3 seconds/.test(await hp.textContent('#code')) && /class ExampleMod/.test(await hp.textContent('#code')), 'hang: timeout message, code still shown', (await hp.textContent('#code')).slice(0, 300));
    await hctx.close();
  }

  // ---------------- desktop: quick view is replaced by Vineflower when it finishes
  console.log('quick -> full');
  await page.goto(BASE + '/?q2');
  await sample('sample.jar');
  await waitState(/^scan done/);
  await page.click('.rtab[data-view=source]');
  ok(await waitFull(), 'full source replaces quick view');
  ok(!/Quick view/.test(await code()) && (await page.textContent('#qv')) === 'quick view', 'toggle offers quick view');
  await page.click('#qv');
  ok(/Quick view/.test(await code()), 'toggle to quick view');
  await page.click('#qv');
  ok(!/Quick view/.test(await code()), 'toggle back to full');

  ok(errors.length === 0, 'no page errors', errors.slice(0, 5));
  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
