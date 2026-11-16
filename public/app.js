// EZLARP: analysis flow + Java engines. Everything runs client-side:
// CheerpJ 5 (WebAssembly JVM, Java 17) runs Vineflower / CFR / dex2jar / ASM
// through small driver classes in ezlarp-helper-v2.jar; JSZip handles archives.
'use strict';

const HELPER = '/app/ezlarp-helper-v2.jar';
const CP_DECOMPILE = `${HELPER}:/app/vineflower-1.12.0.jar:/app/cfr-0.152.jar`;
const CP_D2J = `${HELPER}:/app/d2j-bundle-2.4.jar`;
// source files; above this, decompile on demand (#lazy=N in the URL overrides, handy for testing)
const LAZY_OVER = +((/[#&]lazy=(\d+)/.exec(location.hash) || [])[1] || 150);
const MD5_MAX = 256 * 1024 * 1024;

// ------------------------------------------------------------------ prefs

function loadPref(k, d) { try { const v = localStorage.getItem('ezlarp.' + k); return v == null ? d : v; } catch (e) { return d; } }
function savePref(k, v) { try { localStorage.setItem('ezlarp.' + k, v); } catch (e) { /* storage unavailable */ } }
if (ENGINES[loadPref('engine', 'vf')]) el.engine.value = loadPref('engine', 'vf');
el.fallback.checked = loadPref('fallback', '1') === '1';
el.rename.checked = loadPref('rename', '0') === '1';
el.engine.onchange = () => savePref('engine', el.engine.value);
el.fallback.onchange = () => savePref('fallback', el.fallback.checked ? '1' : '0');
el.rename.onchange = () => savePref('rename', el.rename.checked ? '1' : '0');

// ------------------------------------------------------------------ input

el.pick.onclick = () => el.file.click();
el.file.onchange = e => { handleFiles([...e.target.files]); el.file.value = ''; };

for (const b of document.querySelectorAll('[data-sample]')) b.onclick = () => loadSample(b.dataset.sample);
async function loadSample(name) {
  if (busy) return;
  try {
    el.status.hidden = false;
    setState('fetching sample', 2);
    const r = await fetch('/samples/' + encodeURIComponent(name));
    if (!r.ok) throw new Error('HTTP ' + r.status);
    handleFiles([new File([await r.blob()], name)]);
  } catch (e) { showError('could not load sample: ' + (e.message || e)); }
}
const hashSample = (/[#&]sample=([\w.-]+)/.exec(location.hash) || [])[1];
if (hashSample) window.addEventListener('load', () => loadSample(hashSample));

let dragDepth = 0;
const hasFiles = e => e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
window.addEventListener('dragenter', e => { if (!hasFiles(e)) return; e.preventDefault(); if (dragDepth++ === 0) el.overlay.hidden = false; });
window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener('dragleave', e => { if (!hasFiles(e)) return; if (--dragDepth <= 0) { dragDepth = 0; el.overlay.hidden = true; } });
window.addEventListener('drop', e => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  el.overlay.hidden = true;
  handleFiles([...e.dataTransfer.files]);
});
window.addEventListener('paste', e => {
  const files = e.clipboardData ? [...e.clipboardData.files] : [];
  if (files.length && !/^(INPUT|TEXTAREA)$/.test(document.activeElement && document.activeElement.tagName)) {
    e.preventDefault();
    handleFiles(files);
  }
});

// ------------------------------------------------------------------ entry

async function handleFiles(list) {
  list = list.filter(Boolean);
  if (!list.length) return;
  if (busy) { toast('busy — wait for the current file to finish'); return; }
  stack.length = 0;
  const classes = list.filter(f => /\.class$/i.test(f.name));
  if (list.length > 1 && classes.length === list.length) {
    const items = await Promise.all(list.map(async f => ({ name: f.name, u8: new Uint8Array(await f.arrayBuffer()) })));
    return analyze(`${list.length} class files`, await classesToJar(items), { multiClass: items });
  }
  if (list.length > 1) return analyzeBatch(list.map(f => ({ name: f.name, size: f.size, get: async () => new Uint8Array(await f.arrayBuffer()) })), `${list.length} files`);
  analyze(list[0].name, new Uint8Array(await list[0].arrayBuffer()));
}

async function analyze(name, u8, opts = {}) {
  setBusy(true);
  S = freshState();
  S.engine = el.engine.value;
  S.name = name;
  S.baseName = name.replace(/\.[^.]+$/, '') || 'output';
  S.size = u8.length;
  const t0 = performance.now();

  el.err.hidden = true;
  el.result.hidden = true;
  el.status.hidden = false;
  el.ftags.innerHTML = '';
  el.retry.hidden = true;
  el.ficon.hidden = true;
  el.verdict.hidden = true;
  el.vt.hidden = true;
  el.q.value = '';
  setQMode('files', false);
  el.drop.classList.add('compact');
  el.recent.hidden = true;
  el.fname.textContent = name;
  el.fname.title = name;
  el.fsize.textContent = human(u8.length);
  el.ftype.textContent = '…';
  for (const k of ['fmd5', 'fsha1', 'fhash']) el[k].textContent = '…';
  setState('reading', 3);
  hashes(u8, !!opts.multiClass);

  try {
    let kind = Inspect.sniff(u8, name);
    if (opts.multiClass) {
      el.ftype.textContent = 'Java class files';
      S.kind = 'class';
      S.jarBytes = u8;
    } else if (kind === 'zip') {
      const zip = await JSZip.loadAsync(u8);
      if (zip.file('AndroidManifest.xml') || zip.file(/^classes\d*\.dex$/).length) {
        S.kind = 'apk';
        await analyzeApk(zip);
      } else {
        S.kind = 'jar';
        el.ftype.textContent = /\.aar$/i.test(name) ? 'Android library (aar)' : /\.xapk$/i.test(name) ? 'XAPK bundle' : 'Java archive';
        S.jarBytes = u8;
        S.preZip = zip;
      }
    } else if (kind === 'class') {
      S.kind = 'class';
      S.cls = Inspect.parseClass(u8, true);
      if (!S.cls) throw new Error('not a valid .class file');
      el.ftype.textContent = `Java class · ${Inspect.javaVersion(S.cls.major)}`;
      S.jarBytes = await classesToJar([{ name, u8 }]);
    } else if (kind === 'dex') {
      S.kind = 'dex';
      S.dex = Inspect.dexInfo(u8);
      el.ftype.textContent = `Android DEX v${S.dex.version}`;
      tag(`${S.dex.classes} dex classes`, 'java');
      S.jarBytes = await dex2jar([{ name, u8 }]);
    } else if (kind === 'pe') {
      S.kind = 'pe';
      await analyzePE(u8);
    } else {
      const emb = Inspect.findEmbeddedZip(u8);
      if (!emb) throw new Error('unsupported file type — drop a .jar, .class, .apk, .dex, .exe or .dll');
      S.kind = 'jar';
      el.ftype.textContent = 'archive (unknown extension)';
      S.jarBytes = emb.slice();
    }

    if (S.jarBytes) {
      setState('reading archive', 8);
      S.jarInfo = await analyzeJar(S.jarBytes, S.resZip || S.preZip);
      buildFiles();
      await scanJar();
      addJarTags();
      if (!S.jarInfo.classCount) {
        S.log.push('archive contains no .class files — showing resources only');
        if (S.jarInfo.nestedList.length) S.log.push(`it contains ${S.jarInfo.nestedList.length} nested archive(s): open them from DETAILS or the file tree`);
        finish(`done · no classes${S.jarInfo.nestedList.length ? ' · ' + plural(S.jarInfo.nestedList.length, 'nested archive') : ''}`, t0);
        return;
      }
      const groups = [...S.files.values()].filter(f => f.type === 'src').length;
      if (groups > LAZY_OVER) {
        S.lazy = true;
        S.log.push(`${groups} source files: decompiling on demand. Use "decompile all" to do everything at once.`);
        finish(`ready · ${groups} classes · decompiles as you open them`, t0);
      } else {
        await decompileAll(S.engine, el.fallback.checked);
        finish(`done · ${ENGINES[S.engineUsed]} · ${((performance.now() - t0) / 1000).toFixed(1)}s`, t0);
      }
    } else {
      finish('analysis done', t0);
    }
  } catch (e) {
    console.error(e);
    setState('error', 100);
    showError(e && e.message || String(e));
    if (S.pe || S.files.size || S.scan) renderResult();
  } finally {
    setBusy(false);
  }
}

function finish(msg, t0) {
  setState(msg, 100);
  renderResult();
  if (!stack.length) {
    const lvl = S.batch ? (['high', 'med', 'low', 'none'].find(l => S.batch.some(r => r.level === l)) || 'none') : S.scan ? S.scan.level : 'none';
    const label = S.batch ? `batch · ${S.batch.length} files` : S.scan ? S.scan.label : '';
    pushHistory({ name: S.name, sha256: S.hashes.sha256 || '', level: lvl, label, type: el.ftype.textContent.split(' · ')[0], t: Date.now() });
  }
  if (S.lazy || S.engineUsed) {
    el.retry.textContent = 'retry with ' + (S.engine === 'vf' ? 'CFR' : 'Vineflower');
    el.retry.hidden = false;
  }
}

async function hashes(u8, skip) {
  if (skip) { for (const k of ['fmd5', 'fsha1', 'fhash']) el[k].textContent = '(multiple files)'; return; }
  const hexOf = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  try {
    const [s256, s1] = await Promise.all([crypto.subtle.digest('SHA-256', u8), crypto.subtle.digest('SHA-1', u8)]);
    S.hashes.sha256 = hexOf(s256);
    S.hashes.sha1 = hexOf(s1);
    el.fhash.textContent = S.hashes.sha256;
    el.fsha1.textContent = S.hashes.sha1;
    el.fhash.title = el.fsha1.title = 'click to copy';
    el.vt.href = 'https://www.virustotal.com/gui/file/' + S.hashes.sha256;
    el.vt.hidden = false;
  } catch (e) {
    el.fhash.textContent = el.fsha1.textContent = 'unavailable';
  }
  setTimeout(() => {
    if (u8.length > MD5_MAX) { el.fmd5.textContent = 'skipped (file too large)'; return; }
    S.hashes.md5 = Inspect.md5(u8);
    el.fmd5.textContent = S.hashes.md5;
    el.fmd5.title = 'click to copy';
  }, 0);
}

async function classesToJar(items) {
  const zip = new JSZip();
  for (const { name, u8 } of items) {
    const info = Inspect.parseClass(u8);
    if (!info) throw new Error(`${name} is not a valid .class file`);
    zip.file((info.name || name.replace(/\.class$/i, '')) + '.class', u8);
  }
  return zip.generateAsync({ type: 'uint8array', compression: 'STORE' });
}

// ------------------------------------------------------------------ jar analysis

async function analyzeJar(u8, resZip) {
  const zip = await JSZip.loadAsync(u8);
  const entries = Object.values(zip.files).filter(f => !f.dir);
  const classes = entries.filter(f => /\.class$/i.test(f.name));
  const rz = resZip || zip;
  const resources = Object.values(rz.files).filter(f => !f.dir && !/\.class$/i.test(f.name) && !(S.apk && /^classes\d*\.dex$/.test(f.name)));
  const versions = {};
  for (const c of classes.filter(c => !/^META-INF\/versions\//.test(c.name)).slice(0, 400)) {
    const info = Inspect.parseClass(await c.async('uint8array'));
    if (info) versions[info.major] = (versions[info.major] || 0) + 1;
  }
  const has = n => !!rz.file(n);
  const read = async n => { const f = rz.file(n); return f ? f.async('string') : ''; };
  const manifest = await read('META-INF/MANIFEST.MF');
  const mainClass = (/^Main-Class:\s*(.+)$/mi.exec(manifest) || [])[1];
  const kinds = [];
  if (has('fabric.mod.json')) kinds.push('Fabric mod');
  if (has('quilt.mod.json')) kinds.push('Quilt mod');
  if (has('META-INF/mods.toml')) kinds.push('Forge mod');
  if (has('META-INF/neoforge.mods.toml')) kinds.push('NeoForge mod');
  if (has('mcmod.info')) kinds.push('legacy Forge mod');
  if (has('plugin.yml')) kinds.push('Bukkit/Spigot plugin');
  if (has('paper-plugin.yml')) kinds.push('Paper plugin');
  if (has('bungee.yml')) kinds.push('BungeeCord plugin');
  if (has('velocity-plugin.json')) kinds.push('Velocity plugin');
  if (has('META-INF/MANIFEST.MF') && /Premain-Class|Agent-Class/i.test(manifest)) kinds.push('Java agent');
  if (entries.some(e => e.name.startsWith('BOOT-INF/'))) kinds.push('Spring Boot fat jar');
  if (S.apk) kinds.push('Android app');
  const nestedList = resources.filter(e => ARCHIVE_RE.test(e.name)).map(e => ({ name: e.name, size: (e._data && e._data.uncompressedSize) || 0 }));
  const signed = resources.some(e => /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(e.name));

  const pk = new Map();
  for (const c of classes) {
    const parts = c.name.replace(/^BOOT-INF\/classes\//, '').split('/');
    if (parts.length < 2) { pk.set('(default package)', (pk.get('(default package)') || 0) + 1); continue; }
    const key = parts.slice(0, Math.min(3, parts.length - 1)).join('/');
    pk.set(key, (pk.get(key) || 0) + 1);
  }
  const packages = [...pk.entries()].sort((a, b) => b[1] - a[1]);

  let meta = null;
  try { meta = await modMeta(read, has); } catch (e) { S.log.push('could not parse mod metadata: ' + e.message); }

  return { zip, rz, entries, classes, resources, classCount: classes.length, versions, manifest, mainClass, kinds, nestedList, signed, packages, meta, multiRelease: classes.some(c => /^META-INF\/versions\//.test(c.name)) };
}

// Mod / plugin metadata from the usual descriptor files.
async function modMeta(read, has) {
  const list = v => v == null ? [] : (Array.isArray(v) ? v : [v]).map(x => typeof x === 'string' ? x : (x && (x.name || x.value || x.id)) || JSON.stringify(x));
  for (const file of ['fabric.mod.json', 'quilt.mod.json']) {
    if (!has(file)) continue;
    const j = JSON.parse((await read(file)).replace(/^\uFEFF/, ''));
    const q = j.quilt_loader || {};
    const md = q.metadata || {};
    const eps = [];
    for (const v of Object.values(j.entrypoints || q.entrypoints || {})) for (const e of list(v)) eps.push(e);
    const mixinClasses = [];
    for (const cfg of list(j.mixins || q.mixin)) {
      try {
        const m = JSON.parse(await read(cfg));
        for (const k of ['mixins', 'client', 'server']) for (const c of m[k] || []) mixinClasses.push((m.package ? m.package + '.' : '') + c);
      } catch (e) { /* missing or invalid config */ }
    }
    return {
      mixinClasses,
      kind: file === 'fabric.mod.json' ? 'Fabric mod' : 'Quilt mod',
      id: j.id || q.id, name: j.name || md.name, version: j.version || q.version, description: j.description || md.description,
      authors: list(j.authors || (md.contributors && Object.keys(md.contributors))), environment: j.environment,
      entrypoints: eps, depends: Object.entries(j.depends || {}).map(([k, v]) => `${k} ${Array.isArray(v) ? v.join(' | ') : v}`),
      mixins: list(j.mixins || q.mixin), license: Array.isArray(j.license) ? j.license.join(', ') : j.license
    };
  }
  for (const file of ['META-INF/neoforge.mods.toml', 'META-INF/mods.toml']) {
    if (!has(file)) continue;
    const t = await read(file);
    const g = k => { const m = new RegExp('^\\s*' + k + '\\s*=\\s*["\']{1,3}([^"\'\\n]*)', 'm').exec(t); return m ? m[1] : null; };
    return {
      kind: file.includes('neoforge') ? 'NeoForge mod' : 'Forge mod',
      id: g('modId'), name: g('displayName'), version: g('version'), authors: g('authors') ? [g('authors')] : [],
      description: g('description'), license: g('license'),
      depends: [...t.matchAll(/^\s*modId\s*=\s*"([^"]+)"[\s\S]*?versionRange\s*=\s*"([^"]+)"/gm)].slice(1).map(m => `${m[1]} ${m[2]}`)
    };
  }
  for (const file of ['plugin.yml', 'paper-plugin.yml', 'bungee.yml']) {
    if (!has(file)) continue;
    const t = await read(file);
    const g = k => { const m = new RegExp('^' + k + ':\\s*["\']?([^"\'\\n#]+)', 'm').exec(t); return m ? m[1].trim() : null; };
    const arr = k => { const m = new RegExp('^' + k + ':\\s*\\[([^\\]]*)\\]', 'm').exec(t); return m ? m[1].split(',').map(s => s.trim().replace(/^["']|["']$/g, '')).filter(Boolean) : []; };
    const cmds = /^commands:\s*\n((?:[ \t]+.*\n?)*)/m.exec(t);
    return {
      kind: file === 'bungee.yml' ? 'BungeeCord plugin' : file === 'paper-plugin.yml' ? 'Paper plugin' : 'Bukkit plugin',
      name: g('name'), version: g('version'), description: g('description'),
      authors: g('author') ? [g('author')] : arr('authors'), entrypoints: g('main') ? [g('main')] : [],
      depends: [...arr('depend'), ...arr('softdepend').map(s => s + ' (soft)')],
      commands: cmds ? [...cmds[1].matchAll(/^[ \t]{2}([\w-]+):/gm)].map(m => '/' + m[1]) : []
    };
  }
  if (has('velocity-plugin.json')) {
    const j = JSON.parse(await read('velocity-plugin.json'));
    return { kind: 'Velocity plugin', id: j.id, name: j.name, version: j.version, description: j.description, authors: list(j.authors), entrypoints: j.main ? [j.main] : [], depends: list(j.dependencies && j.dependencies.map(d => d.id)) };
  }
  return null;
}

function buildFiles() {
  const j = S.jarInfo;
  S.files = new Map();
  for (const c of j.classes) {
    if (/^META-INF\/versions\//.test(c.name)) continue;
    const p = srcPathOf(c.name);
    let f = S.files.get(p);
    if (!f) S.files.set(p, f = { path: p, type: 'src', text: null, classes: [] });
    f.classes.push(c);
  }
  for (const r of j.resources) {
    if (S.files.has(r.name)) continue;
    S.files.set(r.name, { path: r.name, type: 'res', zipEntry: r, size: (r._data && r._data.uncompressedSize) || 0 });
  }
  if (j.meta && j.meta.entrypoints) for (const e of j.meta.entrypoints) S.entrypoints.add(e.replace(/::.*$/, '').replace(/\./g, '/'));
  if (j.mainClass) S.entrypoints.add(j.mainClass.trim().replace(/\./g, '/'));
}

async function scanJar() {
  const j = S.jarInfo;
  const res = Scan.newResult();
  const names = [];
  const n = j.classes.length;
  for (let i = 0; i < n; i++) {
    const c = j.classes[i];
    if (i % 150 === 0) { setState(`scanning classes ${i}/${n}`, 8 + 12 * i / Math.max(1, n)); await new Promise(r => setTimeout(r, 0)); }
    const info = Inspect.parseClass(await c.async('uint8array'), true);
    if (!info || !info.name) continue;
    const versioned = /^META-INF\/versions\//.test(c.name);
    if (!versioned) {
      S.classToSrc.set(info.name, srcPathOf(c.name));
      const simple = info.name.slice(info.name.lastIndexOf('/') + 1);
      for (const part of new Set([simple, simple.split('$').pop()])) {
        if (!S.simpleIndex.has(part)) S.simpleIndex.set(part, []);
        S.simpleIndex.get(part).push(info.name);
      }
      names.push(info.name);
      for (const c of info.classes) {
        if (c === info.name || c[0] === '[' || c.startsWith('java/')) continue;
        let set = S.xrefs.get(c);
        if (!set) S.xrefs.set(c, set = new Set());
        set.add(info.name);
      }
      const strs = info.strings.filter(s => s.length >= 2);
      if (strs.length) S.cpStrings.set(info.name, strs.length > 400 ? strs.slice(0, 400) : strs);
    }
    Scan.scanClass(res, info);
  }
  Scan.scanNames(res, names);
  if (S.apk) for (const p of S.apk.perms) if (DANGEROUS_PERMS.test(p)) Scan.scanString(res, p, 'AndroidManifest.xml');
  setScan(res);
  for (const ep of S.entrypoints) { const p = fileForClass(ep); if (p) S.files.get(p).entry = true; }
}

function setScan(res) {
  S.scanRes = res;
  S.scan = Scan.summarize(res);
  S.srcFlags = new Map();
  for (const f of S.scan.findings) {
    if (f.rule.sev !== 'high' && f.rule.sev !== 'med') continue;
    for (const where of f.where.keys()) {
      const p = fileForClass(where);
      if (p && SEV_RANK[f.rule.sev] > SEV_RANK[S.srcFlags.get(p) || 'none']) S.srcFlags.set(p, f.rule.sev);
    }
  }
}

function addJarTags() {
  const j = S.jarInfo;
  if (S.scan) {
    const c = S.scan.count;
    if (c.high) tag(plural(c.high, 'high-risk indicator'), 'bad');
    else if (c.med) tag(plural(c.med, 'indicator') + ' to review', 'warn');
    else tag('no high-risk indicators', 'good');
  }
  tag(plural(j.classCount, 'class'), 'java');
  const top = Object.entries(j.versions).sort((a, b) => b[1] - a[1])[0];
  if (top) tag('target ' + Inspect.javaVersion(+top[0]), 'java');
  j.kinds.forEach(k => tag(k, 'good'));
  if (j.mainClass) tag('runnable', 'good');
  if (j.nestedList.length) tag(plural(j.nestedList.length, 'nested archive'), 'warn');
  if (S.scanRes && S.scanRes.obf) tag('likely obfuscated', 'warn');
  if (j.signed) tag('signed');
}

// ------------------------------------------------------------------ android

async function analyzeApk(zip) {
  el.ftype.textContent = 'Android package';
  const a = { pkg: null, perms: [], dexes: [], activities: 0, services: 0, receivers: 0, providers: 0, nativeLibs: [], signing: [] };
  S.apk = a;
  S.resZip = zip;
  const mf = zip.file('AndroidManifest.xml');
  if (mf) {
    try {
      const xml = Inspect.decodeAXML(await mf.async('uint8array'));
      const attr = (tagRe, name) => { const m = new RegExp('<' + tagRe + '\\b[^>]*?\\s(?:android:)?' + name + '="([^"]*)"').exec(xml); return m ? m[1] : null; };
      a.pkg = attr('manifest', 'package');
      a.versionName = attr('manifest', 'versionName');
      a.versionCode = attr('manifest', 'versionCode');
      a.minSdk = attr('uses-sdk', 'minSdkVersion');
      a.targetSdk = attr('uses-sdk', 'targetSdkVersion');
      a.label = attr('application', 'label');
      a.debuggable = attr('application', 'debuggable') === 'true';
      a.perms = [...new Set([...xml.matchAll(/<uses-permission(?:-sdk-23)?\b[^>]*?android:name="([^"]+)"/g)].map(m => m[1]))];
      for (const t of ['activity', 'service', 'receiver', 'provider']) a[t === 'activity' ? 'activities' : t + 's'] = (xml.match(new RegExp('<' + t + '\\b', 'g')) || []).length;
    } catch (e) {
      S.log.push('could not decode AndroidManifest.xml: ' + e.message);
    }
  }
  const libs = new Set();
  for (const f of Object.values(zip.files)) {
    const m = /^lib\/([^/]+)\//.exec(f.name);
    if (m) libs.add(m[1]);
    if (/^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(f.name)) a.signing.push(f.name.slice(9));
  }
  a.nativeLibs = [...libs];
  const dexFiles = zip.file(/^classes\d*\.dex$/).sort((x, y) => x.name.localeCompare(y.name, undefined, { numeric: true }));
  const items = [];
  for (const d of dexFiles) {
    const u8 = await d.async('uint8array');
    a.dexes.push({ name: d.name, size: u8.length, info: Inspect.dexInfo(u8) });
    items.push({ name: d.name, u8 });
  }
  if (a.pkg) tag(a.pkg, 'java');
  if (a.versionName) tag('v' + a.versionName);
  if (a.perms.length) tag(plural(a.perms.length, 'permission'), a.perms.some(p => DANGEROUS_PERMS.test(p)) ? 'warn' : '');
  if (a.debuggable) tag('debuggable', 'warn');
  if (items.length) S.jarBytes = await dex2jar(items);
  else S.log.push('no classes*.dex found — nothing to decompile');
}

async function dex2jar(items) {
  const merged = new JSZip();
  let total = 0;
  for (let i = 0; i < items.length; i++) {
    const { name, u8 } = items[i];
    const info = Inspect.dexInfo(u8);
    setState(`converting ${name} to Java bytecode (dex2jar)`, 10 + 8 * i / items.length);
    const id = uid();
    const inPath = `/str/dex-${id}.dex`;
    const outPath = `/files/ezlarp-dex/out-${id}.jar`;
    await ensureJVM();
    cheerpOSAddStringFile(inPath, u8);
    await runJava('ezlarp.Dex', CP_D2J, [inPath, outPath], { total: info ? info.classes : 0, label: `dex2jar ${name}`, from: 10, to: 18 });
    const z = await JSZip.loadAsync(await (await cjFileBlob(outPath)).arrayBuffer());
    for (const f of Object.values(z.files)) {
      if (f.dir) continue;
      if (f.name === 'ezlarp/log.txt') {
        const log = (await f.async('string')).trim();
        if (log) S.log.push(`[dex2jar ${name}]\n${log.split('\n').slice(0, 200).join('\n')}`);
        continue;
      }
      if (!merged.file(f.name)) { merged.file(f.name, await f.async('uint8array')); total++; }
    }
  }
  S.log.push(`[dex2jar 2.4] converted ${total} classes from ${items.length} dex file(s)`);
  if (!total) throw new Error('dex2jar produced no classes — the dex file may be damaged or protected');
  return merged.generateAsync({ type: 'uint8array', compression: 'STORE' });
}

// ------------------------------------------------------------------ executables

async function analyzePE(u8) {
  setState('analyzing PE', 5);
  S.raw = u8;
  const pe = Inspect.parsePE(u8);
  S.pe = pe;
  if (!pe.ok) {
    el.ftype.textContent = 'MZ executable (not a valid PE)';
  } else {
    const arch = Inspect.MACHINES[pe.machine] || hex(pe.machine, 4);
    el.ftype.textContent = `${pe.format} ${pe.isDll ? 'DLL' : 'executable'} · ${arch}`;
    if (pe.icon) {
      el.ficon.src = URL.createObjectURL(new Blob([pe.icon], { type: 'image/x-icon' }));
      el.ficon.hidden = false;
      el.ficon.onerror = () => { el.ficon.hidden = true; };
    }
    if (pe.version && pe.version.ProductName) tag(pe.version.ProductName + (pe.version.ProductVersion ? ' ' + pe.version.ProductVersion : ''));
  }
  S.sigs = Inspect.detectSignatures(u8, pe);
  S.sigs.forEach(s => tag(s.label, s.kind === 'java' ? 'java' : (/packed|protect|themida|vmp|enigma/i.test(s.label) ? 'warn' : '')));
  if (pe.signed) tag('has signature blob');
  if (pe.executionLevel === 'requireAdministrator') tag('asks for admin', 'warn');
  if (pe.overlay) tag(`overlay ${human(pe.overlay.size)}`);

  const py = Inspect.parsePyInstaller(u8);
  if (py && py.files.length) {
    S.py = py;
    tag(`PyInstaller · Python ${py.pyver}`, 'warn');
    if (!S.sigs.some(s => s.label === 'PyInstaller')) S.sigs.push({ label: 'PyInstaller', kind: 'info' });
  }

  const emb = py ? null : Inspect.findEmbeddedZip(u8);
  if (emb) {
    try {
      const z = await JSZip.loadAsync(emb);
      const n = Object.keys(z.files).filter(f => /\.class$/i.test(f)).length;
      if (n) {
        S.embedded = { offset: emb.byteOffset - u8.byteOffset, size: emb.length, classes: n };
        S.jarBytes = emb.slice();
        tag('embedded Java jar', 'good');
      }
    } catch (e) { /* not a usable zip */ }
  }

  setState('extracting strings', 7);
  await new Promise(r => setTimeout(r, 0));
  S.strings = Inspect.extractStrings(u8);
  const res = Scan.newResult();
  for (const s of S.strings) Scan.scanString(res, s.s, '0x' + s.off.toString(16).padStart(8, '0'));
  setScan(res);
  if (!S.jarBytes) {
    const c = S.scan.count;
    if (c.high) tag(plural(c.high, 'high-risk indicator'), 'bad');
    else if (c.med) tag(plural(c.med, 'indicator') + ' to review', 'warn');
    S.log.push(pe.dotnet
      ? '.NET assembly: the code is CIL, not Java. Open it in ILSpy or dnSpy to decompile to C#.'
      : py ? 'PyInstaller bundle: see DETAILS for the bundled files.'
        : 'No Java code found in this executable. Native machine code cannot be decompiled to Java — see DETAILS and STRINGS.');
  }
}

async function extractPy(i) {
  const f = S.py.files[i];
  let data = S.raw.subarray(f.off, f.off + f.csize);
  try {
    if (f.compressed) data = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate'))).arrayBuffer());
    download(baseOf(f.name) + (f.type === 's' ? '.pyc-body' : ''), data);
  } catch (e) {
    toast('could not extract: ' + (e.message || e));
  }
}

// ------------------------------------------------------------------ nested archives

async function openNested(path) {
  if (busy) return;
  const f = S.files.get(path);
  if (!f) return;
  const bytes = f.bytes || await f.zipEntry.async('uint8array');
  await descend(() => analyze(baseOf(path), bytes));
}
el.openjar.onclick = () => openNested(S.current);

function goUp(n) {
  if (busy) return;
  let target = null;
  for (let i = 0; i < n && stack.length; i++) target = stack.pop();
  if (!target) return;
  S = target;
  el.fname.textContent = S.name;
  el.fsize.textContent = human(S.size);
  el.ftype.textContent = S.ui.type;
  el.ftags.innerHTML = S.ui.tags;
  setState(S.ui.state, 100);
  el.fmd5.textContent = S.hashes.md5 || '—';
  el.fsha1.textContent = S.hashes.sha1 || '—';
  el.fhash.textContent = S.hashes.sha256 || '—';
  el.vt.href = 'https://www.virustotal.com/gui/file/' + (S.hashes.sha256 || '');
  el.vt.hidden = !S.hashes.sha256;
  if (S.batch) for (const k of ['fmd5', 'fsha1', 'fhash']) el[k].textContent = '(multiple files)';
  el.ficon.hidden = !S.ui.icon;
  if (S.ui.icon) el.ficon.src = S.ui.icon;
  el.engine.value = S.engine;
  renderResult();
}

// ------------------------------------------------------------------ java engines

let cjReady = null;
let javaQueue = Promise.resolve();
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 7);

function ensureJVM() {
  if (!cjReady) {
    if (typeof cheerpjInit !== 'function') return Promise.reject(new Error('CheerpJ failed to load (blocked by an extension, or offline?)'));
    setState('starting JVM (first visit downloads the runtime, cached after)', null);
    cjReady = cheerpjInit({ version: 17, status: 'none' }).catch(e => { cjReady = null; throw e; });
  }
  return cjReady;
}

function ensureJarPath() {
  if (!S.jarPath) {
    S.jarPath = `/str/jar-${uid()}.jar`;
    cheerpOSAddStringFile(S.jarPath, S.jarBytes);
  }
  return S.jarPath;
}

// Runs one Java main at a time (the drivers keep static state).
function runJava(main, cp, args, prog = {}) {
  const job = javaQueue.then(async () => {
    await ensureJVM();
    const stop = prog.total ? watchProgress(prog) : () => {};
    try {
      return await cheerpjRunMain(main, cp, ...args);
    } finally {
      stop();
    }
  });
  javaQueue = job.catch(() => {});
  return job;
}

// CheerpJ mirrors System.out into #console; the drivers print "EZP <n>" per item.
function watchProgress({ total, label, from = 20, to = 96 }) {
  el.console.textContent = '';
  let last = 0;
  const obs = new MutationObserver(() => {
    const txt = el.console.textContent;
    const i = txt.lastIndexOf('EZP ');
    if (i >= 0) {
      const n = parseInt(txt.slice(i + 4), 10);
      if (n > last) {
        last = n;
        setState(`${label} · ${n}/${total}`, from + (to - from) * Math.min(1, n / total));
      }
    }
    if (txt.length > 200000) el.console.textContent = '';
  });
  obs.observe(el.console, { childList: true, characterData: true, subtree: true });
  return () => obs.disconnect();
}

function engineOpts(engine) {
  if (!el.rename.checked) return [];
  return engine === 'cfr' ? ['renameillegalidents=true', 'renamedupmembers=true', 'renamesmallmembers=3'] : ['rename-members=1'];
}

async function runDecompiler(engine, inPath, extra, prog) {
  const outPath = `/files/ezlarp/out-${uid()}.zip`;
  const code = await runJava('ezlarp.Run', CP_DECOMPILE, [engine, inPath, outPath, ...engineOpts(engine), ...extra], prog);
  let blob;
  try { blob = await cjFileBlob(outPath); } catch (e) { throw new Error(`${ENGINES[engine]} produced no output (exit code ${code})`); }
  const zip = await JSZip.loadAsync(await blob.arrayBuffer());
  const sources = {};
  for (const f of Object.values(zip.files)) if (!f.dir && f.name.startsWith('src/')) sources[f.name.slice(4)] = await f.async('string');
  const logFile = zip.file('ezlarp/log.txt');
  const log = logFile ? (await logFile.async('string')).trim() : '';
  if (!Object.keys(sources).length) {
    const tail = log.split('\n').slice(-6).join('\n');
    throw new Error(`${ENGINES[engine]} decompiled 0 classes${tail ? '\n' + tail : ''}`);
  }
  return { sources, log };
}

async function decompileAll(engine, fallback) {
  const order = fallback ? [engine, engine === 'vf' ? 'cfr' : 'vf'] : [engine];
  const groups = [...S.files.values()].filter(f => f.type === 'src').length;
  let lastErr;
  for (const eng of order) {
    try {
      const t0 = performance.now();
      setState(`decompiling with ${ENGINES[eng]}`, 22);
      await ensureJVM();
      const out = await runDecompiler(eng, ensureJarPath(), [], { total: groups, label: `decompiling with ${ENGINES[eng]}` });
      S.seconds = (performance.now() - t0) / 1000;
      S.engine = S.engineUsed = eng;
      for (const f of S.files.values()) if (f.type === 'src') { f.text = null; f.error = null; f.bytecode = null; f.view = 'src'; }
      for (const [p, text] of Object.entries(out.sources)) {
        let f = S.files.get(p);
        if (!f || f.type !== 'src') {
          // CFR names files by package; map back to the archive path if it differs (e.g. BOOT-INF/classes/)
          const alt = [...S.files.values()].find(x => x.type === 'src' && x.path.endsWith('/' + p));
          f = alt || null;
        }
        if (!f) { f = { path: p, type: 'src', text: null, classes: [] }; S.files.set(p, f); }
        f.text = text;
        f.engine = eng;
      }
      for (const f of S.files.values()) if (f.type === 'src' && f.text == null) f.error = 'no output for this file (see LOG)';
      S.lazy = false;
      S.log.push(`[${ENGINES[eng]}] ${Object.keys(out.sources).length} source files in ${S.seconds.toFixed(1)}s`);
      if (out.log) S.log.push(out.log.split('\n').slice(0, 400).join('\n'));
      if (eng !== engine) tag(`fell back to ${ENGINES[eng]}`, 'warn');
      return;
    } catch (e) {
      console.error(e);
      lastErr = e;
      S.log.push(`[${ENGINES[eng]}] failed: ${e && e.message || e}`);
    }
  }
  throw lastErr;
}

async function miniJar(f) {
  const z = new JSZip();
  for (const c of f.classes) z.file(c.name, await c.async('uint8array'));
  const id = uid();
  const path = `/str/one-${id}.jar`;
  await ensureJVM();
  cheerpOSAddStringFile(path, await z.generateAsync({ type: 'uint8array', compression: 'STORE' }));
  return path;
}

// Decompile one source file on demand (its class + inner classes; the whole jar is the library).
async function ensureSource(f) {
  if (f.text != null) return;
  if (f.pending) return f.pending;
  f.pending = (async () => {
    const order = el.fallback.checked ? [S.engine, S.engine === 'vf' ? 'cfr' : 'vf'] : [S.engine];
    const state = el.fstate.textContent;
    setState(`decompiling ${baseOf(f.path)}`, null);
    let lastErr;
    try {
      const inPath = await miniJar(f);
      const lib = ensureJarPath();
      for (const eng of order) {
        try {
          const out = await runDecompiler(eng, inPath, ['ezlarp.lib=' + lib]);
          const key = Object.keys(out.sources).find(k => k === f.path || f.path.endsWith('/' + k)) || Object.keys(out.sources)[0];
          f.text = out.sources[key];
          f.engine = eng;
          f.error = null;
          if (out.log) S.log.push(`[${ENGINES[eng]} · ${f.path}]\n${out.log}`);
          if (eng !== S.engine) S.log.push(`[${f.path}] ${ENGINES[S.engine]} failed, used ${ENGINES[eng]}`);
          renderLog();
          return;
        } catch (e) {
          lastErr = e;
          S.log.push(`[${ENGINES[eng]} · ${f.path}] failed: ${e.message || e}`);
        }
      }
      throw lastErr;
    } finally {
      f.pending = null;
      setState(state, null);
    }
  })();
  return f.pending;
}

async function ensureBytecode(f) {
  if (f.bytecode != null) return;
  const inPath = await miniJar(f);
  const outPath = `/files/ezlarp-asm/out-${uid()}.zip`;
  await runJava('ezlarp.Asm', CP_D2J, [inPath, outPath]);
  const z = await JSZip.loadAsync(await (await cjFileBlob(outPath)).arrayBuffer());
  const parts = Object.values(z.files).filter(x => !x.dir).sort((a, b) => a.name.length - b.name.length || a.name.localeCompare(b.name));
  const texts = [];
  for (const p of parts) texts.push(await p.async('string'));
  f.bytecode = texts.join('\n') || '// no bytecode';
}

// ------------------------------------------------------------------ actions

el.decall.onclick = async () => {
  if (busy) return;
  setBusy(true);
  el.err.hidden = true;
  const t0 = performance.now();
  try {
    await decompileAll(S.engine, el.fallback.checked);
    setState(`done · ${ENGINES[S.engineUsed]} · ${((performance.now() - t0) / 1000).toFixed(1)}s`, 100);
    renderResult();
  } catch (e) {
    showError(e.message || String(e));
    setState('decompile all failed — on-demand mode still works', 100);
  } finally {
    setBusy(false);
  }
};

el.retry.onclick = async () => {
  if (busy || !S.jarBytes) return;
  const other = S.engine === 'vf' ? 'cfr' : 'vf';
  el.err.hidden = true;
  if (S.lazy) {
    S.engine = other;
    for (const f of S.files.values()) if (f.type === 'src') { f.text = null; f.error = null; }
    el.retry.textContent = 'retry with ' + (other === 'vf' ? 'CFR' : 'Vineflower');
    setState(`ready · ${ENGINES[other]} · decompiles as you open them`, 100);
    renderResult();
    return;
  }
  setBusy(true);
  const t0 = performance.now();
  try {
    await decompileAll(other, false);
    finish(`done · ${ENGINES[S.engineUsed]} · ${((performance.now() - t0) / 1000).toFixed(1)}s`, t0);
  } catch (e) {
    showError(e.message || String(e));
    setState('error', 100);
    renderResult();
  } finally {
    setBusy(false);
  }
};

el.dl.onclick = async () => {
  if (!S.files.size || busy) return;
  const pend = pendingCount();
  if (S.lazy && pend && confirm(`Decompile the remaining ${pend} classes first? This can take a few minutes.\n\nCancel = download only what has been decompiled so far.`)) {
    await el.decall.onclick();
  }
  const old = el.dl.textContent;
  el.dl.textContent = 'zipping…';
  try {
    const zip = new JSZip();
    for (const f of S.files.values()) {
      if (f.type === 'src') { if (f.text != null) zip.file(f.path, f.text); }
      else zip.file(f.path, f.bytes || await f.zipEntry.async('uint8array'));
    }
    const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } });
    download(`${S.baseName}-src.zip`, blob);
  } finally {
    el.dl.textContent = old;
  }
};

// ------------------------------------------------------------------ batch scan

const KIND_LABEL = { zip: 'archive', class: 'class file', pe: 'executable', dex: 'dex', unknown: 'unknown' };

async function quickScan(name, u8) {
  const kind = Inspect.sniff(u8, name);
  const res = Scan.newResult();
  const row = { name, size: u8.length, kind, kindLabel: KIND_LABEL[kind], classes: 0, meta: null };
  const scanZip = async zip => {
    const names = [];
    for (const f of Object.values(zip.files)) {
      if (f.dir || !/\.class$/i.test(f.name)) continue;
      const info = Inspect.parseClass(await f.async('uint8array'), true);
      if (info) { Scan.scanClass(res, info); names.push(info.name); row.classes++; }
    }
    Scan.scanNames(res, names);
    const has = n => !!zip.file(n);
    const read = async n => { const f = zip.file(n); return f ? f.async('string') : ''; };
    try { row.meta = await modMeta(read, has); } catch (e) { /* ignore */ }
    if (zip.file(/^classes\d*\.dex$/).length) row.kindLabel = 'Android app (dex code not in quick scan)';
  };
  if (kind === 'zip') await scanZip(await JSZip.loadAsync(u8));
  else if (kind === 'class') { const info = Inspect.parseClass(u8, true); if (info) { Scan.scanClass(res, info); row.classes = 1; } }
  else if (kind === 'pe') {
    for (const s of Inspect.extractStrings(u8)) Scan.scanString(res, s.s, 'strings');
    const emb = Inspect.findEmbeddedZip(u8);
    if (emb) { try { await scanZip(await JSZip.loadAsync(emb)); row.kindLabel = 'exe with embedded jar'; } catch (e) { /* not a zip */ } }
  } else throw new Error('unsupported type');
  row.summary = Scan.summarize(res);
  row.level = row.summary.level;
  return row;
}

async function analyzeBatch(items, title) {
  setBusy(true);
  S = freshState();
  S.name = title;
  S.baseName = 'batch';
  S.size = items.reduce((a, x) => a + (x.size || 0), 0);
  S.kind = 'batch';
  S.batch = [];
  el.err.hidden = true;
  el.result.hidden = true;
  el.status.hidden = false;
  el.recent.hidden = true;
  el.ftags.innerHTML = '';
  el.retry.hidden = true;
  el.ficon.hidden = true;
  el.vt.hidden = true;
  el.drop.classList.add('compact');
  el.fname.textContent = title;
  el.fsize.textContent = human(S.size);
  el.ftype.textContent = 'batch scan';
  for (const k of ['fmd5', 'fsha1', 'fhash']) el[k].textContent = '(multiple files)';
  const t0 = performance.now();
  try {
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      setState(`scanning ${i + 1}/${items.length} · ${it.name}`, 100 * i / items.length);
      let row;
      try {
        row = await quickScan(it.name, await it.get());
      } catch (e) {
        row = { name: it.name, size: it.size || 0, level: 'err', error: e.message === 'unsupported type' ? 'not a jar / class / exe' : String(e.message || e) };
      }
      row.get = it.get;
      S.batch.push(row);
      await new Promise(r => setTimeout(r, 0));
    }
    const c = l => S.batch.filter(r => r.level === l).length;
    if (c('high')) tag(`${c('high')} high risk`, 'bad');
    if (c('med')) tag(`${c('med')} to review`, 'warn');
    tag(`${c('none') + c('low')} without major indicators`, 'good');
    if (c('err')) tag(`${c('err')} skipped`);
    finish(`batch done · ${plural(items.length, 'file')} · ${((performance.now() - t0) / 1000).toFixed(1)}s`, t0);
  } catch (e) {
    showError(e.message || String(e));
  } finally {
    setBusy(false);
  }
}

// Remember the current analysis, run fn (which replaces S), then make the old one the parent.
async function descend(fn) {
  S.ui = { tags: el.ftags.innerHTML, type: el.ftype.textContent, state: el.fstate.textContent, icon: el.ficon.hidden ? null : el.ficon.src };
  const parent = S;
  await fn();
  if (S !== parent) stack.push(parent);
  renderBanner();
}

async function openBatchItem(i) {
  if (busy) return;
  const row = S.batch[i];
  if (!row || row.level === 'err') return;
  const bytes = await row.get();
  await descend(() => analyze(row.name, bytes));
}

async function scanNested() {
  if (busy || !S.jarInfo) return;
  const rz = S.jarInfo.rz;
  const items = S.jarInfo.nestedList.map(n => ({ name: n.name, size: n.size, get: () => rz.file(n.name).async('uint8array') }));
  await descend(() => analyzeBatch(items, `${S.name} · nested`));
}
