// EZLARP: analysis flow + Java engines. Everything runs client-side:
// CheerpJ 5 (WebAssembly JVM, Java 17) runs Vineflower / CFR / dex2jar / ASM
// through small driver classes in ezlarp-helper-v3.jar; JSZip handles archives.
'use strict';

const HELPER = '/app/ezlarp-helper-v3.jar';
const CP_DECOMPILE = `${HELPER}:/app/vineflower-1.12.0.jar:/app/cfr-0.152.jar`;
const CP_D2J = `${HELPER}:/app/d2j-bundle-2.4.jar`;
// source files; above this, decompile on demand (#lazy=N in the URL overrides, handy for testing)
// Up to this many source files are decompiled right away. Default 0: the report comes
// first and code is decompiled when opened (the Java engine is heavy on phones).
const LAZY_OVER = +((/[#&]lazy=(\d+)/.exec(location.hash) || [])[1] || 0);
const CHEERPJ_URL = 'https://cjrtnc.leaningtech.com/5.0/loader.js';
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
// Upload file / Scan with URL tabs
function setMode(m) {
  for (const b of document.querySelectorAll('.mode')) { const on = b.dataset.mode === m; b.classList.toggle('active', on); b.setAttribute('aria-selected', on); }
  for (const p of document.querySelectorAll('[data-panel]')) p.hidden = p.dataset.panel !== m;
  if (m === 'url') setTimeout(() => el.url.focus(), 0);
}
for (const b of document.querySelectorAll('.mode')) b.onclick = () => setMode(b.dataset.mode);
el.file.onchange = e => { handleFiles([...e.target.files]); el.file.value = ''; };

for (const b of document.querySelectorAll('[data-sample]')) b.onclick = () => loadSample(b.dataset.sample);
async function loadSample(name) {
  if (busy) return;
  try {
    el.status.hidden = false;
    setState('fetching sample', 2);
    name = { jar: 'sample.jar', apk: 'sample.apk', exe: 'sample-wrapped.exe', python: 'sample-python.exe', py: 'sample-python.exe' }[name.toLowerCase()] || name;
    const r = await fetch('/samples/' + encodeURIComponent(name));
    // the host answers unknown paths with the home page, so check it isn't HTML
    if (!r.ok || /text\/html/.test(r.headers.get('content-type') || '')) throw new Error(`no sample called "${name}" (try jar, apk, exe or python)`);
    handleFiles([new File([await r.blob()], name)]);
  } catch (e) { showError('could not load sample: ' + (e.message || e)); }
}
const hashSample = (/[#&]sample=([\w.-]+)/.exec(location.hash) || [])[1];
const hashUrl = (/[#&]url=([^&]+)/.exec(location.hash) || [])[1];
window.addEventListener('load', () => {
  if (hashSample) loadSample(hashSample);
  else if (hashUrl) { setMode('url'); el.url.value = decodeURIComponent(hashUrl); loadUrl(el.url.value); }
});

// ------------------------------------------------------------------ open from a link

el.urlform.onsubmit = e => { e.preventDefault(); if (el.url.value.trim()) loadUrl(el.url.value); };

const MODRINTH_RE = /modrinth\.com\/(mod|plugin|datapack|resourcepack|shader|modpack)\/([\w.-]+)(?:\/version\/([^/?#]+))?/i;

async function resolveLink(raw) {
  let url = raw.trim();
  if (url.startsWith('/')) url = location.origin + url;
  else if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const mr = MODRINTH_RE.exec(url);
  if (mr) {
    setState('looking up the Modrinth project', 2);
    const r = await fetch(`https://api.modrinth.com/v2/project/${encodeURIComponent(mr[2])}/version`);
    if (!r.ok) throw new Error(r.status === 404 ? `Modrinth project "${mr[2]}" not found` : `Modrinth API answered HTTP ${r.status}`);
    const versions = await r.json();
    if (!versions.length) throw new Error('this Modrinth project has no files');
    const v = mr[3] ? versions.find(x => x.id === mr[3] || x.version_number === decodeURIComponent(mr[3])) : versions[0];
    if (!v) throw new Error(`version "${mr[3]}" not found on Modrinth`);
    const file = v.files.find(f => f.primary) || v.files[0];
    return { url: file.url, name: file.filename, source: `Modrinth · ${mr[2]} ${v.version_number}`, sha1: file.hashes && file.hashes.sha1,
      modrinth: { slug: mr[2], kind: mr[1].toLowerCase(), versions, current: v.id } };
  }
  // GitHub file pages -> raw (raw.githubusercontent.com allows cross-site downloads)
  const gh = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/(?:blob|raw)\/(.+)$/i.exec(url);
  if (gh) url = `https://raw.githubusercontent.com/${gh[1]}/${gh[2]}`;
  const host = new URL(url).hostname.toLowerCase();
  let name = 'download';
  try { name = decodeURIComponent(new URL(url).pathname.split('/').filter(Boolean).pop() || 'download'); } catch (e) { /* keep default */ }
  // hosts that block in-browser downloads go through our server-side fetcher
  const proxy = PROXY_HOSTS.test(host) && !/^raw\.githubusercontent\.com$/.test(host);
  return { url, name, source: SOURCE_NAMES.find(([re]) => re.test(host))?.[1] || host, proxy };
}
const PROXY_HOSTS = /(^|\.)(discordapp\.com|discordapp\.net|mediafire\.com|gofile\.io|github\.com|githubusercontent\.com|forgecdn\.net|dropbox\.com|dropboxusercontent\.com|drive\.google\.com|googleusercontent\.com)$/;
const SOURCE_NAMES = [[/discordapp\./, 'Discord'], [/mediafire\.com$/, 'MediaFire'], [/gofile\.io$/, 'Gofile'], [/github/, 'GitHub'],
  [/forgecdn\.net$/, 'CurseForge'], [/modrinth\.com$/, 'Modrinth'], [/dropbox/, 'Dropbox'], [/google/, 'Google Drive']];

// Downloads through /api/fetch (a Cloudflare function next to this page).
async function viaServer(url) {
  let r;
  try { r = await fetch('/api/fetch?url=' + encodeURIComponent(url)); } catch (e) { throw new Error('could not reach the EZLARP link downloader. Download the file and drop it here instead.'); }
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { const j = await r.json(); if (j.error) msg = j.error; } catch (e) {
      if (r.status === 404 || r.status === 405) msg = 'the link downloader is not available on this copy of the site';
    }
    throw new Error(msg);
  }
  return r;
}

async function fetchBytes(url, label, onProgress, opts = {}) {
  let r;
  if (opts.proxy) r = await viaServer(url);
  else {
    try {
      r = await fetch(url);
    } catch (e) {
      // blocked by CORS: let the server download it instead
      r = await viaServer(url);
    }
  }
  if (!r.ok) throw new Error(`download failed: HTTP ${r.status}`);
  const served = r.headers.get('x-filename');
  if (served && opts.onName) { try { opts.onName(decodeURIComponent(served)); } catch (e) { /* ignore */ } }
  const total = +r.headers.get('content-length') || 0;
  if (!r.body || !r.body.getReader) return new Uint8Array(await r.arrayBuffer());
  const reader = r.body.getReader();
  const chunks = [];
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    got += value.length;
    if (onProgress) onProgress(got, total);
  }
  const out = new Uint8Array(got);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

// Modrinth: the version to compare against = the newest older version sharing a loader
function modrinthPrevious() {
  const m = S.modrinth;
  if (!m) return null;
  const i = m.versions.findIndex(v => v.id === m.current);
  const cur = m.versions[i];
  if (!cur) return null;
  return m.versions.slice(i + 1).find(v => v.loaders.some(l => cur.loaders.includes(l))) || m.versions[i + 1] || null;
}

async function compareModrinth(versionId) {
  if (busy) return;
  const v = S.modrinth.versions.find(x => x.id === versionId);
  const file = v && (v.files.find(f => f.primary) || v.files[0]);
  if (!file) return;
  const before = el.fstate.textContent;
  try {
    setBusy(true);
    const u8 = await fetchBytes(file.url, file.filename, (got, total) => setState(`downloading ${file.filename} ${human(got)}${total ? ' / ' + human(total) : ''}`, null));
    if (file.hashes && file.hashes.sha1 && await sha1hex(u8) !== file.hashes.sha1) throw new Error('downloaded file does not match the hash Modrinth published for it');
    setBusy(false);
    // compare old -> current, so "new indicators" means "added by the current version"
    compareWith.restoreState = before;
    await compareWith(file.filename, u8, true);
  } catch (e) {
    setBusy(false);
    setState(before, null);
    showError(e.message || String(e));
  }
}

function openModrinthVersion(versionId) {
  const m = S.modrinth;
  el.url.value = `https://modrinth.com/${m.kind}/${m.slug}/version/${versionId}`;
  loadUrl(el.url.value);
}

async function sha1hex(u8) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-1', u8))].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function loadUrl(raw) {
  if (busy) { toast('busy — wait for the current file to finish'); return; }
  el.status.hidden = false;
  el.err.hidden = true;
  el.recent.hidden = true;
  setBusy(true);
  try {
    const link = await resolveLink(raw);
    el.fname.textContent = link.name;
    const u8 = await fetchBytes(link.url, link.name, (got, total) =>
      setState(`downloading ${human(got)}${total ? ' / ' + human(total) : ''}`, total ? 2 + 4 * got / total : null),
    { proxy: link.proxy, onName: n => { if (n && !/^(download|view|file)$/i.test(n)) { link.name = n; el.fname.textContent = n; } } });
    if (link.sha1 && await sha1hex(u8) !== link.sha1) throw new Error('downloaded file does not match the hash Modrinth published for it');
    setBusy(false);
    stack.length = 0;
    await analyze(link.name, u8, { source: link.source, modrinth: link.modrinth });
  } catch (e) {
    setBusy(false);
    setState('error', 100);
    showError(e.message || String(e));
  }
}

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
  const inField = /^(INPUT|TEXTAREA)$/.test(document.activeElement && document.activeElement.tagName);
  if (files.length && !inField) {
    e.preventDefault();
    handleFiles(files);
    return;
  }
  // a pasted link anywhere on the page scans it
  const text = e.clipboardData ? e.clipboardData.getData('text').trim() : '';
  if (!inField && /^https?:\/\/\S+$/.test(text) && !busy) {
    e.preventDefault();
    setMode('url');
    el.url.value = text;
    loadUrl(text);
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
  document.body.classList.add('has-result');
  el.recent.hidden = true;
  clearViewer();
  el.fname.textContent = name;
  el.fname.title = name;
  el.fsize.textContent = human(u8.length);
  el.ftype.textContent = '…';
  for (const k of ['fmd5', 'fsha1', 'fhash']) el[k].textContent = '…';
  setState('reading', 3);
  hashes(u8, !!opts.multiClass);
  if (opts.source) { S.source = opts.source; tag('from ' + opts.source, 'java'); }
  if (opts.modrinth) S.modrinth = opts.modrinth;

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
      } else if (zip.file('modrinth.index.json')) {
        S.kind = 'mrpack';
        await analyzeMrpack(zip);
        S.jarBytes = u8;
        S.preZip = zip;
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
      S.dexMode = { dexes: [{ name, u8 }] };
      S.resZip = new JSZip();
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

    if (S.jarBytes || S.dexMode) {
      setState('reading archive', 8);
      if (S.dexMode) {
        S.jarInfo = await analyzeDex();
        buildFiles();
        await scanDex();
      } else {
        S.jarInfo = await analyzeJar(S.jarBytes, S.resZip || S.preZip);
        buildFiles();
        await scanJar();
      }
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
        S.log.push(`${plural(groups, 'source file')}: each one is decompiled when you open it. "decompile all" does everything at once.`);
        finish(`scan done · ${plural(groups, 'source file')} · open CODE to read them`, t0);
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
    const label = S.batch ? `batch · ${S.batch.length} files` : S.scan ? Scan.VERDICT_TEXT[S.scan.verdict] + (S.scan.detections.length ? ': ' + S.scan.detections.map(d => d.name).join(', ') : '') : '';
    pushHistory({ name: S.name, sha256: S.hashes.sha256 || '', level: lvl, label, type: el.ftype.textContent.split(' · ')[0], t: Date.now() });
  }
  if ((S.lazy || S.engineUsed) && JAVA_AUTO) {
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
      depends: [...t.matchAll(/\[\[dependencies\.[^\]]+\]\]([\s\S]*?)(?=\n\s*\[|$)/g)].map(m => {
        const b = m[1], g2 = k => (new RegExp('^\\s*' + k + '\\s*=\\s*"([^"]*)"', 'm').exec(b) || [])[1];
        const type = (g2('type') || (/mandatory\s*=\s*false/.test(b) ? 'optional' : 'required')).toLowerCase();
        return g2('modId') ? `${g2('modId')} ${g2('versionRange') || ''}${type !== 'required' ? ' (' + type + ')' : ''}`.trim() : null;
      }).filter(Boolean)
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

// Android: read the dex files directly (no JVM). Classes are converted to Java bytecode
// only when they are opened or when "decompile all" runs, in chunks.
async function analyzeDex() {
  const dm = S.dexMode;
  dm.classDex = new Map();
  dm.parsed = [];
  for (let i = 0; i < dm.dexes.length; i++) {
    const d = dm.dexes[i];
    setState(`reading ${d.name} (${i + 1}/${dm.dexes.length})`, 8 + 10 * i / dm.dexes.length);
    await new Promise(r => setTimeout(r, 0));
    let parsed;
    try { parsed = Inspect.parseDex(d.u8); } catch (e) { S.log.push(`could not read ${d.name}: ${e.message}`); continue; }
    for (const c of parsed.classes) {
      if (!c.name || dm.classDex.has(c.name)) continue;
      dm.classDex.set(c.name, i);
      dm.parsed.push(c);
    }
  }
  const rz = S.resZip;
  const resources = Object.values(rz.files).filter(f => !f.dir && !/^classes\d*\.dex$/.test(f.name));
  const has = n => !!rz.file(n);
  const pk = new Map();
  for (const c of dm.parsed) {
    const parts = c.name.split('/');
    const key = parts.length < 2 ? '(default package)' : parts.slice(0, Math.min(3, parts.length - 1)).join('/');
    pk.set(key, (pk.get(key) || 0) + 1);
  }
  return {
    zip: null, rz, entries: [], classes: [], resources, classCount: dm.parsed.length, versions: {}, manifest: '', mainClass: null,
    kinds: S.apk ? ['Android app'] : ['Android dex'], signed: resources.some(e => /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(e.name)),
    nestedList: resources.filter(e => ARCHIVE_RE.test(e.name)).map(e => ({ name: e.name, size: (e._data && e._data.uncompressedSize) || 0 })),
    packages: [...pk.entries()].sort((a, b) => b[1] - a[1]), meta: null, multiRelease: false, dalvik: true, has
  };
}

function buildFiles() {
  const j = S.jarInfo;
  S.files = new Map();
  if (S.dexMode) {
    for (const c of S.dexMode.parsed) {
      const p = srcPathOf(c.name);
      let f = S.files.get(p);
      if (!f) S.files.set(p, f = { path: p, type: 'src', text: null, classes: [], dexClasses: [] });
      f.dexClasses.push(c.name);
    }
  }
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
  if (S.apk && S.apk.entry) for (const e of S.apk.entry) S.entrypoints.add(e.replace(/\./g, '/'));
}

async function scanDex() {
  const res = Scan.newResult();
  const names = [];
  const list = S.dexMode.parsed;
  for (let i = 0; i < list.length; i++) {
    if (i % 2000 === 0) { setState(`scanning classes ${i}/${list.length}`, 18 + 4 * i / list.length); await new Promise(r => setTimeout(r, 0)); }
    indexClass(list[i], srcPathOf(list[i].name), names);
    Scan.scanClass(res, list[i]);
  }
  await finishScan(res, names);
  S.log.push(`[dex] read ${list.length} classes from ${plural(S.dexMode.dexes.length, 'dex file')} directly; classes are converted to Java when opened`);
}

// Indexes one parsed class for jump-to-class, usages and string search.
function indexClass(info, srcPath, names) {
  S.classToSrc.set(info.name, srcPath);
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
  const strs = info.strings.filter(x => x.length >= 2);
  if (strs.length) S.cpStrings.set(info.name, strs.length > 400 ? strs.slice(0, 400) : strs);
}

async function finishScan(res, names) {
  Scan.scanNames(res, names);
  if (S.apk) for (const p of S.apk.perms) if (DANGEROUS_PERMS.test(p)) Scan.scanString(res, p, 'AndroidManifest.xml');
  await scanInside(res, S.jarInfo.rz, '', 0);
  setScan(res);
  for (const ep of S.entrypoints) { const p = fileForClass(ep); if (p) S.files.get(p).entry = true; }
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
      indexClass(info, srcPathOf(c.name), names);
    }
    Scan.scanClass(res, info);
  }
  await finishScan(res, names);
}

const NATIVE_RE = /\.(dll|so|dylib|exe|jnilib|sys)$/i;
const NESTED_MAX = 64 * 1024 * 1024;

// Scan archives and native binaries inside an archive (jar-in-jar is a common hiding place).
// Findings are located as "inner.jar!pkg/Class" or "lib/x.dll".
async function scanInside(res, zip, prefix, depth) {
  const entries = Object.values(zip.files).filter(f => !f.dir && (ARCHIVE_RE.test(f.name) || NATIVE_RE.test(f.name)));
  if (!entries.length) return;
  if (!depth) S.nestedRows = [];
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    const size = (e._data && e._data.uncompressedSize) || 0;
    const where = prefix + e.name;
    if (size > NESTED_MAX) { S.log.push(`skipped ${where}: ${human(size)} is too big to scan inside`); continue; }
    if (!depth) setState(`scanning inside ${e.name} (${i + 1}/${entries.length})`, 20);
    await new Promise(r => setTimeout(r, 0));
    const u8 = await e.async('uint8array');
    if (NATIVE_RE.test(e.name)) {
      Scan.scanNative(res, where, Inspect.extractStrings(u8, 6, 20000));
      if (!depth) S.nestedRows.push({ name: e.name, size, kind: 'native', level: null });
      continue;
    }
    let inner;
    try { inner = await JSZip.loadAsync(u8); } catch (err) { S.log.push(`could not open ${where}: ${err.message}`); continue; }
    const sub = Scan.newResult();
    let classes = 0;
    for (const f of Object.values(inner.files)) {
      if (f.dir || !/\.class$/i.test(f.name)) continue;
      const info = Inspect.parseClass(await f.async('uint8array'), true);
      if (!info) continue;
      classes++;
      Scan.scanClass(res, info, where + '!');
      Scan.scanClass(sub, info);
    }
    if (depth < 2) await scanInside(res, inner, where + '!', depth + 1);
    if (!depth) {
      let meta = null;
      try { meta = await modMeta(async n => { const f = inner.file(n); return f ? f.async('string') : ''; }, n => !!inner.file(n)); } catch (err) { /* ignore */ }
      const sum = Scan.summarize(sub);
      S.nestedRows.push({ name: e.name, size, kind: 'archive', classes, meta, level: sum.level, summary: sum });
    }
  }
}

function setScan(res) {
  S.scanRes = res;
  S.scan = Scan.summarize(res);
  S.srcFlags = new Map();
  for (const f of S.scan.findings) {
    if (f.rule.sev !== 'high' && f.rule.sev !== 'med') continue;
    for (const where of f.where.keys()) {
      const p = fileForClass(where) || (where.includes('!') && S.files.has(where.split('!')[0]) ? where.split('!')[0] : null) || (S.files.has(where) ? where : null);
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
  const nestedClasses = (S.nestedRows || []).reduce((a, r) => a + (r.classes || 0), 0);
  if (j.classCount || (!nestedClasses && !S.mrpack)) tag(plural(j.classCount, 'class'), 'java');
  if (nestedClasses) tag(plural(nestedClasses, 'class') + ' in nested jars', 'java');
  const top = Object.entries(j.versions).sort((a, b) => b[1] - a[1])[0];
  if (top) tag('target ' + Inspect.javaVersion(+top[0]), 'java');
  j.kinds.forEach(k => tag(k, 'good'));
  if (j.mainClass) tag('runnable', 'good');
  if (j.nestedList.length) tag(plural(j.nestedList.length, 'nested archive') + ' (scanned)', 'warn');
  const natives = j.resources.filter(r => NATIVE_RE.test(r.name)).length;
  if (natives) tag(plural(natives, 'native binary') + ' inside', 'warn');
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
      const full = n => !n ? null : n.startsWith('.') ? (a.pkg || '') + n : n.includes('.') ? n : (a.pkg ? a.pkg + '.' + n : n);
      a.entry = [];
      for (const m of xml.matchAll(/<(activity(?:-alias)?)\b([^>]*)>([\s\S]*?)<\/\1>/g)) {
        if (!/android\.intent\.category\.LAUNCHER/.test(m[3])) continue;
        const nm = (/\btargetActivity="([^"]+)"/.exec(m[2]) || /\bname="([^"]+)"/.exec(m[2]) || [])[1];
        if (nm) { a.launcher = full(nm); a.entry.push(a.launcher); }
      }
      const appName = (/<application\b[^>]*?\sandroid:name="([^"]+)"/.exec(xml) || [])[1];
      if (appName) { a.appClass = full(appName); a.entry.push(a.appClass); }
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
  if (items.length) S.dexMode = { dexes: items };
  else S.log.push('no classes*.dex found — nothing to decompile');
}

// ------------------------------------------------------------------ modrinth modpacks

async function analyzeMrpack(zip) {
  const idx = JSON.parse(await zip.file('modrinth.index.json').async('string'));
  el.ftype.textContent = 'Modrinth modpack';
  const files = (idx.files || []).filter(f => f.downloads && f.downloads.length);
  S.mrpack = { name: idx.name, version: idx.versionId, summary: idx.summary, deps: idx.dependencies || {}, files };
  tag(`${idx.name || 'modpack'} ${idx.versionId || ''}`.trim(), 'java');
  tag(plural(files.length, 'file') + ' to download', 'good');
  S.log.push(`modpack lists ${files.length} files to download. Use "download & scan all" in DETAILS.`);
}

async function scanMrpack() {
  if (busy || !S.mrpack) return;
  const items = S.mrpack.files.map(f => ({
    name: f.path.split('/').pop(), size: f.fileSize || 0,
    get: async () => {
      const u8 = await fetchBytes(f.downloads[0], f.path);
      if (f.hashes && f.hashes.sha1 && await sha1hex(u8) !== f.hashes.sha1) throw new Error('hash does not match the modpack index');
      return u8;
    }
  }));
  await descend(() => analyzeBatch(items, `${S.mrpack.name || S.name} · ${items.length} mods`));
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
    const z = await JSZip.loadAsync(await readJavaOutput(outPath, `dex2jar on ${name}`));
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
  if (S.py) await loadPython(u8, res);
  setScan(res);
  if (!S.jarBytes && pe.ok) {
    if (!py) tag(pe.dotnet ? '.NET (C#/VB) code' : 'native machine code', pe.dotnet ? 'java' : '');
    tag(Inspect.MACHINES[pe.machine] || 'unknown CPU');
    const sub = Inspect.SUBSYSTEMS[pe.subsystem] || '';
    if (/gui/i.test(sub)) tag('GUI app'); else if (/console/i.test(sub)) tag('console app');
    if (pe.imports && pe.imports.length) tag(plural(pe.imports.length, 'DLL') + ' imported');
  }
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

// ------------------------------------------------------------------ python (PyInstaller)

const inflate = async data => new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate'))).arrayBuffer());

async function loadPython(u8, res) {
  const py = S.py;
  const mods = [];
  for (const f of py.files) {
    if (f.type === 's') {
      const raw = u8.subarray(f.off, f.off + f.csize);
      mods.push({ name: f.name, script: true, boot: /^(pyiboot|pyi_rth_|_pyi_)/.test(f.name), get: () => f.compressed ? inflate(raw) : Promise.resolve(raw.slice()) });
    } else if (f.type === 'z') {
      const pyzBytes = u8.subarray(f.off, f.off + f.csize);
      try {
        const pyz = Inspect.parsePYZ(pyzBytes, py.pyver);
        py.magic = pyz.magic;
        for (const e of pyz.entries) {
          const raw = pyzBytes.subarray(e.off, e.off + e.len);
          mods.push({ name: e.name, pkg: e.pkg, get: () => inflate(raw) });
        }
      } catch (err) {
        S.log.push(`could not read ${f.name}: ${err.message} (encrypted PYZ archives from old PyInstaller --key builds aren't supported)`);
      }
    }
  }
  py.mods = mods.length;
  let ok = 0, failed = 0;
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if (i % 60 === 0) { setState(`reading Python modules ${i}/${mods.length}`, 8 + 80 * i / mods.length); await new Promise(r => setTimeout(r, 0)); }
    const path = m.script ? (m.boot ? '(pyinstaller)/' : '') + m.name + '.py' : m.name.replace(/\./g, '/') + (m.pkg ? '/__init__.py' : '.py');
    const f = { path, type: 'py', module: m.name, script: !!m.script, boot: !!m.boot, get: m.get, text: null };
    try {
      const code = Inspect.unmarshal(await m.get(), py.pyver).value;
      const sum = Inspect.pyCodeSummary(code);
      f.summary = sum;
      f.text = pyListing(f, sum);
      for (const st of sum.strings) Scan.scanString(res, st, m.name);
      if (sum.strings.length) S.cpStrings.set(m.name, sum.strings.length > 400 ? sum.strings.slice(0, 400) : sum.strings);
      ok++;
    } catch (err) {
      f.text = `# ${m.name}\n# could not read this module: ${err.message}\n`;
      failed++;
    }
    S.files.set(path, f);
    S.classToSrc.set(m.name, path);
    if (m.script && !m.boot) { S.entrypoints.add(m.name); f.entry = true; }
  }
  S.log.push(`[python] read ${ok} modules${failed ? `, ${failed} failed` : ''} from the PyInstaller archive (Python ${py.pyver})`);
  tag(`${ok} Python modules`, 'java');
}

function pyListing(f, sum) {
  const lines = [
    `# ${f.module}${f.script ? '  (entry script)' : ''}`,
    `# compiled Python ${S.py.pyver} — EZLARP shows names and constants, not decompiled source.`,
    `# For full source: download the .pyc (button above) and run pycdc, decompyle3 or pylingual.`, ''];
  if (sum.outline.length) {
    lines.push('# ---- functions and classes ----');
    for (const o of sum.outline.slice(0, 2000)) lines.push('    '.repeat(o.depth - 1) + (o.isClass ? `class ${o.name}:` : `def ${o.name}(${o.args ? o.args + ' args' : ''})`) + `  # line ${o.line}`);
    lines.push('');
  }
  if (sum.names.length) {
    lines.push(`# ---- names used (${sum.names.length}) ----`);
    for (let i = 0; i < sum.names.length; i += 8) lines.push('# ' + sum.names.slice(i, i + 8).join(', '));
    lines.push('');
  }
  lines.push(`# ---- string constants (${sum.strings.length}) ----`);
  for (const st of sum.strings.slice(0, 5000)) lines.push(JSON.stringify(st));
  return lines.join('\n') + '\n';
}

const PY_MAGIC = { '3.7': 0x0d42, '3.8': 0x0d55, '3.9': 0x0d61, '3.10': 0x0d6f, '3.11': 0x0da7, '3.12': 0x0dcb, '3.13': 0x0df3 };
async function pycBytes(f) {
  if (!S.py.magic && PY_MAGIC[S.py.pyver]) { const m = PY_MAGIC[S.py.pyver]; S.py.magic = new Uint8Array([m & 0xff, m >> 8, 0x0d, 0x0a]); }
  const body = await f.get();
  const out = new Uint8Array(16 + body.length);
  if (S.py.magic) out.set(Inspect.pycHeader(S.py.magic), 0);
  out.set(body, 16);
  return out;
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

// The Java runtime (CheerpJ) is only downloaded the first time code is decompiled,
// so the scan works even where it is slow or blocked.
function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error('Could not download the Java engine (CheerpJ). The scan above still works; check your connection or ad blocker to read the code.'));
    document.head.appendChild(s);
  });
}
// iPhone / iPad (every iOS browser is Safari underneath): the in-browser JVM doesn't start
// there, so the built-in quick view is used unless "full source" is tapped.
const IS_IOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const JAVA_AUTO = !IS_IOS && !/[#&]nojava\b/.test(location.hash);
const JVM_TIMEOUT = +((/[#&]jvmtimeout=(\d+)/.exec(location.hash) || [])[1] || 60) * 1000;
let cjInit = null;
function ensureJVM() {
  if (!cjReady) {
    setState('starting the Java engine (first time downloads it, cached after)', null);
    if (!cjInit) {
      cjInit = (typeof cheerpjInit === 'function' ? Promise.resolve() : loadScript(CHEERPJ_URL))
        .then(() => cheerpjInit({ version: 17, status: 'none' }))
        .catch(e => { cjInit = null; throw e; });
    }
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(
      `the Java engine did not start within ${JVM_TIMEOUT / 1000} seconds${IS_IOS ? ' (it does not work on iPhone / iPad)' : ''}. The quick view is built in and works without it.`)), JVM_TIMEOUT); });
    cjReady = Promise.race([cjInit, timeout]).then(v => { clearTimeout(timer); return v; }, e => { clearTimeout(timer); cjReady = null; throw e; });
  }
  return cjReady;
}

// The class files behind one source file, outer class first.
async function classBytesOf(f) {
  const list = [...(f.classes || [])].sort((a, b) => a.name.length - b.name.length || a.name.localeCompare(b.name));
  const out = [];
  for (const c of list) out.push({ name: c.name, u8: await c.async('uint8array') });
  return out;
}
async function quickText(f) {
  if (S.dexMode) {
    const set = new Set(f.dexClasses);
    return JView.dexSummary(S.dexMode.parsed.filter(c => set.has(c.name)));
  }
  return JView.decompile(await classBytesOf(f));
}
// Full decompile in the background; the view refreshes when it lands.
function startFull(f) {
  if (f.text != null || f.pending) return;
  ensureSource(f).catch(e => { f.error = e.message || String(e); }).then(() => {
    renderBanner();
    markTree();
    el.decall.hidden = !(S.lazy && pendingCount() > 0);
    if (!el.q.value.trim() && !S.usagesOf) updateFoot();
    if (S.current === f.path && f.view !== 'bc' && f.view !== 'quick') openFile(f.path, { keepScroll: f.text == null });
  });
}

function ensureJarPath() {
  if (S.dexMode) return null;
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

// Reads a file the JVM wrote. cjFileBlob gives null (not an error) when it is missing,
// which happens when the in-browser JVM runs out of memory or is killed.
async function readJavaOutput(path, what) {
  let blob = null;
  try { blob = await cjFileBlob(path); } catch (e) { /* treated as missing */ }
  if (!blob) {
    throw new Error(`${what} produced no output. The in-browser Java runtime most likely ran out of memory or was stopped by the browser (common on phones with very large files). Try again on a computer, or open single classes instead of "decompile all".`);
  }
  return new Uint8Array(await blob.arrayBuffer());
}

async function runDecompiler(engine, inPath, extra, prog) {
  const outPath = `/files/ezlarp/out-${uid()}.zip`;
  const code = await runJava('ezlarp.Run', CP_DECOMPILE, [engine, inPath, outPath, ...engineOpts(engine), ...extra], prog);
  const zip = await JSZip.loadAsync(await readJavaOutput(outPath, `${ENGINES[engine]} (exit code ${code})`));
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
      const out = S.dexMode ? await decompileDexChunks(eng) : await runDecompiler(eng, ensureJarPath(), [], { total: groups, label: `decompiling with ${ENGINES[eng]}` });
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

// Converts the given dex classes to a jar; returns its path in the CheerpJ file system.
async function dexClassesJar(names, label) {
  const dm = S.dexMode;
  await ensureJVM();
  const byDex = new Map();
  for (const n of names) {
    const i = dm.classDex.get(n);
    if (i == null) continue;
    if (!byDex.has(i)) byDex.set(i, []);
    byDex.get(i).push(n);
  }
  const outs = [];
  for (const [i, list] of byDex) {
    const d = dm.dexes[i];
    if (!d.path) { d.path = `/str/dex-${i}-${uid()}.dex`; cheerpOSAddStringFile(d.path, d.u8); }
    const id = uid();
    const filter = `/str/filter-${id}.txt`, outPath = `/files/ezlarp-dex/out-${id}.jar`;
    cheerpOSAddStringFile(filter, list.join('\n'));
    await runJava('ezlarp.Dex', CP_D2J, [d.path, outPath, filter], list.length > 50 ? { total: list.length, label: `converting ${label || ''} (dex2jar)`, from: 20, to: 40 } : {});
    outs.push(await readJavaOutput(outPath, `dex2jar on ${d.name}`));
  }
  if (!outs.length) throw new Error('class not found in the dex files');
  let bytes = outs[0];
  if (outs.length > 1) {
    const merged = new JSZip();
    for (const o of outs) { const z = await JSZip.loadAsync(o); for (const f of Object.values(z.files)) if (!f.dir && f.name.endsWith('.class')) merged.file(f.name, await f.async('uint8array')); }
    bytes = await merged.generateAsync({ type: 'uint8array', compression: 'STORE' });
  } else {
    const z = await JSZip.loadAsync(bytes);
    const log = z.file('ezlarp/log.txt');
    const txt = log ? (await log.async('string')).trim() : '';
    if (txt) S.log.push(`[dex2jar]\n${txt.split('\n').slice(0, 100).join('\n')}`);
  }
  const path = `/str/dexjar-${uid()}.jar`;
  cheerpOSAddStringFile(path, bytes);
  return path;
}

// "decompile all" for Android: convert + decompile in chunks so memory stays bounded.
async function decompileDexChunks(eng) {
  const files = [...S.files.values()].filter(f => f.type === 'src' && f.dexClasses);
  const CHUNK = 600;
  const sources = {};
  const logs = [];
  let done = 0, failed = 0;
  for (let i = 0; i < files.length;) {
    const chunk = [];
    let n = 0;
    while (i < files.length && (n < CHUNK || !chunk.length)) { chunk.push(files[i]); n += files[i].dexClasses.length; i++; }
    setState(`decompiling with ${ENGINES[eng]} · ${done}/${files.length} files`, 20 + 76 * done / files.length);
    try {
      const jar = await dexClassesJar(chunk.flatMap(f => f.dexClasses), `${done + 1}-${done + chunk.length}`);
      const out = await runDecompiler(eng, jar, []);
      Object.assign(sources, out.sources);
      if (out.log) logs.push(out.log.split('\n').slice(0, 50).join('\n'));
    } catch (e) {
      failed += chunk.length;
      logs.push(`[chunk ${done + 1}-${done + chunk.length}] ${e.message || e}`);
    }
    done += chunk.length;
  }
  if (!Object.keys(sources).length) throw new Error(logs.slice(-1)[0] || 'nothing decompiled');
  if (failed) S.log.push(`${failed} source files could not be decompiled in bulk; open them one by one to retry`);
  return { sources, log: logs.join('\n') };
}

async function miniJar(f) {
  if (S.dexMode) return dexClassesJar(f.dexClasses, baseOf(f.path));
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
          const out = await runDecompiler(eng, inPath, lib ? ['ezlarp.lib=' + lib] : []);
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
  if (!S.dexMode) { f.bytecode = JView.disassemble(await classBytesOf(f)) || '// no bytecode'; return; }
  const inPath = await miniJar(f);
  const outPath = `/files/ezlarp-asm/out-${uid()}.zip`;
  await runJava('ezlarp.Asm', CP_D2J, [inPath, outPath]);
  const z = await JSZip.loadAsync(await readJavaOutput(outPath, 'the bytecode viewer'));
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
    if (!JAVA_AUTO) {
      // no Java engine here (iPhone): run the built-in decompiler over every class instead
      const files = [...S.files.values()].filter(f => f.type === 'src' && f.quick == null);
      for (let i = 0; i < files.length; i++) {
        if (i % 50 === 0) { setState(`quick view · ${i}/${files.length} files`, 100 * i / files.length); await new Promise(r => setTimeout(r, 0)); }
        try { files[i].quick = await quickText(files[i]); } catch (e) { files[i].quick = '// ' + (e.message || e); }
      }
      setState(`done · quick view of every class · ${((performance.now() - t0) / 1000).toFixed(1)}s · code search covers all of it`, 100);
      return;
    }
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
  if (busy || !(S.jarBytes || S.dexMode)) return;
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
      if (f.virtual) continue;
      if (f.type === 'src') { if (f.text != null) zip.file(f.path, f.text); }
      else if (f.type === 'py') zip.file(f.path + 'c', await pycBytes(f));
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
  row.verdict = row.summary.verdict;
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

// installable app + offline page (never in automated browsers, where it would bypass test routing)
if ('serviceWorker' in navigator && location.protocol === 'https:' && !navigator.webdriver) {
  addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
}
