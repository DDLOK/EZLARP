// EZLARP — in-browser Java decompiler + exe analyzer.
// Everything runs client-side: CheerpJ 5 (WebAssembly JVM, Java 17) runs
// Vineflower or CFR through a small driver jar; JSZip handles archives.
'use strict';

const $ = id => document.getElementById(id);

const ENGINES = { vf: 'Vineflower 1.12.0', cfr: 'CFR 0.152' };
const CLASSPATH = '/app/ezlarp-helper-v1.jar:/app/vineflower-1.12.0.jar:/app/cfr-0.152.jar';
const MAX_HIGHLIGHT = 400 * 1024;
const LANGS = {
  java: 'java', kt: 'kotlin', groovy: 'groovy', json: 'json', mcmeta: 'json', xml: 'xml', html: 'xml', fxml: 'xml',
  yml: 'yaml', yaml: 'yaml', properties: 'ini', mf: 'ini', cfg: 'ini', toml: 'ini', ini: 'ini', lang: 'ini',
  js: 'javascript', css: 'css', sql: 'sql', md: 'markdown', sh: 'bash', bat: 'dos', txt: 'plaintext'
};

const el = {
  drop: $('drop'), file: $('file'), pick: $('pick'), engine: $('engine'), fallback: $('fallback'),
  status: $('status'), fname: $('fname'), fsize: $('fsize'), ftype: $('ftype'), fhash: $('fhash'),
  fstate: $('fstate'), ftags: $('ftags'), fill: $('fill'), err: $('err'),
  result: $('result'), rtabs: $('rtabs'), retry: $('retry'), dl: $('dl'),
  q: $('q'), qmode: $('qmode'), tree: $('tree'), sidefoot: $('sidefoot'),
  cpath: $('cpath'), cmeta: $('cmeta'), wrap: $('wrap'), copy: $('copy'), dlone: $('dlone'),
  codebox: $('codebox'), gutter: $('gutter'), code: $('code'),
  details: $('details'), sq: $('sq'), skind: $('skind'), scount: $('scount'), strings: $('strings'),
  logbox: $('logbox'), overlay: $('overlay'), console: $('console')
};

let S = freshState();
let busy = false;
let cjReady = null;

function freshState() {
  return {
    name: '', baseName: '', kind: '', jarBytes: null, jarInfo: null, pe: null, sigs: [], embedded: null,
    files: new Map(),       // path -> { path, type: 'src'|'res', text?, bytes?, size }
    current: null, engineUsed: '', strings: null, log: [], qmode: 'files', seconds: 0
  };
}

// ------------------------------------------------------------------ prefs

try {
  const saved = localStorage.getItem('ezlarp.engine');
  if (saved && ENGINES[saved]) el.engine.value = saved;
  if (localStorage.getItem('ezlarp.fallback') === '0') el.fallback.checked = false;
} catch (e) { /* storage unavailable */ }
el.engine.onchange = () => { try { localStorage.setItem('ezlarp.engine', el.engine.value); } catch (e) {} };
el.fallback.onchange = () => { try { localStorage.setItem('ezlarp.fallback', el.fallback.checked ? '1' : '0'); } catch (e) {} };

// ------------------------------------------------------------------ input

el.pick.onclick = () => el.file.click();
// sample: EZLARP's own driver jar, served from this site
$('sample').onclick = async () => {
  if (busy) return;
  try {
    const r = await fetch('/ezlarp-helper-v1.jar');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    handleFiles([new File([await r.blob()], 'ezlarp-helper-v1.jar')]);
  } catch (e) { showError('could not load sample: ' + (e.message || e)); }
};
el.file.onchange = e => { handleFiles([...e.target.files]); el.file.value = ''; };

let dragDepth = 0;
const hasFiles = e => e.dataTransfer && [...(e.dataTransfer.types || [])].includes('Files');
window.addEventListener('dragenter', e => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  if (dragDepth++ === 0) el.overlay.hidden = false;
});
window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener('dragleave', e => {
  if (!hasFiles(e)) return;
  if (--dragDepth <= 0) { dragDepth = 0; el.overlay.hidden = true; }
});
window.addEventListener('drop', e => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  el.overlay.hidden = true;
  handleFiles([...e.dataTransfer.files]);
});

// ------------------------------------------------------------------ helpers

function human(b) {
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b < 10 && i ? 2 : 0) + ' ' + u[i];
}
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const hex = (n, w = 8) => '0x' + n.toString(16).toUpperCase().padStart(w, '0');
const ext = p => { const m = /\.([^./]+)$/.exec(p); return m ? m[1].toLowerCase() : ''; };
const baseOf = p => p.slice(p.lastIndexOf('/') + 1);

function setState(text, pct) {
  el.fstate.textContent = text;
  if (pct != null) el.fill.style.width = pct + '%';
}
function setBusy(on) {
  busy = on;
  el.fill.parentElement.classList.toggle('busy', on);
}
function tag(label, cls = '') {
  const t = document.createElement('span');
  t.className = 'tagx ' + cls;
  t.textContent = label;
  el.ftags.appendChild(t);
}
function showError(msg) {
  el.err.textContent = '[error] ' + msg;
  el.err.hidden = false;
}
async function sha256(u8) {
  try {
    const d = await crypto.subtle.digest('SHA-256', u8);
    return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
  } catch (e) { return 'unavailable'; }
}
function download(name, data, type = 'application/octet-stream') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(data instanceof Blob ? data : new Blob([data], { type }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
}
function isProbablyText(u8) {
  const n = Math.min(u8.length, 4096);
  for (let i = 0; i < n; i++) if (u8[i] === 0) return false;
  return true;
}

// ------------------------------------------------------------------ main flow

async function handleFiles(list) {
  list = list.filter(Boolean);
  if (!list.length) return;
  if (busy) { el.fstate.textContent = 'busy — wait for the current file to finish'; return; }

  S = freshState();
  setBusy(true);
  el.err.hidden = true;
  el.result.hidden = true;
  el.status.hidden = false;
  el.ftags.innerHTML = '';
  el.retry.hidden = true;
  el.drop.classList.add('compact');

  const classFiles = list.filter(f => /\.class$/i.test(f.name));
  const multiClass = list.length > 1 && classFiles.length === list.length;
  const primary = multiClass ? null : list[0];

  S.name = multiClass ? `${list.length} class files` : primary.name;
  S.baseName = multiClass ? 'classes' : primary.name.replace(/\.[^.]+$/, '');
  el.fname.textContent = S.name;
  el.fsize.textContent = human(list.reduce((a, f) => a + f.size, 0));
  el.ftype.textContent = '…';
  el.fhash.textContent = '…';
  setState('reading', 4);

  try {
    if (multiClass) {
      S.kind = 'class';
      el.ftype.textContent = 'Java class files';
      el.fhash.textContent = '(multiple files)';
      S.jarBytes = await classesToJar(await Promise.all(list.map(async f => ({ name: f.name, u8: new Uint8Array(await f.arrayBuffer()) }))));
    } else {
      const u8 = new Uint8Array(await primary.arrayBuffer());
      sha256(u8).then(h => { el.fhash.textContent = h; el.fhash.title = 'click to copy ' + h; });
      S.kind = Inspect.sniff(u8, primary.name);

      if (S.kind === 'zip') {
        el.ftype.textContent = 'Java archive';
        S.jarBytes = u8;
      } else if (S.kind === 'class') {
        el.ftype.textContent = 'Java class file';
        S.jarBytes = await classesToJar([{ name: primary.name, u8 }]);
      } else if (S.kind === 'pe') {
        await analyzePE(u8);
      } else {
        // last resort: maybe it's a zip with an odd extension
        const emb = Inspect.findEmbeddedZip(u8);
        if (!emb) throw new Error('unsupported file type — drop a .jar, .class, .exe or .dll');
        el.ftype.textContent = 'archive (unknown extension)';
        S.jarBytes = emb.slice();
      }
    }

    if (S.jarBytes) {
      setState('reading archive', 10);
      S.jarInfo = await analyzeJar(S.jarBytes);
      addJarTags(S.jarInfo);
      if (!S.jarInfo.classCount) {
        addResources(S.jarInfo);
        S.log.push('archive contains no .class files — showing resources only');
        finish('done — no classes to decompile');
        return;
      }
      await decompile(el.engine.value);
    } else {
      finish('analysis done');
    }
  } catch (e) {
    console.error(e);
    setState('error', 100);
    showError(e && e.message || String(e));
    if (S.pe || S.files.size) renderResult();
  } finally {
    setBusy(false);
  }
}

function finish(msg) {
  setState(msg, 100);
  renderResult();
}

// Wrap one or more .class files into a jar at their proper package paths.
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

async function analyzeJar(u8) {
  const zip = await JSZip.loadAsync(u8);
  const entries = Object.values(zip.files).filter(f => !f.dir);
  const classes = entries.filter(f => /\.class$/i.test(f.name));
  const resources = entries.filter(f => !/\.class$/i.test(f.name));
  const versions = {};
  const sample = classes.filter(c => !/^META-INF\/versions\//.test(c.name)).slice(0, 300);
  for (const c of sample) {
    const head = await c.async('uint8array');
    const info = Inspect.parseClass(head);
    if (info) versions[info.major] = (versions[info.major] || 0) + 1;
  }
  const has = n => !!zip.file(n);
  const manifestFile = zip.file('META-INF/MANIFEST.MF');
  const manifest = manifestFile ? await manifestFile.async('string') : '';
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
  if (has('AndroidManifest.xml') || has('classes.dex')) kinds.push('Android (dex — not supported yet)');
  if (entries.some(e => e.name.startsWith('BOOT-INF/'))) kinds.push('Spring Boot fat jar');
  const nested = entries.filter(e => /\.jar$/i.test(e.name)).length;
  return {
    zip, entries, classes, resources, classCount: classes.length, versions, manifest, mainClass, kinds, nested,
    multiRelease: classes.some(c => /^META-INF\/versions\//.test(c.name))
  };
}

function versionSummary(versions) {
  return Object.entries(versions).sort((a, b) => b[1] - a[1])
    .map(([m, n]) => `${Inspect.javaVersion(+m)} ×${n}`).join(', ');
}

function addJarTags(info) {
  tag(`${info.classCount} classes`, 'java');
  const top = Object.entries(info.versions).sort((a, b) => b[1] - a[1])[0];
  if (top) tag('target ' + Inspect.javaVersion(+top[0]), 'java');
  info.kinds.forEach(k => tag(k, /not supported/.test(k) ? 'warn' : 'good'));
  if (info.mainClass) tag('runnable', 'good');
  if (info.nested) tag(`${info.nested} nested jar${info.nested > 1 ? 's' : ''}`, 'warn');
}

// ------------------------------------------------------------------ PE analysis

async function analyzePE(u8) {
  setState('analyzing PE', 6);
  const pe = Inspect.parsePE(u8);
  S.pe = pe;
  if (!pe.ok) {
    el.ftype.textContent = 'MZ executable (not a valid PE)';
  } else {
    const arch = Inspect.MACHINES[pe.machine] || hex(pe.machine, 4);
    el.ftype.textContent = `${pe.format} ${pe.isDll ? 'DLL' : 'executable'} · ${arch}`;
  }
  S.sigs = Inspect.detectSignatures(u8, pe);
  S.sigs.forEach(s => tag(s.label, s.kind === 'java' ? 'java' : (/packed|protect|themida|vmp|enigma/i.test(s.label) ? 'warn' : '')));
  if (pe.signed) tag('has signature blob');
  if (pe.overlay) tag(`overlay ${human(pe.overlay.size)}`);

  // jar wrapped inside the exe (Launch4j, exe4j, JSmooth, ...)
  const emb = Inspect.findEmbeddedZip(u8);
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

  setState('extracting strings', 8);
  await new Promise(r => setTimeout(r, 0));
  S.strings = Inspect.extractStrings(u8);
  if (!S.jarBytes) {
    S.log.push(pe.dotnet
      ? '.NET assembly: the code is CIL, not Java bytecode. Open it in ILSpy or dnSpy to decompile to C#.'
      : 'No Java code found in this executable. Native machine code cannot be decompiled to Java — see DETAILS and STRINGS.');
  }
}

// ------------------------------------------------------------------ decompile

function initCheerpJ() {
  if (!cjReady) {
    if (typeof cheerpjInit !== 'function') throw new Error('CheerpJ failed to load (blocked by an extension or offline?)');
    cjReady = cheerpjInit({ version: 17, status: 'none' }).catch(e => { cjReady = null; throw e; });
  }
  return cjReady;
}

async function decompile(engine) {
  const order = el.fallback.checked ? [engine, engine === 'vf' ? 'cfr' : 'vf'] : [engine];
  let lastErr;
  for (const eng of order) {
    try {
      const t0 = performance.now();
      const out = await runEngine(eng, S.jarBytes, S.jarInfo.classCount);
      S.seconds = (performance.now() - t0) / 1000;
      S.engineUsed = eng;
      S.files = new Map();
      for (const [p, text] of Object.entries(out.sources)) S.files.set(p, { path: p, type: 'src', text, size: text.length });
      addResources(S.jarInfo);
      S.log.push(`[${ENGINES[eng]}] ${Object.keys(out.sources).length} source files in ${S.seconds.toFixed(1)}s`);
      if (out.log.trim()) S.log.push(out.log.trim());
      if (eng !== engine) tag(`fell back to ${ENGINES[eng]}`, 'warn');
      el.retry.textContent = 'retry with ' + (eng === 'vf' ? 'CFR' : 'Vineflower');
      el.retry.hidden = false;
      finish(`done · ${ENGINES[eng]} · ${S.seconds.toFixed(1)}s`);
      return;
    } catch (e) {
      console.error(e);
      lastErr = e;
      S.log.push(`[${ENGINES[eng]}] failed: ${e && e.message || e}`);
    }
  }
  throw lastErr;
}

async function runEngine(engine, jarBytes, total) {
  setState('loading JVM (first visit downloads ~20 MB, cached after)', 18);
  await initCheerpJ();

  const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const inPath = `/str/in-${id}.jar`;
  const outPath = `/files/ezlarp/out-${id}.zip`;
  cheerpOSAddStringFile(inPath, jarBytes);

  setState(`decompiling with ${ENGINES[engine]}`, 30);
  const stop = watchProgress(total, engine);
  let code;
  try {
    code = await cheerpjRunMain('ezlarp.Run', CLASSPATH, engine, inPath, outPath);
  } finally {
    stop();
  }

  setState('collecting output', 96);
  let blob;
  try {
    blob = await cjFileBlob(outPath);
  } catch (e) {
    throw new Error(`${ENGINES[engine]} produced no output (exit code ${code})`);
  }
  const zip = await JSZip.loadAsync(await blob.arrayBuffer());
  const sources = {};
  for (const f of Object.values(zip.files)) {
    if (!f.dir && f.name.startsWith('src/')) sources[f.name.slice(4)] = await f.async('string');
  }
  const logFile = zip.file('ezlarp/log.txt');
  const log = logFile ? await logFile.async('string') : '';
  if (!Object.keys(sources).length) {
    const tail = log.trim().split('\n').slice(-6).join('\n');
    throw new Error(`${ENGINES[engine]} decompiled 0 classes (exit code ${code})${tail ? '\n' + tail : ''}`);
  }
  return { sources, log, code };
}

// CheerpJ mirrors System.out into #console; the driver prints "EZP <n>" per class.
function watchProgress(total, engine) {
  el.console.textContent = '';
  let last = 0;
  const obs = new MutationObserver(() => {
    const txt = el.console.textContent;
    const i = txt.lastIndexOf('EZP ');
    if (i >= 0) {
      const n = parseInt(txt.slice(i + 4), 10);
      if (n > last) {
        last = n;
        // sources are per top-level class, so `total` (all .class files) overestimates; cap at 95%
        const pct = 30 + Math.min(65, 65 * n / Math.max(1, total * 0.75));
        setState(`decompiling with ${ENGINES[engine]} · ${n} files`, pct);
      }
    }
    if (txt.length > 200000) el.console.textContent = '';
  });
  obs.observe(el.console, { childList: true, characterData: true, subtree: true });
  return () => obs.disconnect();
}

function addResources(info) {
  for (const f of info.resources) {
    if (S.files.has(f.name)) continue;
    S.files.set(f.name, { path: f.name, type: 'res', zipEntry: f, size: f._data && f._data.uncompressedSize || 0 });
  }
}

el.retry.onclick = async () => {
  if (busy || !S.jarBytes) return;
  const other = S.engineUsed === 'vf' ? 'cfr' : 'vf';
  setBusy(true);
  el.err.hidden = true;
  const keepLog = S.log.slice();
  try {
    S.log = keepLog;
    const fb = el.fallback.checked;
    el.fallback.checked = false;
    try { await decompile(other); } finally { el.fallback.checked = fb; }
  } catch (e) {
    showError(e && e.message || String(e));
    setState('error', 100);
    renderResult();
  } finally {
    setBusy(false);
  }
};

// ------------------------------------------------------------------ result rendering

function renderResult() {
  const hasFiles = S.files.size > 0;
  el.result.hidden = false;
  el.rtabs.querySelector('[data-view=source]').hidden = !hasFiles;
  el.rtabs.querySelector('[data-view=strings]').hidden = !S.strings;
  el.dl.hidden = !hasFiles;
  renderDetails();
  renderLog();
  if (S.strings) renderStrings();
  if (hasFiles) {
    renderTree();
    const first = [...S.files.values()].find(f => f.type === 'src') || S.files.values().next().value;
    openFile(first.path);
    showView('source');
  } else {
    showView('details');
  }
}

function showView(v) {
  for (const b of el.rtabs.querySelectorAll('.rtab')) b.classList.toggle('active', b.dataset.view === v);
  for (const p of el.result.querySelectorAll('.view')) p.hidden = p.dataset.view !== v;
}
el.rtabs.addEventListener('click', e => {
  const b = e.target.closest('.rtab');
  if (b) showView(b.dataset.view);
});

// ---- tree / search

function sortedPaths() {
  return [...S.files.keys()].sort((a, b) => {
    const ta = S.files.get(a).type, tb = S.files.get(b).type;
    if (ta !== tb) return ta === 'src' ? -1 : 1;
    return a.localeCompare(b);
  });
}

function buildTree(paths) {
  const root = { dirs: new Map(), files: [] };
  for (const p of paths) {
    const parts = p.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node.dirs.has(parts[i])) node.dirs.set(parts[i], { dirs: new Map(), files: [] });
      node = node.dirs.get(parts[i]);
    }
    node.files.push(p);
  }
  return root;
}
function countFiles(node) {
  let n = node.files.length;
  for (const d of node.dirs.values()) n += countFiles(d);
  return n;
}

function renderTree() {
  el.tree.innerHTML = '';
  const srcCount = [...S.files.values()].filter(f => f.type === 'src').length;
  el.sidefoot.textContent = `${srcCount} sources · ${S.files.size - srcCount} resources`;
  const q = el.q.value.trim();
  if (q && S.qmode === 'files') return renderFileFilter(q);
  if (q && S.qmode === 'code') return renderCodeSearch(q);
  const root = buildTree(sortedPaths());
  const expandAll = S.files.size <= 150;
  renderDir(root, el.tree, 0, expandAll, true);
}

function renderDir(node, container, depth, expandAll, isRoot) {
  const dirNames = [...node.dirs.keys()].sort();
  for (const name of dirNames) {
    // compact single-child chains: com/example/mod
    let label = name, d = node.dirs.get(name);
    while (d.files.length === 0 && d.dirs.size === 1) {
      const [k, v] = d.dirs.entries().next().value;
      label += '/' + k;
      d = v;
    }
    const row = document.createElement('div');
    row.className = 'node dir';
    row.style.paddingLeft = (8 + depth * 14) + 'px';
    row.innerHTML = `<span class="ic">▸</span><span class="nm">${esc(label)}</span><span class="cnt">${countFiles(d)}</span>`;
    const kids = document.createElement('div');
    kids.hidden = true;
    let built = false;
    const toggle = open => {
      if (open && !built) { renderDir(d, kids, depth + 1, expandAll, false); built = true; }
      kids.hidden = !open;
      row.querySelector('.ic').textContent = open ? '▾' : '▸';
    };
    row.onclick = () => toggle(kids.hidden);
    container.appendChild(row);
    container.appendChild(kids);
    if (expandAll || (isRoot && dirNames.length === 1)) toggle(true);
  }
  for (const p of node.files.sort()) container.appendChild(fileRow(p, baseOf(p), depth));
}

function fileRow(path, label, depth, html) {
  const f = S.files.get(path);
  const row = document.createElement('div');
  row.className = 'node' + (S.current === path ? ' active' : '');
  row.dataset.path = path;
  row.style.paddingLeft = (8 + depth * 14) + 'px';
  const icon = f.type === 'src' ? 'J' : '·';
  row.innerHTML = `<span class="ic" style="color:${f.type === 'src' ? 'var(--accent2)' : 'var(--dim)'}">${icon}</span><span class="nm">${html || esc(label)}</span>`;
  row.title = path;
  row.onclick = () => openFile(path);
  return row;
}

function renderFileFilter(q) {
  const ql = q.toLowerCase();
  const hits = sortedPaths().filter(p => p.toLowerCase().includes(ql));
  if (!hits.length) { el.tree.innerHTML = '<div class="empty">no matching files</div>'; return; }
  const frag = document.createDocumentFragment();
  for (const p of hits.slice(0, 3000)) {
    const i = p.toLowerCase().indexOf(ql);
    const html = esc(p.slice(0, i)) + '<mark>' + esc(p.slice(i, i + q.length)) + '</mark>' + esc(p.slice(i + q.length));
    frag.appendChild(fileRow(p, p, 0, html));
  }
  el.tree.appendChild(frag);
  el.sidefoot.textContent = `${hits.length} matching files`;
}

function renderCodeSearch(q) {
  if (q.length < 2) { el.tree.innerHTML = '<div class="empty">type at least 2 characters</div>'; return; }
  const ql = q.toLowerCase();
  const frag = document.createDocumentFragment();
  let hits = 0, filesHit = 0;
  outer: for (const p of sortedPaths()) {
    const f = S.files.get(p);
    if (f.type !== 'src') continue;
    const lower = f.text.toLowerCase();
    let idx = lower.indexOf(ql);
    if (idx < 0) continue;
    filesHit++;
    while (idx >= 0) {
      const lineNo = countLines(f.text, idx);
      const ls = f.text.lastIndexOf('\n', idx - 1) + 1;
      let le = f.text.indexOf('\n', idx); if (le < 0) le = f.text.length;
      const line = f.text.slice(ls, le);
      const col = idx - ls;
      const div = document.createElement('div');
      div.className = 'hit';
      const snipStart = Math.max(0, col - 40);
      div.innerHTML = `<div class="hp">${esc(p)}:${lineNo}</div><div class="hl">${esc(line.slice(snipStart, col).trimStart())}<mark>${esc(line.slice(col, col + q.length))}</mark>${esc(line.slice(col + q.length, col + q.length + 80))}</div>`;
      div.onclick = () => openFile(p, lineNo);
      frag.appendChild(div);
      if (++hits >= 1000) break outer;
      idx = lower.indexOf(ql, le);
    }
  }
  if (!hits) { el.tree.innerHTML = '<div class="empty">no matches in decompiled code</div>'; return; }
  el.tree.appendChild(frag);
  el.sidefoot.textContent = `${hits}${hits >= 1000 ? '+' : ''} matches in ${filesHit} files`;
}

function countLines(text, upto) {
  let n = 1;
  for (let i = text.indexOf('\n'); i >= 0 && i < upto; i = text.indexOf('\n', i + 1)) n++;
  return n;
}

let searchTimer = 0;
el.q.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(renderTree, S.qmode === 'code' ? 250 : 60);
});
el.qmode.addEventListener('click', e => {
  const b = e.target.closest('button');
  if (!b) return;
  S.qmode = b.dataset.m;
  for (const x of el.qmode.children) x.classList.toggle('on', x === b);
  el.q.placeholder = S.qmode === 'code' ? 'search decompiled code' : 'filter files';
  el.q.focus();
  renderTree();
});

// ---- viewer

async function openFile(path, line) {
  const f = S.files.get(path);
  if (!f) return;
  S.current = path;
  for (const n of el.tree.querySelectorAll('.node.active')) n.classList.remove('active');
  const row = el.tree.querySelector(`.node[data-path="${CSS.escape(path)}"]`);
  if (row) row.classList.add('active');
  el.cpath.textContent = path;

  if (f.type === 'res' && f.text == null && !f.bytes) {
    f.bytes = await f.zipEntry.async('uint8array');
    f.size = f.bytes.length;
    if (isProbablyText(f.bytes) && f.bytes.length < 4 * 1024 * 1024) f.text = new TextDecoder().decode(f.bytes);
  }

  let text;
  if (f.text != null) {
    text = f.text;
    const lines = text.split('\n').length;
    el.cmeta.textContent = `${lines} lines · ${human(new Blob([text]).size)}${f.type === 'src' ? ' · ' + ENGINES[S.engineUsed] : ''}`;
    renderCode(text, ext(path));
  } else {
    el.cmeta.textContent = `binary · ${human(f.size)}`;
    text = hexDump(f.bytes.subarray(0, 4096)) + (f.size > 4096 ? `\n… ${human(f.size - 4096)} more (download to see all)` : '');
    renderCode(text, '');
  }
  if (line) scrollToLine(line); else el.codebox.scrollTop = 0;
}

function renderCode(text, extension) {
  const n = text.split('\n').length;
  let g = '';
  for (let i = 1; i <= n; i++) g += i + '\n';
  el.gutter.textContent = g;
  const lang = LANGS[extension];
  if (window.hljs && lang && lang !== 'plaintext' && hljs.getLanguage(lang) && text.length <= MAX_HIGHLIGHT) {
    try {
      el.code.innerHTML = hljs.highlight(text, { language: lang, ignoreIllegals: true }).value;
      return;
    } catch (e) { /* fall through */ }
  }
  el.code.textContent = text;
}

function scrollToLine(line) {
  const lh = parseFloat(getComputedStyle(el.code.parentElement).lineHeight) || 19;
  const top = 14 + (line - 1) * lh;
  el.codebox.scrollTop = Math.max(0, top - el.codebox.clientHeight / 3);
  let flash = el.codebox.querySelector('.flash');
  if (!flash) {
    flash = document.createElement('div');
    flash.className = 'flash';
    flash.style.cssText = 'position:absolute;left:0;right:0;pointer-events:none;background:rgba(122,240,161,.13);transition:opacity 1.2s';
    el.codebox.style.position = 'relative';
    el.codebox.appendChild(flash);
  }
  flash.style.top = top + 'px';
  flash.style.height = lh + 'px';
  flash.style.width = el.codebox.scrollWidth + 'px';
  flash.style.opacity = '1';
  clearTimeout(flash._t);
  flash._t = setTimeout(() => { flash.style.opacity = '0'; }, 1600);
}

function hexDump(u8) {
  let out = '';
  for (let i = 0; i < u8.length; i += 16) {
    const row = u8.subarray(i, i + 16);
    const h = [...row].map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47);
    const a = [...row].map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
    out += i.toString(16).padStart(8, '0') + '  ' + h + '  ' + a + '\n';
  }
  return out;
}

el.wrap.onclick = () => el.codebox.classList.toggle('wrap');

el.copy.onclick = async () => {
  const f = S.files.get(S.current);
  if (!f || f.text == null) return;
  try {
    await navigator.clipboard.writeText(f.text);
    flashBtn(el.copy, 'copied');
  } catch (e) {
    const r = document.createRange();
    r.selectNodeContents(el.code);
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
    flashBtn(el.copy, 'selected — ctrl+c');
  }
};
function flashBtn(b, text) {
  const old = b.dataset.label || b.textContent;
  b.dataset.label = old;
  b.textContent = text;
  b.classList.add('ok');
  setTimeout(() => { b.textContent = old; b.classList.remove('ok'); }, 1400);
}

el.dlone.onclick = async () => {
  const f = S.files.get(S.current);
  if (!f) return;
  if (f.text != null) download(baseOf(f.path), f.text, 'text/plain');
  else download(baseOf(f.path), f.bytes || await f.zipEntry.async('uint8array'));
};

el.dl.onclick = async () => {
  if (!S.files.size) return;
  const old = el.dl.textContent;
  el.dl.textContent = 'zipping…';
  try {
    const zip = new JSZip();
    for (const f of S.files.values()) {
      if (f.type === 'src') zip.file(f.path, f.text);
      else zip.file(f.path, f.bytes || await f.zipEntry.async('uint8array'));
    }
    const blob = await zip.generateAsync({ type: 'blob', compression: 'DEFLATE', compressionOptions: { level: 6 } });
    download(`${S.baseName}-src.zip`, blob);
  } finally {
    el.dl.textContent = old;
  }
};

el.fhash.onclick = async () => {
  const h = el.fhash.textContent;
  if (!/^[0-9a-f]{64}$/.test(h)) return;
  try { await navigator.clipboard.writeText(h); el.fhash.textContent = 'copied'; setTimeout(() => { el.fhash.textContent = h; }, 1000); } catch (e) {}
};

// ---- details

function kv(rows) {
  return '<div class="kv">' + rows.filter(r => r && r[1] != null && r[1] !== '')
    .map(([k, v]) => `<div>${esc(k)}</div><div>${v}</div>`).join('') + '</div>';
}

function renderDetails() {
  let h = '';
  if (S.pe) h += peDetails();
  if (S.jarInfo) h += jarDetails();
  el.details.innerHTML = h || '<div class="empty">no details</div>';
}

function jarDetails() {
  const j = S.jarInfo;
  let h = `<section><h3>${S.embedded ? 'EMBEDDED JAVA ARCHIVE' : 'JAVA ARCHIVE'}</h3>`;
  if (S.embedded) h += `<div class="note" style="margin-bottom:10px">Found a jar inside the executable at offset <b>${hex(S.embedded.offset)}</b> (${human(S.embedded.size)}). The exe is just a launcher; the real program is this jar, decompiled under SOURCE.</div>`;
  h += kv([
    ['classes', j.classCount],
    ['source files', S.engineUsed ? [...S.files.values()].filter(f => f.type === 'src').length : '—'],
    ['resources', j.resources.length],
    ['bytecode target', esc(versionSummary(j.versions) || '—') + (j.classCount > 300 ? ' <span class="meta">(sampled)</span>' : '')],
    ['main class', j.mainClass ? esc(j.mainClass.trim()) : null],
    ['detected', j.kinds.length ? esc(j.kinds.join(', ')) : null],
    ['multi-release', j.multiRelease ? 'yes' : null],
    ['nested jars', j.nested || null],
    ['engine', S.engineUsed ? esc(ENGINES[S.engineUsed]) + ` · ${S.seconds.toFixed(1)}s` : null],
  ]);
  h += '</section>';
  if (j.manifest.trim()) h += `<section><h3>MANIFEST</h3><pre class="note" style="white-space:pre-wrap;margin:0">${esc(j.manifest.trim())}</pre></section>`;
  return h;
}

function peDetails() {
  const p = S.pe;
  if (!p.ok) return `<section><h3>EXECUTABLE</h3><div class="note">Starts with MZ but the PE header could not be parsed${p.error ? ': ' + esc(p.error) : ''}.</div></section>`;
  const ts = p.timestamp;
  const date = ts && ts < 0x7fffffff ? new Date(ts * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : null;
  let h = '<section><h3>PORTABLE EXECUTABLE</h3>';
  if (!S.jarBytes) {
    h += `<div class="note" style="margin-bottom:10px">${p.dotnet
      ? '<b>.NET assembly.</b> Contains CIL bytecode, not Java. Use ILSpy or dnSpy to decompile it to C#.'
      : '<b>Native executable.</b> Machine code can\'t be turned back into Java or readable source here. Use the sections, imports and strings below to see what it does.'}</div>`;
  }
  h += kv([
    ['format', `${p.format} ${p.isDll ? 'DLL' : 'executable'}`],
    ['machine', esc(Inspect.MACHINES[p.machine] || hex(p.machine, 4))],
    ['subsystem', esc(Inspect.SUBSYSTEMS[p.subsystem] || p.subsystem)],
    ['compile timestamp', date ? esc(date) : `${hex(ts)} (zeroed or reproducible build)`],
    ['linker', p.linker],
    ['entry point', hex(p.entryPoint)],
    ['image base', '0x' + p.imageBase.toString(16).toUpperCase()],
    ['ASLR / DEP', `${p.dllCharacteristics & 0x40 ? 'ASLR' : 'no ASLR'} · ${p.dllCharacteristics & 0x100 ? 'DEP' : 'no DEP'}`],
    ['signature blob', p.signed ? 'present (not verified)' : 'none'],
    ['overlay', p.overlay ? `${human(p.overlay.size)} at ${hex(p.overlay.offset)}` : 'none'],
    ['.NET runtime', p.dotnet ? esc((p.dotnet.version || '') + ' · CLR ' + (p.dotnet.runtime || '?') + (p.dotnet.ilOnly ? ' · IL only' : ' · mixed mode')) : null],
    ['export name', p.exportName ? esc(p.exportName) : null],
    ['detected', S.sigs.length ? esc(S.sigs.map(s => s.label).join(', ')) : 'nothing recognized'],
  ]);
  h += '</section>';

  if (p.sections.length) {
    h += '<section><h3>SECTIONS</h3><table class="t"><tr><th>name</th><th>virtual addr</th><th>virtual size</th><th>raw size</th><th>entropy</th><th>flags</th></tr>';
    for (const s of p.sections) {
      h += `<tr><td>${esc(s.name)}</td><td>${hex(s.va)}</td><td>${human(s.vsize)}</td><td>${human(s.rawSize)}</td>` +
        `<td class="${s.entropy > 7.2 ? 'ent-hi' : ''}" title="${s.entropy > 7.2 ? 'high entropy: likely packed or encrypted' : ''}">${s.entropy.toFixed(2)}</td><td>${s.flags}</td></tr>`;
    }
    h += '</table></section>';
  }

  if (p.imports.length) {
    const total = p.imports.reduce((a, i) => a + i.funcs.length, 0);
    h += `<section><h3>IMPORTS · ${p.imports.length} DLLS · ${total} FUNCTIONS</h3>`;
    for (const imp of p.imports) {
      h += `<details class="imp"><summary>${esc(imp.dll)}<span>${imp.funcs.length}</span></summary><div class="fn">${imp.funcs.map(esc).join('<br>')}</div></details>`;
    }
    h += '</section>';
  }
  if (p.exports.length) {
    h += `<section><h3>EXPORTS · ${p.exports.length}</h3><div class="imp"><div class="fn" style="padding-left:0">${p.exports.slice(0, 1000).map(esc).join('<br>')}</div></div></section>`;
  }
  return h;
}

// ---- strings

function renderStrings() {
  const q = el.sq.value.trim().toLowerCase();
  const kind = el.skind.value;
  const rows = [];
  let shown = 0, matched = 0;
  for (const s of S.strings) {
    if (q && !s.s.toLowerCase().includes(q)) continue;
    const k = Inspect.classifyString(s.s);
    if (kind && k !== kind) continue;
    matched++;
    if (shown >= 3000) continue;
    shown++;
    let body = esc(s.s.length > 400 ? s.s.slice(0, 400) + '…' : s.s);
    if (q) body = body.replace(new RegExp(esc(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), m => `<mark>${m}</mark>`);
    rows.push(`<div class="srow ${k}"><span class="o">${s.off.toString(16).padStart(8, '0')}</span><span class="e">${s.enc}</span><span class="s">${body}</span></div>`);
  }
  el.strings.innerHTML = rows.join('') || '<div class="empty">no strings match</div>';
  el.scount.textContent = matched > shown ? `showing ${shown} of ${matched}` : `${matched} strings`;
}
let strTimer = 0;
el.sq.addEventListener('input', () => { clearTimeout(strTimer); strTimer = setTimeout(renderStrings, 150); });
el.skind.addEventListener('change', renderStrings);

// ---- log

function renderLog() {
  el.logbox.textContent = S.log.length ? S.log.join('\n\n') : 'no warnings';
}
