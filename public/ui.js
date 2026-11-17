// EZLARP UI: shared state, rendering, viewer, tree, search, scan/details views.
// The analysis flow and the Java engines live in app.js.
'use strict';

const $ = id => document.getElementById(id);

const ENGINES = { vf: 'Vineflower 1.12.0', cfr: 'CFR 0.152' };
const MAX_HIGHLIGHT = 400 * 1024;
const LANGS = {
  java: 'java', kt: 'kotlin', groovy: 'groovy', json: 'json', mcmeta: 'json', xml: 'xml', html: 'xml', fxml: 'xml', svg: 'xml',
  yml: 'yaml', yaml: 'yaml', properties: 'ini', mf: 'ini', cfg: 'ini', toml: 'ini', ini: 'ini', lang: 'ini',
  js: 'javascript', css: 'css', sql: 'sql', md: 'markdown', sh: 'bash', bat: 'dos', cmd: 'dos', ps1: 'powershell',
  py: 'python', lua: 'lua', glsl: 'glsl', vsh: 'glsl', fsh: 'glsl', txt: 'plaintext'
};
const IMG_RE = /\.(png|jpe?g|gif|webp|bmp|ico)$/i;
const ARCHIVE_RE = /\.(jar|apk|zip|war|ear|aar|xapk|mrpack)$/i;
const NATIVE_FILE_RE = /\.(dll|exe|so|dylib|jnilib|sys)$/i;
const SEV_RANK = { high: 3, med: 2, low: 1, info: 0, none: 0 };

const el = {};
for (const id of ['drop', 'file', 'pick', 'engine', 'fallback', 'rename', 'status', 'ficon', 'verdict', 'fname', 'fsize', 'ftype',
  'fstate', 'fmd5', 'fsha1', 'fhash', 'vt', 'ftags', 'fill', 'err', 'result', 'rtabs', 'scandot', 'decall', 'retry', 'report', 'dl',
  'banner', 'q', 'qmode', 'tree', 'sidefoot', 'ftabs', 'cpath', 'cmeta', 'outline', 'openjar', 'bc', 'wrap', 'copy', 'dlone',
  'codebox', 'gutter', 'code', 'preview', 'usages', 'urlform', 'url', 'cmp', 'cmpfile', 'cmpview', 'recent', 'recentlist', 'clearhist', 'scan', 'details', 'sq', 'skind', 'scount', 'strings', 'logbox', 'overlay', 'console']) {
  el[id] = $(id);
}

let busy = false;
let S = freshState();
const stack = []; // parent analyses while a nested archive is open

function freshState() {
  return {
    name: '', baseName: '', kind: '', size: 0, hashes: {},
    jarBytes: null, jarInfo: null, jarPath: null, resZip: null, apk: null, dex: null, cls: null,
    pe: null, sigs: [], py: null, embedded: null, strings: null, icon: null,
    scan: null, scanRes: null, cpStrings: new Map(), xrefs: new Map(), usagesOf: null, batch: null, classToSrc: new Map(), simpleIndex: new Map(), srcFlags: new Map(),
    entrypoints: new Set(), files: new Map(), lazy: false, engine: 'vf', engineUsed: '', current: null, tabs: [],
    qmode: 'files', log: [], seconds: 0
  };
}

// ------------------------------------------------------------------ helpers

function human(b) {
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b < 10 && i ? 2 : 0) + ' ' + u[i];
}
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const hex = (n, w = 8) => '0x' + n.toString(16).toUpperCase().padStart(w, '0');
const ext = p => { const m = /\.([^./]+)$/.exec(p); return m ? m[1].toLowerCase() : ''; };
const baseOf = p => p.slice(p.lastIndexOf('/') + 1);
const dots = s => s.replace(/\//g, '.');
const plural = (n, w) => `${n} ${n === 1 ? w : /(?:s|x|ch|sh)$/.test(w) ? w + 'es' : w + 's'}`;

function setState(text, pct) {
  el.fstate.textContent = text;
  el.fstate.title = text;
  if (pct != null) el.fill.style.width = pct + '%';
}
function setBusy(on) {
  busy = on;
  el.fill.parentElement.classList.toggle('busy', on);
}
function tag(label, cls = '', title = '') {
  const t = document.createElement('span');
  t.className = 'tagx ' + cls;
  t.textContent = label;
  if (title) t.title = title;
  el.ftags.appendChild(t);
}
function showError(msg) {
  el.err.textContent = '[error] ' + msg;
  el.err.hidden = false;
}
function toast(msg, ms = 1800) {
  const t = document.createElement('div');
  t.className = 'toast';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), ms);
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
function flashBtn(b, text) {
  const old = b.dataset.label || b.textContent;
  b.dataset.label = old;
  b.textContent = text;
  b.classList.add('ok');
  setTimeout(() => { b.textContent = old; b.classList.remove('ok'); }, 1400);
}
async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) flashBtn(btn, 'copied'); else toast('copied');
  } catch (e) {
    toast('clipboard blocked — select and press ctrl+c');
  }
}
function kv(rows) {
  return '<div class="kv">' + rows.filter(r => r && r[1] != null && r[1] !== '')
    .map(([k, v]) => `<div>${esc(k)}</div><div>${v}</div>`).join('') + '</div>';
}
const section = (title, body) => `<section><h3>${esc(title)}</h3>${body}</section>`;

// source path for an internal class name (inner classes live in their outer file)
function srcPathOf(entryOrInternal) {
  const base = entryOrInternal.replace(/\.class$/i, '');
  const slash = base.lastIndexOf('/');
  const simple = base.slice(slash + 1);
  const d = simple.indexOf('$');
  return base.slice(0, slash + 1) + (d > 0 ? simple.slice(0, d) : simple) + '.java';
}
function fileForClass(internal) {
  const p = S.classToSrc.get(internal);
  if (p && S.files.has(p)) return p;
  const alt = srcPathOf(internal);
  return S.files.has(alt) ? alt : null;
}

// ------------------------------------------------------------------ result shell

function renderResult() {
  const hasFiles = S.files.size > 0;
  el.result.hidden = false;
  el.rtabs.querySelector('[data-view=source]').hidden = !hasFiles;
  el.rtabs.querySelector('[data-view=strings]').hidden = !S.strings;
  el.rtabs.querySelector('[data-view=scan]').hidden = !S.scan && !S.batch;
  el.report.hidden = !!S.batch;
  el.dl.hidden = !hasFiles;
  el.decall.hidden = !(S.lazy && pendingCount() > 0);
  el.cmp.hidden = !S.jarInfo || !S.jarInfo.classCount;
  el.rtabs.querySelector('[data-view=compare]').hidden = !S.cmp;
  renderVerdict();
  renderBanner();
  renderDetails();
  renderScan();
  renderLog();
  if (S.strings) renderStrings();
  if (hasFiles) {
    renderTree();
    if (!S.current || !S.files.has(S.current)) {
      S.tabs = [];
      openFile(pickFirstFile());
    } else {
      openFile(S.current);
    }
    const onlyNested = S.jarInfo && !S.jarInfo.classCount && S.nestedRows && S.nestedRows.length;
    showView(S.mrpack ? 'details' : onlyNested ? 'scan' : 'source');
  } else {
    showView(S.mrpack ? 'details' : S.batch || (S.scan && S.scan.level !== 'none') ? 'scan' : 'details');
  }
}

function pickFirstFile() {
  const paths = sortedPaths();
  for (const ep of S.entrypoints) { const p = fileForClass(ep); if (p) return p; }
  if (S.jarInfo && S.jarInfo.mainClass) {
    const p = fileForClass(S.jarInfo.mainClass.trim().replace(/\./g, '/'));
    if (p) return p;
  }
  const isLib = p => LIB_PREFIX.some(pre => p.startsWith(pre));
  if (S.apk && S.apk.pkg) { const own = S.apk.pkg.replace(/\./g, '/') + '/'; const p = paths.find(x => x.startsWith(own) && S.files.get(x).type === 'src'); if (p) return p; }
  return paths.find(p => S.files.get(p).type !== 'res' && !isLib(p)) || paths.find(p => S.files.get(p).type !== 'res') || paths[0];
}
const LIB_PREFIX = ['android/', 'androidx/', 'kotlin/', 'kotlinx/', 'com/google/', 'org/apache/', 'org/slf4j/', 'okhttp3/', 'okio/', 'com/fasterxml/', 'io/netty/',
  'org/jetbrains/', 'javax/', 'org/intellij/', 'com/squareup/', 'io/reactivex/', 'org/json/', 'net/kyori/', 'org/objectweb/', 'org/spongepowered/', '(pyinstaller)/'];

function pendingCount() {
  let n = 0;
  for (const f of S.files.values()) if (f.type === 'src' && f.text == null && !f.error) n++;
  return n;
}

function showView(v) {
  for (const b of el.rtabs.querySelectorAll('.rtab')) b.classList.toggle('active', b.dataset.view === v);
  for (const p of el.result.querySelectorAll('.view')) p.hidden = p.dataset.view !== v;
}
el.rtabs.addEventListener('click', e => {
  const b = e.target.closest('.rtab');
  if (b) showView(b.dataset.view);
});

function renderVerdict() {
  const v = el.verdict;
  if (S.batch) {
    const worst = ['high', 'med', 'low', 'none'].find(l => S.batch.some(r => r.level === l)) || 'none';
    const n = S.batch.filter(r => r.level === worst).length;
    v.hidden = false;
    v.className = 'verdict ' + worst;
    v.innerHTML = `<div class="n">${worst === 'none' ? '✓' : n}</div><div class="l">${worst === 'none' ? 'no indicators in ' + plural(S.batch.length, 'file') : `of ${S.batch.length} files ${worst === 'high' ? 'high risk' : worst === 'med' ? 'to review' : 'minor'}`}</div>`;
    v.onclick = () => showView('scan');
    el.scandot.hidden = false;
    el.scandot.className = 'dot ' + worst;
    return;
  }
  if (!S.scan) { v.hidden = true; el.scandot.hidden = true; return; }
  const sc = S.scan;
  const n = sc.level === 'high' ? sc.count.high : sc.level === 'med' ? sc.count.med : sc.count.low;
  const label = { high: plural(n, 'high-risk indicator').replace(/^\d+ /, ''), med: n === 1 ? 'indicator to review' : 'indicators to review', low: n === 1 ? 'minor indicator' : 'minor indicators', none: 'no known indicators' }[sc.level];
  v.hidden = false;
  v.className = 'verdict ' + sc.level;
  v.innerHTML = `<div class="n">${sc.level === 'none' ? '✓' : n}</div><div class="l">${esc(label)}</div>`;
  v.title = `${sc.rulesHit} of ${sc.rulesTotal} indicator rules matched. Click for details.`;
  v.onclick = () => showView('scan');
  el.scandot.hidden = false;
  el.scandot.className = 'dot ' + sc.level;
}

function renderBanner() {
  const b = el.banner;
  const parts = [];
  if (stack.length) {
    const crumbs = stack.map((s, i) => `<a data-up="${stack.length - i}">${esc(s.name)}</a>`).join(' › ');
    parts.push(`<span class="crumbs">${crumbs} › <b>${esc(S.name)}</b></span>`);
  }
  const pend = pendingCount();
  if (S.lazy && pend) {
    parts.push(`<span>large archive: classes decompile when you open them (${pend} not decompiled yet). Code search covers decompiled files; the <b>strings</b> search covers every class.</span>`);
  }
  b.hidden = !parts.length;
  b.className = 'banner' + (stack.length && !(S.lazy && pend) ? ' info' : '');
  b.innerHTML = parts.join('');
  for (const a of b.querySelectorAll('[data-up]')) a.onclick = () => goUp(+a.dataset.up);
}

// ------------------------------------------------------------------ tree

const TYPE_RANK = { src: 0, py: 0, res: 1 };
function sortedPaths() {
  return [...S.files.keys()].filter(k => !S.files.get(k).virtual).sort((a, b) => {
    const ra = TYPE_RANK[S.files.get(a).type] || 0, rb = TYPE_RANK[S.files.get(b).type] || 0;
    if (ra !== rb) return ra - rb;
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

function updateFoot() {
  const files = [...S.files.values()];
  const real = files.filter(f => !f.virtual);
  const py = real.filter(f => f.type === 'py').length;
  const srcCount = real.filter(f => f.type === 'src').length;
  const done = real.filter(f => f.type === 'src' && f.text != null).length;
  el.sidefoot.textContent = py ? `${py} Python modules · ${real.length - py} other` :
    `${srcCount} sources${S.lazy ? ` (${done} decompiled)` : ''} · ${real.length - srcCount} resources`;
}

function renderTree() {
  el.tree.innerHTML = '';
  updateFoot();
  const q = el.q.value.trim();
  if (!q && S.usagesOf) return renderUsages(S.usagesOf);
  if (q && S.qmode === 'files') return renderFileFilter(q);
  if (q && S.qmode === 'code') return renderCodeSearch(q);
  if (q && S.qmode === 'strings') return renderConstSearch(q);
  if (!q && S.qmode !== 'files') {
    el.tree.innerHTML = `<div class="empty">${S.qmode === 'code'
      ? 'search the decompiled source of every file' + (S.lazy ? ' that has been decompiled' : '')
      : 'search string constants in every class (urls, messages, keys...) without decompiling'}</div>`;
    return;
  }
  const root = buildTree(sortedPaths());
  renderDir(root, el.tree, 0, S.files.size <= 150, true, '');
}

function renderDir(node, container, depth, expandAll, isRoot, prefix) {
  const dirNames = [...node.dirs.keys()].sort();
  for (const name of dirNames) {
    let label = name, d = node.dirs.get(name);
    while (d.files.length === 0 && d.dirs.size === 1) {
      const [k, v] = d.dirs.entries().next().value;
      label += '/' + k;
      d = v;
    }
    const full = prefix + label + '/';
    const row = document.createElement('div');
    row.className = 'node dir';
    row.style.paddingLeft = (8 + depth * 14) + 'px';
    row.innerHTML = `<span class="ic">▸</span><span class="nm">${esc(label)}</span><span class="cnt">${countFiles(d)}</span>`;
    const kids = document.createElement('div');
    kids.hidden = true;
    let built = false;
    const toggle = open => {
      if (open && !built) { renderDir(d, kids, depth + 1, expandAll, false, full); built = true; }
      kids.hidden = !open;
      row.querySelector('.ic').textContent = open ? '▾' : '▸';
    };
    row.onclick = () => toggle(kids.hidden);
    container.appendChild(row);
    container.appendChild(kids);
    if (expandAll || (isRoot && dirNames.length === 1) || (S.current && S.current.startsWith(full))) toggle(true);
  }
  for (const p of node.files.sort()) container.appendChild(fileRow(p, baseOf(p), depth));
}

function fileRow(path, label, depth, html) {
  const f = S.files.get(path);
  const row = document.createElement('div');
  const flag = S.srcFlags.get(path);
  row.className = 'node' + (S.current === path ? ' active' : '') + (f.type === 'src' && f.text == null ? ' pending' : '') +
    (flag === 'high' ? ' flag' : flag === 'med' ? ' flag-med' : '');
  row.dataset.path = path;
  row.style.paddingLeft = (8 + depth * 14) + 'px';
  const icon = f.type === 'src' ? 'J' : f.type === 'py' ? 'P' : ARCHIVE_RE.test(path) ? '⧉' : NATIVE_FILE_RE.test(path) ? '⚙' : IMG_RE.test(path) ? '▣' : '·';
  const color = f.type === 'src' || f.type === 'py' ? 'var(--accent2)' : ARCHIVE_RE.test(path) || NATIVE_FILE_RE.test(path) ? 'var(--warn)' : 'var(--dim)';
  const star = f.entry ? '<span class="star" title="entrypoint">★</span>' : '';
  row.innerHTML = `<span class="ic" style="color:${color}">${icon}</span><span class="nm">${html || esc(label)}</span>${star}`;
  row.title = path + (f.type === 'src' && f.text == null ? ' (not decompiled yet)' : '');
  row.onclick = () => openFile(path);
  return row;
}

function markTree() {
  for (const n of el.tree.querySelectorAll('.node.active')) n.classList.remove('active');
  const row = el.tree.querySelector(`.node[data-path="${CSS.escape(S.current || '')}"]`);
  if (row) {
    row.classList.add('active');
    const f = S.files.get(S.current);
    if (f && f.text != null) row.classList.remove('pending');
  }
}

function hl(text, q, start) {
  return esc(text.slice(0, start)) + '<mark>' + esc(text.slice(start, start + q.length)) + '</mark>' + esc(text.slice(start + q.length));
}

function renderFileFilter(q) {
  const ql = q.toLowerCase();
  const hits = sortedPaths().filter(p => p.toLowerCase().includes(ql));
  if (!hits.length) { el.tree.innerHTML = '<div class="empty">no matching files</div>'; return; }
  const frag = document.createDocumentFragment();
  for (const p of hits.slice(0, 3000)) frag.appendChild(fileRow(p, p, 0, hl(p, q, p.toLowerCase().indexOf(ql))));
  el.tree.appendChild(frag);
  el.sidefoot.textContent = `${hits.length} matching files`;
}

function countLines(text, upto) {
  let n = 1;
  for (let i = text.indexOf('\n'); i >= 0 && i < upto; i = text.indexOf('\n', i + 1)) n++;
  return n;
}

function hitRow(title, snippetHtml, onclick) {
  const div = document.createElement('div');
  div.className = 'hit';
  div.innerHTML = `<div class="hp">${title}</div><div class="hl">${snippetHtml}</div>`;
  div.onclick = onclick;
  return div;
}

function renderCodeSearch(q) {
  if (q.length < 2) { el.tree.innerHTML = '<div class="empty">type at least 2 characters</div>'; return; }
  let re = null;
  if (q.length > 2 && q.startsWith('/') && q.endsWith('/')) {
    try { re = new RegExp(q.slice(1, -1), 'gi'); } catch (e) { el.tree.innerHTML = `<div class="empty">bad regex: ${esc(e.message)}</div>`; return; }
  }
  const ql = q.toLowerCase();
  const frag = document.createDocumentFragment();
  let hits = 0, filesHit = 0, searched = 0;
  outer: for (const p of sortedPaths()) {
    const f = S.files.get(p);
    if (f.text == null) continue;
    searched++;
    const matches = [];
    if (re) {
      re.lastIndex = 0;
      for (let m; (m = re.exec(f.text)) && matches.length < 200;) { matches.push([m.index, m[0].length || 1]); if (!m[0].length) re.lastIndex++; }
    } else {
      const lower = f.text.toLowerCase();
      for (let i = lower.indexOf(ql); i >= 0 && matches.length < 200; i = lower.indexOf(ql, i + ql.length)) matches.push([i, q.length]);
    }
    if (!matches.length) continue;
    filesHit++;
    let lastLine = -1;
    for (const [idx, len] of matches) {
      const lineNo = countLines(f.text, idx);
      if (lineNo === lastLine) continue;
      lastLine = lineNo;
      const ls = f.text.lastIndexOf('\n', idx - 1) + 1;
      let le = f.text.indexOf('\n', idx); if (le < 0) le = f.text.length;
      const line = f.text.slice(ls, le);
      const col = idx - ls;
      const a = Math.max(0, col - 40);
      const snip = esc(line.slice(a, col).trimStart()) + '<mark>' + esc(line.slice(col, col + len)) + '</mark>' + esc(line.slice(col + len, col + len + 80));
      frag.appendChild(hitRow(`${esc(p)}:${lineNo}`, snip, () => openFile(p, { line: lineNo })));
      if (++hits >= 1500) break outer;
    }
  }
  if (!hits) {
    el.tree.innerHTML = `<div class="empty">no matches in decompiled code${S.lazy && pendingCount() ? `<br><br>${pendingCount()} classes aren't decompiled yet. Try the <b>strings</b> search or <b>decompile all</b>.` : ''}</div>`;
    return;
  }
  el.tree.appendChild(frag);
  el.sidefoot.textContent = `${hits}${hits >= 1500 ? '+' : ''} matches in ${filesHit} files${S.lazy ? ` (searched ${searched} decompiled)` : ''}`;
}

function renderConstSearch(q) {
  if (!S.cpStrings.size) { el.tree.innerHTML = '<div class="empty">no class constants indexed</div>'; return; }
  const ql = q.toLowerCase();
  const frag = document.createDocumentFragment();
  let hits = 0;
  outer: for (const [cls, strs] of S.cpStrings) {
    for (const s of strs) {
      const i = s.toLowerCase().indexOf(ql);
      if (i < 0) continue;
      const a = Math.max(0, i - 30);
      const snip = esc(s.slice(a, i)) + '<mark>' + esc(s.slice(i, i + q.length)) + '</mark>' + esc(s.slice(i + q.length, i + q.length + 90));
      frag.appendChild(hitRow(esc(dots(cls)), '"' + snip + '"', () => openClass(cls, s)));
      if (++hits >= 1500) break outer;
    }
  }
  if (!hits) { el.tree.innerHTML = '<div class="empty">no string constant matches</div>'; return; }
  el.tree.appendChild(frag);
  el.sidefoot.textContent = `${hits}${hits >= 1500 ? '+' : ''} string constants`;
}

// classes (by constant pool) that reference any class in the given source file
function usagesOf(path) {
  const own = new Set();
  for (const [internal, p] of S.classToSrc) if (p === path) own.add(internal);
  const users = new Map();
  for (const c of own) for (const u of S.xrefs.get(c) || []) if (!own.has(u)) {
    if (!users.has(u)) users.set(u, new Set());
    users.get(u).add(c);
  }
  return users;
}
function renderUsages(path) {
  const users = usagesOf(path);
  el.tree.innerHTML = '';
  const head = document.createElement('div');
  head.className = 'usage-head';
  head.innerHTML = `<span>usages of <b>${esc(baseOf(path).replace(/\.java$/, ''))}</b> · ${users.size}</span><a>close</a>`;
  head.querySelector('a').onclick = () => { S.usagesOf = null; renderTree(); };
  el.tree.appendChild(head);
  if (!users.size) { el.tree.insertAdjacentHTML('beforeend', '<div class="empty">no other class in this archive references it</div>'); return; }
  const frag = document.createDocumentFragment();
  for (const [u, targets] of [...users.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const t = [...targets][0];
    const simple = t.slice(t.lastIndexOf('/') + 1).split('$').pop();
    frag.appendChild(hitRow(esc(dots(u)), 'uses ' + esc([...targets].map(x => dots(x).slice(dots(x).lastIndexOf('.') + 1)).join(', ')), () => openClass(u, simple)));
  }
  el.tree.appendChild(frag);
  el.sidefoot.textContent = `${users.size} referencing classes`;
}
el.usages.onclick = () => {
  if (!S.current) return;
  S.usagesOf = S.current;
  el.q.value = '';
  showView('source');
  renderTree();
};

let searchTimer = 0;
el.q.addEventListener('input', () => {
  S.usagesOf = null;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(renderTree, S.qmode === 'files' ? 60 : 250);
});
el.q.addEventListener('keydown', e => {
  if (e.key === 'Escape') { el.q.value = ''; renderTree(); }
  if (e.key === 'Enter') { const first = el.tree.querySelector('.node:not(.dir), .hit'); if (first) first.click(); }
});
function setQMode(m, focus = true) {
  S.qmode = m;
  for (const x of el.qmode.children) x.classList.toggle('on', x.dataset.m === m);
  el.q.placeholder = { files: 'filter files', code: 'search code (/regex/ ok)', strings: 'search string constants' }[m];
  if (focus) el.q.focus();
  renderTree();
}
el.qmode.addEventListener('click', e => { const b = e.target.closest('button'); if (b) setQMode(b.dataset.m); });

// ------------------------------------------------------------------ viewer

function renderTabs() {
  el.ftabs.innerHTML = '';
  for (const p of S.tabs) {
    const t = document.createElement('div');
    t.className = 'ftab' + (p === S.current ? ' active' : '');
    t.title = p;
    t.innerHTML = `<span>${esc(baseOf(p))}</span><b class="x" title="close">×</b>`;
    t.onclick = e => {
      if (e.target.classList.contains('x')) closeTab(p);
      else openFile(p);
    };
    t.onauxclick = e => { if (e.button === 1) closeTab(p); };
    el.ftabs.appendChild(t);
  }
  const act = el.ftabs.querySelector('.active');
  if (act) act.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}
function closeTab(p) {
  const i = S.tabs.indexOf(p);
  if (i < 0) return;
  S.tabs.splice(i, 1);
  if (p === S.current) {
    const next = S.tabs[Math.min(i, S.tabs.length - 1)];
    if (next) openFile(next);
    else { S.current = null; renderTabs(); el.code.textContent = ''; el.gutter.textContent = ''; el.cpath.textContent = '—'; el.cmeta.textContent = ''; }
  } else renderTabs();
}

let openSeq = 0;
async function openFile(path, opts = {}) {
  const f = S.files.get(path);
  if (!f) return;
  const seq = ++openSeq;
  S.current = path;
  if (!S.tabs.includes(path)) {
    S.tabs.push(path);
    while (S.tabs.length > 14) S.tabs.splice(S.tabs.findIndex(t => t !== path), 1);
  }
  renderTabs();
  markTree();
  el.cpath.textContent = path;
  el.openjar.hidden = !(f.type === 'res' && (ARCHIVE_RE.test(path) || /\.(exe|dll|class|dex)$/i.test(path)));
  el.openjar.textContent = ARCHIVE_RE.test(path) ? 'open this archive' : 'analyze this file';
  el.bc.hidden = f.type !== 'src' || !S.jarInfo;
  el.dlone.textContent = f.type === 'py' ? 'download .pyc' : 'download';
  el.usages.hidden = f.type !== 'src' || !S.xrefs.size;
  el.bc.textContent = f.view === 'bc' ? 'source' : 'bytecode';
  el.outline.hidden = true;
  el.preview.hidden = true;
  el.code.parentElement.hidden = false;
  el.gutter.hidden = false;

  let text, lang = '';
  if (f.type === 'py' || f.type === 'diff') {
    text = f.text;
    lang = f.type === 'py' ? 'python' : 'diff';
    el.cmeta.textContent = f.type === 'py'
      ? `compiled Python ${S.py ? S.py.pyver : ''} · ${f.summary ? `${f.summary.outline.length} defs · ${f.summary.strings.length} strings` : ''}`
      : f.meta || 'diff';
    if (f.type === 'py') renderOutline(text, /^(\s*)((?:def|class) [\w.<>]+)/);
    renderCode(text, lang);
    if (opts.line) scrollToLine(opts.line); else if (opts.find) scrollToFind(text, opts.find); else el.codebox.scrollTop = 0;
    return;
  }
  if (f.type === 'src') {
    if (f.view === 'bc') {
      if (f.bytecode == null) {
        showPlaceholder(`// reading bytecode of ${baseOf(path)}…`);
        try { await ensureBytecode(f); } catch (e) { f.bytecode = '// could not read bytecode: ' + (e.message || e); }
        if (seq !== openSeq) return;
      }
      text = f.bytecode;
      el.cmeta.textContent = `bytecode · ${text.split('\n').length} lines`;
    } else {
      if (f.text == null && !f.error) {
        showPlaceholder(`// decompiling ${baseOf(path)} with ${ENGINES[S.engine]}…\n// (first one per visit also starts the JVM)`);
        try { await ensureSource(f); } catch (e) { f.error = e.message || String(e); }
        if (seq !== openSeq) return;
        renderBanner();
        el.decall.hidden = !(S.lazy && pendingCount() > 0);
        markTree();
        if (!el.q.value.trim() && !S.usagesOf) updateFoot();
      }
      el.codebox.classList.remove('loading');
      text = f.text != null ? f.text : `// ${ENGINES[S.engine]} could not decompile this class\n// ${String(f.error).split('\n').join('\n// ')}\n// try "retry with" the other engine, or view the bytecode`;
      lang = 'java';
      const lines = text.split('\n').length;
      el.cmeta.textContent = `${lines} lines · ${human(new Blob([text]).size)} · ${ENGINES[f.engine || S.engineUsed || S.engine]}`;
      renderOutline(text);
    }
  } else {
    if (f.text == null && f.bytes == null) {
      f.bytes = await f.zipEntry.async('uint8array');
      if (seq !== openSeq) return;
      f.size = f.bytes.length;
      if (f.bytes.length >= 8 && f.bytes[0] === 3 && f.bytes[1] === 0 && f.bytes[2] === 8 && f.bytes[3] === 0) {
        try { f.text = Inspect.decodeAXML(f.bytes); f.axml = true; } catch (e) { /* not AXML */ }
      }
      if (f.text == null && !IMG_RE.test(path) && isProbablyText(f.bytes) && f.bytes.length < 4 * 1024 * 1024) {
        f.text = new TextDecoder().decode(f.bytes);
        if (/\.(json|mcmeta)$/i.test(path) && f.text.length < 512 * 1024) {
          try { const pretty = JSON.stringify(JSON.parse(f.text), null, 2); if (!/\n/.test(f.text.trim())) f.text = pretty; } catch (e) { /* keep raw */ }
        }
      }
    }
    if (IMG_RE.test(path) && f.bytes) {
      showImage(f);
      return;
    }
    if (f.text != null) {
      text = f.text;
      lang = f.axml ? 'xml' : LANGS[ext(path)] || '';
      el.cmeta.textContent = `${text.split('\n').length} lines · ${human(f.size || text.length)}${f.axml ? ' · decoded binary XML' : ''}`;
    } else {
      el.cmeta.textContent = `binary · ${human(f.size)}`;
      text = hexDump(f.bytes.subarray(0, 8192)) + (f.size > 8192 ? `\n… ${human(f.size - 8192)} more (download to see all)` : '');
    }
  }
  renderCode(text, lang);
  if (opts.line) scrollToLine(opts.line);
  else if (opts.find) scrollToFind(text, opts.find);
  else el.codebox.scrollTop = 0;
}

function clearViewer() {
  el.code.textContent = '';
  el.gutter.textContent = '';
  el.ftabs.innerHTML = '';
  el.cpath.textContent = '—';
  el.cmeta.textContent = '';
  el.outline.hidden = true;
  el.preview.hidden = true;
}

function showPlaceholder(text) {
  el.codebox.classList.add('loading');
  el.cmeta.textContent = 'working…';
  renderCode(text, '', true);
}

function showImage(f) {
  el.code.parentElement.hidden = true;
  el.gutter.hidden = true;
  el.preview.hidden = false;
  const url = URL.createObjectURL(new Blob([f.bytes]));
  el.preview.innerHTML = '';
  const img = new Image();
  img.onload = () => {
    el.cmeta.textContent = `image · ${img.naturalWidth}×${img.naturalHeight} · ${human(f.size)}`;
    if (img.naturalWidth < 64) img.style.width = (img.naturalWidth * 8) + 'px';
  };
  img.src = url;
  el.preview.appendChild(img);
}

function renderCode(text, lang, placeholder) {
  if (!placeholder) el.codebox.classList.remove('loading');
  const n = text.split('\n').length;
  let g = '';
  for (let i = 1; i <= n; i++) g += i + '\n';
  el.gutter.textContent = g;
  if (lang === 'diff') {
    el.code.innerHTML = text.split('\n').map(l => {
      const c = l.startsWith('+++') || l.startsWith('---') ? 'hljs-meta' : l[0] === '+' ? 'hljs-addition' : l[0] === '-' ? 'hljs-deletion' : l.startsWith('@@') ? 'hljs-meta' : '';
      return c ? `<span class="${c}">${esc(l)}</span>` : esc(l);
    }).join('\n');
    return;
  }
  if (window.hljs && lang && lang !== 'plaintext' && hljs.getLanguage(lang) && text.length <= MAX_HIGHLIGHT) {
    try {
      el.code.innerHTML = hljs.highlight(text, { language: lang, ignoreIllegals: true }).value;
      return;
    } catch (e) { /* fall through */ }
  }
  el.code.textContent = text;
}

const OUTLINE_TYPE = /^(\s*)(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|abstract|sealed|non-sealed|strictfp)\s+)*(class|interface|enum|record|@interface)\s+([\w$]+)/;
const OUTLINE_METHOD = /^(\s+)(?:@\w+(?:\([^)]*\))?\s+)*(?:(?:public|protected|private|static|final|abstract|synchronized|native|default|strictfp)\s+)*(?:<[^>]+>\s+)?([\w$.]+(?:<[^()]*>)?(?:\[\])*\s+)?([\w$]+)\s*\(([^)]*)\)?\s*(?:throws [\w$., ]+)?\s*[{;]?\s*$/;
const NOT_METHOD = new Set(['if', 'for', 'while', 'switch', 'catch', 'synchronized', 'return', 'new', 'else', 'try', 'do', 'throw', 'case']);

function renderOutline(text, simpleRe) {
  const lines = text.split('\n');
  const items = [];
  for (let i = 0; i < lines.length && items.length < 600; i++) {
    const L = lines[i];
    if (simpleRe) { const m = simpleRe.exec(L); if (m) items.push({ line: i + 1, label: '  '.repeat(Math.min(6, m[1].length / 4)) + m[2] }); continue; }
    let m = OUTLINE_TYPE.exec(L);
    if (m) { items.push({ line: i + 1, label: '  '.repeat(Math.min(4, m[1].length / 4)) + m[2] + ' ' + m[3] }); continue; }
    m = OUTLINE_METHOD.exec(L);
    if (m && !NOT_METHOD.has(m[3]) && (m[2] || /^[A-Z]/.test(m[3])) && !/=/.test(L) && !/^\s*(return|throw)\b/.test(L)) {
      items.push({ line: i + 1, label: '  '.repeat(Math.min(4, m[1].length / 4)) + m[3] + '(' + (m[4] || '').split(',').filter(Boolean).length + ')' });
    }
  }
  if (items.length < 2) { el.outline.hidden = true; return; }
  el.outline.innerHTML = `<option value="">outline · ${items.length}</option>` +
    items.map(it => `<option value="${it.line}">${esc(it.label.replace(/ /g, ' '))}</option>`).join('');
  el.outline.hidden = false;
}
el.outline.onchange = () => {
  const n = +el.outline.value;
  if (n) scrollToLine(n);
  el.outline.value = '';
};

function lineHeight() { return parseFloat(getComputedStyle(el.code.parentElement).lineHeight) || 19; }

function scrollToLine(line) {
  const lh = lineHeight();
  const top = 14 + (line - 1) * lh;
  el.codebox.scrollTop = Math.max(0, top - el.codebox.clientHeight / 3);
  let flash = el.codebox.querySelector('.flash');
  if (!flash) {
    flash = document.createElement('div');
    flash.className = 'flash';
    flash.style.cssText = 'position:absolute;left:0;pointer-events:none;background:rgba(122,240,161,.13);transition:opacity 1.2s';
    el.codebox.style.position = 'relative';
    el.codebox.appendChild(flash);
  }
  flash.style.top = top + 'px';
  flash.style.height = lh + 'px';
  flash.style.width = el.codebox.scrollWidth + 'px';
  flash.style.opacity = '1';
  clearTimeout(flash._t);
  flash._t = setTimeout(() => { flash.style.opacity = '0'; }, 1800);
}

function scrollToFind(text, needle) {
  const tries = [needle, JSON.stringify(needle).slice(1, -1), needle.slice(0, 40), needle.slice(needle.lastIndexOf('.') + 1)];
  for (const t of tries) {
    if (!t || t.length < 2) continue;
    const i = text.indexOf(t);
    if (i >= 0) { scrollToLine(countLines(text, i)); return; }
  }
  el.codebox.scrollTop = 0;
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

// A scan location: "pkg/Class", "python.module", "lib/x.dll", or "inner.jar!pkg/Class"
async function openLocation(where, find) {
  if (fileForClass(where)) return openClass(where, find);
  const bang = where.indexOf('!');
  if (bang > 0 && S.files.has(where.slice(0, bang))) {
    await openNested(where.slice(0, bang));
    const rest = where.slice(bang + 1);
    if (S.name === baseOf(where.slice(0, bang))) openLocation(rest, find);
    return;
  }
  if (S.files.has(where)) { showView('source'); openFile(where); return; }
  if (/^0x[0-9a-f]+$/.test(where) && S.strings) { showView('strings'); el.sq.value = (find || '').slice(0, 40); renderStrings(); }
}

// open the source file of a class, optionally scrolling to some text inside it
function openClass(internal, find) {
  const p = fileForClass(internal);
  if (!p) { toast('class not in this archive: ' + dots(internal)); return false; }
  showView('source');
  openFile(p, { find: find || internal.slice(internal.lastIndexOf('$') + 1).slice(internal.lastIndexOf('/') + 1) });
  return true;
}

// ---- jump to class: double-click or ctrl/cmd+click an identifier

function wordAtPoint(ev) {
  let node, off;
  if (document.caretPositionFromPoint) {
    const p = document.caretPositionFromPoint(ev.clientX, ev.clientY);
    if (p) { node = p.offsetNode; off = p.offset; }
  } else if (document.caretRangeFromPoint) {
    const r = document.caretRangeFromPoint(ev.clientX, ev.clientY);
    if (r) { node = r.startContainer; off = r.startOffset; }
  }
  if (!node || node.nodeType !== 3) return null;
  const t = node.textContent;
  let a = off, b = off;
  while (a > 0 && /[\w$]/.test(t[a - 1])) a--;
  while (b < t.length && /[\w$]/.test(t[b])) b++;
  return t.slice(a, b) || null;
}

function resolveClass(word, text) {
  if (!word || !/^[A-Za-z_$][\w$]*$/.test(word)) return null;
  const cands = [];
  const imp = new RegExp('^import\\s+(?:static\\s+)?([\\w.$]+)\\.' + word.replace(/\$/g, '\\$') + '\\s*;', 'm').exec(text);
  if (imp) {
    const base = imp[1].replace(/\./g, '/');
    cands.push(base + '/' + word, base + '$' + word);
  }
  const pkg = (/^package\s+([\w.]+)\s*;/m.exec(text) || [])[1];
  const pfx = pkg ? pkg.replace(/\./g, '/') + '/' : '';
  cands.push(pfx + word);
  const outer = S.current ? S.current.replace(/\.java$/, '') : '';
  if (outer) cands.push(outer + '$' + word);
  for (const c of cands) { const p = fileForClass(c); if (p) return { path: p, internal: c }; }
  const list = S.simpleIndex.get(word);
  if (list && list.length) {
    const same = list.find(c => c.startsWith(pfx)) || list[0];
    const p = fileForClass(same);
    if (p) return { path: p, internal: same };
  }
  return null;
}

function tryJump(word) {
  const f = S.files.get(S.current);
  if (!f || f.type !== 'src' || f.text == null) return false;
  const r = resolveClass(word, f.text);
  if (!r) return false;
  const simple = r.internal.slice(r.internal.lastIndexOf('/') + 1).split('$').pop();
  const re = new RegExp('(?:class|interface|enum|record)\\s+' + simple.replace(/\$/g, '\\$') + '\\b');
  if (r.path === S.current) {
    const m = re.exec(f.text);
    if (m) scrollToLine(countLines(f.text, m.index));
    return true;
  }
  openFile(r.path).then(() => {
    const g = S.files.get(r.path);
    if (g && g.text) { const m = re.exec(g.text); if (m) scrollToLine(countLines(g.text, m.index)); }
  });
  return true;
}

el.code.addEventListener('dblclick', () => {
  const w = String(getSelection()).trim();
  if (tryJump(w)) getSelection().removeAllRanges();
});
el.code.addEventListener('click', e => {
  if (!(e.ctrlKey || e.metaKey)) return;
  const w = wordAtPoint(e);
  if (w && tryJump(w)) e.preventDefault();
});
el.code.addEventListener('mousemove', e => {
  el.code.style.cursor = (e.ctrlKey || e.metaKey) ? 'pointer' : '';
});

el.gutter.addEventListener('click', e => {
  if (!S.current) return;
  const r = el.gutter.getBoundingClientRect();
  const line = Math.floor((e.clientY - r.top - 14) / lineHeight()) + 1;
  if (line < 1) return;
  scrollToLine(line);
  copyText(`${S.current}:${line}`);
});

el.wrap.onclick = () => el.codebox.classList.toggle('wrap');

el.copy.onclick = () => {
  const f = S.files.get(S.current);
  if (!f) return;
  const t = f.type === 'src' && f.view === 'bc' ? f.bytecode : f.text;
  if (t != null) copyText(t, el.copy);
};

el.dlone.onclick = async () => {
  const f = S.files.get(S.current);
  if (!f) return;
  if (f.type === 'py') { download(baseOf(f.path).replace(/\.py$/, '.pyc'), await pycBytes(f)); return; }
  if (f.type === 'diff') { download(baseOf(f.path) + '.diff', f.text, 'text/plain'); return; }
  if (f.type === 'src') {
    if (f.view === 'bc') download(baseOf(f.path).replace(/\.java$/, '.bytecode.txt'), f.bytecode || '', 'text/plain');
    else download(baseOf(f.path), f.text || '', 'text/plain');
  } else {
    download(baseOf(f.path), f.bytes || (f.zipEntry ? await f.zipEntry.async('uint8array') : f.text));
  }
};

el.bc.onclick = () => {
  const f = S.files.get(S.current);
  if (!f || f.type !== 'src') return;
  f.view = f.view === 'bc' ? 'src' : 'bc';
  openFile(f.path);
};

el.fhash.onclick = el.fmd5.onclick = el.fsha1.onclick = e => {
  const h = e.currentTarget.textContent;
  if (/^[0-9a-f]{32,64}$/.test(h)) copyText(h);
};

// ------------------------------------------------------------------ scan view

function renderBatch() {
  const rows = S.batch;
  const order = { high: 0, med: 1, low: 2, none: 3, err: 4 };
  const sorted = rows.map((r, i) => [r, i]).sort((a, b) => order[a[0].level] - order[b[0].level] || a[0].name.localeCompare(b[0].name));
  const cnt = k => rows.filter(r => r.level === k).length;
  let h = `<section><div class="scan-sum">
    <div class="pill high"><b>${cnt('high')}</b>high risk</div><div class="pill med"><b>${cnt('med')}</b>review</div>
    <div class="pill low"><b>${cnt('low')}</b>minor</div><div class="pill ok"><b>${cnt('none')}</b>no indicators</div>
    ${cnt('err') ? `<div class="pill"><b>${cnt('err')}</b>skipped</div>` : ''}</div></section>`;
  h += `<section><h3>FILES · ${rows.length}</h3><table class="batch"><tr><th>result</th><th>file</th><th>what</th><th>top indicators</th></tr>`;
  for (const [r, i] of sorted) {
    const what = r.error ? esc(r.error) : [r.meta && r.meta.name ? esc(r.meta.name) + (r.meta.version ? ' ' + esc(r.meta.version) : '') : '', r.meta ? esc(r.meta.kind) : esc(r.kindLabel), r.classes ? plural(r.classes, 'class') : ''].filter(Boolean).join('<br>');
    const top = r.summary ? r.summary.findings.filter(f => f.rule.sev !== 'low').slice(0, 3).map(f => esc(f.rule.title)).join('<br>') : '';
    const lbl = { high: 'HIGH', med: 'REVIEW', low: 'MINOR', none: 'CLEAN', err: 'SKIPPED' }[r.level];
    h += `<tr class="brow" data-i="${i}"><td><span class="lvl ${r.level === 'err' ? '' : r.level}">${lbl}</span></td><td><div class="fn">${esc(r.name)}</div><div class="sub">${human(r.size)}</div></td><td class="sub">${what}</td><td class="hits">${top || '<span class="sub">—</span>'}</td></tr>`;
  }
  h += '</table></section><div class="disclaimer">Quick scan of class constant pools and executable strings, no decompiling. Click a file to open it with the full decompiler. "CLEAN" means no rule matched, not that a file is proven safe.</div>';
  el.scan.innerHTML = h;
  for (const tr of el.scan.querySelectorAll('tr.brow')) tr.onclick = () => openBatchItem(+tr.dataset.i);
}

function renderScan() {
  if (S.batch) return renderBatch();
  if (!S.scan) { el.scan.innerHTML = '<div class="empty">nothing scanned</div>'; return; }
  const sc = S.scan, r = S.scanRes;
  let h = `<section><div class="scan-sum">
    <button class="btn ghost sm" id="copysum" title="Copy a short summary (URLs defanged) for Discord or a bug report" style="margin-left:auto;order:9">copy summary</button>
    <div class="pill high"><b>${sc.count.high}</b>high</div>
    <div class="pill med"><b>${sc.count.med}</b>medium</div>
    <div class="pill low"><b>${sc.count.low}</b>low</div>
    <div class="pill ok"><b>${r.classCount || (S.strings ? S.strings.length : 0)}</b>${r.classCount ? 'classes scanned' : 'strings scanned'}</div>
    <div class="pill"><b>${r.urls.size}</b>urls</div>
    <div class="pill"><b>${r.ips.size}</b>ips</div>
  </div></section>`;

  if (sc.findings.length) {
    h += '<section><h3>INDICATORS</h3>';
    for (const fd of sc.findings) {
      const rule = fd.rule;
      const locs = [...fd.where.entries()].slice(0, 60);
      h += `<details class="finding ${rule.sev}"${rule.sev === 'high' ? ' open' : ''}><summary><span class="sev">${rule.sev.toUpperCase()}</span><span>${esc(rule.title)}</span><span class="cnt">${plural(fd.where.size, 'place')}</span></summary><div class="body"><div class="why">${esc(rule.why)}</div>`;
      for (const [where, evs] of locs) {
        const clickable = fileForClass(where) || where.includes('!') || (S.files.has(where) && S.files.get(where).type === 'res');
        h += `<div class="loc">${clickable ? `<a data-cls="${esc(where)}" data-find="${esc([...evs][0] || '')}">${esc(dots(where))}</a>` : esc(where)}</div>`;
        for (const ev of evs) h += `<div class="ev">${esc(ev)}</div>`;
      }
      if (fd.where.size > locs.length) h += `<div class="loc" style="color:var(--dim)">… ${fd.where.size - locs.length} more</div>`;
      h += '</div></details>';
    }
    h += '</section>';
  } else {
    h += section('INDICATORS', `<div class="note">None of the ${sc.rulesTotal} indicator rules matched.</div>`);
  }

  if (S.nestedRows && S.nestedRows.length) {
    const rows = S.nestedRows.slice().sort((a, b) => (SEV_RANK[b.level] || 0) - (SEV_RANK[a.level] || 0));
    const lbl = { high: 'HIGH', med: 'REVIEW', low: 'MINOR', none: 'CLEAN' };
    h += section(`INSIDE THIS ARCHIVE · ${rows.length}`, '<table class="batch"><tr><th>result</th><th>file</th><th>what</th><th>top indicators</th></tr>' + rows.map(x => {
      const top = x.summary ? x.summary.findings.filter(f => f.rule.sev !== 'low').slice(0, 3).map(f => esc(f.rule.title)).join('<br>') : '';
      const what = x.kind === 'native' ? 'native binary (strings scanned)' : [x.meta && x.meta.name ? esc(x.meta.name) + (x.meta.version ? ' ' + esc(x.meta.version) : '') : '', plural(x.classes, 'class')].filter(Boolean).join('<br>');
      return `<tr class="brow" data-open="${esc(x.name)}"><td>${x.level ? `<span class="lvl ${x.level}">${lbl[x.level]}</span>` : '<span class="lvl">NATIVE</span>'}</td><td><div class="fn">${esc(x.name)}</div><div class="sub">${human(x.size)}</div></td><td class="sub">${what}</td><td class="hits">${top || '<span class="sub">—</span>'}</td></tr>`;
    }).join('') + '</table>');
  }

  if (r.decoded && r.decoded.length) {
    h += section(`DECODED HIDDEN STRINGS · ${r.decoded.length}`, '<div class="ioc">' + r.decoded.slice(0, 200).map(d =>
      `<div><span class="u"><span style="color:var(--dim)">${esc(d.kind)}:</span> ${esc(d.text.length > 300 ? d.text.slice(0, 300) + '…' : d.text)}</span><span class="w" data-cls="${esc(d.where)}" data-find="${esc(d.raw.slice(0, 40))}" title="${esc(d.raw)}">${esc(dots(d.where))}</span></div>`).join('') + '</div>');
  }

  if (r.obf) {
    h += section('OBFUSCATION', `<div class="note">${Math.round(r.obf.frac * 100)}% of ${r.obf.total} class names are 1–2 characters or look generated. The code is probably obfuscated, so readable names may be missing and the indicators above could miss things hidden in encrypted strings. The <b>rename obfuscated names</b> option helps readability.</div>`);
  }

  const iocList = (map, cls) => [...map.entries()].slice(0, 400).map(([u, where]) => {
    const w = [...where];
    return `<div><span class="${cls}">${esc(u)}</span><span class="w" data-cls="${esc(w[0])}" data-find="${esc(u)}" title="${esc(w.map(dots).join(', '))}">${esc(dots(w[0]))}${w.length > 1 ? ' +' + (w.length - 1) : ''}</span></div>`;
  }).join('');
  if (r.urls.size) h += section(`URLS · ${r.urls.size}`, `<div class="ioc">${iocList(r.urls, 'u')}</div>`);
  if (r.ips.size) h += section(`IP ADDRESSES · ${r.ips.size}`, `<div class="ioc">${iocList(r.ips, 'u')}</div>`);

  h += `<div class="disclaimer">Static heuristics over string constants and API references. A hit means "read this code", not "this is malware", and a clean result doesn't prove a file is safe. Hashes can be checked on VirusTotal from the link at the top (only the hash leaves your browser, and only when you click it).</div>`;
  el.scan.innerHTML = h;
  for (const a of el.scan.querySelectorAll('[data-cls]')) a.onclick = () => openLocation(a.dataset.cls, a.dataset.find);
  for (const tr of el.scan.querySelectorAll('tr[data-open]')) tr.onclick = () => openNested(tr.dataset.open);
  const cs = el.scan.querySelector('#copysum');
  if (cs) cs.onclick = () => copyText(Scan.textSummary(S.name, S.hashes.sha256, S.scan, S.scanRes), cs);
}

// ------------------------------------------------------------------ details

function renderDetails() {
  let h = '';
  if (S.pe) h += peDetails();
  if (S.py) h += pyDetails();
  if (S.apk) h += apkDetails();
  if (S.dex) h += section('DEX FILE', kv([['format version', S.dex.version], ['classes', S.dex.classes], ['methods', S.dex.methods], ['strings', S.dex.strings]]));
  if (S.cls) h += section('CLASS FILE', kv([['class', esc(dots(S.cls.name || '?'))], ['bytecode', esc(Inspect.javaVersion(S.cls.major)) + ` (major ${S.cls.major}, minor ${S.cls.minor})`], ['superclass', S.cls.superName ? esc(dots(S.cls.superName)) : null]]));
  if (S.modrinth) {
    const m = S.modrinth, prev = modrinthPrevious();
    const cur = m.versions.find(v => v.id === m.current) || {};
    h += section('MODRINTH', kv([
      ['project', `<a class="link" href="https://modrinth.com/${esc(m.kind)}/${esc(m.slug)}" target="_blank" rel="noopener">${esc(m.slug)} ↗</a>`],
      ['this version', esc(cur.version_number || '?') + ` <span style="color:var(--dim)">· ${esc((cur.loaders || []).join(', '))} · ${esc((cur.game_versions || []).slice(-3).join(', '))}</span>`],
      ['published', cur.date_published ? esc(cur.date_published.slice(0, 10)) : null],
    ]) + (prev ? `<button class="btn" data-mrcmp="${esc(prev.id)}" style="margin:10px 0">compare with previous release (${esc(prev.version_number)})</button>` : '') +
      '<div class="ioc">' + m.versions.slice(0, 40).map(v => `<div><span class="u" style="${v.id === m.current ? 'color:var(--fg)' : ''}">${esc(v.version_number)} <span style="color:var(--dim)">· ${esc(v.loaders.join(', '))} · ${esc(v.game_versions.slice(-2).join(', '))}</span></span>` +
        (v.id === m.current ? '<span class="w">open now</span>' : `<span class="w"><a data-mropen="${esc(v.id)}">open</a> · <a data-mrcmp="${esc(v.id)}">compare</a></span>`) + '</div>').join('') + '</div>');
  }
  if (S.mrpack) {
    const m = S.mrpack;
    h += section('MODRINTH MODPACK', kv([
      ['name', m.name ? esc(m.name) : null], ['version', m.version ? esc(m.version) : null], ['summary', m.summary ? esc(m.summary) : null],
      ['requires', Object.entries(m.deps).map(([k, v]) => esc(k + ' ' + v)).join(', ') || null],
      ['files', `${m.files.length} · ${human(m.files.reduce((a, f) => a + (f.fileSize || 0), 0))}`],
    ]) + `<button class="btn" id="mrscan" style="margin:10px 0">download &amp; scan all ${m.files.length} files</button>` +
      '<div class="ioc">' + m.files.map(f => `<div><span class="u">${esc(f.path)}</span><span class="w">${human(f.fileSize || 0)}</span></div>`).join('') + '</div>');
  }
  if (S.jarInfo) h += jarDetails();
  if (S.batch) h += section('BATCH', kv([['files', S.batch.length], ['total size', human(S.batch.reduce((a, r) => a + r.size, 0))], ['classes scanned', S.batch.reduce((a, r) => a + (r.classes || 0), 0)]]));
  h += section('KEYBOARD', `<div class="help">
    <span><span class="kbd">/</span></span><span>filter files</span>
    <span><span class="kbd">ctrl</span> <span class="kbd">shift</span> <span class="kbd">F</span></span><span>search decompiled code</span>
    <span><span class="kbd">ctrl</span> <span class="kbd">shift</span> <span class="kbd">S</span></span><span>search string constants</span>
    <span>double-click / <span class="kbd">ctrl</span>+click</span><span>jump to a class name in the code</span>
    <span><span class="kbd">alt</span> <span class="kbd">W</span></span><span>close tab</span>
    <span><span class="kbd">alt</span> <span class="kbd">←</span> <span class="kbd">→</span></span><span>previous / next tab</span>
    <span><span class="kbd">ctrl</span> <span class="kbd">V</span></span><span>paste a file to analyze it</span>
    <span>click a line number</span><span>copy path:line</span></div>`);
  el.details.innerHTML = h;
  for (const a of el.details.querySelectorAll('[data-cls]')) a.onclick = () => openClass(a.dataset.cls);
  for (const a of el.details.querySelectorAll('[data-open]')) a.onclick = () => openNested(a.dataset.open);
  for (const a of el.details.querySelectorAll('[data-py]')) a.onclick = () => extractPy(+a.dataset.py);
  for (const a of el.details.querySelectorAll('[data-mrcmp]')) a.onclick = () => compareModrinth(a.dataset.mrcmp);
  for (const a of el.details.querySelectorAll('[data-mropen]')) a.onclick = () => openModrinthVersion(a.dataset.mropen);
  const ms = el.details.querySelector('#mrscan');
  if (ms) ms.onclick = () => scanMrpack();
  const sn = el.details.querySelector('#scannested');
  if (sn) sn.onclick = () => scanNested();
}

function versionSummary(versions) {
  return Object.entries(versions).sort((a, b) => b[1] - a[1]).map(([m, n]) => `${Inspect.javaVersion(+m)} ×${n}`).join(', ');
}

const KNOWN_LIBS = [
  ['kotlin/', 'Kotlin stdlib'], ['com/google/gson/', 'Gson'], ['com/google/common/', 'Guava'], ['okhttp3/', 'OkHttp'], ['okio/', 'Okio'],
  ['org/apache/commons/', 'Apache Commons'], ['org/apache/http/', 'Apache HttpClient'], ['com/fasterxml/jackson/', 'Jackson'],
  ['io/netty/', 'Netty'], ['org/slf4j/', 'SLF4J'], ['org/json/', 'org.json'], ['com/sun/jna/', 'JNA'], ['org/yaml/snakeyaml/', 'SnakeYAML'],
  ['net/kyori/', 'Adventure'], ['org/spongepowered/asm/', 'Mixin'], ['org/objectweb/asm/', 'ASM'], ['javassist/', 'Javassist'],
  ['net/bytebuddy/', 'ByteBuddy'], ['com/mojang/', 'Mojang libs'], ['org/lwjgl/', 'LWJGL'], ['org/sqlite/', 'SQLite JDBC'],
  ['com/zaxxer/hikari/', 'HikariCP'], ['org/bstats/', 'bStats'], ['de/tr7zw/', 'NBT-API'], ['me/lucko/', 'lucko libs'],
  ['org/jetbrains/annotations/', 'JetBrains annotations'], ['javax/annotation/', 'javax.annotation'], ['androidx/', 'AndroidX'],
  ['com/google/android/', 'Google Play services'], ['com/google/firebase/', 'Firebase'], ['org/bouncycastle/', 'BouncyCastle'],
  ['club/minnced/discord/', 'Discord webhook lib'], ['net/dv8tion/jda/', 'JDA (Discord)'], ['com/github/benmanes/caffeine/', 'Caffeine']
];

function jarDetails() {
  const j = S.jarInfo;
  let h = '';
  if (S.embedded) h += `<div class="note">Found a jar inside the executable at offset <b>${hex(S.embedded.offset)}</b> (${human(S.embedded.size)}). The exe is just a launcher; the real program is this jar.</div>`;
  if (j.meta) {
    const m = j.meta;
    const eps = (m.entrypoints || []).map(e => {
      const internal = e.replace(/::.*$/, '').replace(/\./g, '/');
      return fileForClass(internal) ? `<a class="link" data-cls="${esc(internal)}">${esc(e)}</a>` : esc(e);
    }).join('<br>');
    h += section(m.kind.toUpperCase(), kv([
      ['name', m.name ? esc(m.name) : null], ['id', m.id ? esc(m.id) : null], ['version', m.version ? esc(m.version) : null],
      ['authors', m.authors && m.authors.length ? esc(m.authors.join(', ')) : null],
      ['description', m.description ? esc(m.description) : null],
      ['environment', m.environment ? esc(m.environment) : null],
      ['entrypoints', eps || null],
      ['depends', m.depends && m.depends.length ? esc(m.depends.join(', ')) : null],
      ['mixin configs', m.mixins && m.mixins.length ? esc(m.mixins.join(', ')) : null],
      ['mixin classes', m.mixinClasses && m.mixinClasses.length ? m.mixinClasses.map(c => {
        const internal = c.replace(/\./g, '/');
        return fileForClass(internal) ? `<a class="link" data-cls="${esc(internal)}">${esc(c)}</a>` : esc(c);
      }).join('<br>') : null],
      ['commands', m.commands && m.commands.length ? esc(m.commands.join(', ')) : null],
      ['license', m.license ? esc(m.license) : null],
    ]));
  }
  h += section(S.embedded ? 'EMBEDDED JAVA ARCHIVE' : S.apk ? 'CONVERTED CLASSES (dex2jar)' : 'JAVA ARCHIVE', kv([
    ['classes', j.classCount],
    ['source files', [...S.files.values()].filter(f => f.type === 'src').length + (S.lazy ? ` (${[...S.files.values()].filter(f => f.type === 'src' && f.text != null).length} decompiled so far)` : '')],
    ['resources', S.files.size - [...S.files.values()].filter(f => f.type === 'src').length],
    ['bytecode target', esc(versionSummary(j.versions) || '—')],
    ['main class', j.mainClass ? (fileForClass(j.mainClass.trim().replace(/\./g, '/')) ? `<a class="link" data-cls="${esc(j.mainClass.trim().replace(/\./g, '/'))}">${esc(j.mainClass.trim())}</a>` : esc(j.mainClass.trim())) : null],
    ['detected', j.kinds.length ? esc(j.kinds.join(', ')) : null],
    ['multi-release', j.multiRelease ? 'yes' : null],
    ['signed', j.signed ? 'yes (signature files present, not verified)' : null],
    ['engine', S.engineUsed || S.lazy ? esc(ENGINES[S.engine]) + (S.seconds ? ` · ${S.seconds.toFixed(1)}s` : '') + (S.lazy ? ' · on demand' : '') : null],
  ]));
  if (j.nestedList.length) {
    h += section(`NESTED ARCHIVES · ${j.nestedList.length}`, (j.nestedList.length > 1 ? '<button class="btn ghost sm" id="scannested" style="margin-bottom:8px">scan all nested archives</button>' : '') + '<div class="ioc">' + j.nestedList.slice(0, 200).map(n =>
      `<div><a class="u" data-open="${esc(n.name)}" style="cursor:pointer">${esc(n.name)}</a><span class="w">${human(n.size)}</span></div>`).join('') + '</div>');
  }
  if (j.packages.length > 1) {
    const max = j.packages[0][1];
    h += section('PACKAGES', '<div class="bars">' + j.packages.slice(0, 14).map(([p, n]) => {
      const lib = KNOWN_LIBS.find(([pre]) => (p + '/').startsWith(pre) || pre.startsWith(p + '/'));
      return `<div><span class="nm" title="${esc(dots(p))}">${esc(dots(p))}${lib ? ` <span style="color:var(--dim)">· ${esc(lib[1])}</span>` : ''}</span><span class="b" style="width:${Math.max(2, 100 * n / max)}%"></span><span class="c">${n}</span></div>`;
    }).join('') + '</div>');
  }
  if (j.manifest.trim()) h += section('MANIFEST', `<pre class="note" style="white-space:pre-wrap;margin:0">${esc(j.manifest.trim())}</pre>`);
  return h;
}

const DANGEROUS_PERMS = /READ_CONTACTS|WRITE_CONTACTS|READ_SMS|SEND_SMS|RECEIVE_SMS|READ_CALL_LOG|WRITE_CALL_LOG|CALL_PHONE|RECORD_AUDIO|CAMERA|ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|READ_PHONE_STATE|READ_PHONE_NUMBERS|BIND_ACCESSIBILITY_SERVICE|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|BIND_DEVICE_ADMIN|READ_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE|QUERY_ALL_PACKAGES|BIND_NOTIFICATION_LISTENER_SERVICE|PROCESS_OUTGOING_CALLS|GET_ACCOUNTS|BODY_SENSORS|USE_FULL_SCREEN_INTENT|WRITE_SETTINGS|RECEIVE_BOOT_COMPLETED/;

function apkDetails() {
  const a = S.apk;
  let h = section('ANDROID PACKAGE', kv([
    ['package', a.pkg ? esc(a.pkg) : null], ['label', a.label ? esc(a.label) : null],
    ['version', a.versionName ? esc(a.versionName) + (a.versionCode ? ` (${esc(a.versionCode)})` : '') : null],
    ['min / target sdk', (a.minSdk || a.targetSdk) ? `${esc(a.minSdk || '?')} / ${esc(a.targetSdk || '?')}` : null],
    ['dex files', a.dexes.map(d => `${esc(d.name)} · ${d.info ? d.info.classes + ' classes' : human(d.size)}`).join('<br>')],
    ['components', `${a.activities} activities · ${a.services} services · ${a.receivers} receivers · ${a.providers} providers`],
    ['debuggable', a.debuggable ? '<span style="color:var(--warn)">yes</span>' : null],
    ['native libs', a.nativeLibs.length ? esc(a.nativeLibs.join(', ')) : null],
    ['signing', a.signing.length ? esc(a.signing.join(', ')) : 'no v1 signature files'],
  ]));
  if (a.perms.length) {
    h += section(`PERMISSIONS · ${a.perms.length}`, '<div class="perm">' + a.perms.map(p =>
      `<span class="${DANGEROUS_PERMS.test(p) ? 'danger' : ''}" title="${DANGEROUS_PERMS.test(p) ? 'sensitive permission' : ''}">${esc(p.replace(/^android\.permission\./, ''))}</span>`).join('') + '</div>');
  }
  return h;
}

function peDetails() {
  const p = S.pe;
  if (!p.ok) return section('EXECUTABLE', `<div class="note">Starts with MZ but the PE header could not be parsed${p.error ? ': ' + esc(p.error) : ''}.</div>`);
  const ts = p.timestamp;
  const date = ts && ts < 0x7fffffff ? new Date(ts * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : null;
  let h = '';
  if (!S.jarBytes && !S.py) {
    h += `<div class="note">${p.dotnet
      ? '<b>.NET assembly.</b> Contains CIL bytecode, not Java. Use ILSpy or dnSpy to decompile it to C#.'
      : '<b>Native executable.</b> Machine code can\'t be turned back into readable source here. The sections, imports and strings show what it does.'}</div>`;
  }
  const v = p.version || {};
  h += section('PORTABLE EXECUTABLE', kv([
    ['product', v.ProductName ? esc(v.ProductName) + (v.ProductVersion ? ' ' + esc(v.ProductVersion) : '') : null],
    ['company', v.CompanyName ? esc(v.CompanyName) : null],
    ['description', v.FileDescription ? esc(v.FileDescription) : null],
    ['original name', v.OriginalFilename ? esc(v.OriginalFilename) : null],
    ['copyright', v.LegalCopyright ? esc(v.LegalCopyright) : null],
    ['file version', v.FileVersion || v.FixedFileVersion ? esc(v.FileVersion || v.FixedFileVersion) : null],
    ['format', `${p.format} ${p.isDll ? 'DLL' : 'executable'}`],
    ['machine', esc(Inspect.MACHINES[p.machine] || hex(p.machine, 4))],
    ['subsystem', esc(Inspect.SUBSYSTEMS[p.subsystem] || p.subsystem)],
    ['compile timestamp', date ? esc(date) : `${hex(ts)} (zeroed or reproducible build)`],
    ['linker', p.linker],
    ['entry point', hex(p.entryPoint)],
    ['image base', '0x' + p.imageBase.toString(16).toUpperCase()],
    ['ASLR / DEP', `${p.dllCharacteristics & 0x40 ? 'ASLR' : 'no ASLR'} · ${p.dllCharacteristics & 0x100 ? 'DEP' : 'no DEP'}`],
    ['UAC level', p.executionLevel ? (p.executionLevel === 'requireAdministrator' ? '<span style="color:var(--warn)">requireAdministrator (asks for admin)</span>' : esc(p.executionLevel)) : null],
    ['signature blob', p.signed ? 'present (not verified)' : 'none'],
    ['overlay', p.overlay ? `${human(p.overlay.size)} at ${hex(p.overlay.offset)}` : 'none'],
    ['.NET runtime', p.dotnet ? esc((p.dotnet.version || '') + ' · CLR ' + (p.dotnet.runtime || '?') + (p.dotnet.ilOnly ? ' · IL only' : ' · mixed mode')) : null],
    ['export name', p.exportName ? esc(p.exportName) : null],
    ['detected', S.sigs.length ? esc(S.sigs.map(s => s.label).join(', ')) : 'nothing recognized'],
  ]));

  if (p.sections.length) {
    h += section('SECTIONS', '<table class="t"><tr><th>name</th><th>virtual addr</th><th>virtual size</th><th>raw size</th><th>entropy</th><th>flags</th></tr>' +
      p.sections.map(s => `<tr><td>${esc(s.name)}</td><td>${hex(s.va)}</td><td>${human(s.vsize)}</td><td>${human(s.rawSize)}</td>` +
        `<td class="${s.entropy > 7.2 ? 'ent-hi' : ''}" title="${s.entropy > 7.2 ? 'high entropy: likely packed or encrypted' : ''}">${s.entropy.toFixed(2)}</td><td>${s.flags}</td></tr>`).join('') + '</table>');
  }
  if (p.imports.length) {
    const total = p.imports.reduce((a, i) => a + i.funcs.length, 0);
    h += section(`IMPORTS · ${p.imports.length} DLLS · ${total} FUNCTIONS`, p.imports.map(imp =>
      `<details class="imp"><summary>${esc(imp.dll)}<span>${imp.funcs.length}</span></summary><div class="fn">${imp.funcs.map(esc).join('<br>')}</div></details>`).join(''));
  }
  if (p.exports.length) {
    h += section(`EXPORTS · ${p.exports.length}`, `<div class="imp"><div class="fn" style="padding-left:0">${p.exports.slice(0, 1000).map(esc).join('<br>')}</div></div>`);
  }
  if (p.manifest) h += section('APPLICATION MANIFEST', `<pre class="note" style="white-space:pre-wrap;margin:0;max-height:300px;overflow:auto">${esc(p.manifest.trim())}</pre>`);
  return h;
}

const PY_TYPES = { s: 'script', m: 'module', M: 'package', b: 'binary', z: 'PYZ archive', Z: 'zip', x: 'data', o: 'option', l: 'splash', n: 'symlink' };
function pyDetails() {
  const py = S.py;
  const scripts = py.files.filter(f => f.type === 's' && !/^pyi|^_pyi|^pyiboot/.test(f.name));
  let h = `<div class="note"><b>PyInstaller bundle</b> (Python ${esc(py.pyver)}). The entry script${scripts.length === 1 ? ' is' : 's are'} <b>${esc(scripts.map(s => s.name).join(', ') || '?')}</b>. Script entries are compiled bytecode (.pyc without a header). Extract them and use a Python decompiler such as pycdc or decompyle3.</div>`;
  h += section(`BUNDLED FILES · ${py.files.length}`, py.files.slice(0, 2000).map((f, i) =>
    `<div class="pyfile"><a data-py="${i}" title="extract">${esc(f.name)}</a><span>${esc(PY_TYPES[f.type] || f.type)}</span><span>${human(f.usize)}</span><span>${f.compressed ? 'zlib' : 'raw'}</span></div>`).join(''));
  return h;
}

// ------------------------------------------------------------------ strings (executables)

function renderStrings() {
  const q = el.sq.value.trim().toLowerCase();
  const kind = el.skind.value;
  const rows = [];
  let shown = 0, matched = 0;
  const qre = q ? new RegExp(esc(q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi') : null;
  for (const s of S.strings) {
    if (q && !s.s.toLowerCase().includes(q)) continue;
    const k = Inspect.classifyString(s.s);
    if (kind && k !== kind) continue;
    matched++;
    if (shown >= 3000) continue;
    shown++;
    let body = esc(s.s.length > 400 ? s.s.slice(0, 400) + '…' : s.s);
    if (qre) body = body.replace(qre, m => `<mark>${m}</mark>`);
    rows.push(`<div class="srow ${k}"><span class="o">${s.off.toString(16).padStart(8, '0')}</span><span class="e">${s.enc}</span><span class="s">${body}</span></div>`);
  }
  el.strings.innerHTML = rows.join('') || '<div class="empty">no strings match</div>';
  el.scount.textContent = matched > shown ? `showing ${shown} of ${matched}` : `${matched} strings`;
}
let strTimer = 0;
el.sq.addEventListener('input', () => { clearTimeout(strTimer); strTimer = setTimeout(renderStrings, 150); });
el.skind.addEventListener('change', renderStrings);

// ------------------------------------------------------------------ log + report

function renderLog() {
  el.logbox.textContent = S.log.length ? S.log.join('\n\n') : 'no warnings';
}

function buildReport() {
  const r = S.scanRes;
  return {
    tool: 'EZLARP v0.4', generated: new Date().toISOString(),
    file: { name: S.name, size: S.size, type: el.ftype.textContent, ...S.hashes },
    tags: [...el.ftags.children].map(t => t.textContent),
    scan: S.scan ? {
      level: S.scan.level, label: S.scan.label, counts: S.scan.count,
      findings: S.scan.findings.map(f => ({
        id: f.rule.id, severity: f.rule.sev, title: f.rule.title,
        locations: [...f.where.entries()].map(([w, ev]) => ({ where: dots(w), evidence: [...ev] }))
      })),
      urls: [...r.urls.keys()], ips: [...r.ips.keys()], obfuscation: r.obf || null
    } : null,
    java: S.jarInfo ? {
      classes: S.jarInfo.classCount, bytecode: versionSummary(S.jarInfo.versions), mainClass: S.jarInfo.mainClass || null,
      detected: S.jarInfo.kinds, metadata: S.jarInfo.meta || null,
      packages: S.jarInfo.packages.slice(0, 30).map(([p, n]) => ({ package: dots(p), classes: n }))
    } : null,
    android: S.apk ? { package: S.apk.pkg, version: S.apk.versionName, minSdk: S.apk.minSdk, targetSdk: S.apk.targetSdk, permissions: S.apk.perms } : null,
    pe: S.pe && S.pe.ok ? {
      format: S.pe.format, machine: Inspect.MACHINES[S.pe.machine] || S.pe.machine, subsystem: Inspect.SUBSYSTEMS[S.pe.subsystem] || S.pe.subsystem,
      timestamp: S.pe.timestamp, version: S.pe.version || null, detected: S.sigs.map(s => s.label),
      sections: S.pe.sections.map(s => ({ name: s.name, size: s.rawSize, entropy: +s.entropy.toFixed(3) })),
      imports: S.pe.imports.map(i => ({ dll: i.dll, functions: i.funcs.length }))
    } : null,
    pyinstaller: S.py ? { python: S.py.pyver, files: S.py.files.map(f => f.name) } : null
  };
}
el.report.onclick = () => download(`${S.baseName}.ezlarp-report.json`, JSON.stringify(buildReport(), null, 2), 'application/json');

// ------------------------------------------------------------------ keyboard

window.addEventListener('keydown', e => {
  if (el.result.hidden) return;
  const inField = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement && document.activeElement.tagName);
  if (e.key === '/' && !inField) { e.preventDefault(); showView('source'); setQMode('files'); el.q.select(); }
  else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'f') { e.preventDefault(); showView('source'); setQMode('code'); el.q.select(); }
  else if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 's') { e.preventDefault(); showView('source'); setQMode('strings'); el.q.select(); }
  else if (e.altKey && e.key.toLowerCase() === 'w') { e.preventDefault(); if (S.current) closeTab(S.current); }
  else if (e.altKey && (e.key === 'ArrowLeft' || e.key === 'ArrowRight') && S.tabs.length > 1 && !inField) {
    e.preventDefault();
    const i = S.tabs.indexOf(S.current);
    const n = S.tabs[(i + (e.key === 'ArrowLeft' ? -1 : 1) + S.tabs.length) % S.tabs.length];
    openFile(n);
  }
});

// ------------------------------------------------------------------ recent scans (metadata only)

function loadHistory() { try { return JSON.parse(localStorage.getItem('ezlarp.history') || '[]'); } catch (e) { return []; } }
function pushHistory(entry) {
  try {
    const h = loadHistory().filter(x => !(x.sha256 && x.sha256 === entry.sha256 && x.name === entry.name));
    h.unshift(entry);
    localStorage.setItem('ezlarp.history', JSON.stringify(h.slice(0, 15)));
  } catch (e) { /* storage unavailable */ }
}
function renderHistory() {
  const h = loadHistory();
  el.recent.hidden = !h.length || !el.status.hidden;
  if (!h.length) return;
  const ago = t => { const s = (Date.now() - t) / 1000; return s < 3600 ? Math.max(1, Math.round(s / 60)) + 'm ago' : s < 86400 ? Math.round(s / 3600) + 'h ago' : Math.round(s / 86400) + 'd ago'; };
  el.recentlist.innerHTML = h.map(x => `<div class="rrow"><span class="sevdot ${esc(x.level)}"></span><span class="nm" title="${esc(x.sha256 || '')}">${esc(x.name)} <span style="color:var(--dim)">· ${esc(x.label || '')}</span></span><span class="when">${esc(x.type || '')}</span><span class="when">${ago(x.t)}</span></div>`).join('');
}
el.clearhist.onclick = () => { try { localStorage.removeItem('ezlarp.history'); } catch (e) {} renderHistory(); };
renderHistory();
