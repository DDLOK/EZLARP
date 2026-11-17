// EZLARP compare: diff this file against another version of it (classes, resources,
// scan indicators, URLs), with a line diff of decompiled source for changed classes.
'use strict';

el.cmp.onclick = () => { if (!busy) el.cmpfile.click(); };
el.cmpfile.onchange = async e => {
  const f = e.target.files[0];
  e.target.value = '';
  if (f) compareWith(f.name, new Uint8Array(await f.arrayBuffer()));
};

function fnv(u8) {
  let h = 0x811c9dc5;
  for (let i = 0; i < u8.length; i++) { h ^= u8[i]; h = Math.imul(h, 0x01000193); }
  return (h >>> 0).toString(16) + ':' + u8.length;
}

async function toJarBytes(name, u8) {
  const kind = Inspect.sniff(u8, name);
  if (kind === 'zip') {
    const zip = await JSZip.loadAsync(u8);
    const dex = zip.file(/^classes\d*\.dex$/);
    if (dex.length) {
      const items = [];
      for (const d of dex) items.push({ name: d.name, u8: await d.async('uint8array') });
      return { jar: await dex2jar(items), res: zip };
    }
    return { jar: u8, res: zip };
  }
  if (kind === 'class') return { jar: await classesToJar([{ name, u8 }]) };
  if (kind === 'dex') return { jar: await dex2jar([{ name, u8 }]) };
  if (kind === 'pe') { const emb = Inspect.findEmbeddedZip(u8); if (emb) return { jar: emb.slice() }; }
  throw new Error('compare works with jars, .class files, apks / dex, and exes that contain a jar');
}

// Nested jars are paired across versions by name with version-like parts removed,
// e.g. META-INF/jars/fabric-api-base-0.4.42+6573ed8c19.jar -> META-INF/jars/fabric-api-base.jar
function nestKey(path) {
  const dir = path.slice(0, path.lastIndexOf('/') + 1);
  const base = path.slice(dir.length).replace(/\.(jar|zip)$/i, '');
  const kept = base.split(/[-_+]/).filter(t => t && !/\d/.test(t));
  return dir + (kept.join('-') || base) + '.jar';
}

// class key -> { hash, entry, jarKey, srcInJar }, resource key -> { hash, entry }, nested jars, and a scan.
// Keys of things inside nested jars are "<nestKey>!<name>".
async function indexSide(classZip, resZip, label) {
  const classes = new Map(), res = new Map(), jars = new Map([['', { zip: classZip }]]);
  const scan = Scan.newResult();
  const addClasses = async (zip, jarKey) => {
    const prefix = jarKey ? jarKey + '!' : '';
    const files = Object.values(zip.files).filter(f => !f.dir && /\.class$/i.test(f.name) && !/^META-INF\/versions\//.test(f.name));
    for (let i = 0; i < files.length; i++) {
      if (i % 200 === 0) { setState(`indexing ${label}${jarKey ? ' › ' + baseOf(jarKey) : ''} ${i}/${files.length}`, null); await new Promise(r => setTimeout(r, 0)); }
      const u8 = await files[i].async('uint8array');
      const info = Inspect.parseClass(u8, true);
      if (!info || !info.name) continue;
      classes.set(prefix + info.name, { hash: fnv(u8), entry: files[i], jarKey, srcInJar: srcPathOf(files[i].name) });
      Scan.scanClass(scan, info, prefix);
    }
  };
  const addResources = async (zip, jarKey, depth) => {
    const prefix = jarKey ? jarKey + '!' : '';
    for (const f of Object.values(zip.files)) {
      if (f.dir || /\.class$/i.test(f.name) || /^classes\d*\.dex$/.test(f.name) || /^META-INF\/[^/]+\.(SF|RSA|DSA|EC|MF)$/i.test(f.name)) continue;
      const size = (f._data && f._data.uncompressedSize) || 0;
      if (depth < 1 && /\.(jar|zip)$/i.test(f.name) && size < 64 * 1024 * 1024) {
        try {
          const inner = await JSZip.loadAsync(await f.async('uint8array'));
          const key = nestKey(f.name);
          jars.set(key, { zip: inner, entry: f, name: f.name });
          await addClasses(inner, key);
          await addResources(inner, key, depth + 1);
          continue;
        } catch (e) { /* not a zip: compare as a plain file */ }
      }
      res.set(prefix + f.name, { hash: fnv(await f.async('uint8array')), entry: f });
    }
  };
  await addClasses(classZip, '');
  await addResources(resZip || classZip, '', 0);
  return { classes, res, jars, scan, sum: Scan.summarize(scan) };
}

async function compareWith(name, u8, reverse) {
  if (busy || !S.jarInfo) return;
  setBusy(true);
  el.err.hidden = true;
  const prevState = el.fstate.textContent;
  try {
    setState(`reading ${name}`, null);
    const b = await toJarBytes(name, u8);
    const bZip = await JSZip.loadAsync(b.jar);
    let A = await indexSide(S.jarInfo.zip, S.jarInfo.rz, S.name);
    let B = await indexSide(bZip, b.res || bZip, name);
    if (reverse) [A, B] = [B, A];
    const diff = (ma, mb) => {
      const added = [], removed = [], changed = [];
      for (const [k, v] of mb) { const o = ma.get(k); if (!o) added.push(k); else if (o.hash !== v.hash) changed.push(k); }
      for (const k of ma.keys()) if (!mb.has(k)) removed.push(k);
      return { added: added.sort(), removed: removed.sort(), changed: changed.sort() };
    };
    const cls = diff(A.classes, B.classes), res = diff(A.res, B.res);
    // indicator changes: rule+location pairs present in B but not A
    const locs = scan => { const m = new Map(); for (const [id, h] of scan.hits) m.set(id, h); return m; };
    const la = locs(A.scan), lb = locs(B.scan);
    const newHits = [], goneHits = [];
    for (const [id, h] of lb) {
      const before = la.get(id);
      const fresh = [...h.where.keys()].filter(w => !before || !before.where.has(w));
      if (fresh.length) newHits.push({ rule: h.rule, where: fresh, ev: h.where, brandNew: !before });
    }
    for (const [id, h] of la) if (!lb.has(id)) goneHits.push(h.rule);
    newHits.sort((x, y) => SEV_RANK[y.rule.sev] - SEV_RANK[x.rule.sev]);
    const urlsNew = [...B.scan.urls.keys()].filter(u => !A.scan.urls.has(u));
    const urlsGone = [...A.scan.urls.keys()].filter(u => !B.scan.urls.has(u));
    S.cmp = { name, reverse: !!reverse, A, B, otherJar: b.jar, cls, res, newHits, goneHits, urlsNew, urlsGone };
    renderCompare();
    el.rtabs.querySelector('[data-view=compare]').hidden = false;
    showView('compare');
    setState(prevState, null);
  } catch (e) {
    console.error(e);
    showError('compare failed: ' + (e.message || e));
    setState(prevState, null);
  } finally {
    setBusy(false);
  }
}

function renderCompare() {
  const c = S.cmp;
  if (!c) return;
  const lvl = c.newHits.some(h => h.rule.sev === 'high') ? 'high' : c.newHits.some(h => h.rule.sev === 'med') ? 'med' : c.newHits.length ? 'low' : 'none';
  const nameA = c.reverse ? c.name : S.name, nameB = c.reverse ? S.name : c.name;
  let h = `<section><div class="note"><b>${esc(nameA)}</b> → <b>${esc(nameB)}</b>. "New" means present in the second file but not the first.
    ${lvl === 'high' ? '<br><span style="color:var(--danger)">The new version adds high-risk indicators. Read the classes listed below before using it.</span>' : ''}</div></section>`;
  h += `<section><div class="scan-sum">
    <div class="pill ok"><b>+${c.cls.added.length}</b>classes added</div>
    <div class="pill high"><b>−${c.cls.removed.length}</b>removed</div>
    <div class="pill med"><b>~${c.cls.changed.length}</b>changed</div>
    <div class="pill"><b>${c.res.added.length}/${c.res.removed.length}/${c.res.changed.length}</b>resources +/−/~</div>
    <div class="pill ${lvl === 'none' ? 'ok' : lvl}"><b>${c.newHits.length}</b>new indicators</div>
  </div></section>`;

  if (c.newHits.length) {
    h += '<section><h3>NEW INDICATORS</h3>';
    for (const nh of c.newHits) {
      h += `<details class="finding ${nh.rule.sev} new" open><summary><span class="sev">${nh.rule.sev.toUpperCase()}</span><span>${esc(nh.rule.title)}${nh.brandNew ? ' <span style="color:var(--dim)">(not in the old version at all)</span>' : ''}</span><span class="cnt">${plural(nh.where.length, 'new place')}</span></summary><div class="body"><div class="why">${esc(nh.rule.why)}</div>`;
      for (const w of nh.where.slice(0, 40)) {
        h += `<div class="loc"><a data-cdiff="${esc(w)}">${esc(dots(w))}</a></div>`;
        for (const ev of nh.ev.get(w) || []) h += `<div class="ev">${esc(ev)}</div>`;
      }
      h += '</div></details>';
    }
    h += '</section>';
  } else {
    h += section('NEW INDICATORS', '<div class="note">The second file adds no indicators that the first one didn\'t already have.</div>');
  }
  if (c.goneHits.length) h += section('INDICATORS NO LONGER PRESENT', '<div class="ioc">' + c.goneHits.map(r => `<div><span class="u">${esc(r.title)}</span></div>`).join('') + '</div>');
  if (c.urlsNew.length) h += section(`NEW URLS · ${c.urlsNew.length}`, '<div class="ioc">' + c.urlsNew.slice(0, 200).map(u => `<div><span class="u">${esc(u)}</span></div>`).join('') + '</div>');
  if (c.urlsGone.length) h += section(`REMOVED URLS · ${c.urlsGone.length}`, '<div class="ioc">' + c.urlsGone.slice(0, 200).map(u => `<div><span class="u" style="color:var(--dim)">${esc(u)}</span></div>`).join('') + '</div>');

  const list = (items, cls, attr) => `<div class="cmp-list">${items.slice(0, 1500).map(x => `<a class="${cls}" ${attr}="${esc(x)}" title="${esc(x)}">${esc(attr === 'data-cdiff' ? dots(x) : x)}</a>`).join('')}${items.length > 1500 ? `<span class="meta">… ${items.length - 1500} more</span>` : ''}</div>`;
  if (c.cls.changed.length) h += section(`CHANGED CLASSES · ${c.cls.changed.length} (click for a source diff)`, list(c.cls.changed, 'chg', 'data-cdiff'));
  if (c.cls.added.length) h += section(`ADDED CLASSES · ${c.cls.added.length}`, list(c.cls.added, 'add', 'data-cdiff'));
  if (c.cls.removed.length) h += section(`REMOVED CLASSES · ${c.cls.removed.length}`, list(c.cls.removed, 'del', 'data-cdiff'));
  const resAll = [...c.res.changed.map(x => ['chg', x]), ...c.res.added.map(x => ['add', x]), ...c.res.removed.map(x => ['del', x])];
  if (resAll.length) h += section(`CHANGED RESOURCES · ${resAll.length}`, `<div class="cmp-list">${resAll.slice(0, 1000).map(([k, x]) => `<a class="${k}" data-rdiff="${esc(x)}">${esc(x)}</a>`).join('')}</div>`);
  h += '<div class="disclaimer">Classes are compared by their bytes, so a recompile with no code change can still show up as "changed". Indicators come from the same static rules as the SCAN tab.</div>';
  el.cmpview.innerHTML = h;
  for (const a of el.cmpview.querySelectorAll('[data-cdiff]')) a.onclick = () => classDiff(a.dataset.cdiff);
  for (const a of el.cmpview.querySelectorAll('[data-rdiff]')) a.onclick = () => resourceDiff(a.dataset.rdiff);
}

// ---- decompiled source of one source file on one side of the comparison

function sideOf(which) { const c = S.cmp; return which === 'open' ? (c.reverse ? c.B : c.A) : (c.reverse ? c.A : c.B); }

async function jarPathFor(which, jarKey) {
  const side = sideOf(which), j = side.jars.get(jarKey);
  if (j.path) return j.path;
  await ensureJVM();
  const bytes = jarKey ? await j.entry.async('uint8array') : which === 'other' ? S.cmp.otherJar : S.jarBytes;
  j.path = `/str/cmp-${uid()}.jar`;
  cheerpOSAddStringFile(j.path, bytes);
  return j.path;
}

async function sideSource(which, jarKey, srcInJar) {
  if (which === 'open' && !jarKey) {
    const f = S.files.get(srcInJar);
    if (!f || f.type !== 'src') return null;
    await ensureSource(f);
    return f.text;
  }
  const side = sideOf(which);
  const group = [...side.classes.values()].filter(v => v.jarKey === jarKey && v.srcInJar === srcInJar);
  if (!group.length) return null;
  const lib = await jarPathFor(which, jarKey);
  const z = new JSZip();
  for (const g of group) z.file(g.entry.name, await g.entry.async('uint8array'));
  const inPath = `/str/cmpone-${uid()}.jar`;
  cheerpOSAddStringFile(inPath, await z.generateAsync({ type: 'uint8array', compression: 'STORE' }));
  const out = await runDecompiler(S.engine, inPath, ['ezlarp.lib=' + lib]);
  const key = Object.keys(out.sources).find(k => k === srcInJar || srcInJar.endsWith('/' + k)) || Object.keys(out.sources)[0];
  return out.sources[key];
}

async function classDiff(key) {
  const c = S.cmp;
  const ent = c.B.classes.get(key) || c.A.classes.get(key);
  if (!ent) return;
  const label = (ent.jarKey ? baseOf(ent.jarKey) + ' › ' : '') + ent.srcInJar;
  const vpath = '⇄ ' + label;
  showView('source');
  showPlaceholder(`// decompiling both versions of ${baseOf(ent.srcInJar)}…`);
  try {
    const mine = await sideSource('open', ent.jarKey, ent.srcInJar);
    const other = await sideSource('other', ent.jarKey, ent.srcInJar);
    if (c.reverse) showDiff(vpath, other, mine, label); else showDiff(vpath, mine, other, label);
  } catch (e) {
    renderCode('// could not build the diff: ' + (e.message || e), '');
  }
}

async function resourceDiff(path) {
  const c = S.cmp;
  const read = async side => { const r = side.res.get(path); if (!r) return null; const u8 = await r.entry.async('uint8array'); return isProbablyText(u8) ? new TextDecoder().decode(u8) : `(binary, ${human(u8.length)}, hash ${r.hash})`; };
  showView('source');
  showDiff('⇄ ' + path, await read(c.A), await read(c.B), path);
}

function showDiff(vpath, a, b, label) {
  const al = a == null ? [] : a.split('\n'), bl = b == null ? [] : b.split('\n');
  const c = S.cmp;
  const { text, plus, minus } = unifiedDiff(al, bl, label, c.reverse ? c.name : S.name, c.reverse ? S.name : c.name);
  S.files.set(vpath, { path: vpath, type: 'diff', virtual: true, text, meta: `diff · +${plus} −${minus}` });
  openFile(vpath);
}

// ---- Myers line diff -> unified diff text

function diffOps(a, b) {
  const n = a.length, m = b.length, max = n + m;
  if (max === 0) return [];
  const off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace = [];
  const LIMIT = 4000;
  for (let d = 0; d <= max; d++) {
    if (d > LIMIT) return null;
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = (k === -d || (k !== d && v[k - 1 + off] < v[k + 1 + off])) ? v[k + 1 + off] : v[k - 1 + off] + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v[k + off] = x;
      if (x >= n && y >= m) {
        const ops = [];
        let cx = n, cy = m;
        for (let dd = d; dd >= 0; dd--) {
          const tv = trace[dd];
          const ck = cx - cy;
          const pk = (ck === -dd || (ck !== dd && tv[ck - 1 + off] < tv[ck + 1 + off])) ? ck + 1 : ck - 1;
          const px = tv[pk + off], py = px - pk;
          while (cx > px && cy > py) { ops.push([' ', a[cx - 1]]); cx--; cy--; }
          if (dd > 0) { if (cx === px) ops.push(['+', b[cy - 1]]); else ops.push(['-', a[cx - 1]]); }
          cx = px; cy = py;
        }
        return ops.reverse();
      }
    }
  }
  return null;
}

function unifiedDiff(a, b, label, nameA, nameB) {
  let ops = diffOps(a, b);
  if (!ops) ops = [...a.map(l => ['-', l]), ...b.map(l => ['+', l])]; // too different: show as replace
  let plus = 0, minus = 0;
  for (const [t] of ops) { if (t === '+') plus++; else if (t === '-') minus++; }
  const out = [`--- ${nameA} / ${label}`, `+++ ${nameB} / ${label}`];
  if (!plus && !minus) { out.push('', '(no differences in the decompiled text; the bytecode differs only in ways the decompiler hides, e.g. line numbers or constant order)'); return { text: out.join('\n'), plus, minus }; }
  const CTX = 3;
  let ia = 0, ib = 0, i = 0;
  while (i < ops.length) {
    if (ops[i][0] === ' ') { ia++; ib++; i++; continue; }
    const start = Math.max(0, i - CTX);
    let end = i;
    // extend hunk while changes are within 2*CTX of each other
    for (let j = i, quiet = 0; j < ops.length; j++) {
      if (ops[j][0] === ' ') { if (++quiet > 2 * CTX) break; } else { quiet = 0; end = j; }
    }
    end = Math.min(ops.length - 1, end + CTX);
    let sa = ia - (i - start), sb = ib - (i - start);
    let ca = 0, cb = 0;
    const body = [];
    for (let j = start; j <= end; j++) {
      const [t, l] = ops[j];
      body.push(t + l);
      if (t !== '+') ca++;
      if (t !== '-') cb++;
    }
    out.push(`@@ -${sa + 1},${ca} +${sb + 1},${cb} @@`, ...body);
    for (let j = i; j <= end; j++) { if (ops[j][0] !== '+') ia++; if (ops[j][0] !== '-') ib++; }
    i = end + 1;
  }
  return { text: out.join('\n'), plus, minus };
}
