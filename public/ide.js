// EZLARP workspace in the style of Visual Studio Code: title bar with menus, activity bar,
// explorer + outline, editor tabs, breadcrumbs, minimap, problems/output panel, status bar,
// quick open (Ctrl+P) and command palette (Ctrl+Shift+P).
// On by default in the Windows app; PC browsers can switch to it (View → Layout, or the footer).
// It moves the page's existing pieces into a new frame, so every feature keeps working.
'use strict';
const IDE = (() => {
  const KEY = 'ezlarp.layout';
  const store = (k, v) => { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } };
  const setLayout = v => { store(KEY, v); location.reload(); };
  const wanted = !PHONE.matches && (/[#&]ide\b/.test(location.hash) || store(KEY) === 'ide' || (App.on && store(KEY) !== 'classic'));

  // classic layout: just offer the switch (PC)
  if (!wanted) {
    const foot = document.querySelector('.foot .pc-only');
    if (foot) {
      const b = document.createElement('button');
      b.className = 'link'; b.textContent = 'VS Code layout'; b.id = 'idetoggle';
      b.onclick = () => setLayout('ide');
      foot.append(' · ', b);
    }
    return { on: false };
  }

  const $ = (sel, root = document) => root.querySelector(sel);
  const mk = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
  const ICON = {
    files: '<path d="M13.5 3H7a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1V8.5z"/><path d="M13.5 3v5.5H19"/><path d="M6 6H4.5v14.5a1 1 0 0 0 1 1H16"/>',
    search: '<circle cx="10.5" cy="10.5" r="6"/><path d="M15 15l5.5 5.5"/>',
    scan: '<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6z"/><path d="M9 12l2 2 4-4"/>',
    strings: '<path d="M4 7h16M4 12h16M4 17h10"/>',
    details: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5M12 8v.5"/>',
    compare: '<path d="M7 4v13M17 7v13M4 14l3 3 3-3M14 10l3-3 3 3"/>',
    log: '<rect x="3.5" y="4.5" width="17" height="15" rx="1"/><path d="M7 10l3 2-3 2M12 15h5"/>',
    account: '<circle cx="12" cy="9" r="4"/><path d="M4.5 20c1.2-3.6 4-5.5 7.5-5.5s6.3 1.9 7.5 5.5"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"/>',
    file: '<path d="M13.5 3H7a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V7.5z"/><path d="M13.5 3v4.5H18"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    cube: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>',
    beaker: '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 18l-5-9V3"/><path d="M7.5 14h9"/>',
  };
  const svg = n => `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON[n]}</svg>`;
  const isMac = /Mac/.test(navigator.platform);
  const K = s => isMac ? s.replace(/Ctrl\+/g, '⌘').replace(/Shift\+/g, '⇧').replace(/Alt\+/g, '⌥') : s;
  const extOf = p => ((/\.([a-z0-9]+)$/i.exec(p || '') || [])[1] || '').toLowerCase();
  const LANG = { java: 'Java', cs: 'C#', py: 'Python', asm: 'x86 Assembly', json: 'JSON', xml: 'XML', yml: 'YAML', yaml: 'YAML', toml: 'TOML', properties: 'Properties',
    txt: 'Plain Text', md: 'Markdown', mf: 'Manifest', js: 'JavaScript', html: 'HTML', css: 'CSS', diff: 'Diff', cfg: 'Config', mcmeta: 'JSON', lang: 'Properties' };

  document.body.classList.add('ide', 'ide-home', 'ide-explorer');
  const fs = +store('ezlarp.ide.fs');
  if (fs >= 10 && fs <= 24) document.body.style.setProperty('--ide-fs', fs + 'px');
  if (store('ezlarp.ide.minimap') === 'off') document.body.classList.add('ide-nomini');
  if (store('ezlarp.ide.panel') === 'off') document.body.classList.add('ide-nopanel');

  // ---------------------------------------------------------------- frame
  const shell = mk('div', '', `
    <header class="ide-title">
      <div class="ide-logo"><span>EZ</span></div>
      <nav class="ide-menubar" id="idemenus"></nav>
      <div class="ide-ttl" id="idettl">EZLARP</div>
      <div class="ide-actions" id="ideactions"></div>
    </header>
    <div class="ide-mid">
      <nav class="ide-act" id="ideact"></nav>
      <main class="ide-work" id="idework"><section class="ide-welcome" id="idewelcome"></section></main>
    </div>
    <footer class="ide-status" id="idestatus"></footer>`);
  shell.id = 'ide';
  document.body.prepend(shell);
  const work = $('#idework'), welcome = $('#idewelcome'), status = $('#idestatus'), actions = $('#ideactions');

  // activity bar
  const ACTS = [['source', 'files', 'Explorer', 'Ctrl+Shift+E'], ['search', 'search', 'Search in code', 'Ctrl+Shift+F'], ['scan', 'scan', 'Report', ''],
    ['strings', 'strings', 'Strings', ''], ['details', 'details', 'Details', ''], ['compare', 'compare', 'Compare', ''], ['log', 'log', 'Log', '']];
  const act = $('#ideact');
  for (const [v, ic, title, k] of ACTS) {
    const b = mk('button', '', svg(ic));
    b.dataset.v = v; b.title = title + (k ? ` (${K(k)})` : '');
    b.onclick = () => activity(v);
    act.append(b);
  }
  act.append(mk('div', 'grow'));
  const accBtn = mk('button', '', svg('account')); accBtn.title = 'Account';
  accBtn.onclick = () => { const a = Account; if (a.user) toast('logged in as ' + a.user.name); else if (a.login) location.href = '/auth/login'; else toast('login isn\'t set up on this server'); };
  const gearBtn = mk('button', '', svg('gear')); gearBtn.title = 'Settings (Ctrl+,)';
  gearBtn.onclick = () => settings();
  act.append(accBtn, gearBtn);

  // move the page's pieces into the frame
  const vpn = $('#vpnbar'); if (vpn) work.prepend(vpn);
  work.append(el.status, el.err, el.result);
  for (const id of ['cmp', 'decall', 'retry', 'share', 'report', 'dl']) { const b = document.getElementById(id); if (b) { b.classList.remove('ghost'); actions.append(b); } }
  const acct = document.getElementById('acct'); if (acct) actions.append(acct);

  // welcome page
  welcome.innerHTML = `
    <h1>EZLARP</h1><div class="wsub">Malware scanner and decompiler · jar, apk, exe, dll, class</div>
    <div class="ide-cols">
      <div>
        <h2>Start</h2>
        <div class="ide-start">
          <button data-c="open">${svg('file')}Open File…</button>
          <button data-c="url">${svg('link')}Scan a Download Link…</button>
          ${App.on ? `<button data-c="mods">${svg('cube')}Scan My Minecraft Mods</button>` : ''}
          <button data-c="samples">${svg('beaker')}Open a Sample…</button>
        </div>
        <div id="idewrecent"></div>
        <div class="tip">Tip: drop files anywhere · <kbd>${K('Ctrl+P')}</kbd> go to file · <kbd>${K('Ctrl+Shift+P')}</kbd> all commands</div>
      </div>
      <div id="idewright"></div>
    </div>`;
  welcome.querySelector('.ide-start').onclick = e => { const b = e.target.closest('button'); if (b) run(b.dataset.c); };
  const recent = document.querySelector('.recent') || document.getElementById('recentlist');
  if (recent) $('#idewrecent').append(recent);
  $('#idewright').append(el.drop);
  const checks = document.getElementById('features'); if (checks) $('#idewright').append(checks);

  // explorer sidebar
  const side = el.result.querySelector('.view[data-view=source] .side');
  const sideHead = mk('div', 'ide-sidehead', '<span class="t">EXPLORER</span>');
  const filterBtn = mk('button', 'btn ghost sm', '⌕'); filterBtn.title = 'Filter files'; filterBtn.style.cssText = 'background:none;border:0;color:#ccc;font-size:15px';
  filterBtn.onclick = () => { document.body.classList.toggle('ide-filter'); if (document.body.classList.contains('ide-filter')) { setQMode('files'); el.q.select(); } };
  sideHead.append(filterBtn);
  const treeSec = mk('div', 'ide-sec', '<span class="nm">—</span><span class="cnt"></span>');
  const outSec = mk('div', 'ide-sec', 'Outline');
  const outline = mk('div', 'ide-outline');
  side.prepend(sideHead);
  el.tree.before(treeSec);
  side.insertBefore(outSec, el.sidefoot);
  side.insertBefore(outline, el.sidefoot);
  for (const s of [treeSec, outSec]) s.onclick = () => s.classList.toggle('closed');

  // editor: breadcrumbs, minimap, panel
  const pane = el.result.querySelector('.view[data-view=source] .pane');
  const head = pane.querySelector('.pane-head');
  const crumbs = mk('div', 'ide-crumbs');
  head.prepend(crumbs);
  const editor = mk('div', 'ide-editor');
  el.codebox.before(editor);
  editor.append(el.codebox);
  const mini = mk('canvas', 'ide-minimap');
  editor.append(mini);
  const panel = mk('section', 'ide-panel', `<div class="ide-panel-h"><button data-p="problems" class="on">Problems<span class="n" id="idepn">0</span></button><button data-p="output">Output</button><span class="sp"></span><button class="x" title="Close panel (${K('Ctrl+J')})">×</button></div><div class="ide-panel-b" id="idepb"></div>`);
  pane.append(panel);
  let panelTab = 'problems';
  panel.querySelector('.ide-panel-h').onclick = e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.classList.contains('x')) return togglePanel(false);
    panelTab = b.dataset.p; renderPanel();
  };

  // status bar
  status.innerHTML = `<span class="v click" id="sbv" title="Report">EZLARP</span><span class="click" id="sbp" title="Problems (${K('Ctrl+J')})">⊗ 0 ⚠ 0</span><span id="sbs"></span>
    <span class="grow"></span><span id="sbpos"></span><span id="sbm"></span><span id="sbenc">UTF-8</span><span class="click" id="sbl"></span><span class="click" id="sbapp" hidden></span><span class="click" id="sbbell" title="Notifications">🔔</span>`;
  $('#sbv').onclick = () => activity('scan');
  $('#sbp').onclick = () => { activity('source'); togglePanel(true); panelTab = 'problems'; renderPanel(); };
  $('#sbl').onclick = () => palette('>');
  $('#sbbell').onclick = () => toast(lastNote || 'no new notifications', 3000);
  let lastNote = '';

  // ---------------------------------------------------------------- views
  function activity(v) {
    if (v === 'search') { showWelcome(false); showView('source'); document.body.classList.remove('ide-explorer'); setQMode('code'); el.q.select(); return syncAct(); }
    document.body.classList.toggle('ide-explorer', v === 'source');
    if (v === 'source' && S.qmode !== 'files') setQMode('files', false);
    if (el.result.hidden) { toast('open a file first'); return; }
    showWelcome(false);
    const tab = el.rtabs.querySelector(`.rtab[data-view="${v}"]`);
    if (tab && tab.hidden) { toast('nothing to show there for this file'); return; }
    showView(v);
  }
  let curView = 'scan';
  function syncAct() {
    const searching = curView === 'source' && !document.body.classList.contains('ide-explorer');
    for (const b of act.querySelectorAll('button[data-v]')) {
      const v = b.dataset.v;
      b.classList.toggle('on', !document.body.classList.contains('ide-home') && (v === 'search' ? searching : v === curView && !(v === 'source' && searching)));
      const tab = el.rtabs.querySelector(`.rtab[data-view="${v === 'search' ? 'source' : v}"]`);
      b.hidden = !!(tab && tab.hidden) && v !== 'source' && v !== 'search' || (v === 'compare' && (!tab || tab.hidden));
    }
    sideHead.querySelector('.t').textContent = searching ? 'SEARCH' : 'EXPLORER';
    for (const c of [...document.body.classList]) if (c.startsWith('ide-v-')) document.body.classList.remove(c);
    document.body.classList.add('ide-v-' + curView);
  }
  function showWelcome(on) {
    document.body.classList.toggle('ide-home', on);
    syncAct(); syncTitle(); syncStatus();
  }
  const _showView = showView;
  showView = function (v) { curView = v; _showView(v); syncAct(); if (v === 'source') requestAnimationFrame(drawMini); };
  const _renderResult = renderResult;
  renderResult = function () {
    _renderResult.apply(this, arguments);
    document.body.classList.add('ide-has-result');
    showWelcome(false);
    treeSec.querySelector('.nm').textContent = S.name || 'FILES';
    treeSec.querySelector('.cnt').textContent = S.files.size ? S.files.size : '';
    renderPanel(); syncStatus(); syncTitle(); syncAct();
    if (S.scan && S.scan.count && (S.scan.count.high || S.scan.count.med) && store('ezlarp.ide.panel') !== 'off') togglePanel(true, true);
  };
  // a new file is being analysed: leave the welcome page
  new MutationObserver(() => { if (!el.status.hidden) showWelcome(false); syncStatus(); }).observe(el.status, { attributes: true, attributeFilter: ['hidden'] });
  new MutationObserver(syncStatus).observe(el.fstate, { childList: true, characterData: true, subtree: true });

  // ---------------------------------------------------------------- editor hooks
  let lastText = '', lastLang = '';
  const _renderCode = renderCode;
  renderCode = function (text, lang) {
    _renderCode.apply(this, arguments);
    lastText = text || ''; lastLang = lang || '';
    requestAnimationFrame(() => { drawMini(); syncCrumbs(); });
  };
  const _openFile = openFile;
  openFile = async function (path) {
    const r = await _openFile.apply(this, arguments);
    showWelcome(false);
    syncCrumbs(); syncTitle(); syncStatus();
    return r;
  };
  const _renderTabs = renderTabs;
  renderTabs = function () {
    _renderTabs.apply(this, arguments);
    for (const t of el.ftabs.children) t.dataset.ext = extOf(t.title);
  };
  // outline: mirror the select into a list
  let symbols = [];
  new MutationObserver(() => {
    symbols = [...el.outline.options].filter(o => o.value).map(o => ({ line: +o.value, label: o.textContent.replace(/ /g, ' ') }));
    outline.innerHTML = symbols.length ? symbols.map(s => {
      const m = /^(\s*)(.*)$/.exec(s.label);
      const kind = /^(class|interface|enum|record|struct|def |delegate)/.test(m[2].trim()) ? 'c' : 'm';
      return `<div data-l="${s.line}" style="padding-left:${20 + m[1].length * 6}px"><b class="${kind}">${kind === 'c' ? '◇' : 'ƒ'}</b>${esc(m[2].trim())}</div>`;
    }).join('') : '<div class="none">No symbols</div>';
    syncCrumbs();
  }).observe(el.outline, { childList: true });
  outline.onclick = e => { const d = e.target.closest('[data-l]'); if (d) gotoLine(+d.dataset.l); };
  function gotoLine(n) { el.outline.value = String(n); el.outline.dispatchEvent(new Event('change')); }

  function currentSymbol() {
    if (!symbols.length) return null;
    const first = Math.floor(el.codebox.scrollTop / lineHeight()) + 2;
    let s = null;
    for (const x of symbols) if (x.line <= first) s = x;
    return s || symbols[0];
  }
  function syncCrumbs() {
    if (!S.current) { crumbs.innerHTML = ''; return; }
    const parts = S.current.split('/');
    const sym = currentSymbol();
    crumbs.innerHTML = parts.map((p, i) => `<span data-i="${i}">${esc(p)}</span>`).join('<i>›</i>') +
      (sym ? `<i>›</i><span class="sym" data-sym="1"><b>${/^(\s*)(class|interface|enum|record|struct|def )/.test(sym.label) ? '◇' : 'ƒ'}</b>${esc(sym.label.trim())}</span>` : '');
  }
  crumbs.onclick = e => {
    const s = e.target.closest('span'); if (!s) return;
    if (s.dataset.sym) palette('@');
    else { const dir = S.current.split('/').slice(0, +s.dataset.i + 1).join('/'); palette('', dir + '/'); }
  };
  el.codebox.addEventListener('scroll', () => { drawMini(); if (symbols.length) syncCrumbsThrottled(); }, { passive: true });
  let crumbT = 0;
  const syncCrumbsThrottled = () => { if (crumbT) return; crumbT = setTimeout(() => { crumbT = 0; syncCrumbs(); }, 120); };

  // cursor position
  document.addEventListener('selectionchange', () => {
    const sel = document.getSelection();
    if (!sel || !sel.rangeCount || !el.code.contains(sel.focusNode)) return;
    try {
      const r = document.createRange();
      r.setStart(el.code, 0);
      r.setEnd(sel.focusNode, sel.focusOffset);
      const before = r.toString();
      if (before.length > 3e6) return;
      const ln = before.split('\n').length, col = before.length - before.lastIndexOf('\n');
      $('#sbpos').textContent = `Ln ${ln}, Col ${col}` + (sel.toString().length ? ` (${sel.toString().length} selected)` : '');
    } catch (e) { /* detached */ }
  });

  // ---------------------------------------------------------------- minimap
  const KW = /\b(public|private|protected|internal|static|final|abstract|class|interface|enum|struct|void|int|long|bool|boolean|string|String|byte|char|double|float|new|return|if|else|while|for|foreach|do|switch|case|break|continue|try|catch|finally|throw|throws|import|package|using|namespace|def|self|true|false|null|this|base|extends|implements|var|const|readonly|override|virtual|call|jmp|ret|push|pop|mov|lea)\b/g;
  function drawMini() {
    if (document.body.classList.contains('ide-nomini') || mini.offsetParent === null) return;
    const dpr = window.devicePixelRatio || 1;
    const w = mini.clientWidth, h = mini.clientHeight;
    if (!w || !h) return;
    if (mini.width !== Math.round(w * dpr) || mini.height !== Math.round(h * dpr)) { mini.width = Math.round(w * dpr); mini.height = Math.round(h * dpr); }
    const c = mini.getContext('2d');
    c.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.clearRect(0, 0, w, h);
    const lines = lastText ? lastText.split('\n') : [];
    if (!lines.length) return;
    const LH = 2, CW = 1;
    const lh = lineHeight();
    const total = lines.length * LH;
    const visLines = el.codebox.clientHeight / lh;
    const topLine = Math.max(0, (el.codebox.scrollTop - 14) / lh);
    const maxScroll = Math.max(1, el.codebox.scrollHeight - el.codebox.clientHeight);
    const offset = total > h ? (total - h) * (el.codebox.scrollTop / maxScroll) : 0;
    const first = Math.floor(offset / LH), last = Math.min(lines.length, first + Math.ceil(h / LH) + 1);
    const asm = lastLang === 'x86asm', py = lastLang === 'python';
    for (let i = first; i < last; i++) {
      const L = lines[i];
      if (!L) continue;
      const y = i * LH - offset;
      const ci = asm ? L.indexOf(';') : py ? L.indexOf('#') : L.indexOf('//');
      const strs = [];
      L.replace(/"(?:[^"\\]|\\.)*"/g, (m, o) => { strs.push([o, o + m.length]); return m; });
      const kws = [];
      L.replace(KW, (m, o) => { kws.push([o, o + m.length]); return m; });
      for (let x = 0; x < L.length && x < 120; x++) {
        if (L.charCodeAt(x) <= 32) continue;
        let col = 'rgba(190,190,190,.55)';
        if (ci >= 0 && x >= ci && !strs.some(s => ci >= s[0] && ci < s[1])) col = 'rgba(106,153,85,.9)';
        else if (strs.some(s => x >= s[0] && x < s[1])) col = 'rgba(206,145,120,.95)';
        else if (kws.some(s => x >= s[0] && x < s[1])) col = 'rgba(86,156,214,.95)';
        c.fillStyle = col;
        c.fillRect(6 + x * CW, y, CW, LH - .5);
      }
    }
    c.fillStyle = 'rgba(121,121,121,.18)';
    c.fillRect(0, topLine * LH - offset, w, Math.max(8, visLines * LH));
    mini._map = { offset, LH, lh };
  }
  let dragMini = false;
  const miniTo = e => {
    const m = mini._map; if (!m) return;
    const y = e.clientY - mini.getBoundingClientRect().top;
    const line = (y + m.offset) / m.LH;
    el.codebox.scrollTop = Math.max(0, line * m.lh - el.codebox.clientHeight / 2);
  };
  mini.addEventListener('pointerdown', e => { dragMini = true; mini.setPointerCapture(e.pointerId); miniTo(e); });
  mini.addEventListener('pointermove', e => { if (dragMini) miniTo(e); });
  mini.addEventListener('pointerup', () => { dragMini = false; });
  mini.addEventListener('wheel', e => { el.codebox.scrollTop += e.deltaY; }, { passive: true });
  window.addEventListener('resize', () => requestAnimationFrame(drawMini));

  // ---------------------------------------------------------------- problems / output
  function problems() {
    const out = [];
    if (!S.scan || !S.scan.findings) return out;
    for (const d of S.scan.detections || []) out.push({ sev: 'high', title: d.name + ' (' + d.kind + ')', where: d.where[0], ev: d.because ? d.because.join(' + ') : '' });
    for (const fd of S.scan.findings) {
      for (const [where, evs] of [...fd.where.entries()].slice(0, 40)) out.push({ sev: fd.rule.sev, title: fd.rule.title, where, ev: [...evs][0] || '' });
    }
    return out;
  }
  function renderPanel() {
    const pb = $('#idepb');
    const list = problems();
    $('#idepn').textContent = list.length;
    for (const b of panel.querySelectorAll('[data-p]')) b.classList.toggle('on', b.dataset.p === panelTab);
    if (panelTab === 'output') { pb.innerHTML = `<pre>${esc(S.log ? S.log.join('\n') : '')}</pre>`; return; }
    if (!list.length) { pb.innerHTML = '<div class="none">No problems have been detected in this file.</div>'; return; }
    const icon = { high: '⊗', med: '⚠', low: 'ⓘ', info: 'ⓘ' };
    pb.innerHTML = list.map((p, i) => `<div class="ide-prob ${p.sev}" data-i="${i}"><span class="i">${icon[p.sev] || 'ⓘ'}</span><span>${esc(p.title)}</span><span class="w">${esc(dots(p.where || ''))}</span><span class="e">${esc((p.ev || '').slice(0, 140))}</span></div>`).join('');
    pb.onclick = e => {
      const r = e.target.closest('.ide-prob'); if (!r) return;
      const p = list[+r.dataset.i];
      if (p.where) openLocation(p.where, p.ev);
    };
  }
  function togglePanel(on, auto) {
    if (on === undefined) on = document.body.classList.contains('ide-nopanel');
    document.body.classList.toggle('ide-nopanel', !on);
    if (!auto) store('ezlarp.ide.panel', on ? 'on' : 'off');
    requestAnimationFrame(drawMini);
  }

  // ---------------------------------------------------------------- status + title
  function syncTitle() {
    const parts = [];
    if (!document.body.classList.contains('ide-home')) { if (S.current && curView === 'source') parts.push(baseOf(S.current)); if (S.name) parts.push(S.name); }
    else parts.push('Welcome');
    parts.push('EZLARP');
    $('#idettl').textContent = document.title = parts.join(' — ');
  }
  function syncStatus() {
    const v = $('#sbv');
    const word = (el.verdict.className.match(/\b(malicious|suspicious|review|clean)\b/) || [])[1];
    v.className = 'v click' + (word ? ' ' + word : '');
    v.textContent = word ? '⛨ ' + (el.verdict.querySelector('.word') ? el.verdict.querySelector('.word').textContent : word.toUpperCase()) : '⛨ EZLARP';
    const c = S.scan && S.scan.count;
    $('#sbp').textContent = `⊗ ${c ? c.high : 0}  ⚠ ${c ? c.med : 0}`;
    $('#sbs').textContent = el.status.hidden ? '' : (el.fstate.textContent || '').replace(/^idle$/, '');
    const f = S.current && S.files.get(S.current);
    const show = f && curView === 'source' && !document.body.classList.contains('ide-home');
    $('#sbl').textContent = show ? (LANG[extOf(S.current)] || (f.type === 'res' ? 'Binary' : 'Plain Text')) : '';
    $('#sbm').textContent = show ? (el.cmeta.textContent || '').split(' · ').filter(x => !/^(C#|x86 disassembly|IL|bytecode)$/.test(x)).slice(0, 2).join(' · ') : '';
    $('#sbenc').hidden = !show;
    if (!show) $('#sbpos').textContent = '';
  }
  new MutationObserver(syncStatus).observe(el.cmeta, { childList: true, characterData: true, subtree: true });

  // ---------------------------------------------------------------- menus
  const SAMPLES = [['mod .jar', 'jar'], ['wrapped .exe', 'exe'], ['.apk', 'apk'], ['python .exe', 'python'], ['C# .exe', 'dotnet']];
  const COMMANDS = [
    // [menu, label, shortcut, fn, enabled?]
    ['File', 'Open File…', 'Ctrl+O', () => el.file.click()],
    ['File', 'Scan a Download Link…', '', () => run('url')],
    ['File', 'Scan My Minecraft Mods', '', () => run('mods'), () => App.on],
    ['File', 'Open Sample…', '', () => run('samples')],
    ['File', '-'],
    ['File', 'Export Source (.zip)', 'Ctrl+Shift+X', () => el.dl.click(), () => !el.dl.hidden && !el.result.hidden],
    ['File', 'Export Report (JSON)', '', () => el.report.click(), () => !el.result.hidden],
    ['File', 'Copy Share Link', '', () => document.getElementById('share').click(), () => !el.result.hidden],
    ['File', 'Compare With Another Version…', '', () => el.cmp.click(), () => !el.cmp.hidden && !el.result.hidden],
    ['File', '-'],
    ['File', 'Close Editor', 'Alt+W', () => S.current && closeTab(S.current), () => !!S.current],
    ['File', 'Welcome', '', () => showWelcome(true)],
    ['Edit', 'Copy File Contents', '', () => el.copy.click(), () => !!S.current],
    ['Edit', 'Download This File', '', () => el.dlone.click(), () => !!S.current],
    ['Edit', '-'],
    ['Edit', 'Find in Files', 'Ctrl+Shift+F', () => activity('search'), () => !el.result.hidden],
    ['Edit', 'Find in Strings', 'Ctrl+Shift+S', () => { activity('search'); setQMode('strings'); el.q.select(); }, () => !el.result.hidden],
    ['View', 'Command Palette…', 'Ctrl+Shift+P', () => palette('>')],
    ['View', '-'],
    ['View', 'Explorer', 'Ctrl+Shift+E', () => activity('source')],
    ['View', 'Report', '', () => activity('scan')],
    ['View', 'Strings', '', () => activity('strings')],
    ['View', 'Details', '', () => activity('details')],
    ['View', 'Log', '', () => activity('log')],
    ['View', '-'],
    ['View', 'Toggle Side Bar', 'Ctrl+B', () => { document.body.classList.toggle('ide-noside'); requestAnimationFrame(drawMini); }],
    ['View', 'Toggle Panel', 'Ctrl+J', () => togglePanel()],
    ['View', 'Toggle Minimap', '', () => { const off = !document.body.classList.toggle('ide-nomini'); store('ezlarp.ide.minimap', off ? 'on' : 'off'); requestAnimationFrame(drawMini); }],
    ['View', 'Toggle Word Wrap', 'Alt+Z', () => el.wrap.click()],
    ['View', 'Zoom In', 'Ctrl+=', () => zoom(1)],
    ['View', 'Zoom Out', 'Ctrl+-', () => zoom(-1)],
    ['View', 'Reset Zoom', 'Ctrl+0', () => zoom(0)],
    ['View', '-'],
    ['View', 'Classic EZLARP Layout', '', () => setLayout('classic')],
    ['Go', 'Go to File…', 'Ctrl+P', () => palette('')],
    ['Go', 'Go to Symbol in Editor…', 'Ctrl+Shift+O', () => palette('@'), () => !!S.current],
    ['Go', 'Go to Line…', 'Ctrl+G', () => palette(':'), () => !!S.current],
    ['Go', '-'],
    ['Go', 'Next Editor', 'Alt+→', () => cycle(1), () => S.tabs.length > 1],
    ['Go', 'Previous Editor', 'Alt+←', () => cycle(-1), () => S.tabs.length > 1],
    ['Help', 'Keyboard Shortcuts', '?', () => toggleKeys(true)],
    ['Help', 'Settings', 'Ctrl+,', () => settings()],
    ['Help', 'Check for App Updates', '', () => checkUpdate(true), () => App.on],
    ['Help', '-'],
    ['Help', 'Source Code on GitHub', '', () => window.open('https://github.com/DDLOK/EZLARP', '_blank', 'noopener')],
    ['Help', 'About EZLARP', '', () => about()],
  ];
  const MENUS = ['File', 'Edit', 'View', 'Go', 'Help'];
  const bar = $('#idemenus');
  let openMenu = null;
  for (const m of MENUS) {
    const b = mk('button', '', m);
    b.onclick = e => { e.stopPropagation(); openMenu === m ? closeMenus() : showMenu(m, b); };
    b.onmouseenter = () => { if (openMenu && openMenu !== m) showMenu(m, b); };
    bar.append(b);
  }
  function showMenu(m, btn) {
    closeMenus();
    openMenu = m;
    btn.classList.add('open');
    const dd = mk('div', 'ide-dd');
    for (const c of COMMANDS.filter(c => c[0] === m)) {
      if (c[1] === '-') { dd.append(mk('hr')); continue; }
      const it = mk('button', '', `<span>${esc(c[1])}</span>${c[2] ? `<span class="k">${esc(K(c[2]))}</span>` : ''}`);
      it.disabled = !!(c[4] && !c[4]());
      it.onclick = () => { closeMenus(); c[3](); };
      dd.append(it);
    }
    const r = btn.getBoundingClientRect();
    dd.style.left = r.left + 'px'; dd.style.top = r.bottom + 'px';
    dd.id = 'idedd';
    document.body.append(dd);
  }
  function closeMenus() {
    openMenu = null;
    const d = document.getElementById('idedd'); if (d) d.remove();
    for (const b of bar.children) b.classList.remove('open');
  }
  document.addEventListener('click', e => { if (openMenu && !e.target.closest('#idedd')) closeMenus(); });

  function run(c) {
    if (c === 'open') el.file.click();
    else if (c === 'mods') { const b = document.getElementById('appmods'); if (b) b.click(); }
    else if (c === 'samples') palette('sample');
    else if (c === 'url') palette('url');
  }
  function cycle(d) { const i = S.tabs.indexOf(S.current); if (i >= 0) openFile(S.tabs[(i + d + S.tabs.length) % S.tabs.length]); }
  function zoom(d) {
    let v = d === 0 ? 14 : Math.max(10, Math.min(24, (parseFloat(getComputedStyle(document.body).getPropertyValue('--ide-fs')) || 14) + d));
    document.body.style.setProperty('--ide-fs', v + 'px');
    store('ezlarp.ide.fs', v);
    requestAnimationFrame(drawMini);
  }

  // ---------------------------------------------------------------- quick open / palette
  function fuzzy(q, s) {
    if (!q) return { score: 0, hl: esc(s) };
    const lq = q.toLowerCase(), ls = s.toLowerCase();
    const at = ls.indexOf(lq);
    if (at >= 0) return { score: 1000 - at - s.length / 100 + (ls.lastIndexOf('/') < at ? 200 : 0), hl: esc(s.slice(0, at)) + '<mark>' + esc(s.slice(at, at + q.length)) + '</mark>' + esc(s.slice(at + q.length)) };
    let i = 0, score = 0, hl = '', last = -2;
    for (let k = 0; k < s.length; k++) {
      if (i < lq.length && ls[k] === lq[i]) { hl += '<mark>' + esc(s[k]) + '</mark>'; score += last === k - 1 ? 5 : 1; last = k; i++; }
      else hl += esc(s[k]);
    }
    return i === lq.length ? { score, hl } : null;
  }
  function palette(mode, preset = '') {
    closeMenus();
    let pal = document.getElementById('idepal');
    if (pal) pal.remove();
    pal = mk('div', 'ide-pal', '<input spellcheck="false" autocomplete="off"><div class="list"></div>');
    pal.id = 'idepal';
    document.body.append(pal);
    const input = pal.querySelector('input'), list = pal.querySelector('.list');
    const fixed = mode === 'url' || mode === 'sample';
    input.value = fixed ? '' : (mode === '' ? preset : mode);
    input.placeholder = mode === 'url' ? 'Paste a download link (Discord, MediaFire, GitHub, Modrinth…) and press Enter'
      : mode === 'sample' ? 'Open a sample' : 'Search files by name (> commands, @ symbols, : line)';
    let items = [], sel = 0;
    const render = () => {
      const v = input.value;
      if (mode === 'url') {
        items = v.trim() ? [{ label: 'Scan ' + v.trim(), run: () => loadUrl(v.trim()) }] : [];
      } else if (mode === 'sample') {
        items = SAMPLES.map(([l, n]) => ({ ...fuzzy(v, l), label: l, run: () => loadSample(n) })).filter(x => x.hl != null);
      } else if (v.startsWith('>')) {
        const q = v.slice(1).trim();
        items = COMMANDS.filter(c => c[1] !== '-' && (!c[4] || c[4]())).map(c => { const t = c[0] + ': ' + c[1]; const f = fuzzy(q, t); return f && { ...f, label: t, k: c[2], run: c[3] }; }).filter(Boolean).sort((a, b) => b.score - a.score);
      } else if (v.startsWith('@')) {
        const q = v.slice(1).trim();
        items = symbols.map(s => { const f = fuzzy(q, s.label.trim()); return f && { ...f, label: s.label.trim(), d: 'line ' + s.line, run: () => gotoLine(s.line) }; }).filter(Boolean);
        if (q) items.sort((a, b) => b.score - a.score);
      } else if (v.startsWith(':')) {
        const n = parseInt(v.slice(1), 10);
        items = n > 0 ? [{ label: 'Go to line ' + n, run: () => scrollToLine(n) }] : [{ label: 'Type a line number', run: () => {} }];
      } else {
        const q = v.trim();
        items = [];
        for (const [p, f] of S.files) {
          if (f.virtual) continue;
          const r = fuzzy(q, p);
          if (r) items.push({ ...r, label: baseOf(p), path: p, d: p, run: () => { showWelcome(false); showView('source'); openFile(p); } });
        }
        items.sort((a, b) => b.score - a.score);
        items = items.slice(0, 300);
        for (const it of items) { const f = fuzzy(q, it.label); it.hl = f ? f.hl : esc(it.label); }
        if (!S.files.size) items = [{ label: 'No file is open. Open one with Ctrl+O, or drop it on the window.', run: () => {} }];
      }
      sel = Math.min(sel, Math.max(0, items.length - 1));
      list.innerHTML = items.length ? items.map((it, i) => `<div class="it${i === sel ? ' on' : ''}" data-i="${i}"><span>${it.hl || esc(it.label)}</span>${it.d ? `<span class="d">${esc(it.d)}</span>` : ''}${it.k ? `<span class="k">${esc(K(it.k))}</span>` : ''}</div>`).join('')
        : `<div class="empty">${mode === 'url' ? 'Paste a link' : 'No matching results'}</div>`;
      const on = list.querySelector('.on'); if (on) on.scrollIntoView({ block: 'nearest' });
    };
    const close = () => pal.remove();
    const pick = i => { const it = items[i]; close(); if (it) it.run(); };
    input.oninput = () => { sel = 0; render(); };
    input.onkeydown = e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); render(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(0, sel - 1); render(); }
      else if (e.key === 'Enter') { e.preventDefault(); pick(sel); }
      else if (e.key === 'Escape') { e.preventDefault(); close(); }
    };
    list.onclick = e => { const it = e.target.closest('.it'); if (it) pick(+it.dataset.i); };
    input.onblur = () => setTimeout(() => { if (document.activeElement !== input) close(); }, 150);
    render();
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  }

  // ---------------------------------------------------------------- settings / about
  function dialog(html, onOpen) {
    const d = mk('div', 'ide-dlg', `<div>${html}</div>`);
    d.onclick = e => { if (e.target === d) d.remove(); };
    document.body.append(d);
    if (onOpen) onOpen(d, () => d.remove());
    return d;
  }
  function settings() {
    const fsNow = parseFloat(getComputedStyle(document.body).getPropertyValue('--ide-fs')) || 14;
    const engines = [...el.engine.options].map(o => `<option value="${esc(o.value)}"${o.value === el.engine.value ? ' selected' : ''}>${esc(o.textContent)}</option>`).join('');
    dialog(`<h3>Settings</h3>
      <label><span>Decompiler (Java)</span><select id="setEng">${engines}</select></label>
      <label><span>Editor font size</span><input type="number" id="setFs" min="10" max="24" value="${fsNow}"></label>
      <label><span>Minimap</span><input type="checkbox" id="setMini"${document.body.classList.contains('ide-nomini') ? '' : ' checked'}></label>
      <label><span>Problems panel opens when something is found</span><input type="checkbox" id="setPanel"${store('ezlarp.ide.panel') === 'off' ? '' : ' checked'}></label>
      <label><span>Layout</span><select id="setLayout"><option value="ide">VS Code</option><option value="classic">Classic EZLARP</option></select></label>
      ${App.on ? `<p class="muted" id="setApp">EZLARP app ${esc(appInfo.version || '')}</p>` : ''}
      <div class="row"><button class="btn primary" id="setOk">Done</button></div>`, (d, close) => {
      d.querySelector('#setEng').onchange = e => { el.engine.value = e.target.value; el.engine.dispatchEvent(new Event('change')); };
      d.querySelector('#setFs').onchange = e => { const v = Math.max(10, Math.min(24, +e.target.value || 14)); document.body.style.setProperty('--ide-fs', v + 'px'); store('ezlarp.ide.fs', v); requestAnimationFrame(drawMini); };
      d.querySelector('#setMini').onchange = e => { document.body.classList.toggle('ide-nomini', !e.target.checked); store('ezlarp.ide.minimap', e.target.checked ? 'on' : 'off'); requestAnimationFrame(drawMini); };
      d.querySelector('#setPanel').onchange = e => store('ezlarp.ide.panel', e.target.checked ? 'on' : 'off');
      d.querySelector('#setLayout').onchange = e => { if (e.target.value === 'classic') setLayout('classic'); };
      d.querySelector('#setOk').onclick = close;
    });
  }
  function about() {
    const ver = (document.querySelector('.foot') || {}).textContent || '';
    dialog(`<h3>EZLARP</h3><p>${esc((/v[\d.]+/.exec(ver) || [''])[0])} · malware scanner and decompiler for jar, apk, exe and dll files.</p>
      <p class="muted">Java: Vineflower, JADX, CFR, Procyon, JD-Core (CheerpJ) and the built-in quick view. .NET: built-in C# decompiler. Native: built-in x86/x64 disassembler. Files are read on your device and never uploaded.</p>
      ${App.on ? `<p class="muted">Windows app ${esc(appInfo.version || '?')}</p>` : ''}
      <div class="row"><button class="btn primary">OK</button></div>`, (d, close) => { d.querySelector('button').onclick = close; });
  }

  // ---------------------------------------------------------------- app version + updates
  const appInfo = { version: '', latest: '', available: false };
  async function checkUpdate(loud) {
    if (!App.on) return;
    try {
      const p = await appFetch('/ping').then(r => r.json());
      appInfo.version = p.version;
      let u = null;
      try { u = await appFetch('/update').then(r => r.json()); } catch (e) { /* helper from before updates existed */ }
      const sb = $('#sbapp');
      sb.hidden = false;
      if (u && u.available) {
        appInfo.latest = u.latest; appInfo.available = true;
        sb.className = 'click upd'; sb.textContent = '⟳ Update to ' + u.latest; sb.title = 'A new version of the EZLARP app is ready. Click to update (takes a few seconds).';
        sb.onclick = () => applyUpdate();
        lastNote = 'EZLARP app ' + u.latest + ' is available (you have ' + p.version + ').';
        if (loud !== false) toast(lastNote + ' Click "Update" in the status bar.', 5000);
      } else if (!u) {
        // helpers from 1.0.0 can't update themselves: offer the installer, which updates in place
        let latest = null;
        try { latest = await fetch('/download/version.json', { cache: 'no-store' }).then(r => r.json()); } catch (e) { /* offline */ }
        if (latest && latest.version && latest.version !== p.version) {
          sb.className = 'click upd'; sb.textContent = '⟳ Get app ' + latest.version; sb.title = 'Download the new installer and run it: it updates the installed app.';
          sb.onclick = () => { location.href = '/download/EZLARP-Setup.exe'; toast('run EZLARP-Setup.exe when it finishes downloading, then choose Yes to update', 6000); };
          lastNote = 'EZLARP app ' + latest.version + ' is available. This version updates through the installer once; after that it updates itself.';
        } else { sb.className = 'click'; sb.textContent = 'app ' + p.version; sb.onclick = () => checkUpdate(true); }
      } else {
        sb.className = 'click'; sb.textContent = 'app ' + p.version; sb.title = 'EZLARP app version';
        sb.onclick = () => checkUpdate(true);
        if (loud === true) toast(u ? 'the EZLARP app is up to date (' + p.version + ')' : 'this app version can\'t update itself: download the new installer from ezlarp.pages.dev', 4000);
      }
    } catch (e) { if (loud === true) appHelperDown(); }
  }
  async function applyUpdate() {
    const sb = $('#sbapp');
    sb.textContent = '⟳ Updating…'; sb.onclick = null;
    try {
      const r = await fetch(APP_HELPER + '/update', { method: 'POST', headers: { 'X-EZLARP-Token': App.token } });
      if (!r.ok) throw new Error(await r.text());
      for (let i = 0; i < 40; i++) {
        await new Promise(res => setTimeout(res, 500));
        try { const p = await appFetch('/ping').then(x => x.json()); if (p.version === appInfo.latest) { toast('EZLARP app updated to ' + p.version, 4000); lastNote = 'Updated to ' + p.version + '.'; return checkUpdate(false); } } catch (e) { /* restarting */ }
      }
      throw new Error('the app didn\'t come back after updating; restart it from the Start menu');
    } catch (e) {
      toast('update failed: ' + (e.message || e), 6000);
      checkUpdate(false);
    }
  }
  if (App.on) { setTimeout(() => checkUpdate(), 1500); setInterval(() => checkUpdate(false), 3 * 3600 * 1000); }

  // ---------------------------------------------------------------- keys
  window.addEventListener('keydown', e => {
    const mod = e.ctrlKey || e.metaKey, k = e.key.toLowerCase();
    const pal = document.getElementById('idepal');
    if (e.key === 'Escape') { closeMenus(); if (pal) pal.remove(); document.querySelectorAll('.ide-dlg').forEach(d => d.remove()); return; }
    if (mod && e.shiftKey && k === 'p') { e.preventDefault(); palette('>'); }
    else if (mod && !e.shiftKey && k === 'p') { e.preventDefault(); palette(''); }
    else if (mod && e.shiftKey && k === 'o') { e.preventDefault(); palette('@'); }
    else if (mod && !e.shiftKey && k === 'g') { e.preventDefault(); palette(':'); }
    else if (mod && !e.shiftKey && k === 'o') { e.preventDefault(); el.file.click(); }
    else if (mod && !e.shiftKey && k === 'b') { e.preventDefault(); document.body.classList.toggle('ide-noside'); requestAnimationFrame(drawMini); }
    else if (mod && !e.shiftKey && k === 'j') { e.preventDefault(); togglePanel(); }
    else if (mod && e.shiftKey && k === 'e') { e.preventDefault(); activity('source'); }
    else if (mod && e.shiftKey && k === 'x') { e.preventDefault(); if (!el.dl.hidden) el.dl.click(); }
    else if (mod && k === ',') { e.preventDefault(); settings(); }
    else if (mod && (k === '=' || k === '+')) { e.preventDefault(); zoom(1); }
    else if (mod && k === '-') { e.preventDefault(); zoom(-1); }
    else if (mod && k === '0') { e.preventDefault(); zoom(0); }
    else if (e.altKey && k === 'z') { e.preventDefault(); el.wrap.click(); }
  }, true);

  syncAct(); syncTitle(); syncStatus(); renderPanel();
  return { on: true, palette, activity, showWelcome };
})();
