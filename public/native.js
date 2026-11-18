// EZLARP native code view: walks a Windows PE from its entry point and exports, follows calls,
// and prints an x86/x64 listing with Windows API names and referenced strings filled in.
'use strict';
const Native = (() => {
  const hx = (n, w = 0) => n.toString(16).padStart(w, '0');

  function parse(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const e = dv.getUint32(0x3c, true);
    if (dv.getUint32(e, true) !== 0x4550) throw new Error('not a PE file');
    const machine = dv.getUint16(e + 4, true);
    const nsec = dv.getUint16(e + 6, true), optSize = dv.getUint16(e + 20, true), opt = e + 24;
    const x64 = dv.getUint16(opt, true) === 0x20b;
    const entry = dv.getUint32(opt + 16, true);
    const base = x64 ? Number(dv.getBigUint64(opt + 24, true)) : dv.getUint32(opt + 28, true);
    const dd = opt + (x64 ? 112 : 96);
    const dir = i => ({ rva: dv.getUint32(dd + i * 8, true), size: dv.getUint32(dd + i * 8 + 4, true) });
    const secs = [];
    for (let i = 0, s = opt + optSize; i < nsec; i++, s += 40) {
      let name = ''; for (let k = 0; k < 8 && u8[s + k]; k++) name += String.fromCharCode(u8[s + k]);
      secs.push({ name, va: dv.getUint32(s + 12, true), vsize: dv.getUint32(s + 8, true), raw: dv.getUint32(s + 20, true), rsize: dv.getUint32(s + 16, true), ch: dv.getUint32(s + 36, true) });
    }
    const secOf = rva => secs.find(s => rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize));
    const off = rva => { const s = secOf(rva); if (!s) return rva < (secs[0] ? secs[0].raw : 0x400) ? rva : -1; const o = rva - s.va; return o < s.rsize ? s.raw + o : -1; };
    const cstr = (o, max = 256) => { let r = ''; for (let i = 0; i < max && o + i < u8.length && u8[o + i]; i++) r += String.fromCharCode(u8[o + i]); return r; };
    const P = { u8, dv, x64, machine, entry, base, secs, secOf, off, imports: new Map(), exports: [], importList: [] };
    // imports: IAT slot address -> "dll!name"
    const imp = dir(1);
    if (imp.rva) {
      for (let d = off(imp.rva), n = 0; d > 0 && d + 20 <= u8.length && n < 512; d += 20, n++) {
        const ilt = dv.getUint32(d, true), nameRva = dv.getUint32(d + 12, true), iat = dv.getUint32(d + 16, true);
        if (!nameRva && !iat) break;
        const dll = cstr(off(nameRva)).toLowerCase();
        const step = x64 ? 8 : 4;
        let t = off(ilt || iat);
        for (let k = 0; t > 0 && t + step <= u8.length && k < 4096; k++, t += step) {
          const v = x64 ? dv.getBigUint64(t, true) : BigInt(dv.getUint32(t, true));
          if (!v) break;
          const ord = x64 ? v >> 63n : (v >> 31n) & 1n;
          let fn;
          if (ord) fn = '#' + Number(v & 0xffffn);
          else { const h = off(Number(v & 0x7fffffffn)); fn = h > 0 ? cstr(h + 2) : '?'; }
          const slot = base + iat + k * step;
          P.imports.set(slot, dll + '!' + fn);
          P.importList.push({ dll, fn, slot });
        }
      }
    }
    // exports
    const ex = dir(0);
    if (ex.rva && off(ex.rva) > 0) {
      const o = off(ex.rva);
      const nFn = dv.getUint32(o + 20, true), nNames = dv.getUint32(o + 24, true);
      const fns = off(dv.getUint32(o + 28, true)), names = off(dv.getUint32(o + 32, true)), ords = off(dv.getUint32(o + 36, true));
      const named = new Map();
      for (let i = 0; i < nNames && i < 20000 && names > 0; i++) named.set(dv.getUint16(ords + i * 2, true), cstr(off(dv.getUint32(names + i * 4, true))));
      for (let i = 0; i < nFn && i < 20000 && fns > 0; i++) {
        const rva = dv.getUint32(fns + i * 4, true);
        if (!rva || (rva >= ex.rva && rva < ex.rva + ex.size)) continue; // forwarded
        P.exports.push({ name: named.get(i) || 'ordinal_' + (i + dv.getUint32(o + 16, true)), rva });
      }
    }
    P.tls = [];
    const tls = dir(9);
    if (tls.rva && off(tls.rva) > 0) {
      const o = off(tls.rva);
      const cb = x64 ? Number(dv.getBigUint64(o + 24, true)) : dv.getUint32(o + 12, true);
      const co = cb ? off(cb - base) : -1;
      for (let k = 0; co > 0 && k < 16; k++) {
        const v = x64 ? Number(dv.getBigUint64(co + k * 8, true)) : dv.getUint32(co + k * 4, true);
        if (!v) break;
        P.tls.push(v - base);
      }
    }
    return P;
  }

  // printable string at a virtual address (ASCII or UTF-16LE), for comments
  function stringAt(P, va) {
    const o = P.off(va - P.base);
    if (o < 0) return null;
    const u8 = P.u8;
    let a = '';
    for (let i = 0; i < 200 && o + i < u8.length; i++) { const c = u8[o + i]; if (c === 0) break; if (c < 32 && c !== 9 && c !== 10 && c !== 13 || c > 126) { a = null; break; } a += String.fromCharCode(c); }
    if (a && a.length >= 4) return JSON.stringify(a);
    let w = '';
    for (let i = 0; i < 400 && o + i + 1 < u8.length; i += 2) { const c = u8[o + i] | (u8[o + i + 1] << 8); if (c === 0) break; if (c < 32 && c !== 9 && c !== 10 && c !== 13 || c > 0xfffd) { w = null; break; } w += String.fromCharCode(c); }
    if (w && w.length >= 3) return 'L' + JSON.stringify(w);
    return null;
  }

  const isExec = s => s && (s.ch & 0x20000000 || s.ch & 0x20);

  // recursive descent over functions; returns ordered function list with instructions
  function analyze(P, opts = {}) {
    const maxFuncs = opts.maxFuncs || 400, maxIns = opts.maxIns || 60000;
    const { u8, base, x64 } = P;
    const funcs = new Map(); // va -> { va, name, ins: Map(va -> insn) }
    const queue = [];
    const names = new Map();
    const addFunc = (va, name) => {
      if (funcs.has(va) || funcs.size >= maxFuncs) { if (name && !names.has(va)) names.set(va, name); return; }
      if (!isExec(P.secOf(va - base))) return;
      funcs.set(va, { va, name: name || null, ins: new Map(), targets: new Set() });
      if (name) names.set(va, name);
      queue.push(va);
    };
    addFunc(base + P.entry, 'start');
    for (const t of P.tls) addFunc(base + t, 'tls_callback');
    for (const e of P.exports) addFunc(base + e.rva, e.name);
    let total = 0;
    while (queue.length && total < maxIns) {
      const fva = queue.shift();
      const f = funcs.get(fva);
      const work = [fva];
      const seen = new Set();
      let count = 0;
      while (work.length && count < 8000 && total < maxIns) {
        let va = work.pop();
        while (!seen.has(va)) {
          const o = P.off(va - base);
          if (o < 0 || !isExec(P.secOf(va - base))) break;
          seen.add(va);
          const r = X86.decode(u8, o, va, x64);
          r.va = va;
          f.ins.set(va, r);
          count++; total++;
          const mn = r.mn.replace(/^(bnd|lock|rep|repz|repnz) /, '');
          if (r.target != null) {
            if (mn === 'call') addFunc(r.target);
            else {
              f.targets.add(r.target);
              if (!seen.has(r.target)) work.push(r.target);
            }
          }
          // call [import]
          const slot = r.rip != null ? r.rip : r.abs;
          if ((mn === 'call' || mn === 'jmp') && slot != null && P.imports.has(slot)) r.api = P.imports.get(slot);
          if (mn === 'call' && r.target != null && r.target !== va + r.len) { /* falls through after the call */ }
          if (/^(ret|retf|iret|int3|hlt|ud2|jmp)$/.test(mn) || r.mn === '(bad)') {
            // jmp [import] at the very start of a function: thunk
            if (mn === 'jmp' && r.api && va === fva && !f.name) names.set(fva, 'j_' + r.api.split('!')[1]);
            if (mn === 'jmp' && r.target != null && f.targets.size === 0 && va === fva) { /* tail jump */ }
            break;
          }
          va += r.len;
        }
      }
    }
    // name the thunks to imports: a function that is a single "jmp [iat]"
    for (const f of funcs.values()) {
      if (!f.name && names.has(f.va)) f.name = names.get(f.va);
      if (!f.name) f.name = 'sub_' + hx(f.va);
    }
    return { funcs, names };
  }

  function listing(u8, opts = {}) {
    const P = parse(u8);
    const { funcs, names } = analyze(P, opts);
    const out = [];
    const bits = P.x64 ? 64 : 32;
    out.push(`; EZLARP native view · ${bits}-bit x86 · image base 0x${hx(P.base)} · entry 0x${hx(P.base + P.entry)}`);
    out.push(`; ${funcs.size} functions found by following calls from the entry point${P.exports.length ? ' and exports' : ''}. Code reached only`);
    out.push('; through pointers (callbacks, vtables) is not shown. Calls to Windows APIs and string references are labelled.');
    out.push('');
    const ordered = [...funcs.values()];
    for (const f of ordered) {
      let list = [...f.ins.values()].sort((a, b) => a.va - b.va);
      if (!list.length) continue;
      // start the listing at the function's entry; pieces placed below it follow after
      const at0 = list.findIndex(r => r.va >= f.va);
      if (at0 > 0) list = list.slice(at0).concat(list.slice(0, at0));
      out.push('');
      out.push(`${f.name} proc    ; 0x${hx(f.va)}`);
      for (const r of list) {
        if (f.targets.has(r.va) && r.va !== f.va) out.push(`loc_${hx(r.va)}:`);
        let ops = r.ops;
        let note = '';
        if (r.target != null) {
          const n = names.get(r.target) || (funcs.has(r.target) ? funcs.get(r.target).name : f.targets.has(r.target) ? 'loc_' + hx(r.target) : null);
          if (n) ops = n;
        }
        if (r.api) note = r.api;
        else {
          const ref = r.rip != null ? r.rip : r.abs != null ? r.abs : (r.imm != null && r.imm > P.base && r.imm < P.base + 0x10000000 ? r.imm : null);
          if (ref != null) {
            if (P.imports.has(ref)) note = P.imports.get(ref);
            else if (names.has(ref)) note = names.get(ref);
            else { const s = stringAt(P, ref); if (s) note = s.length > 120 ? s.slice(0, 117) + '…"' : s; }
          }
        }
        let line = `    ${hx(r.va, P.x64 ? 12 : 8)}  ${r.mn.padEnd(8)} ${ops}`;
        if (note) line = line.padEnd(60) + ' ; ' + note;
        out.push(line);
      }
      out.push(`${f.name} endp`);
    }
    return out.join('\n') + '\n';
  }

  function importsText(u8) {
    const P = parse(u8);
    const by = new Map();
    for (const i of P.importList) { if (!by.has(i.dll)) by.set(i.dll, []); by.get(i.dll).push(i.fn); }
    const out = [`; ${P.importList.length} imported functions from ${by.size} DLLs`, ''];
    for (const [dll, fns] of [...by].sort()) { out.push(dll); for (const f of fns.sort()) out.push('    ' + f); out.push(''); }
    if (P.exports.length) {
      out.push(`; ${P.exports.length} exported functions`);
      for (const e of P.exports) out.push('    ' + e.name + '  ; 0x' + hx(P.base + e.rva));
    }
    return out.join('\n') + '\n';
  }

  return { parse, listing, importsText };
})();
if (typeof module !== 'undefined') module.exports = Native;
