// EZLARP .NET decompiler: reads the CLI metadata of a .NET exe/dll and turns the IL into C#.
// Everything runs in the browser. Output is readable C#, not always compilable: control flow the
// structurer can't map to if/else/while stays as goto.
'use strict';
const Cil = (() => {
  const td = new TextDecoder('utf-8'), td16 = new TextDecoder('utf-16le');

  // ------------------------------------------------------------------ PE + metadata
  function load(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const e = dv.getUint32(0x3c, true);
    if (dv.getUint32(e, true) !== 0x4550) throw new Error('not a PE file');
    const nsec = dv.getUint16(e + 6, true), optSize = dv.getUint16(e + 20, true), opt = e + 24;
    const pe32p = dv.getUint16(opt, true) === 0x20b;
    const dd = opt + (pe32p ? 112 : 96);
    const secs = [];
    for (let i = 0, s = opt + optSize; i < nsec; i++, s += 40) {
      secs.push({ va: dv.getUint32(s + 12, true), vsize: dv.getUint32(s + 8, true), raw: dv.getUint32(s + 20, true), rsize: dv.getUint32(s + 16, true) });
    }
    const rva = r => {
      for (const s of secs) if (r >= s.va && r < s.va + Math.max(s.vsize, s.rsize)) return r - s.va + s.raw;
      return r < u8.length ? r : -1;
    };
    const clrRva = dv.getUint32(dd + 14 * 8, true);
    if (!clrRva) throw new Error('no .NET header');
    const clr = rva(clrRva);
    const mdOff = rva(dv.getUint32(clr + 8, true));
    const flags = dv.getUint32(clr + 16, true);
    const entryTok = dv.getUint32(clr + 20, true);
    const resRva = dv.getUint32(clr + 24, true), resSize = dv.getUint32(clr + 28, true);
    if (dv.getUint32(mdOff, true) !== 0x424a5342) throw new Error('bad metadata signature');
    const vlen = dv.getUint32(mdOff + 12, true);
    const version = td.decode(u8.subarray(mdOff + 16, mdOff + 16 + vlen)).replace(/\0.*$/s, '');
    let p = mdOff + 16 + vlen + 2;
    const nstreams = dv.getUint16(p, true); p += 2;
    const streams = {};
    for (let i = 0; i < nstreams; i++) {
      const off = dv.getUint32(p, true), size = dv.getUint32(p + 4, true);
      let n = p + 8, name = '';
      while (u8[n] && name.length < 32) name += String.fromCharCode(u8[n++]);
      p = (n + 4) & ~3;
      if (!streams[name]) streams[name] = { off: mdOff + off, size }; // obfuscators add decoy streams later on
    }
    const A = { u8, dv, rva, version, flags, entryTok, streams, ilOnly: !!(flags & 1) };
    A.strings = streams['#Strings'] || { off: 0, size: 0 };
    A.us = streams['#US'] || { off: 0, size: 0 };
    A.blob = streams['#Blob'] || { off: 0, size: 0 };
    A.guid = streams['#GUID'] || { off: 0, size: 0 };
    A.res = resRva ? { off: rva(resRva), size: resSize } : null;
    readTables(A, streams['#~'] || streams['#-']);
    index(A);
    return A;
  }

  // table schemas (ECMA-335 II.22). Column kinds: 2/4 fixed, 's' string, 'g' guid, 'b' blob,
  // a number >= 100 is "index into table N-100", a string 'c:NAME' is a coded index.
  const T = {
    0x00: ['Module', [2, 's', 'g', 'g', 'g']],
    0x01: ['TypeRef', ['c:ResScope', 's', 's']],
    0x02: ['TypeDef', [4, 's', 's', 'c:TDOR', 104, 106]],
    0x03: ['FieldPtr', [104]],
    0x04: ['Field', [2, 's', 'b']],
    0x05: ['MethodPtr', [106]],
    0x06: ['MethodDef', [4, 2, 2, 's', 'b', 108]],
    0x07: ['ParamPtr', [108]],
    0x08: ['Param', [2, 2, 's']],
    0x09: ['InterfaceImpl', [102, 'c:TDOR']],
    0x0a: ['MemberRef', ['c:MRP', 's', 'b']],
    0x0b: ['Constant', [2, 'c:HasConst', 'b']],
    0x0c: ['CustomAttribute', ['c:HasCA', 'c:CAType', 'b']],
    0x0d: ['FieldMarshal', ['c:HasFM', 'b']],
    0x0e: ['DeclSecurity', [2, 'c:HasDS', 'b']],
    0x0f: ['ClassLayout', [2, 4, 102]],
    0x10: ['FieldLayout', [4, 104]],
    0x11: ['StandAloneSig', ['b']],
    0x12: ['EventMap', [102, 120]],
    0x13: ['EventPtr', [120]],
    0x14: ['Event', [2, 's', 'c:TDOR']],
    0x15: ['PropertyMap', [102, 123]],
    0x16: ['PropertyPtr', [123]],
    0x17: ['Property', [2, 's', 'b']],
    0x18: ['MethodSemantics', [2, 106, 'c:HasSem']],
    0x19: ['MethodImpl', [102, 'c:MDOR', 'c:MDOR']],
    0x1a: ['ModuleRef', ['s']],
    0x1b: ['TypeSpec', ['b']],
    0x1c: ['ImplMap', [2, 'c:MemFwd', 's', 126]],
    0x1d: ['FieldRVA', [4, 104]],
    0x1e: ['EncLog', [4, 4]],
    0x1f: ['EncMap', [4]],
    0x20: ['Assembly', [4, 2, 2, 2, 2, 4, 'b', 's', 's']],
    0x21: ['AssemblyProcessor', [4]],
    0x22: ['AssemblyOS', [4, 4, 4]],
    0x23: ['AssemblyRef', [2, 2, 2, 2, 4, 'b', 's', 's', 'b']],
    0x24: ['AssemblyRefProcessor', [4, 135]],
    0x25: ['AssemblyRefOS', [4, 4, 4, 135]],
    0x26: ['File', [4, 's', 'b']],
    0x27: ['ExportedType', [4, 4, 's', 's', 'c:Impl']],
    0x28: ['ManifestResource', [4, 4, 's', 'c:Impl']],
    0x29: ['NestedClass', [102, 102]],
    0x2a: ['GenericParam', [2, 2, 'c:TOMD', 's']],
    0x2b: ['MethodSpec', ['c:MDOR', 'b']],
    0x2c: ['GenericParamConstraint', [142, 'c:TDOR']],
  };
  const CODED = {
    TDOR: [0x02, 0x01, 0x1b],
    HasConst: [0x04, 0x08, 0x17],
    HasCA: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
    HasFM: [0x04, 0x08],
    HasDS: [0x02, 0x06, 0x20],
    MRP: [0x02, 0x01, 0x1a, 0x06, 0x1b],
    HasSem: [0x14, 0x17],
    MDOR: [0x06, 0x0a],
    MemFwd: [0x04, 0x06],
    Impl: [0x26, 0x23, 0x27],
    CAType: [-1, -1, 0x06, 0x0a, -1],
    ResScope: [0x00, 0x1a, 0x23, 0x01],
    TOMD: [0x02, 0x06],
  };

  function readTables(A, st) {
    if (!st) throw new Error('no metadata tables');
    const { u8, dv } = A;
    let p = st.off + 6;
    const heap = u8[p]; p += 2;
    const valid = dv.getBigUint64(p, true); p += 16;
    const rows = new Array(64).fill(0);
    for (let i = 0; i < 64; i++) if ((valid >> BigInt(i)) & 1n) { rows[i] = dv.getUint32(p, true); p += 4; }
    if (heap & 0x40) p += 4; // extra data
    const strW = heap & 1 ? 4 : 2, guidW = heap & 2 ? 4 : 2, blobW = heap & 4 ? 4 : 2;
    const codedW = {};
    for (const [k, tabs] of Object.entries(CODED)) {
      const bits = Math.ceil(Math.log2(tabs.length));
      const max = Math.max(...tabs.map(t => t >= 0 ? rows[t] : 0));
      codedW[k] = max < (1 << (16 - bits)) ? 2 : 4;
    }
    const colW = c => c === 2 || c === 4 ? c : c === 's' ? strW : c === 'g' ? guidW : c === 'b' ? blobW
      : typeof c === 'number' ? (rows[c - 100] < 0x10000 ? 2 : 4) : codedW[c.slice(2)];
    A.rows = rows;
    A.tables = {};
    for (let t = 0; t < 64; t++) {
      if (!rows[t]) continue;
      const sch = T[t];
      if (!sch) throw new Error('unknown metadata table 0x' + t.toString(16));
      const cols = sch[1], widths = cols.map(colW);
      const rowSize = widths.reduce((a, b) => a + b, 0);
      const list = new Array(rows[t] + 1);
      for (let r = 1; r <= rows[t]; r++) {
        const row = new Array(cols.length);
        let q = p;
        for (let c = 0; c < cols.length; c++) {
          const w = widths[c];
          let v = q + w <= u8.length ? (w === 2 ? dv.getUint16(q, true) : dv.getUint32(q, true)) : 0;
          const kind = cols[c];
          if (typeof kind === 'string' && kind.startsWith('c:')) {
            const tabs = CODED[kind.slice(2)], bits = Math.ceil(Math.log2(tabs.length));
            v = { t: tabs[v & ((1 << bits) - 1)], r: v >>> bits };
          }
          row[c] = v;
          q += w;
        }
        list[r] = row;
        p += rowSize;
      }
      A.tables[sch[0]] = list;
    }
    A.n = name => A.rows[Object.keys(T).find(k => T[k][0] === name)] || 0;
  }

  const str = (A, i) => {
    if (!i || i >= A.strings.size) return '';
    const s = A.strings.off + i;
    let e = s;
    while (A.u8[e] && e - s < 4096) e++;
    return td.decode(A.u8.subarray(s, e));
  };
  function blobAt(A, i) {
    let p = A.blob.off + i;
    const b = A.u8[p];
    let len;
    if ((b & 0x80) === 0) { len = b; p += 1; } else if ((b & 0xc0) === 0x80) { len = ((b & 0x3f) << 8) | A.u8[p + 1]; p += 2; } else { len = ((b & 0x1f) << 24) | (A.u8[p + 1] << 16) | (A.u8[p + 2] << 8) | A.u8[p + 3]; p += 4; }
    return A.u8.subarray(p, Math.min(p + len, A.u8.length));
  }
  function userString(A, i) {
    let p = A.us.off + i;
    const b = A.u8[p];
    let len;
    if ((b & 0x80) === 0) { len = b; p += 1; } else if ((b & 0xc0) === 0x80) { len = ((b & 0x3f) << 8) | A.u8[p + 1]; p += 2; } else { len = ((b & 0x1f) << 24) | (A.u8[p + 1] << 16) | (A.u8[p + 2] << 8) | A.u8[p + 3]; p += 4; }
    if (len > 0) len -= 1; // trailing flag byte
    return td16.decode(A.u8.subarray(p, Math.min(p + (len & ~1), A.u8.length)));
  }

  // ------------------------------------------------------------------ indexes: members per type
  function index(A) {
    const t = A.tables;
    const ptr = (name, i) => t[name] ? t[name][i][0] : i;
    const typeN = A.n('TypeDef'), fieldN = A.n('Field'), methN = A.n('MethodDef'), paramN = A.n('Param');
    A.types = [];
    for (let i = 1; i <= typeN; i++) {
      const r = t.TypeDef[i];
      const fEnd = i < typeN ? t.TypeDef[i + 1][4] : (t.FieldPtr ? A.n('FieldPtr') : fieldN) + 1;
      const mEnd = i < typeN ? t.TypeDef[i + 1][5] : (t.MethodPtr ? A.n('MethodPtr') : methN) + 1;
      const fields = [], methods = [];
      for (let f = r[4]; f < fEnd && f <= (t.FieldPtr ? A.n('FieldPtr') : fieldN); f++) fields.push(ptr('FieldPtr', f));
      for (let m = r[5]; m < mEnd && m <= (t.MethodPtr ? A.n('MethodPtr') : methN); m++) methods.push(ptr('MethodPtr', m));
      A.types[i] = { i, flags: r[0], name: str(A, r[1]), ns: str(A, r[2]), ext: r[3], fields, methods, nested: [], props: [], events: [], ifaces: [], gparams: [] };
    }
    A.methodOwner = new Map(); A.fieldOwner = new Map();
    for (let i = 1; i <= typeN; i++) {
      for (const m of A.types[i].methods) A.methodOwner.set(m, i);
      for (const f of A.types[i].fields) A.fieldOwner.set(f, i);
    }
    A.methods = [];
    for (let m = 1; m <= methN; m++) {
      const r = t.MethodDef[m];
      const pEnd = m < methN ? t.MethodDef[m + 1][5] : (t.ParamPtr ? A.n('ParamPtr') : paramN) + 1;
      const params = [];
      for (let q = r[5]; q < pEnd && q <= (t.ParamPtr ? A.n('ParamPtr') : paramN); q++) {
        const pr = t.Param[ptr('ParamPtr', q)];
        if (pr) params.push({ flags: pr[0], seq: pr[1], name: str(A, pr[2]) });
      }
      A.methods[m] = { i: m, rva: r[0], implFlags: r[1], flags: r[2], name: str(A, r[3]), sig: r[4], params, gparams: [] };
    }
    for (let i = 1; i <= A.n('NestedClass'); i++) {
      const [inner, outer] = t.NestedClass[i];
      if (A.types[inner] && A.types[outer]) { A.types[inner].outer = outer; A.types[outer].nested.push(inner); }
    }
    for (let i = 1; i <= A.n('InterfaceImpl'); i++) { const [c, iface] = t.InterfaceImpl[i]; if (A.types[c]) A.types[c].ifaces.push(iface); }
    for (let i = 1; i <= A.n('GenericParam'); i++) {
      const [num, , owner, name] = t.GenericParam[i];
      const o = owner.t === 0x02 ? A.types[owner.r] : A.methods[owner.r];
      if (o) o.gparams[num] = str(A, name);
    }
    // properties and events
    const mapped = (mapName, listName, ptrName, n, tgt) => {
      const mp = t[mapName];
      if (!mp) return;
      const count = A.n(mapName), total = t[ptrName] ? A.n(ptrName) : A.n(listName);
      for (let i = 1; i <= count; i++) {
        const end = i < count ? mp[i + 1][1] : total + 1;
        const ty = A.types[mp[i][0]];
        if (!ty) continue;
        for (let k = mp[i][1]; k < end && k <= total; k++) ty[tgt].push(ptr(ptrName, k));
      }
    };
    mapped('PropertyMap', 'Property', 'PropertyPtr', 0, 'props');
    mapped('EventMap', 'Event', 'EventPtr', 0, 'events');
    A.semByAssoc = new Map(); // "table:row" of a property/event -> [{ m, sem }]
    for (let i = 1; i <= A.n('MethodSemantics'); i++) {
      const [sem, m, assoc] = t.MethodSemantics[i];
      const k = assoc.t + ':' + assoc.r;
      if (!A.semByAssoc.has(k)) A.semByAssoc.set(k, []);
      A.semByAssoc.get(k).push({ m, sem });
    }
    A.constants = new Map();
    for (let i = 1; i <= A.n('Constant'); i++) {
      const [type, parent, val] = t.Constant[i];
      A.constants.set(parent.t + ':' + parent.r, { type: type & 0xff, blob: val });
    }
    A.implMap = new Map();
    for (let i = 1; i <= A.n('ImplMap'); i++) {
      const [fl, fwd, name, scope] = t.ImplMap[i];
      if (fwd.t === 0x06) A.implMap.set(fwd.r, { name: str(A, name), dll: t.ModuleRef && t.ModuleRef[scope] ? str(A, t.ModuleRef[scope][0]) : '?' });
    }
    A.fieldRva = new Map();
    for (let i = 1; i <= A.n('FieldRVA'); i++) A.fieldRva.set(t.FieldRVA[i][1], t.FieldRVA[i][0]);
    A.classSize = new Map();
    for (let i = 1; i <= A.n('ClassLayout'); i++) A.classSize.set(t.ClassLayout[i][2], t.ClassLayout[i][1]);
    A.cattrs = new Map(); // "table:row" -> [[typeIndex, blob]]
    for (let i = 1; i <= A.n('CustomAttribute'); i++) {
      const [parent, type, val] = t.CustomAttribute[i];
      const k = parent.t + ':' + parent.r;
      if (!A.cattrs.has(k)) A.cattrs.set(k, []);
      A.cattrs.get(k).push({ ctor: type, blob: val });
    }
  }

  // ------------------------------------------------------------------ names and signatures
  const ALIAS = { 'System.Void': 'void', 'System.Boolean': 'bool', 'System.Char': 'char', 'System.SByte': 'sbyte', 'System.Byte': 'byte', 'System.Int16': 'short',
    'System.UInt16': 'ushort', 'System.Int32': 'int', 'System.UInt32': 'uint', 'System.Int64': 'long', 'System.UInt64': 'ulong', 'System.Single': 'float',
    'System.Double': 'double', 'System.String': 'string', 'System.Object': 'object', 'System.Decimal': 'decimal', 'System.IntPtr': 'IntPtr', 'System.UIntPtr': 'UIntPtr' };
  const PRIM = { 0x01: 'void', 0x02: 'bool', 0x03: 'char', 0x04: 'sbyte', 0x05: 'byte', 0x06: 'short', 0x07: 'ushort', 0x08: 'int', 0x09: 'uint', 0x0a: 'long',
    0x0b: 'ulong', 0x0c: 'float', 0x0d: 'double', 0x0e: 'string', 0x16: 'TypedReference', 0x18: 'IntPtr', 0x19: 'UIntPtr', 0x1c: 'object' };
  const clean = s => s.replace(/`\d+$/, '').replace(/[\x00-\x1f\x7f]/g, c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));

  // full name parts of a TypeDef/TypeRef: { ns, name (with outer types joined by '.'), full }
  function typeInfo(A, tab, row) {
    const t = A.tables;
    if (tab === 0x02) {
      const ty = A.types[row];
      if (!ty) return { ns: '', name: '?', full: '?' };
      if (ty.outer) { const o = typeInfo(A, 0x02, ty.outer); return { ns: o.ns, name: o.name + '.' + clean(ty.name), full: o.full + '.' + ty.name, def: row }; }
      return { ns: ty.ns, name: clean(ty.name), full: (ty.ns ? ty.ns + '.' : '') + ty.name, def: row };
    }
    if (tab === 0x01) {
      const r = t.TypeRef && t.TypeRef[row];
      if (!r) return { ns: '', name: '?', full: '?' };
      const name = str(A, r[1]), ns = str(A, r[2]);
      if (r[0].t === 0x01 && r[0].r && r[0].r !== row) { const o = typeInfo(A, 0x01, r[0].r); return { ns: o.ns, name: o.name + '.' + clean(name), full: o.full + '.' + name }; }
      return { ns, name: clean(name), full: (ns ? ns + '.' : '') + name };
    }
    return { ns: '', name: '?', full: '?' };
  }

  class Sig {
    constructor(b) { this.b = b; this.p = 0; }
    u() {
      const b = this.b, p = this.p, x = b[p];
      if ((x & 0x80) === 0) { this.p += 1; return x; }
      if ((x & 0xc0) === 0x80) { this.p += 2; return ((x & 0x3f) << 8) | b[p + 1]; }
      this.p += 4; return (((x & 0x1f) << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
    }
    tdor() { const v = this.u(); return { t: [0x02, 0x01, 0x1b][v & 3], r: v >>> 2 }; }
    get end() { return this.p >= this.b.length; }
  }

  // Ctx: what the renderer knows (generic names, current type, collected usings)
  function readType(A, s, ctx, depth = 0) {
    if (depth > 40 || s.end) return { s: '?', k: 'x' };
    const et = s.b[s.p++];
    if (PRIM[et]) return { s: PRIM[et], k: 'p', full: 'System.' + ({ void: 'Void', bool: 'Boolean', string: 'String', object: 'Object', int: 'Int32' }[PRIM[et]] || PRIM[et]) };
    switch (et) {
      case 0x0f: { const x = readType(A, s, ctx, depth + 1); return { s: x.s + '*', k: 'ptr' }; }
      case 0x10: { const x = readType(A, s, ctx, depth + 1); return { s: x.s, k: x.k, byref: true, full: x.full }; }
      case 0x11: case 0x12: { const tr = s.tdor(); return typeRefName(A, tr, ctx, depth); }
      case 0x13: { const n = s.u(); return { s: (ctx && ctx.tgen && ctx.tgen[n]) || ('T' + n), k: 'g' }; }
      case 0x1e: { const n = s.u(); return { s: (ctx && ctx.mgen && ctx.mgen[n]) || ('M' + n), k: 'g' }; }
      case 0x14: {
        const x = readType(A, s, ctx, depth + 1);
        const rank = s.u(); const nsz = s.u(); for (let i = 0; i < nsz; i++) s.u(); const nlo = s.u(); for (let i = 0; i < nlo; i++) s.u();
        return { s: x.s + '[' + ','.repeat(Math.max(0, rank - 1)) + ']', k: 'arr', el: x };
      }
      case 0x1d: { const x = readType(A, s, ctx, depth + 1); return { s: x.s + '[]', k: 'arr', el: x }; }
      case 0x15: {
        const base = readType(A, s, ctx, depth + 1);
        const n = s.u(), args = [];
        for (let i = 0; i < n && i < 64; i++) args.push(readType(A, s, ctx, depth + 1).s);
        if (base.full === 'System.Nullable`1') return { s: args[0] + '?', k: 'c', full: base.full };
        return { s: base.s + '<' + args.join(', ') + '>', k: 'c', full: base.full };
      }
      case 0x1b: { readMethodSig(A, s, ctx); return { s: 'delegate*', k: 'p' }; }
      case 0x1f: case 0x20: { s.tdor(); return readType(A, s, ctx, depth + 1); }
      case 0x45: { const x = readType(A, s, ctx, depth + 1); return x; }
      case 0x41: return readType(A, s, ctx, depth + 1);
      default: return { s: '/*type 0x' + et.toString(16) + '*/', k: 'x' };
    }
  }
  function typeRefName(A, tr, ctx, depth = 0) {
    if (tr.t === 0x1b) {
      const r = A.tables.TypeSpec && A.tables.TypeSpec[tr.r];
      if (!r || depth > 20) return { s: '?', k: 'x' };
      return readType(A, new Sig(blobAt(A, r[0])), ctx, depth + 1);
    }
    const ti = typeInfo(A, tr.t, tr.r);
    if (ALIAS[ti.full]) return { s: ALIAS[ti.full], k: 'p', full: ti.full };
    if (ctx && ctx.usings && ti.ns && ti.ns !== ctx.ns) ctx.usings.add(ti.ns);
    return { s: ti.name, k: 'c', full: ti.full, def: ti.def };
  }
  function readMethodSig(A, s, ctx) {
    const flags = s.b[s.p++];
    let gen = 0;
    if (flags & 0x10) gen = s.u();
    const n = s.u();
    const ret = readType(A, s, ctx);
    const params = [];
    for (let i = 0; i < n && !s.end; i++) {
      if (s.b[s.p] === 0x41) { s.p++; }
      params.push(readType(A, s, ctx));
    }
    return { hasThis: !!(flags & 0x20), explicitThis: !!(flags & 0x40), gen, ret, params, conv: flags & 0x0f };
  }
  const methodSig = (A, blobIdx, ctx) => readMethodSig(A, new Sig(blobAt(A, blobIdx)), ctx);
  const fieldSig = (A, blobIdx, ctx) => { const s = new Sig(blobAt(A, blobIdx)); s.p++; return readType(A, s, ctx); };

  // resolve a token used by an instruction: method/field/type/string
  function member(A, tok, ctx) {
    const tab = tok >>> 24, row = tok & 0xffffff;
    const t = A.tables;
    if (tab === 0x06) {
      const m = A.methods[row]; if (!m) return null;
      const owner = A.methodOwner.get(row);
      const octx = { ...ctx, tgen: owner ? A.types[owner].gparams : [], mgen: m.gparams };
      return { kind: 'method', name: m.name, owner: typeRefName(A, { t: 0x02, r: owner || 0 }, ctx), ownerDef: owner, def: row, sig: methodSig(A, m.sig, octx) };
    }
    if (tab === 0x04) {
      const owner = A.fieldOwner.get(row);
      const f = t.Field[row]; if (!f) return null;
      return { kind: 'field', name: str(A, f[1]), owner: typeRefName(A, { t: 0x02, r: owner || 0 }, ctx), ownerDef: owner, def: row, type: fieldSig(A, f[2], ctx), static: !!(f[0] & 0x10) };
    }
    if (tab === 0x0a) {
      const r = t.MemberRef[row]; if (!r) return null;
      const blob = blobAt(A, r[2]);
      let owner;
      if (r[0].t === 0x06) owner = typeRefName(A, { t: 0x02, r: A.methodOwner.get(r[0].r) || 0 }, ctx);
      else if (r[0].t === 0x1a) owner = { s: '<Module>', k: 'c', full: '<Module>' };
      else owner = typeRefName(A, r[0], ctx);
      const name = str(A, r[1]);
      if (blob[0] === 0x06) { const s = new Sig(blob); s.p = 1; return { kind: 'field', name, owner, type: readType(A, s, ctx), ref: true }; }
      return { kind: 'method', name, owner, sig: readMethodSig(A, new Sig(blob), ctx), ref: true };
    }
    if (tab === 0x2b) {
      const r = t.MethodSpec[row]; if (!r) return null;
      const base = member(A, ((r[0].t === 0x06 ? 0x06 : 0x0a) << 24) | r[0].r, ctx);
      const s = new Sig(blobAt(A, r[1])); s.p++;
      const n = s.u(), args = [];
      for (let i = 0; i < n && i < 32; i++) args.push(readType(A, s, ctx).s);
      if (base) base.gargs = args;
      return base;
    }
    if (tab === 0x02 || tab === 0x01 || tab === 0x1b) return { kind: 'type', type: typeRefName(A, { t: tab, r: row }, ctx) };
    if (tab === 0x70) return { kind: 'string', value: userString(A, row) };
    if (tab === 0x11) {
      const r = t.StandAloneSig && t.StandAloneSig[row];
      return r ? { kind: 'sig', sig: methodSig(A, r[0], ctx) } : null;
    }
    return null;
  }
  // reference string for the scanner: "System/Net/WebClient.DownloadFile"
  function refKey(m) {
    if (!m || !m.owner || !m.owner.full) return null;
    return m.owner.full.replace(/`\d+/g, '').replace(/\./g, '/') + '.' + m.name;
  }

  // ------------------------------------------------------------------ method bodies + IL
  const OPS = {};
  const op = (code, name, arg = '') => { OPS[code] = { name, arg }; };
  'nop break ldarg.0 ldarg.1 ldarg.2 ldarg.3 ldloc.0 ldloc.1 ldloc.2 ldloc.3 stloc.0 stloc.1 stloc.2 stloc.3'.split(' ').forEach((n, i) => op(i, n));
  op(0x0e, 'ldarg.s', 'u8'); op(0x0f, 'ldarga.s', 'u8'); op(0x10, 'starg.s', 'u8'); op(0x11, 'ldloc.s', 'u8'); op(0x12, 'ldloca.s', 'u8'); op(0x13, 'stloc.s', 'u8');
  op(0x14, 'ldnull'); op(0x15, 'ldc.i4.m1');
  for (let i = 0; i <= 8; i++) op(0x16 + i, 'ldc.i4.' + i);
  op(0x1f, 'ldc.i4.s', 'i8'); op(0x20, 'ldc.i4', 'i32'); op(0x21, 'ldc.i8', 'i64'); op(0x22, 'ldc.r4', 'r4'); op(0x23, 'ldc.r8', 'r8');
  op(0x25, 'dup'); op(0x26, 'pop'); op(0x27, 'jmp', 'tok'); op(0x28, 'call', 'tok'); op(0x29, 'calli', 'tok'); op(0x2a, 'ret');
  'br brfalse brtrue beq bge bgt ble blt bne.un bge.un bgt.un ble.un blt.un'.split(' ').forEach((n, i) => { op(0x2b + i, n + '.s', 'br8'); op(0x38 + i, n, 'br32'); });
  op(0x45, 'switch', 'switch');
  'ldind.i1 ldind.u1 ldind.i2 ldind.u2 ldind.i4 ldind.u4 ldind.i8 ldind.i ldind.r4 ldind.r8 ldind.ref stind.ref stind.i1 stind.i2 stind.i4 stind.i8 stind.r4 stind.r8 add sub mul div div.un rem rem.un and or xor shl shr shr.un neg not conv.i1 conv.i2 conv.i4 conv.i8 conv.r4 conv.r8 conv.u4 conv.u8'
    .split(' ').forEach((n, i) => op(0x46 + i, n));
  op(0x6f, 'callvirt', 'tok'); op(0x70, 'cpobj', 'tok'); op(0x71, 'ldobj', 'tok'); op(0x72, 'ldstr', 'tok'); op(0x73, 'newobj', 'tok'); op(0x74, 'castclass', 'tok');
  op(0x75, 'isinst', 'tok'); op(0x76, 'conv.r.un'); op(0x79, 'unbox', 'tok'); op(0x7a, 'throw'); op(0x7b, 'ldfld', 'tok'); op(0x7c, 'ldflda', 'tok'); op(0x7d, 'stfld', 'tok');
  op(0x7e, 'ldsfld', 'tok'); op(0x7f, 'ldsflda', 'tok'); op(0x80, 'stsfld', 'tok'); op(0x81, 'stobj', 'tok');
  'conv.ovf.i1.un conv.ovf.i2.un conv.ovf.i4.un conv.ovf.i8.un conv.ovf.u1.un conv.ovf.u2.un conv.ovf.u4.un conv.ovf.u8.un conv.ovf.i.un conv.ovf.u.un'.split(' ').forEach((n, i) => op(0x82 + i, n));
  op(0x8c, 'box', 'tok'); op(0x8d, 'newarr', 'tok'); op(0x8e, 'ldlen'); op(0x8f, 'ldelema', 'tok');
  'ldelem.i1 ldelem.u1 ldelem.i2 ldelem.u2 ldelem.i4 ldelem.u4 ldelem.i8 ldelem.i ldelem.r4 ldelem.r8 ldelem.ref stelem.i stelem.i1 stelem.i2 stelem.i4 stelem.i8 stelem.r4 stelem.r8 stelem.ref'
    .split(' ').forEach((n, i) => op(0x90 + i, n));
  op(0xa3, 'ldelem', 'tok'); op(0xa4, 'stelem', 'tok'); op(0xa5, 'unbox.any', 'tok');
  'conv.ovf.i1 conv.ovf.u1 conv.ovf.i2 conv.ovf.u2 conv.ovf.i4 conv.ovf.u4 conv.ovf.i8 conv.ovf.u8'.split(' ').forEach((n, i) => op(0xb3 + i, n));
  op(0xc2, 'refanyval', 'tok'); op(0xc3, 'ckfinite'); op(0xc6, 'mkrefany', 'tok'); op(0xd0, 'ldtoken', 'tok');
  'conv.u2 conv.u1 conv.i conv.ovf.i conv.ovf.u add.ovf add.ovf.un mul.ovf mul.ovf.un sub.ovf sub.ovf.un endfinally'.split(' ').forEach((n, i) => op(0xd1 + i, n));
  op(0xdd, 'leave', 'br32'); op(0xde, 'leave.s', 'br8'); op(0xdf, 'stind.i'); op(0xe0, 'conv.u');
  const op2 = (code, name, arg = '') => { OPS[0xfe00 | code] = { name, arg }; };
  op2(0x00, 'arglist'); op2(0x01, 'ceq'); op2(0x02, 'cgt'); op2(0x03, 'cgt.un'); op2(0x04, 'clt'); op2(0x05, 'clt.un'); op2(0x06, 'ldftn', 'tok'); op2(0x07, 'ldvirtftn', 'tok');
  op2(0x09, 'ldarg', 'u16'); op2(0x0a, 'ldarga', 'u16'); op2(0x0b, 'starg', 'u16'); op2(0x0c, 'ldloc', 'u16'); op2(0x0d, 'ldloca', 'u16'); op2(0x0e, 'stloc', 'u16');
  op2(0x0f, 'localloc'); op2(0x11, 'endfilter'); op2(0x12, 'unaligned.', 'u8'); op2(0x13, 'volatile.'); op2(0x14, 'tail.'); op2(0x15, 'initobj', 'tok');
  op2(0x16, 'constrained.', 'tok'); op2(0x17, 'cpblk'); op2(0x18, 'initblk'); op2(0x19, 'no.', 'u8'); op2(0x1a, 'rethrow'); op2(0x1c, 'sizeof', 'tok'); op2(0x1d, 'refanytype'); op2(0x1e, 'readonly.');

  function body(A, m) {
    if (!m.rva) return null;
    const { u8, dv } = A;
    const p = A.rva(m.rva);
    if (p < 0 || p >= u8.length) return null;
    const b = u8[p];
    let code, maxStack = 8, localTok = 0, eh = [], hdr;
    if ((b & 3) === 2) { hdr = 1; code = u8.subarray(p + 1, p + 1 + (b >> 2)); }
    else if ((b & 3) === 3) {
      const fl = dv.getUint16(p, true);
      hdr = (fl >> 12) * 4;
      maxStack = dv.getUint16(p + 2, true);
      const size = dv.getUint32(p + 4, true);
      localTok = dv.getUint32(p + 8, true);
      if (p + hdr + size > u8.length) return null;
      code = u8.subarray(p + hdr, p + hdr + size);
      if (fl & 0x08) {
        let q = (p + hdr + size + 3) & ~3;
        for (let guard = 0; guard < 16 && q < u8.length; guard++) {
          const kind = u8[q];
          const fat = kind & 0x40;
          const dsize = fat ? (u8[q + 1] | (u8[q + 2] << 8) | (u8[q + 3] << 16)) : u8[q + 1];
          if (kind & 1) {
            const n = fat ? Math.floor((dsize - 4) / 24) : Math.floor((dsize - 4) / 12);
            for (let i = 0; i < n; i++) {
              const c = q + 4 + i * (fat ? 24 : 12);
              if (c + (fat ? 24 : 12) > u8.length) break;
              eh.push(fat
                ? { flags: dv.getUint32(c, true), tryOff: dv.getUint32(c + 4, true), tryLen: dv.getUint32(c + 8, true), hOff: dv.getUint32(c + 12, true), hLen: dv.getUint32(c + 16, true), tok: dv.getUint32(c + 20, true) }
                : { flags: dv.getUint16(c, true), tryOff: dv.getUint16(c + 2, true), tryLen: u8[c + 4], hOff: dv.getUint16(c + 5, true), hLen: u8[c + 7], tok: dv.getUint32(c + 8, true) });
            }
          }
          if (!(kind & 0x80)) break;
          q = (q + dsize + 3) & ~3;
        }
      }
    } else return null;
    return { code, maxStack, localTok, eh };
  }

  function decode(code) {
    const out = [];
    const dv = new DataView(code.buffer, code.byteOffset, code.byteLength);
    let p = 0;
    while (p < code.length) {
      const off = p;
      let c = code[p++];
      if (c === 0xfe) c = 0xfe00 | code[p++];
      const o = OPS[c] || { name: 'unknown_' + c.toString(16), arg: '' };
      const ins = { off, op: o.name, code: c };
      try {
        switch (o.arg) {
          case 'u8': ins.v = code[p]; p += 1; break;
          case 'i8': ins.v = dv.getInt8(p); p += 1; break;
          case 'u16': ins.v = dv.getUint16(p, true); p += 2; break;
          case 'i32': ins.v = dv.getInt32(p, true); p += 4; break;
          case 'i64': ins.v = dv.getBigInt64(p, true); p += 8; break;
          case 'r4': ins.v = dv.getFloat32(p, true); p += 4; break;
          case 'r8': ins.v = dv.getFloat64(p, true); p += 8; break;
          case 'tok': ins.v = dv.getUint32(p, true); p += 4; break;
          case 'br8': ins.v = dv.getInt8(p); p += 1; ins.target = p + ins.v; break;
          case 'br32': ins.v = dv.getInt32(p, true); p += 4; ins.target = p + ins.v; break;
          case 'switch': {
            const n = dv.getUint32(p, true); p += 4;
            const rel = [];
            for (let i = 0; i < n && i < 10000; i++) { rel.push(dv.getInt32(p, true)); p += 4; }
            ins.targets = rel.map(r => p + r);
            break;
          }
        }
      } catch (e) { ins.op = 'truncated'; p = code.length; }
      ins.end = p;
      out.push(ins);
    }
    return out;
  }

  const csString = s => '"' + s.replace(/[\\"\x00-\x1f\u2028\u2029\u007f-\u009f]/g, c => ({ '\\': '\\\\', '"': '\\"', '\n': '\\n', '\r': '\\r', '\t': '\\t', '\0': '\\0' }[c]
    || '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))) + '"';
  const hex = (n, w = 4) => n.toString(16).padStart(w, '0');

  function ilText(A, ins, ctx) {
    const pad = 'IL_' + hex(ins.off) + ': ' + ins.op.padEnd(12);
    if (ins.target != null) return pad + ' IL_' + hex(ins.target);
    if (ins.targets) return pad + ' (' + ins.targets.map(t => 'IL_' + hex(t)).join(', ') + ')';
    if (ins.v == null) return pad.trimEnd();
    if (/^(ldstr)$/.test(ins.op)) { const m = member(A, ins.v, ctx); return pad + ' ' + csString(m ? m.value : '?'); }
    if (OPS[ins.code].arg === 'tok') {
      const m = member(A, ins.v, ctx);
      if (!m) return pad + ' 0x' + hex(ins.v, 8);
      if (m.kind === 'method') return pad + ' ' + m.sig.ret.s + ' ' + m.owner.s + '::' + m.name + (m.gargs ? '<' + m.gargs.join(', ') + '>' : '') + '(' + m.sig.params.map(x => x.s).join(', ') + ')';
      if (m.kind === 'field') return pad + ' ' + m.type.s + ' ' + m.owner.s + '::' + m.name;
      if (m.kind === 'type') return pad + ' ' + m.type.s;
      return pad + ' 0x' + hex(ins.v, 8);
    }
    return pad + ' ' + String(ins.v);
  }

  // ------------------------------------------------------------------ decompiler: IL -> C#
  const E = (s, p = 16, extra) => Object.assign({ s, p }, extra);
  const wrap = (e, p) => (e.p < p ? '(' + e.s + ')' : e.s);
  const BIN = { add: ['+', 12], sub: ['-', 12], mul: ['*', 13], div: ['/', 13], 'div.un': ['/', 13], rem: ['%', 13], 'rem.un': ['%', 13], and: ['&', 8], or: ['|', 6], xor: ['^', 7],
    shl: ['<<', 11], shr: ['>>', 11], 'shr.un': ['>>', 11], 'add.ovf': ['+', 12], 'add.ovf.un': ['+', 12], 'sub.ovf': ['-', 12], 'sub.ovf.un': ['-', 12], 'mul.ovf': ['*', 13], 'mul.ovf.un': ['*', 13] };
  const CMP_BR = { beq: '==', bge: '>=', bgt: '>', ble: '<=', blt: '<', 'bne.un': '!=', 'bge.un': '>=', 'bgt.un': '>', 'ble.un': '<=', 'blt.un': '<' };
  const NEG = { '==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>' };
  const CONV = { 'conv.i1': 'sbyte', 'conv.i2': 'short', 'conv.i4': 'int', 'conv.i8': 'long', 'conv.r4': 'float', 'conv.r8': 'double', 'conv.u4': 'uint', 'conv.u8': 'ulong',
    'conv.u2': 'ushort', 'conv.u1': 'byte', 'conv.i': 'IntPtr', 'conv.u': 'UIntPtr', 'conv.r.un': 'double' };
  const OPER = { op_Equality: ['==', 9], op_Inequality: ['!=', 9], op_Addition: ['+', 12], op_Subtraction: ['-', 12], op_Multiply: ['*', 13], op_Division: ['/', 13],
    op_LessThan: ['<', 10], op_GreaterThan: ['>', 10], op_LessThanOrEqual: ['<=', 10], op_GreaterThanOrEqual: ['>=', 10], op_Modulus: ['%', 13],
    op_BitwiseAnd: ['&', 8], op_BitwiseOr: ['|', 6], op_ExclusiveOr: ['^', 7] };

  function negate(e) {
    if (e.cmp) return E(e.l + ' ' + NEG[e.cmp] + ' ' + e.r, 9, { cmp: NEG[e.cmp], l: e.l, r: e.r, t: 'bool' });
    if (e.not) return e.not;
    return E('!' + wrap(e, 15), 14, { not: e, t: 'bool' });
  }
  const isBoolish = e => e.t === 'bool' || e.cmp || e.not;
  function truthy(e) {
    if (isBoolish(e) || !e.t) return e;
    if (/^(int|uint|long|ulong|short|ushort|byte|sbyte|char|IntPtr)$/.test(e.t)) return cmp(e, E('0'), '!=');
    return cmp(e, E('null'), '!=');
  }
  function cmp(a, b, opx) {
    if (a.t === 'char' && b.num != null) b = E(lit(b.num, 'char'), 16, { t: 'char' });
    else if (b.t === 'char' && a.num != null) a = E(lit(a.num, 'char'), 16, { t: 'char' });
    else if (a.t === 'bool' && b.num != null && (opx === '==' || opx === '!=')) return opx === '==' ? (b.num ? a : negate(a)) : (b.num ? negate(a) : a);
    const p = /[<>]/.test(opx) && opx.length <= 2 && opx !== '==' && opx !== '!=' ? 10 : 9;
    const l = wrap(a, p + 1), r = wrap(b, p + 1);
    return E(l + ' ' + opx + ' ' + r, p, { cmp: opx, l, r, t: 'bool' });
  }
  function lit(v, t) {
    if (t === 'bool') return v ? 'true' : 'false';
    if (t === 'char') return v >= 32 && v < 127 && v !== 39 && v !== 92 ? "'" + String.fromCharCode(v) + "'" : "'\\u" + hex(v) + "'";
    return String(v);
  }

  // "x = x + 1" -> "x++", "x = x + y" -> "x += y"; also literal fix-ups for bool/char targets
  function assign(target, v, ttype) {
    if (v.bin && v.l && v.l.s === target) {
      if (v.r.num === 1 && (v.bin === '+' || v.bin === '-')) return target + (v.bin === '+' ? '++' : '--') + ';';
      return target + ' ' + v.bin + '= ' + v.r.s + ';';
    }
    let rhs = v.s;
    if (v.num != null && ttype === 'bool') rhs = v.num ? 'true' : 'false';
    else if (v.num != null && ttype === 'char') rhs = lit(v.num, 'char');
    return target + ' = ' + rhs + ';';
  }

  function localName(type, i, used) {
    const base = { string: 'text', int: 'num', bool: 'flag', object: 'obj', long: 'num', byte: 'b', char: 'c', double: 'num', float: 'num', uint: 'num', IntPtr: 'ptr' }[type]
      || (type.endsWith('[]') ? 'array' : (type.replace(/<.*$/, '').replace(/[^A-Za-z0-9_]/g, '') || 'v').replace(/^./, c => c.toLowerCase()));
    let n = base + i;
    while (used.has(n)) n += '_';
    used.add(n);
    return n;
  }

  function decompileMethod(A, mi, tctx) {
    const m = A.methods[mi];
    const ctx = { ...tctx, mgen: m.gparams };
    const sig = methodSig(A, m.sig, ctx);
    const isStatic = !!(m.flags & 0x10);
    const b = body(A, m);
    if (!b) return { sig, lines: null };
    const ins = decode(b.code);
    if (ins.length > 20000) return { sig, lines: ['// method too large to decompile here (' + ins.length + ' instructions); see the IL view'] };
    const at = new Map(ins.map((x, i) => [x.off, i]));

    // names
    const used = new Set();
    const pnames = sig.params.map((p, i) => {
      const pm = m.params.find(q => q.seq === i + 1);
      let n = pm && pm.name && /^[\p{L}_][\p{L}\p{N}_]*$/u.test(pm.name) ? pm.name : 'arg' + (i + 1);
      if (used.has(n)) n += i;
      used.add(n);
      return n;
    });
    const argName = n => (isStatic ? pnames[n] : n === 0 ? 'this' : pnames[n - 1]) || 'arg' + n;
    const argType = n => (isStatic ? sig.params[n] : n === 0 ? { s: tctx.self } : sig.params[n - 1]);
    let locals = [];
    if (b.localTok) {
      const r = A.tables.StandAloneSig && A.tables.StandAloneSig[b.localTok & 0xffffff];
      if (r) {
        try {
          const s = new Sig(blobAt(A, r[0]));
          if (s.b[s.p++] === 0x07) { const n = s.u(); for (let i = 0; i < n && !s.end && i < 5000; i++) locals.push(readType(A, s, ctx)); }
        } catch (e) { /* bad local sig */ }
      }
    }
    const lnames = locals.map((t, i) => localName(t.s, i, used));
    const locName = i => lnames[i] || 'loc' + i;
    const usedLocals = new Set();

    // leaders and stack depths
    const leaders = new Set([0]);
    for (const x of ins) {
      if (x.target != null) { leaders.add(x.target); leaders.add(x.end); }
      if (x.targets) { x.targets.forEach(t => leaders.add(t)); leaders.add(x.end); }
      if (/^(ret|throw|rethrow|endfinally|endfilter|jmp)$/.test(x.op)) leaders.add(x.end);
    }
    for (const c of b.eh) { leaders.add(c.tryOff); leaders.add(c.tryOff + c.tryLen); leaders.add(c.hOff); leaders.add(c.hOff + c.hLen); if (c.flags & 1) leaders.add(c.tok); }
    const depthAt = new Map();
    const effect = x => {
      const o = x.op;
      if (/^(call|callvirt|newobj|calli)$/.test(o)) {
        const mm = member(A, x.v, ctx);
        const sg = mm && (mm.sig || null);
        if (!sg) return [0, 0];
        if (o === 'newobj') return [sg.params.length, 1];
        return [sg.params.length + (sg.hasThis && !sg.explicitThis ? 1 : 0) + (o === 'calli' ? 1 : 0), sg.ret.s === 'void' ? 0 : 1];
      }
      if (o === 'ret') return [sig.ret.s === 'void' ? 0 : 1, 0];
      if (o === 'dup') return [1, 2];
      if (/^(ldarg|ldloc|ldnull|ldc|ldstr|ldsfld|ldsflda|ldtoken|ldftn|sizeof|arglist|ldarga|ldloca)/.test(o)) return [0, 1];
      if (/^(stloc|starg|pop|brtrue|brfalse|switch|throw|stsfld|initobj|endfilter)/.test(o)) return [1, 0];
      if (/^(beq|bge|bgt|ble|blt|bne|stfld|cpobj|stobj|stind)/.test(o)) return [2, 0];
      if (/^(stelem|cpblk|initblk)/.test(o)) return [3, 0];
      if (/^(ldelem|ldelema|ceq|cgt|clt|add|sub|mul|div|rem|and$|or$|xor|shl|shr)/.test(o)) return [2, 1];
      if (/^(neg|not|conv|castclass|isinst|box|unbox|ldlen|ckfinite|localloc|refany|mkrefany|newarr|ldfld|ldflda|ldind|ldobj|ldvirtftn)/.test(o)) return [1, 1];
      return [0, 0];
    };
    const work = [[0, 0]];
    for (const c of b.eh) { work.push([c.hOff, (c.flags & 2) || (c.flags & 4) ? 0 : 1]); if (c.flags & 1) work.push([c.tok, 1]); }
    let guard = 0;
    while (work.length && guard++ < 200000) {
      let [off, d] = work.pop();
      let i = at.get(off);
      if (i == null || depthAt.has(off)) continue;
      while (i != null && i < ins.length) {
        const x = ins[i];
        if (depthAt.has(x.off) && x.off !== off) break;
        depthAt.set(x.off, d);
        const [pop, push] = effect(x);
        d = Math.max(0, d - pop) + push;
        if (/^leave/.test(x.op)) { work.push([x.target, 0]); break; }
        if (x.target != null) { work.push([x.target, d]); if (/^br(\.s)?$/.test(x.op)) break; }
        if (x.targets) x.targets.forEach(t => work.push([t, d]));
        if (/^(ret|throw|rethrow|endfinally|endfilter|jmp)$/.test(x.op)) break;
        i++;
        if (i < ins.length && leaders.has(ins[i].off)) { work.push([ins[i].off, d]); break; }
      }
    }

    // exception regions -> nested constructs
    const groups = new Map();
    for (const c of b.eh) {
      const k = c.tryOff + ':' + c.tryLen;
      if (!groups.has(k)) groups.set(k, { start: c.tryOff, tryEnd: c.tryOff + c.tryLen, handlers: [] });
      groups.get(k).handlers.push(c);
    }
    const constructs = [...groups.values()].map(g => {
      g.handlers.sort((a, b2) => a.hOff - b2.hOff);
      g.end = Math.max(g.tryEnd, ...g.handlers.map(h => h.hOff + h.hLen));
      return g;
    }).sort((a, b2) => a.start - b2.start || b2.end - a.end);

    const labelOf = off => 'IL_' + hex(off);
    const tempName = i => 'stack' + i;

    function emitRange(start, end, initial, out) {
      let st = initial.slice();
      const s = t => out.push({ k: 's', text: t });
      const flush = () => {
        st.forEach((e, i) => { if (e.s !== tempName(i)) s(tempName(i) + ' = ' + e.s + ';'); });
        st = st.map((e, i) => E(tempName(i)));
      };
      const pop = () => st.length ? st.pop() : E('/*stack empty*/');
      const spillRefs = name => {
        const re = new RegExp('(^|[^\\w.])' + name.replace(/[$@]/g, '\\$&') + '\\b');
        st.forEach((e, i) => { if (re.test(e.s) && e.s !== name) { s(tempName(i) + ' = ' + e.s + ';'); st[i] = E(tempName(i)); } });
      };
      let i = at.get(start);
      if (i == null) return;
      while (i < ins.length && ins[i].off < end) {
        const x = ins[i];
        // nested try construct starting here
        const con = constructs.find(c => c.start === x.off && c.end <= end && !(c.start === start && c.end === end && initial.isTry) && !c.done);
        if (con) {
          con.done = true;
          if (st.length) flush();
          const node = { k: 'try', body: [], handlers: [], end: con.end };
          const tryList = [];
          node.body = tryList;
          emitRange(con.start, con.tryEnd, Object.assign([], { isTry: true, conEnd: con.end }), tryList);
          for (const h of con.handlers) {
            const hl = [];
            let head;
            const kind = h.flags & 7;
            if (kind === 2) head = 'finally';
            else if (kind === 4) head = 'fault';
            else if (kind === 1) head = 'catch when (filter at ' + labelOf(h.tok) + ')';
            else {
              const tt = member(A, h.tok, ctx);
              head = 'catch (' + (tt && tt.type ? tt.type.s : 'Exception') + ' ex)';
            }
            emitRange(h.hOff, h.hOff + h.hLen, Object.assign(kind === 0 || kind === 1 ? [E('ex', 16, { t: 'Exception' })] : [], { conEnd: con.end }), hl);
            node.handlers.push({ head, body: hl });
          }
          out.push(node);
          i = at.get(con.end);
          if (i == null) break;
          continue;
        }
        if (leaders.has(x.off) && x.off !== start) {
          if (st.length) flush();
          out.push({ k: 'label', name: labelOf(x.off), off: x.off });
          const d = depthAt.get(x.off) || 0;
          st = []; for (let k = 0; k < d; k++) st.push(E(tempName(k)));
        } else if (x.off === start && start !== 0) {
          out.push({ k: 'label', name: labelOf(x.off), off: x.off });
        }
        step(x);
        i++;
      }
      if (st.length) flush();

      function call(x, mm, isNew) {
        const sg = mm.sig;
        const args = [];
        for (let k = 0; k < sg.params.length; k++) args.unshift(pop());
        const hasThis = !isNew && sg.hasThis && !sg.explicitThis;
        let obj = hasThis ? pop() : null;
        if (obj && obj.addr) obj = obj.addr;
        const ga = mm.gargs ? '<' + mm.gargs.join(', ') + '>' : '';
        const nm = mm.name;
        const argList = args.map(a => (a.addr ? 'ref ' + a.addr.s : a.s)).join(', ');
        const self = mm.ownerDef && mm.ownerDef === tctx.def;
        const target = obj ? (obj.s === 'this' && self ? '' : wrap(obj, 16) + '.') : (self ? '' : mm.owner.s + '.');
        if (isNew) {
          if (mm.owner.full === 'System.Object' && !args.length) return E('new object()');
          const dlg = args.length === 2 && args[1].fn ? args[1] : null;
          if (dlg) return E('new ' + mm.owner.s + '(' + (args[0].s === 'null' ? '' : wrap(args[0], 16) + '.') + dlg.fn + ')', 16, { side: true, t: mm.owner.s });
          return E('new ' + mm.owner.s + '(' + argList + ')', 16, { side: true, t: mm.owner.s });
        }
        if (nm === '.ctor') return { stmt: (obj && obj.s === 'this' ? (self ? 'this' : 'base') : wrap(obj || E('?'), 16) + '.ctor') + '(' + argList + ');', base: obj && obj.s === 'this' };
        const ret = sg.ret.s;
        // accessors, events, operators
        if (/^get_/.test(nm) && args.length === 0) return E(target + nm.slice(4), 16, { side: true, t: ret });
        if (/^get_(Item|Chars)$/.test(nm) && args.length) return E((obj ? wrap(obj, 16) : mm.owner.s) + '[' + argList + ']', 16, { side: true, t: ret });
        if (/^set_/.test(nm) && args.length === 1 && ret === 'void') return { stmt: target + nm.slice(4) + ' = ' + args[0].s + ';' };
        if (/^set_Item$/.test(nm) && args.length >= 2) return { stmt: (obj ? wrap(obj, 16) : mm.owner.s) + '[' + args.slice(0, -1).map(a => a.s).join(', ') + '] = ' + args[args.length - 1].s + ';' };
        if (/^add_/.test(nm) && args.length === 1) return { stmt: target + nm.slice(4) + ' += ' + args[0].s + ';' };
        if (/^remove_/.test(nm) && args.length === 1) return { stmt: target + nm.slice(7) + ' -= ' + args[0].s + ';' };
        if (OPER[nm] && args.length === 2) { const [o2, p2] = OPER[nm]; return o2 === '==' || o2 === '!=' || p2 === 10 ? cmp(args[0], args[1], o2) : E(wrap(args[0], p2) + ' ' + o2 + ' ' + wrap(args[1], p2 + 1), p2, { t: ret }); }
        if ((nm === 'op_Implicit' || nm === 'op_Explicit') && args.length === 1) return nm === 'op_Implicit' ? args[0] : E('(' + ret + ')' + wrap(args[0], 15), 14, { t: ret });
        if (nm === 'Concat' && mm.owner.full === 'System.String' && args.length >= 2 && args.length <= 4 && sg.params.every(p => p.s === 'string' || p.s === 'object'))
          return E(args.map(a => wrap(a, 13)).join(' + '), 12, { t: 'string' });
        if (nm === 'InitializeArray' && mm.owner.full === 'System.Runtime.CompilerServices.RuntimeHelpers' && args[0].arr && args[1].fieldRva) {
          args[0].arr.init = args[1].fieldRva;
          return { stmt: null };
        }
        if (nm === 'GetTypeFromHandle' && args.length === 1 && args[0].tok) return E(args[0].tok, 16, { t: 'Type' });
        const e = E(target + nm + ga + '(' + argList + ')', 16, { side: true, t: ret });
        if (ret === 'void') return { stmt: e.s + ';' };
        return e;
      }
      function renderArr(a) {
        const n = a.len;
        let init = '';
        if (a.init) {
          const el = a.elType;
          const sz = { byte: 1, sbyte: 1, bool: 1, short: 2, ushort: 2, char: 2, int: 4, uint: 4, float: 4, long: 8, ulong: 8, double: 8 }[el];
          const off = A.rva(a.init.rva);
          const count = +n.s;
          if (sz && off >= 0 && count >= 0 && count <= 65536) {
            const dv = A.dv, vals = [];
            for (let k = 0; k < count; k++) {
              const q = off + k * sz;
              if (q + sz > A.u8.length) break;
              let v = sz === 1 ? (el === 'sbyte' ? dv.getInt8(q) : dv.getUint8(q)) : sz === 2 ? (el === 'short' ? dv.getInt16(q, true) : dv.getUint16(q, true))
                : sz === 4 ? (el === 'float' ? dv.getFloat32(q, true) : el === 'int' ? dv.getInt32(q, true) : dv.getUint32(q, true))
                  : (el === 'double' ? dv.getFloat64(q, true) : el === 'long' ? dv.getBigInt64(q, true) : dv.getBigUint64(q, true));
              vals.push(el === 'byte' ? v : el === 'bool' ? (v ? 'true' : 'false') : el === 'char' ? lit(v, 'char') : v);
            }
            init = ' { ' + vals.join(', ') + ' }';
            if (vals.length > 4096) init = ' { /* ' + vals.length + ' values */ }';
          }
        } else if (a.items && a.items.length) {
          init = ' { ' + a.items.map(v => v.s).join(', ') + ' }';
        }
        return 'new ' + a.elType + '[' + (init && a.items && a.items.length === +n.s ? '' : n.s) + ']' + init;
      }
      function step(x) {
        const o = x.op;
        let mm;
        if (o === 'nop' || o === 'break' || /\.$/.test(o)) return;
        if (/^ldarg(\.|$)/.test(o)) { const n = /\.\d$/.test(o) ? +o.slice(-1) : x.v; const at2 = argType(n); st.push(E(argName(n), 16, { t: at2 && at2.s })); return; }
        if (/^ldarga/.test(o)) { const n = x.v; const nm = E(argName(n)); st.push(E('ref ' + nm.s, 16, { addr: nm })); return; }
        if (/^starg/.test(o)) { const v = pop(); spillRefs(argName(x.v)); s(assign(argName(x.v), v, (argType(x.v) || {}).s)); return; }
        if (/^ldloc\b|^ldloc\.\d|^ldloc\.s/.test(o) && !/ldloca/.test(o)) { const n = /\.\d$/.test(o) ? +o.slice(-1) : x.v; usedLocals.add(n); st.push(E(locName(n), 16, { t: locals[n] && locals[n].s })); return; }
        if (/^ldloca/.test(o)) { usedLocals.add(x.v); const nm = E(locName(x.v), 16, { t: locals[x.v] && locals[x.v].s }); st.push(E('ref ' + nm.s, 16, { addr: nm })); return; }
        if (/^stloc/.test(o)) {
          const n = /\.\d$/.test(o) ? +o.slice(-1) : x.v; usedLocals.add(n);
          const v = pop(); spillRefs(locName(n));
          s(assign(locName(n), v, locals[n] && locals[n].s)); return;
        }
        if (o === 'ldnull') { st.push(E('null')); return; }
        if (/^ldc\.i4/.test(o)) { const v = o === 'ldc.i4.m1' ? -1 : /\.\d$/.test(o) ? +o.slice(-1) : x.v; st.push(E(String(v), v < 0 ? 14 : 16, { num: v })); return; }
        if (/^ldc\./.test(o)) { const v = typeof x.v === 'bigint' ? x.v + 'L' : Number.isFinite(x.v) ? String(x.v) + (o === 'ldc.r4' ? 'f' : String(x.v).includes('.') || /e/.test(String(x.v)) ? '' : '.0') : 'double.NaN'; st.push(E(v)); return; }
        if (o === 'ldstr') { mm = member(A, x.v, ctx); st.push(E(csString(mm ? mm.value : ''), 16, { t: 'string' })); return; }
        if (o === 'dup') {
          const v = pop();
          if (/^[\w.@$]+$/.test(v.s) || v.arr || v.num != null || /^"/.test(v.s)) { st.push(v); st.push(v); return; }
          const tn = tempName(st.length);
          s(tn + ' = ' + v.s + ';');
          st.push(E(tn, 16, { t: v.t })); st.push(E(tn, 16, { t: v.t }));
          return;
        }
        if (o === 'pop') { const v = pop(); if (v.side || v.arr) s((v.arr ? renderArr(v.arr) : v.s) + ';'); return; }
        if (o === 'ret') { if (sig.ret.s === 'void') s('return;'); else { const v = pop(); s('return ' + (v.arr ? renderArr(v.arr) : sig.ret.s === 'bool' && v.num != null ? (v.num ? 'true' : 'false') : v.s) + ';'); } out[out.length - 1].term = true; return; }
        if (o === 'throw') { s('throw ' + pop().s + ';'); out[out.length - 1].term = true; return; }
        if (o === 'rethrow') { s('throw;'); out[out.length - 1].term = true; return; }
        if (o === 'endfinally' || o === 'endfilter') { if (o === 'endfilter') pop(); return; }
        if (/^leave/.test(o)) {
          st = [];
          if (x.target === initial.conEnd) return;
          out.push({ k: 'goto', to: labelOf(x.target), term: true });
          return;
        }
        if (/^br(\.s)?$/.test(o)) { if (st.length) flush(); out.push({ k: 'goto', to: labelOf(x.target), term: true }); return; }
        if (/^brtrue|^brfalse/.test(o)) {
          let c = truthy(pop());
          if (/^brfalse/.test(o)) c = negate(c);
          if (st.length) flush();
          out.push({ k: 'goto', to: labelOf(x.target), cond: c });
          return;
        }
        const bo = o.replace(/\.s$/, '');
        if (CMP_BR[bo]) {
          const r = pop(), l = pop();
          const c = cmp(l, r, CMP_BR[bo]);
          if (st.length) flush();
          out.push({ k: 'goto', to: labelOf(x.target), cond: c });
          return;
        }
        if (o === 'switch') {
          const v = pop();
          if (st.length) flush();
          out.push({ k: 'switch', expr: v.s, cases: x.targets.map((t, k) => ({ v: k, to: labelOf(t) })) });
          return;
        }
        if (BIN[o]) {
          const r = pop(), l = pop();
          const [o2, p2] = BIN[o];
          st.push(E(wrap(l, p2) + ' ' + o2 + ' ' + wrap(r, p2 + 1), p2, { t: l.t === 'string' || r.t === 'string' ? 'string' : l.t, bin: o2, l, r }));
          return;
        }
        if (o === 'ceq' || o === 'cgt' || o === 'cgt.un' || o === 'clt' || o === 'clt.un') {
          const r = pop(), l = pop();
          if (o === 'ceq' && r.num === 0 && isBoolish(l)) { st.push(negate(l)); return; }
          if (o === 'ceq' && r.num === 0 && l.cmp) { st.push(negate(l)); return; }
          if (o === 'cgt.un' && r.s === 'null') { st.push(cmp(l, r, '!=')); return; }
          st.push(cmp(l, r, o === 'ceq' ? '==' : /^cgt/.test(o) ? '>' : '<'));
          return;
        }
        if (o === 'neg') { const v = pop(); st.push(E('-' + wrap(v, 15), 14, { t: v.t })); return; }
        if (o === 'not') { const v = pop(); st.push(E('~' + wrap(v, 15), 14, { t: v.t })); return; }
        if (/^conv/.test(o)) {
          const v = pop();
          const ty = CONV[o] || (o.match(/conv\.ovf\.([iu]\d?)/) || [])[1] && ({ i1: 'sbyte', i2: 'short', i4: 'int', i8: 'long', u1: 'byte', u2: 'ushort', u4: 'uint', u8: 'ulong', i: 'IntPtr', u: 'UIntPtr' }[o.match(/conv\.ovf\.([iu]\d?)/)[1]]) || 'int';
          if (v.num != null && /^(long|ulong|int|IntPtr)$/.test(ty)) { st.push(E(v.s + (ty === 'long' ? 'L' : ''), v.p, { num: v.num, t: ty })); return; }
          if (v.t === ty) { st.push(v); return; }
          st.push(E('(' + ty + ')' + wrap(v, 15), 14, { t: ty }));
          return;
        }
        if (o === 'call' || o === 'callvirt' || o === 'newobj') {
          mm = member(A, x.v, ctx);
          if (!mm || mm.kind !== 'method') { st.push(E('/*bad call 0x' + hex(x.v, 8) + '*/')); return; }
          const r = call(x, mm, o === 'newobj');
          if (r.stmt === null) return;
          if (r.stmt) {
            if (r.base && mm.owner.full === 'System.Object') return;
            s(r.stmt);
            return;
          }
          st.push(r);
          return;
        }
        if (o === 'calli') { mm = member(A, x.v, ctx); const sg = mm && mm.sig; const fn = pop(); const args = []; if (sg) for (let k = 0; k < sg.params.length; k++) args.unshift(pop()); const e = E('((delegate*)' + fn.s + ')(' + args.map(a => a.s).join(', ') + ')', 16, { side: true }); if (sg && sg.ret.s === 'void') s(e.s + ';'); else st.push(e); return; }
        if (o === 'ldftn' || o === 'ldvirtftn') {
          mm = member(A, x.v, ctx); if (o === 'ldvirtftn') pop();
          st.push(E('&' + (mm ? mm.name : '?'), 16, { fn: mm ? mm.name : '?' })); return;
        }
        if (o === 'ldfld' || o === 'ldflda') {
          mm = member(A, x.v, ctx);
          let obj = pop(); if (obj.addr) obj = obj.addr;
          const self = obj.s === 'this' && mm && mm.ownerDef === tctx.def;
          const fe = E((self ? 'this.' : wrap(obj, 16) + '.') + (mm ? mm.name : '?'), 16, { t: mm && mm.type && mm.type.s });
          st.push(o === 'ldflda' ? E('ref ' + fe.s, 16, { addr: fe }) : fe);
          return;
        }
        if (o === 'ldsfld' || o === 'ldsflda') {
          mm = member(A, x.v, ctx);
          const self = mm && mm.ownerDef === tctx.def;
          const fe = E((self ? '' : (mm ? mm.owner.s : '?') + '.') + (mm ? mm.name : '?'), 16, { t: mm && mm.type && mm.type.s });
          st.push(o === 'ldsflda' ? E('ref ' + fe.s, 16, { addr: fe }) : fe);
          return;
        }
        if (o === 'stfld') {
          mm = member(A, x.v, ctx);
          const v = pop(); let obj = pop(); if (obj.addr) obj = obj.addr;
          const self = obj.s === 'this' && mm && mm.ownerDef === tctx.def;
          s(assign((self ? 'this.' : wrap(obj, 16) + '.') + (mm ? mm.name : '?'), v, mm && mm.type && mm.type.s));
          return;
        }
        if (o === 'stsfld') {
          mm = member(A, x.v, ctx);
          const v = pop();
          const self = mm && mm.ownerDef === tctx.def;
          s(assign((self ? '' : (mm ? mm.owner.s : '?') + '.') + (mm ? mm.name : '?'), v, mm && mm.type && mm.type.s));
          return;
        }
        if (o === 'newarr') {
          mm = member(A, x.v, ctx);
          const n = pop();
          const arr = { elType: mm && mm.type ? mm.type.s : 'object', len: n, items: [] };
          const ae = { p: 16, arr, t: arr.elType + '[]' };
          Object.defineProperty(ae, 's', { get() { return renderArr(arr); }, enumerable: true });
          st.push(ae);
          return;
        }
        if (o === 'ldlen') { const a = pop(); st.push(E(wrap(a, 16) + '.Length', 16, { t: 'int' })); return; }
        if (/^ldelema/.test(o)) { const i2 = pop(), a = pop(); const e = E(wrap(a, 16) + '[' + i2.s + ']'); st.push(E('ref ' + e.s, 16, { addr: e })); return; }
        if (/^ldelem/.test(o)) { const i2 = pop(), a = pop(); st.push(E(wrap(a, 16) + '[' + i2.s + ']', 16, { t: a.t && a.t.endsWith('[]') ? a.t.slice(0, -2) : undefined })); return; }
        if (/^stelem/.test(o)) {
          const v = pop(), i2 = pop(), a = pop();
          if (a.arr && i2.num === a.arr.items.length) { a.arr.items.push(v); return; }
          s(wrap(a, 16) + '[' + i2.s + '] = ' + v.s + ';');
          return;
        }
        if (o === 'box') { const v = pop(); mm = member(A, x.v, ctx); if (v.num != null && mm && mm.type && mm.type.s === 'bool') st.push(E(v.num ? 'true' : 'false')); else st.push(v); return; }
        if (o === 'unbox.any' || o === 'castclass' || o === 'unbox') { mm = member(A, x.v, ctx); const v = pop(); const ty = mm && mm.type ? mm.type.s : '?'; st.push(E('(' + ty + ')' + wrap(v, 15), 14, { t: ty })); return; }
        if (o === 'isinst') { mm = member(A, x.v, ctx); const v = pop(); const ty = mm && mm.type ? mm.type.s : '?'; st.push(E(wrap(v, 11) + ' as ' + ty, 10, { t: ty })); return; }
        if (o === 'ldtoken') {
          mm = member(A, x.v, ctx);
          if (mm && mm.kind === 'type') st.push(E('typeof(' + mm.type.s + ')', 16, { tok: 'typeof(' + mm.type.s + ')' }));
          else if (mm && mm.kind === 'field') st.push(E('fieldof(' + mm.name + ')', 16, { fieldRva: mm.def && A.fieldRva.has(mm.def) ? { rva: A.fieldRva.get(mm.def) } : null }));
          else st.push(E('methodof(' + (mm ? mm.name : '?') + ')'));
          return;
        }
        if (o === 'sizeof') { mm = member(A, x.v, ctx); st.push(E('sizeof(' + (mm && mm.type ? mm.type.s : '?') + ')', 16, { t: 'int' })); return; }
        if (o === 'initobj') { mm = member(A, x.v, ctx); let a = pop(); if (a.addr) a = a.addr; s(a.s + ' = default(' + (mm && mm.type ? mm.type.s : '?') + ');'); return; }
        if (/^ldind|^ldobj/.test(o)) { let a = pop(); st.push(a.addr ? a.addr : E('*' + wrap(a, 15), 14)); if (o === 'ldobj') { /* token = type */ } return; }
        if (/^stind|^stobj/.test(o)) { const v = pop(); let a = pop(); s((a.addr ? a.addr.s : '*' + wrap(a, 15)) + ' = ' + v.s + ';'); return; }
        if (o === 'localloc') { const n = pop(); st.push(E('stackalloc byte[' + n.s + ']')); return; }
        if (o === 'ckfinite') return;
        if (o === 'arglist') { st.push(E('__arglist')); return; }
        if (o === 'jmp') { s('/* jmp */ return;'); return; }
        if (o === 'cpblk' || o === 'initblk') { const c = pop(), b2 = pop(), a = pop(); s(o + '(' + a.s + ', ' + b2.s + ', ' + c.s + ');'); return; }
        const [pp, pu] = effect(x);
        const args = []; for (let k = 0; k < pp; k++) args.unshift(pop());
        if (pu) st.push(E('/*' + o + '*/(' + args.map(a => a.s).join(', ') + ')'));
        else s('/* ' + o + ' */');
      }
    }

    const out = [];
    try {
      emitRange(0, b.code.length, [], out);
    } catch (e) {
      return { sig, lines: ['// could not decompile this method: ' + e.message, ...ins.map(x => '// ' + ilText(A, x, ctx))] };
    }
    if (ins.length <= 6000) { structure(out); ternaries(out); }
    // trailing "return;" in void methods
    if (sig.ret.s === 'void' && out.length && out[out.length - 1].k === 's' && out[out.length - 1].text === 'return;') out.pop();
    const decl = [];
    for (const n of [...usedLocals].sort((a, b2) => a - b2)) if (locals[n]) decl.push(locals[n].s + ' ' + locName(n) + ';');
    const temps = new Set();
    const findTemps = list => list.forEach(n => {
      const scanText = t => { const re = /\bstack(\d+)\b/g; let mt; while ((mt = re.exec(t))) temps.add(+mt[1]); };
      if (n.text) scanText(n.text);
      if (n.cond) scanText(n.cond.s);
      if (n.expr) scanText(n.expr);
      for (const k of ['then', 'else', 'body']) if (n[k]) findTemps(n[k]);
      if (n.handlers) n.handlers.forEach(h => findTemps(h.body));
    });
    findTemps(out);
    for (const k of [...temps].sort()) decl.push('object ' + tempName(k) + ';');
    const lines = [];
    if (decl.length) { decl.forEach(d => lines.push(d)); lines.push(''); }
    render(out, 0, lines);
    return { sig, lines, pnames };
  }

  // ---- structuring: goto soup -> if / else / while / do-while
  function refsIn(list, counts) {
    for (const n of list) {
      if (n.k === 'goto') counts.set(n.to, (counts.get(n.to) || 0) + 1);
      if (n.k === 'switch') n.cases.forEach(c => counts.set(c.to, (counts.get(c.to) || 0) + 1));
      for (const k of ['then', 'else', 'body']) if (n[k]) refsIn(n[k], counts);
      if (n.handlers) n.handlers.forEach(h => refsIn(h.body, counts));
    }
    return counts;
  }
  function labelsIn(list, set) {
    for (const n of list) {
      if (n.k === 'label') set.add(n.name);
      for (const k of ['then', 'else', 'body']) if (n[k]) labelsIn(n[k], set);
      if (n.handlers) n.handlers.forEach(h => labelsIn(h.body, set));
    }
    return set;
  }
  // a range can be moved into a block if no label inside it is the target of a goto outside it
  function closed(list, a, b, total) {
    const inner = list.slice(a, b);
    const labels = labelsIn(inner, new Set());
    if (!labels.size) return true;
    const innerRefs = refsIn(inner, new Map());
    for (const l of labels) if ((total.get(l) || 0) !== (innerRefs.get(l) || 0)) return false;
    return true;
  }
  const isTerm = n => n && (n.term || (n.k === 's' && /^(return\b|throw\b)/.test(n.text)));
  function structure(list, depth = 0) {
    if (depth > 60) return;
    let changed = true, rounds = 0;
    const root = list;
    while (changed && rounds++ < 4000) {
      changed = false;
      const total = refsIn(root, new Map());
      changed = pass(root, total) || changed;
    }
    function pass(L, total) {
      for (let i = 0; i < L.length; i++) {
        const n = L[i];
        // recurse into blocks
        for (const k of ['then', 'else', 'body']) if (n[k] && pass(n[k], total)) return true;
        if (n.handlers) for (const h of n.handlers) if (pass(h.body, total)) return true;
        // goto to the label right after a loop -> break
        if ((n.k === 'while' || n.k === 'do') && L[i + 1] && L[i + 1].k === 'label') {
          const X = L[i + 1].name;
          let hit2 = false;
          const toBreak = list => {
            for (let q = 0; q < list.length; q++) {
              const c = list[q];
              if (c.k === 'goto' && c.to === X) {
                list[q] = c.cond ? { k: 'if', cond: c.cond, then: [{ k: 's', text: 'break;', term: true }] } : { k: 's', text: 'break;', term: true };
                hit2 = true;
              } else if (c.k !== 'while' && c.k !== 'do' && c.k !== 'switch') {
                for (const k of ['then', 'else', 'body']) if (c[k]) toBreak(c[k]);
                if (c.handlers) c.handlers.forEach(h => toBreak(h.body));
              }
            }
          };
          toBreak(n.body);
          if (hit2) return true;
        }
        // goto L; L:  -> nothing
        if (n.k === 'goto') {
          let j = i + 1;
          while (j < L.length && L[j].k === 'label') { if (L[j].name === n.to) { L.splice(i, 1); return true; } j++; }
        }
        // unreferenced label
        if (n.k === 'label' && !total.get(n.name)) { L.splice(i, 1); return true; }
        // dead code after an unconditional jump / return, up to the next label
        if (isTerm(n) && i + 1 < L.length && L[i + 1].k !== 'label') {
          let j = i + 1; while (j < L.length && L[j].k !== 'label') j++;
          if (j > i + 1 && closed(L, i + 1, j, total)) { L.splice(i + 1, j - i - 1); return true; }
        }
        if (n.k === 'goto' && n.cond) {
          const j = L.findIndex((x, k) => k > i && x.k === 'label' && x.name === n.to);
          if (j > i) {
            // if (c) goto X; A; goto Y; X: B; Y:   -> if (!c) { A } else { B }
            const last = L[j - 1];
            if (last && last.k === 'goto' && !last.cond && (total.get(n.to) || 0) === 1) {
              const k2 = L.findIndex((x, k) => k > j && x.k === 'label' && x.name === last.to);
              if (k2 > j && closed(L, i + 1, j - 1, total) && closed(L, j + 1, k2, total)) {
                const thenB = L.slice(i + 1, j - 1), elseB = L.slice(j + 1, k2);
                L.splice(i, k2 - i, { k: 'if', cond: negate(n.cond), then: thenB, else: elseB });
                return true;
              }
            }
            // if (c) goto X; A; X:  -> if (!c) { A }
            if (closed(L, i + 1, j, total)) {
              const thenB = L.slice(i + 1, j);
              L.splice(i, j - i, { k: 'if', cond: negate(n.cond), then: thenB });
              return true;
            }
          }
          // do { B } while (c):  B: ...; if (c) goto B;
          const b2 = L.findIndex((x, k) => k < i && x.k === 'label' && x.name === n.to);
          if (b2 >= 0 && (total.get(n.to) || 0) === 1 && closed(L, b2 + 1, i, total)) {
            L.splice(b2, i - b2 + 1, { k: 'do', cond: n.cond, body: L.slice(b2 + 1, i) });
            return true;
          }
        }
        // while (c) { B }:  goto C; B: body; C: if (c) goto B;
        if (n.k === 'goto' && !n.cond && L[i + 1] && L[i + 1].k === 'label') {
          const bodyLabel = L[i + 1].name;
          const c = L.findIndex((x, k) => k > i + 1 && x.k === 'label' && x.name === n.to);
          if (c > 0 && L[c + 1] && L[c + 1].k === 'goto' && L[c + 1].cond && L[c + 1].to === bodyLabel
            && (total.get(bodyLabel) || 0) === 1 && (total.get(n.to) || 0) === 1 && closed(L, i + 2, c, total)) {
            L.splice(i, c - i + 2, { k: 'while', cond: L[c + 1].cond, body: L.slice(i + 2, c) });
            return true;
          }
        }
        // while (true) { B }:  B: ...; goto B;
        if (n.k === 'label') {
          const j = L.findIndex((x, k) => k > i && x.k === 'goto' && !x.cond && x.to === n.name);
          if (j > i && (total.get(n.name) || 0) === 1 && closed(L, i + 1, j, total)) {
            L.splice(i, j - i + 1, { k: 'while', cond: E('true'), body: L.slice(i + 1, j) });
            return true;
          }
        }
      }
      return false;
    }
  }
  // if (c) { stackN = a; } else { stackN = b; }  use(stackN)  ->  use(c ? a : b)
  function ternaries(list) {
    for (const n of list) {
      for (const k of ['then', 'else', 'body']) if (n[k]) ternaries(n[k]);
      if (n.handlers) n.handlers.forEach(h => ternaries(h.body));
    }
    for (let i = 0; i + 1 < list.length; i++) {
      const n = list[i], nx = list[i + 1];
      if (n.k !== 'if' || !n.else || n.then.length !== 1 || n.else.length !== 1) continue;
      const a = /^(stack\d+) = (.*);$/s.exec(n.then[0].text || ''), b = /^(stack\d+) = (.*);$/s.exec(n.else[0].text || '');
      if (!a || !b || a[1] !== b[1]) continue;
      const re = new RegExp('\\b' + a[1] + '\\b', 'g');
      const tern = n.cond.s + ' ? ' + a[2] + ' : ' + b[2];
      if (nx.k === 's' && (nx.text.match(re) || []).length === 1 && !new RegExp('^' + a[1] + ' =').test(nx.text)) {
        nx.text = /^(return |[\w.\[\]@]+ = )stack\d+;$/.test(nx.text) ? nx.text.replace(re, tern) : nx.text.replace(re, '(' + tern + ')');
      } else if (nx.cond && (nx.cond.s.match(re) || []).length === 1) {
        nx.cond = E(nx.cond.s.replace(re, '(' + tern + ')'), nx.cond.p);
      } else continue;
      list.splice(i, 1);
      i--;
    }
  }
  function render(list, ind, out) {
    const pad = '    '.repeat(ind);
    for (const n of list) {
      if (n.k === 's') out.push(pad + n.text);
      else if (n.k === 'label') out.push(pad.slice(4) + n.name + ':');
      else if (n.k === 'goto') out.push(pad + (n.cond ? 'if (' + n.cond.s + ') ' : '') + 'goto ' + n.to + ';');
      else if (n.k === 'if') {
        out.push(pad + 'if (' + n.cond.s + ')'); out.push(pad + '{'); render(n.then, ind + 1, out); out.push(pad + '}');
        if (n.else && n.else.length) {
          if (n.else.length === 1 && n.else[0].k === 'if') { const sub = []; render(n.else, ind, sub); out.push(pad + 'else ' + sub[0].trimStart()); out.push(...sub.slice(1)); }
          else { out.push(pad + 'else'); out.push(pad + '{'); render(n.else, ind + 1, out); out.push(pad + '}'); }
        }
      } else if (n.k === 'while') { out.push(pad + 'while (' + n.cond.s + ')'); out.push(pad + '{'); render(n.body, ind + 1, out); out.push(pad + '}'); }
      else if (n.k === 'do') { out.push(pad + 'do'); out.push(pad + '{'); render(n.body, ind + 1, out); out.push(pad + '}'); out.push(pad + 'while (' + n.cond.s + ');'); }
      else if (n.k === 'try') {
        out.push(pad + 'try'); out.push(pad + '{'); render(n.body, ind + 1, out); out.push(pad + '}');
        for (const h of n.handlers) { out.push(pad + h.head); out.push(pad + '{'); render(h.body, ind + 1, out); out.push(pad + '}'); }
      } else if (n.k === 'switch') {
        out.push(pad + 'switch (' + n.expr + ')'); out.push(pad + '{');
        for (const c of n.cases) out.push(pad + '    case ' + c.v + ': goto ' + c.to + ';');
        out.push(pad + '}');
      }
    }
  }

  // ------------------------------------------------------------------ types -> C# files
  const ACCESS_M = ['', 'private', 'private protected', 'internal', 'protected', 'protected internal', 'public', ''];
  const ACCESS_T = ['internal', 'public', 'public', 'private', 'protected', 'internal', 'private protected', 'protected internal'];

  function constValue(A, c) {
    if (!c) return null;
    const b = blobAt(A, c.blob), dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    try {
      switch (c.type) {
        case 0x02: return b[0] ? 'true' : 'false';
        case 0x03: return lit(dv.getUint16(0, true), 'char');
        case 0x04: return String(dv.getInt8(0)); case 0x05: return String(b[0]);
        case 0x06: return String(dv.getInt16(0, true)); case 0x07: return String(dv.getUint16(0, true));
        case 0x08: return String(dv.getInt32(0, true)); case 0x09: return String(dv.getUint32(0, true));
        case 0x0a: return String(dv.getBigInt64(0, true)) + 'L'; case 0x0b: return String(dv.getBigUint64(0, true)) + 'UL';
        case 0x0c: return String(dv.getFloat32(0, true)) + 'f'; case 0x0d: return String(dv.getFloat64(0, true));
        case 0x0e: return csString(td16.decode(b));
        case 0x12: return 'null';
      }
    } catch (e) { /* short blob */ }
    return null;
  }

  // custom attribute: name + simple fixed args
  function attribute(A, ca, ctx) {
    const ctor = member(A, ((ca.ctor.t === 0x06 ? 0x06 : 0x0a) << 24) | ca.ctor.r, ctx);
    if (!ctor) return null;
    const name = ctor.owner.s.replace(/Attribute$/, '');
    const b = blobAt(A, ca.blob);
    const args = [];
    try {
      if (b[0] === 1 && b[1] === 0) {
        let p = 2;
        const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
        for (const prm of ctor.sig.params) {
          const t = prm.s;
          if (t === 'string') {
            if (b[p] === 0xff) { args.push('null'); p++; continue; }
            const s = new Sig(b); s.p = p; const len = s.u(); p = s.p;
            args.push(csString(td.decode(b.subarray(p, p + len)))); p += len;
          } else if (t === 'bool') { args.push(b[p] ? 'true' : 'false'); p += 1; }
          else if (t === 'int' || t === 'uint') { args.push(String(t === 'int' ? dv.getInt32(p, true) : dv.getUint32(p, true))); p += 4; }
          else if (t === 'short' || t === 'ushort' || t === 'char') { args.push(String(dv.getInt16(p, true))); p += 2; }
          else if (t === 'byte' || t === 'sbyte') { args.push(String(b[p])); p += 1; }
          else if (t === 'long' || t === 'ulong') { args.push(String(dv.getBigInt64(p, true))); p += 8; }
          else break;
        }
      }
    } catch (e) { /* malformed */ }
    return { name, full: ctor.owner.full, args };
  }
  const NOISE_ATTR = /^System\.(Runtime\.CompilerServices\.(CompilerGenerated|IsReadOnly|Nullable|NullableContext|IsByRefLike|TupleElementNames|AsyncStateMachine|IteratorStateMachine|Extension|RefSafetyRules|ScopedRef)|Diagnostics\.(DebuggerHidden|DebuggerStepThrough|DebuggerBrowsable|DebuggerNonUserCode|DebuggerDisplay)|ParamArray|Reflection\.DefaultMember|CLSCompliant)Attribute$/;
  function attrLines(A, key, ctx, pad) {
    const list = A.cattrs.get(key) || [];
    const out = [];
    for (const ca of list) {
      const tmp = { ...ctx, usings: new Set() };
      const a = attribute(A, ca, tmp);
      if (!a || NOISE_ATTR.test(a.full) || /^Microsoft\.CodeAnalysis\.|^System\.Runtime\.CompilerServices\.(Nullable|Extension)/.test(a.full)) continue;
      if (ctx.usings) for (const u of tmp.usings) ctx.usings.add(u);
      out.push(pad + '[' + a.name + (a.args.length ? '(' + a.args.join(', ') + ')' : '') + ']');
    }
    return out;
  }

  function typeKind(A, ty) {
    if (ty.flags & 0x20) return 'interface';
    const base = ty.ext && ty.ext.r ? typeRefName(A, ty.ext, null) : null;
    const full = base && base.full;
    if (full === 'System.Enum') return 'enum';
    if (full === 'System.ValueType') return 'struct';
    if (full === 'System.MulticastDelegate') return 'delegate';
    return 'class';
  }

  function renderType(A, ti, ctx, ind, out) {
    const ty = A.types[ti];
    const pad = '    '.repeat(ind), pad1 = pad + '    ';
    const tctx = { ...ctx, tgen: ty.gparams, def: ti, self: clean(ty.name), ns: ctx.ns };
    const kind = typeKind(A, ty);
    const vis = ACCESS_T[ty.flags & 7];
    const mods = [vis];
    if (kind === 'class') {
      if ((ty.flags & 0x80) && (ty.flags & 0x100)) mods.push('static');
      else if (ty.flags & 0x80) mods.push('abstract');
      else if (ty.flags & 0x100) mods.push('sealed');
    }
    const gp = ty.gparams.filter(Boolean);
    const gen = gp.length ? '<' + gp.join(', ') + '>' : '';
    out.push(...attrLines(A, '2:' + ti, tctx, pad));
    if (kind === 'delegate') {
      const inv = ty.methods.find(m => A.methods[m].name === 'Invoke');
      if (inv) {
        const s = methodSig(A, A.methods[inv].sig, tctx);
        const pn = s.params.map((p, i) => { const q = A.methods[inv].params.find(x => x.seq === i + 1); return p.s + ' ' + (q && q.name || 'arg' + i); });
        out.push(pad + mods.join(' ') + ' delegate ' + s.ret.s + ' ' + clean(ty.name) + gen + '(' + pn.join(', ') + ');');
        return;
      }
    }
    const bases = [];
    if (kind === 'class' && ty.ext && ty.ext.r) { const b = typeRefName(A, ty.ext, tctx); if (b.full !== 'System.Object') bases.push(b.s); }
    for (const i of ty.ifaces) bases.push(typeRefName(A, i, tctx).s);
    let enumBase = '';
    if (kind === 'enum') {
      const vf = ty.fields.find(f => !(A.tables.Field[f][0] & 0x10));
      if (vf) { const t = fieldSig(A, A.tables.Field[vf][2], tctx).s; if (t !== 'int') enumBase = ' : ' + t; }
    }
    out.push(pad + mods.join(' ') + ' ' + kind + ' ' + clean(ty.name) + gen + enumBase + (bases.length ? ' : ' + bases.join(', ') : ''));
    out.push(pad + '{');
    const startLen = out.length;
    if (kind === 'enum') {
      for (const f of ty.fields) {
        const r = A.tables.Field[f];
        if (!(r[0] & 0x10)) continue;
        const v = constValue(A, A.constants.get('4:' + f));
        out.push(pad1 + clean(str(A, r[1])) + (v != null ? ' = ' + v : '') + ',');
      }
      out.push(pad + '}');
      return;
    }
    // fields
    const accessorOf = new Map(); // method -> property/event
    for (const p of ty.props) for (const a of A.semByAssoc.get('23:' + p) || []) accessorOf.set(a.m, { kind: 'prop', id: p, sem: a.sem });
    for (const e of ty.events) for (const a of A.semByAssoc.get('20:' + e) || []) accessorOf.set(a.m, { kind: 'event', id: e, sem: a.sem });
    const eventNames = new Set(ty.events.map(e => str(A, A.tables.Event[e][1])));
    for (const f of ty.fields) {
      const r = A.tables.Field[f];
      const fl = r[0], name = str(A, r[1]);
      if (eventNames.has(name) && !(fl & 0x10)) continue; // backing field of a field-like event
      if (/^<.+>k__BackingField$/.test(name)) continue; // auto-property storage
      const ft = fieldSig(A, r[2], tctx);
      const fm = [ACCESS_M[fl & 7] || 'private'];
      if (fl & 0x40) fm.push('const'); else { if (fl & 0x10) fm.push('static'); if (fl & 0x20) fm.push('readonly'); }
      let init = '';
      if (fl & 0x8000) { const v = constValue(A, A.constants.get('4:' + f)); if (v != null) init = ' = ' + v; }
      if (A.fieldRva.has(f)) init += ' // data at RVA 0x' + hex(A.fieldRva.get(f), 8);
      out.push(...attrLines(A, '4:' + f, tctx, pad1));
      out.push(pad1 + fm.join(' ') + ' ' + ft.s + ' ' + clean(name) + (init.startsWith(' //') ? ';' + init : init + ';'));
    }
    if (out.length > startLen) out.push('');
    // events
    for (const e of ty.events) {
      const r = A.tables.Event[e];
      out.push(pad1 + 'public event ' + typeRefName(A, r[2], tctx).s + ' ' + clean(str(A, r[1])) + ';');
    }
    if (ty.events.length) out.push('');
    // methods (properties grouped)
    const doneProps = new Set();
    const methodBlock = (mi, header, ipad) => {
      const res = decompileMethod(A, mi, tctx);
      if (!res.lines) { out.push(header + ';'); return; }
      out.push(header);
      out.push(ipad + '{');
      for (const l of res.lines) out.push(l ? ipad + '    ' + l : '');
      out.push(ipad + '}');
    };
    const isExt = mi => (A.cattrs.get('6:' + mi) || []).some(ca => { const a = attribute(A, ca, {}); return a && a.full === 'System.Runtime.CompilerServices.ExtensionAttribute'; });
    const sigText = (mi) => {
      const m = A.methods[mi];
      const s = methodSig(A, m.sig, { ...tctx, mgen: m.gparams });
      const ext = (m.flags & 0x10) && isExt(mi);
      const params = s.params.map((p, i) => {
        const q = m.params.find(x => x.seq === i + 1);
        const nm = q && q.name && /^[\p{L}_][\p{L}\p{N}_]*$/u.test(q.name) ? q.name : 'arg' + (i + 1);
        const isOut = q && (q.flags & 2) && !(q.flags & 1);
        return (i === 0 && ext ? 'this ' : '') + (p.byref ? (isOut ? 'out ' : 'ref ') : '') + p.s + ' ' + nm;
      });
      return { s, params };
    };
    for (const mi of ty.methods) {
      const m = A.methods[mi];
      const acc = accessorOf.get(mi);
      if (acc && acc.kind === 'prop') {
        if (doneProps.has(acc.id)) continue;
        doneProps.add(acc.id);
        const pr = A.tables.Property[acc.id];
        const pname = clean(str(A, pr[1]));
        const accs = [...accessorOf].filter(([, a]) => a.kind === 'prop' && a.id === acc.id).map(([m2, a]) => ({ m: m2, sem: a.sem }));
        const getter = accs.find(a => a.sem & 2), setter = accs.find(a => a.sem & 1);
        const ref = getter || setter;
        const st = sigText(ref.m);
        const ptype = getter ? st.s.ret.s : (st.s.params[st.s.params.length - 1] || { s: '?' }).s;
        const fl = A.methods[ref.m].flags;
        const pm = [ACCESS_M[fl & 7] || 'public'];
        if (fl & 0x10) pm.push('static');
        if (fl & 0x400) pm.push('abstract'); else if ((fl & 0x40) && (fl & 0x100) && !(ty.flags & 0x20)) pm.push('virtual'); else if (fl & 0x40 && !(ty.flags & 0x20) && !(fl & 0x20)) pm.push('override');
        const isIdx = getter ? st.params.length > 0 : st.params.length > 1;
        const head = (ty.flags & 0x20 ? '' : pm.join(' ') + ' ') + ptype + ' ' + (isIdx ? 'this[' + (getter ? st.params : st.params.slice(0, -1)).join(', ') + ']' : pname);
        out.push(pad1 + head);
        out.push(pad1 + '{');
        for (const [a, kw] of [[getter, 'get'], [setter, 'set']]) {
          if (!a) continue;
          const res = decompileMethod(A, a.m, tctx);
          if (!res.lines) { out.push(pad1 + '    ' + kw + ';'); continue; }
          const auto = res.lines.length === 1 && /^return this\.<\w+>k__BackingField;$|^return <\w+>k__BackingField;$|^this\.<\w+>k__BackingField = value;$|^<\w+>k__BackingField = value;$/.test(res.lines[0].trim());
          if (auto) { out.push(pad1 + '    ' + kw + ';'); continue; }
          out.push(pad1 + '    ' + kw);
          out.push(pad1 + '    {');
          for (const l of res.lines) out.push(l ? pad1 + '        ' + l : '');
          out.push(pad1 + '    }');
        }
        out.push(pad1 + '}');
        out.push('');
        continue;
      }
      if (acc && acc.kind === 'event') continue;
      const fl = m.flags;
      const st = sigText(mi);
      const mm = [];
      if (!(ty.flags & 0x20)) mm.push(ACCESS_M[fl & 7] || 'private');
      if (fl & 0x10) mm.push('static');
      if (A.implMap.has(mi)) mm.push('extern');
      else if (!(ty.flags & 0x20)) { if (fl & 0x400) mm.push('abstract'); else if ((fl & 0x40) && (fl & 0x100)) { if (!(fl & 0x20)) mm.push('virtual'); } else if (fl & 0x40) mm.push('override'); }
      const mgp = m.gparams.filter(Boolean);
      let name = clean(m.name);
      let head;
      if (m.name === '.cctor') head = 'static ' + clean(ty.name) + '()';
      else if (m.name === '.ctor') head = mm.filter(x => x !== 'virtual').join(' ') + ' ' + clean(ty.name) + '(' + st.params.join(', ') + ')';
      else if (m.name === 'Finalize' && !st.params.length) head = '~' + clean(ty.name) + '()';
      else head = mm.join(' ') + (mm.length ? ' ' : '') + st.s.ret.s + ' ' + name + (mgp.length ? '<' + mgp.join(', ') + '>' : '') + '(' + st.params.join(', ') + ')';
      const im = A.implMap.get(mi);
      out.push(...attrLines(A, '6:' + mi, tctx, pad1));
      if (im) out.push(pad1 + '[DllImport(' + csString(im.dll) + (im.name !== m.name ? ', EntryPoint = ' + csString(im.name) : '') + ')]');
      if (A.entryTok === ((0x06 << 24) | mi)) out.push(pad1 + '// ★ program entry point');
      if (im || !m.rva) { out.push(pad1 + head + ';'); out.push(''); continue; }
      methodBlock(mi, pad1 + head, pad1);
      out.push('');
    }
    for (const n of ty.nested) { renderType(A, n, ctx, ind + 1, out); out.push(''); }
    while (out.length && out[out.length - 1] === '') out.pop();
    out.push(pad + '}');
  }

  // public: one C# file per top-level type
  function listTypes(A) {
    const list = [];
    for (let i = 1; i < A.types.length; i++) {
      const ty = A.types[i];
      if (ty.outer) continue;
      if (ty.name === '<Module>' && !ty.methods.length && !ty.fields.length) continue;
      const nsPath = ty.ns ? ty.ns.replace(/\./g, '/') + '/' : '';
      const fname = (ty.name.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/`(\d+)$/, '`$1') || 'type' + i) + '.cs';
      list.push({ i, ns: ty.ns, name: ty.name, path: nsPath + fname, kind: typeKind(A, ty), entry: A.entryTok >>> 24 === 6 && containsMethod(A, i, A.entryTok & 0xffffff) });
    }
    return list;
  }
  function containsMethod(A, ti, mi) {
    const ty = A.types[ti];
    if (ty.methods.includes(mi)) return true;
    return ty.nested.some(n => containsMethod(A, n, mi));
  }
  function decompileType(A, ti) {
    const ty = A.types[ti];
    const ctx = { usings: new Set(), ns: ty.ns };
    const body2 = [];
    const ind = ty.ns ? 1 : 0;
    renderType(A, ti, ctx, ind, body2);
    const head = ['// Decompiled by EZLARP (built-in .NET decompiler) · ' + (asmName(A) || 'assembly'), ''];
    const us = [...ctx.usings].filter(u => u && u !== ty.ns && !ty.ns.startsWith(u + '.')).sort();
    if (us.length) { us.forEach(u => head.push('using ' + u + ';')); head.push(''); }
    if (ty.ns) return head.concat(['namespace ' + ty.ns, '{'], body2, ['}']).join('\n') + '\n';
    return head.concat(body2).join('\n') + '\n';
  }
  function ilType(A, ti) {
    const ty = A.types[ti];
    const ctx = { ns: ty.ns, tgen: ty.gparams };
    const out = ['// IL of ' + (ty.ns ? ty.ns + '.' : '') + ty.name, ''];
    const walk = (t2, pfx) => {
      const T2 = A.types[t2];
      for (const mi of T2.methods) {
        const m = A.methods[mi];
        const b = body(A, m);
        out.push('.method ' + pfx + m.name + (A.entryTok === ((6 << 24) | mi) ? '   // entry point' : ''));
        if (!b) { out.push('  // no body'); out.push(''); continue; }
        out.push('  // code size ' + b.code.length + ', max stack ' + b.maxStack);
        for (const c of b.eh) out.push('  // try IL_' + hex(c.tryOff) + '-IL_' + hex(c.tryOff + c.tryLen) + ' ' + ['catch', 'filter', 'finally', '', 'fault'][c.flags & 7] + ' IL_' + hex(c.hOff) + '-IL_' + hex(c.hOff + c.hLen));
        for (const x of decode(b.code)) out.push('  ' + ilText(A, x, { ...ctx, mgen: m.gparams }));
        out.push('');
      }
      for (const n of T2.nested) walk(n, pfx + A.types[n].name + '::');
    };
    walk(ti, '');
    return out.join('\n');
  }
  function asmName(A) {
    const r = A.tables.Assembly && A.tables.Assembly[1];
    if (!r) { const mo = A.tables.Module && A.tables.Module[1]; return mo ? str(A, mo[1]) : ''; }
    return str(A, r[7]) + ', Version=' + r[1] + '.' + r[2] + '.' + r[3] + '.' + r[4];
  }
  // assembly-level info: attributes, references, P/Invokes, resources
  function assemblyInfo(A) {
    const ctx = { usings: new Set(), ns: '' };
    const out = ['// ' + (asmName(A) || 'module'), '// runtime ' + A.version + (A.ilOnly ? ' · IL only' : ' · mixed mode (contains native code too)'), ''];
    const at = attrLines(A, '32:1', ctx, '[assembly: ').map(l => l.replace('[assembly: [', '[assembly: '));
    if (at.length) { out.push(...at); out.push(''); }
    const refs = [];
    for (let i = 1; i <= A.n('AssemblyRef'); i++) { const r = A.tables.AssemblyRef[i]; refs.push(str(A, r[6]) + ' ' + r[0] + '.' + r[1] + '.' + r[2] + '.' + r[3]); }
    if (refs.length) { out.push('// ---- references'); refs.forEach(r => out.push('//   ' + r)); out.push(''); }
    const pin = [...A.implMap].map(([mi, im]) => im.dll + '!' + im.name);
    if (pin.length) { out.push('// ---- native calls (P/Invoke)'); [...new Set(pin)].sort().forEach(r => out.push('//   ' + r)); out.push(''); }
    const res = resources(A);
    if (res.length) { out.push('// ---- embedded resources'); res.forEach(r => out.push('//   ' + r.name + ' (' + r.size + ' bytes)')); out.push(''); }
    if (A.entryTok) {
      const m = member(A, A.entryTok, ctx);
      if (m) out.push('// entry point: ' + m.owner.s + '.' + m.name + '()');
    }
    return out.join('\n') + '\n';
  }
  function resources(A) {
    const out = [];
    for (let i = 1; i <= A.n('ManifestResource'); i++) {
      const [off, fl, name, impl] = A.tables.ManifestResource[i];
      if (impl.r || !A.res) continue;
      const p = A.res.off + off;
      if (p + 4 > A.u8.length) continue;
      const len = A.dv.getUint32(p, true);
      out.push({ name: str(A, name), size: len, bytes: () => A.u8.slice(p + 4, Math.min(p + 4 + len, A.u8.length)) });
    }
    return out;
  }
  // for the scanner: per type, the strings it uses and the API members it calls
  function scanInfo(A) {
    const out = [];
    for (const t of listTypes(A)) {
      const refs = new Set(), strings = [], seen = new Set();
      const ctx = { ns: t.ns };
      const walk = ti => {
        const ty = A.types[ti];
        for (const mi of ty.methods) {
          const b = body(A, A.methods[mi]);
          if (!b) continue;
          let insList;
          try { insList = decode(b.code); } catch (e) { continue; }
          for (const x of insList) {
            if (x.op === 'ldstr') { const s = userString(A, x.v & 0xffffff); if (!seen.has(s)) { seen.add(s); strings.push(s); } }
            else if (/^(call|callvirt|newobj|ldftn|ldsfld|ldfld)$/.test(x.op)) {
              const k = (x.v >>> 24);
              if (k === 0x0a || k === 0x2b) { try { const k2 = refKey(member(A, x.v, ctx)); if (k2) refs.add(k2); } catch (e) { /* bad token */ } }
            }
          }
        }
        for (const n of ty.nested) walk(n);
      };
      walk(t.i);
      for (const [mi, im] of A.implMap) if (containsMethod(A, t.i, mi)) refs.add('native/' + im.dll.toLowerCase().replace(/(\.dll)?$/, '.dll') + '.' + im.name);
      out.push({ path: t.path, name: (t.ns ? t.ns + '.' : '') + t.name, refs: [...refs], strings });
    }
    return out;
  }

  return { load, listTypes, decompileType, ilType, assemblyInfo, resources, scanInfo, asmName };
})();
if (typeof module !== 'undefined') module.exports = Cil;
