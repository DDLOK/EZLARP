// EZLARP quick decompiler: turns .class bytecode into readable Java-like code in plain
// JavaScript, with no Java runtime. Control flow is shown as labels and gotos instead of
// loops, but every call, string, field and constant is there, so it works everywhere
// (including iPhone, where the in-browser JVM doesn't start) and opens instantly.
'use strict';

const JView = (() => {

  // ------------------------------------------------------------ class file

  function parse(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (dv.getUint32(0) !== 0xCAFEBABE) throw new Error('not a class file');
    let p = 8;
    const n = dv.getUint16(p); p += 2;
    const cp = new Array(n);
    for (let i = 1; i < n; i++) {
      const tag = u8[p++];
      const e = { tag };
      switch (tag) {
        case 1: { const len = dv.getUint16(p); e.v = mutf8(u8, p + 2, len); p += 2 + len; break; }
        case 3: e.v = dv.getInt32(p); p += 4; break;
        case 4: e.v = dv.getFloat32(p); p += 4; break;
        case 5: e.v = dv.getBigInt64(p); p += 8; break;
        case 6: e.v = dv.getFloat64(p); p += 8; break;
        case 7: case 8: case 16: case 19: case 20: e.a = dv.getUint16(p); p += 2; break;
        case 9: case 10: case 11: case 12: case 17: case 18: e.a = dv.getUint16(p); e.b = dv.getUint16(p + 2); p += 4; break;
        case 15: e.kind = u8[p]; e.a = dv.getUint16(p + 1); p += 3; break;
        default: throw new Error('bad constant pool tag ' + tag);
      }
      cp[i] = e;
      if (tag === 5 || tag === 6) i++;
    }
    const c = { cp, u8, dv };
    c.access = dv.getUint16(p); c.thisName = cls(cp, dv.getUint16(p + 2)); const sup = dv.getUint16(p + 4);
    c.superName = sup ? cls(cp, sup) : null; p += 6;
    const ni = dv.getUint16(p); p += 2;
    c.interfaces = [];
    for (let i = 0; i < ni; i++, p += 2) c.interfaces.push(cls(cp, dv.getUint16(p)));
    const members = () => {
      const cnt = dv.getUint16(p); p += 2;
      const out = [];
      for (let i = 0; i < cnt; i++) {
        const m = { access: dv.getUint16(p), name: utf(cp, dv.getUint16(p + 2)), desc: utf(cp, dv.getUint16(p + 4)) };
        p += 6;
        m.attrs = attrs();
        out.push(m);
      }
      return out;
    };
    const attrs = () => {
      const cnt = dv.getUint16(p); p += 2;
      const out = {};
      for (let i = 0; i < cnt; i++) {
        const name = utf(cp, dv.getUint16(p)); const len = dv.getUint32(p + 2);
        out[name] = { off: p + 6, len };
        p += 6 + len;
      }
      return out;
    };
    c.fields = members();
    c.methods = members();
    c.attrs = attrs();
    // bootstrap methods (string concatenation, lambdas)
    c.bsm = [];
    const bm = c.attrs.BootstrapMethods;
    if (bm) {
      let q = bm.off;
      const cnt = dv.getUint16(q); q += 2;
      for (let i = 0; i < cnt; i++) {
        const ref = dv.getUint16(q), na = dv.getUint16(q + 2); q += 4;
        const args = [];
        for (let k = 0; k < na; k++, q += 2) args.push(dv.getUint16(q));
        c.bsm.push({ ref, args });
      }
    }
    return c;
  }

  function mutf8(u8, start, len) {
    let s = '';
    for (let i = start, end = start + len; i < end;) {
      const a = u8[i++];
      if (a < 0x80) s += String.fromCharCode(a);
      else if ((a & 0xE0) === 0xC0) s += String.fromCharCode(((a & 0x1F) << 6) | (u8[i++] & 0x3F));
      else s += String.fromCharCode(((a & 0x0F) << 12) | ((u8[i++] & 0x3F) << 6) | (u8[i++] & 0x3F));
    }
    return s;
  }
  const utf = (cp, i) => (cp[i] && cp[i].v) || '';
  const cls = (cp, i) => cp[i] ? utf(cp, cp[i].a) : '?';
  function ref(cp, i) {
    const e = cp[i];
    const nat = cp[e.b];
    return { owner: cls(cp, e.a), name: utf(cp, nat.a), desc: utf(cp, nat.b) };
  }

  // ------------------------------------------------------------ types

  let ctx = { pkg: '' }; // current class, for shortening names
  function jname(internal) {
    if (!internal) return '?';
    if (internal[0] === '[') return typeOf(internal);
    const dotted = internal.replace(/\//g, '.');
    const pkg = internal.lastIndexOf('/') >= 0 ? internal.slice(0, internal.lastIndexOf('/')) : '';
    if (pkg === 'java/lang' || pkg === ctx.pkg) return internal.slice(internal.lastIndexOf('/') + 1).replace(/\$/g, '.');
    return dotted.replace(/\$/g, '.');
  }
  const PRIM = { B: 'byte', C: 'char', D: 'double', F: 'float', I: 'int', J: 'long', S: 'short', Z: 'boolean', V: 'void' };
  function readType(d, i) {
    let dims = 0;
    while (d[i] === '[') { dims++; i++; }
    let t;
    if (d[i] === 'L') { const e = d.indexOf(';', i); t = jname(d.slice(i + 1, e)); i = e + 1; } else { t = PRIM[d[i]] || '?'; i++; }
    return [t + '[]'.repeat(dims), i];
  }
  const typeOf = d => readType(d, 0)[0];
  function methodSig(desc) {
    const args = [];
    let i = 1;
    while (desc[i] !== ')') { const [t, j] = readType(desc, i); args.push(t); i = j; }
    return { args, ret: typeOf(desc.slice(i + 1)) };
  }
  const wide = t => t === 'long' || t === 'double';

  function flags(a, kind) {
    const f = [];
    if (a & 1) f.push('public'); if (a & 2) f.push('private'); if (a & 4) f.push('protected');
    if (a & 8) f.push('static'); if (a & 0x10) f.push('final');
    if (kind === 'm') { if (a & 0x20) f.push('synchronized'); if (a & 0x100) f.push('native'); if (a & 0x400) f.push('abstract'); }
    if (kind === 'f') { if (a & 0x40) f.push('volatile'); if (a & 0x80) f.push('transient'); }
    return f;
  }

  // ------------------------------------------------------------ literals

  function jstr(s) {
    let o = '"';
    for (const ch of s) {
      const c = ch.codePointAt(0);
      if (ch === '"') o += '\\"'; else if (ch === '\\') o += '\\\\';
      else if (ch === '\n') o += '\\n'; else if (ch === '\r') o += '\\r'; else if (ch === '\t') o += '\\t';
      else if (c < 32 || (c >= 0x7f && c < 0xa0)) o += '\\u' + c.toString(16).padStart(4, '0');
      else o += ch;
    }
    return o + '"';
  }
  function charLit(v) {
    if (v === 39) return "'\\''"; if (v === 92) return "'\\\\'";
    if (v >= 32 && v < 127) return `'${String.fromCharCode(v)}'`;
    if (v === 10) return "'\\n'"; if (v === 13) return "'\\r'"; if (v === 9) return "'\\t'";
    return `'\\u${v.toString(16).padStart(4, '0')}'`;
  }
  function numLit(v, t) {
    if (t === 'float') return Number.isFinite(v) ? (Number.isInteger(v) ? v + '.0F' : v + 'F') : (Number.isNaN(v) ? 'Float.NaN' : v > 0 ? 'Float.POSITIVE_INFINITY' : 'Float.NEGATIVE_INFINITY');
    if (t === 'double') return Number.isFinite(v) ? (Number.isInteger(v) ? v + '.0' : String(v)) : (Number.isNaN(v) ? 'Double.NaN' : v > 0 ? 'Double.POSITIVE_INFINITY' : 'Double.NEGATIVE_INFINITY');
    if (t === 'long') return v + 'L';
    return String(v);
  }

  // expression: { s, t (java type), p (precedence), side (has side effects), k (int constant) }
  const E = (s, t, p = 100, extra) => Object.assign({ s, t, p }, extra);
  const paren = (e, p) => e.p < p ? `(${e.s})` : e.s;

  // Turn int constants into booleans / chars where the target type says so.
  function as(e, t) {
    if (e && e.k !== undefined && typeof e.k === 'number') {
      if (t === 'boolean' && (e.k === 0 || e.k === 1)) return E(e.k ? 'true' : 'false', t);
      if (t === 'char' && e.k >= 0 && e.k < 0x10000) return E(charLit(e.k), t);
    }
    return e;
  }

  // ------------------------------------------------------------ instructions

  function decode(code) {
    const dv = new DataView(code.buffer, code.byteOffset, code.byteLength);
    const out = [];
    let pc = 0;
    while (pc < code.length) {
      const at = pc;
      let op = code[pc++];
      const ins = { pc: at, op };
      if (op === 196) { // wide
        op = ins.op = code[pc++];
        ins.wide = true;
        ins.idx = dv.getUint16(pc); pc += 2;
        if (op === 132) { ins.c = dv.getInt16(pc); pc += 2; }
      } else if (op === 16) { ins.v = dv.getInt8(pc++); }
      else if (op === 17) { ins.v = dv.getInt16(pc); pc += 2; }
      else if (op === 18) { ins.idx = code[pc++]; }
      else if (op === 19 || op === 20 || (op >= 178 && op <= 184) || op === 187 || op === 189 || op === 192 || op === 193) { ins.idx = dv.getUint16(pc); pc += 2; }
      else if ((op >= 21 && op <= 25) || (op >= 54 && op <= 58) || op === 169) { ins.idx = code[pc++]; }
      else if (op === 132) { ins.idx = code[pc++]; ins.c = dv.getInt8(pc++); }
      else if ((op >= 153 && op <= 168) || op === 198 || op === 199) { ins.t = at + dv.getInt16(pc); pc += 2; }
      else if (op === 200 || op === 201) { ins.t = at + dv.getInt32(pc); pc += 4; }
      else if (op === 185) { ins.idx = dv.getUint16(pc); pc += 4; }
      else if (op === 186) { ins.idx = dv.getUint16(pc); pc += 4; }
      else if (op === 188) { ins.v = code[pc++]; }
      else if (op === 197) { ins.idx = dv.getUint16(pc); ins.dims = code[pc + 2]; pc += 3; }
      else if (op === 170) {
        pc = (pc + 3) & ~3;
        const def = dv.getInt32(pc), lo = dv.getInt32(pc + 4), hi = dv.getInt32(pc + 8); pc += 12;
        ins.cases = [];
        for (let k = lo; k <= hi; k++, pc += 4) ins.cases.push([k, at + dv.getInt32(pc)]);
        ins.def = at + def;
      } else if (op === 171) {
        pc = (pc + 3) & ~3;
        const def = dv.getInt32(pc), np = dv.getInt32(pc + 4); pc += 8;
        ins.cases = [];
        for (let k = 0; k < np; k++, pc += 8) ins.cases.push([dv.getInt32(pc), at + dv.getInt32(pc + 4)]);
        ins.def = at + def;
      }
      out.push(ins);
    }
    return out;
  }

  const OPNAMES = ('nop aconst_null iconst_m1 iconst_0 iconst_1 iconst_2 iconst_3 iconst_4 iconst_5 lconst_0 lconst_1 fconst_0 fconst_1 fconst_2 dconst_0 dconst_1 bipush sipush ldc ldc_w ldc2_w iload lload fload dload aload ' +
    'iload_0 iload_1 iload_2 iload_3 lload_0 lload_1 lload_2 lload_3 fload_0 fload_1 fload_2 fload_3 dload_0 dload_1 dload_2 dload_3 aload_0 aload_1 aload_2 aload_3 iaload laload faload daload aaload baload caload saload ' +
    'istore lstore fstore dstore astore istore_0 istore_1 istore_2 istore_3 lstore_0 lstore_1 lstore_2 lstore_3 fstore_0 fstore_1 fstore_2 fstore_3 dstore_0 dstore_1 dstore_2 dstore_3 astore_0 astore_1 astore_2 astore_3 ' +
    'iastore lastore fastore dastore aastore bastore castore sastore pop pop2 dup dup_x1 dup_x2 dup2 dup2_x1 dup2_x2 swap iadd ladd fadd dadd isub lsub fsub dsub imul lmul fmul dmul idiv ldiv fdiv ddiv irem lrem frem drem ' +
    'ineg lneg fneg dneg ishl lshl ishr lshr iushr lushr iand land ior lor ixor lxor iinc i2l i2f i2d l2i l2f l2d f2i f2l f2d d2i d2l d2f i2b i2c i2s lcmp fcmpl fcmpg dcmpl dcmpg ifeq ifne iflt ifge ifgt ifle ' +
    'if_icmpeq if_icmpne if_icmplt if_icmpge if_icmpgt if_icmple if_acmpeq if_acmpne goto jsr ret tableswitch lookupswitch ireturn lreturn freturn dreturn areturn return getstatic putstatic getfield putfield ' +
    'invokevirtual invokespecial invokestatic invokeinterface invokedynamic new newarray anewarray arraylength athrow checkcast instanceof monitorenter monitorexit wide multianewarray ifnull ifnonnull goto_w jsr_w').split(' ');

  // ------------------------------------------------------------ method body

  const T_LOAD = ['int', 'long', 'float', 'double', null];
  const T_ARR = ['int', 'long', 'float', 'double', null, 'byte', 'char', 'short'];
  const ATYPE = { 4: 'boolean', 5: 'char', 6: 'float', 7: 'double', 8: 'byte', 9: 'short', 10: 'int', 11: 'long' };
  const BIN = { 96: '+', 100: '-', 104: '*', 108: '/', 112: '%', 120: '<<', 122: '>>', 124: '>>>', 126: '&', 128: '|', 130: '^' };
  const BINP = { '*': 80, '/': 80, '%': 80, '+': 70, '-': 70, '<<': 60, '>>': 60, '>>>': 60, '&': 40, '^': 35, '|': 30 };
  const CMP = ['==', '!=', '<', '>=', '>', '<='];
  const NEG = { '==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>' };

  function body(c, m, code, out, ind) {
    const cp = c.cp, dv = c.dv;
    const isStatic = !!(m.access & 8);
    const sig = methodSig(m.desc);
    const ins = decode(code.bytes);

    // names: LocalVariableTable when present (often stripped), else p1.. for params, v1.. for locals
    const names = new Map();
    if (code.lvt) for (const v of code.lvt) if (/^[A-Za-z_$][\w$]*$/.test(v.name) && !names.has(v.idx)) names.set(v.idx, v.name);
    const paramSlots = new Set();
    let slot = 0;
    if (!isStatic) { names.set(0, 'this'); paramSlots.add(0); slot = 1; }
    const params = [];
    sig.args.forEach((t, i) => {
      if (!names.has(slot) || names.get(slot) === 'this') names.set(slot, 'p' + (i + 1));
      params.push(`${t} ${names.get(slot)}`);
      paramSlots.add(slot);
      slot += wide(t) ? 2 : 1;
    });
    const nm = i => names.get(i) || 'v' + i;
    const declared = new Set(paramSlots);

    // labels for branch targets and handlers
    const targets = new Set();
    for (const x of ins) { if (x.t !== undefined) targets.add(x.t); if (x.cases) { x.cases.forEach(cc => targets.add(cc[1])); targets.add(x.def); } }
    const handlers = new Map();
    for (const h of code.exc) { targets.add(h.handler); handlers.set(h.handler, h.type); targets.add(h.start); }
    const labelOf = new Map();
    [...targets].sort((a, b) => a - b).forEach((pc, i) => labelOf.set(pc, 'L' + (i + 1)));
    const L = pc => labelOf.get(pc) || 'L?' + pc;

    const lines = [];
    const emit = s => lines.push(ind + s);
    for (const h of code.exc) emit(`// try ${L(h.start)}..${labelOf.get(h.end) || 'end'} catch (${h.type ? jname(h.type) : 'any'}) -> ${L(h.handler)}`);

    let st = [];
    const pop = () => st.length ? st.pop() : E('?', '?');
    const push = e => st.push(e);
    const entry = new Map();   // label pc -> stack expected there
    const spills = new Map();
    let spillN = 0;
    const flushSide = () => { // side-effecting values still on the stack before a jump stay in order
      st = st.map(e => {
        if (!e.side) return e;
        const n = '$s' + (spillN++);
        emit(`${e.t && e.t !== '?' ? e.t : 'var'} ${n} = ${e.s};`);
        return E(n, e.t);
      });
    };
    const branchTo = pc => { if (!entry.has(pc)) entry.set(pc, st.slice()); };
    let dead = false;

    for (let k = 0; k < ins.length; k++) {
      const x = ins[k];
      const op = x.op;
      if (labelOf.has(x.pc)) {
        if (handlers.has(x.pc)) st = [E('ex', handlers.get(x.pc) ? jname(handlers.get(x.pc)) : 'Throwable')];
        else if (dead) st = (entry.get(x.pc) || []).slice();
        else if (spills.has(x.pc) && st.length === spills.get(x.pc).length) {
          spills.get(x.pc).forEach((n, i) => emit(`${n} = ${st[i].s};`));
          st = spills.get(x.pc).map((n, i) => E(n, st[i].t));
        }
        lines.push(ind.slice(2) + L(x.pc) + ':');
      } else if (dead) { continue; }
      dead = false;

      if (op === 0) continue;
      if (op === 1) { push(E('null', 'null')); continue; }
      if (op >= 2 && op <= 8) { push(E(String(op - 3), 'int', 100, { k: op - 3 })); continue; }
      if (op === 9 || op === 10) { push(E((op - 9) + 'L', 'long')); continue; }
      if (op >= 11 && op <= 13) { push(E((op - 11) + '.0F', 'float')); continue; }
      if (op === 14 || op === 15) { push(E((op - 14) + '.0', 'double')); continue; }
      if (op === 16 || op === 17) { push(E(String(x.v), 'int', x.v < 0 ? 90 : 100, { k: x.v })); continue; }
      if (op >= 18 && op <= 20) {
        const e = cp[x.idx];
        if (e.tag === 8) push(E(jstr(utf(cp, e.a)), 'String', 100, { str: utf(cp, e.a) }));
        else if (e.tag === 3) push(E(String(e.v), 'int', e.v < 0 ? 90 : 100, { k: e.v }));
        else if (e.tag === 4) push(E(numLit(e.v, 'float'), 'float'));
        else if (e.tag === 5) push(E(numLit(e.v, 'long'), 'long'));
        else if (e.tag === 6) push(E(numLit(e.v, 'double'), 'double'));
        else if (e.tag === 7) push(E(jname(utf(cp, e.a)) + '.class', 'Class'));
        else push(E('/*constant*/', 'Object'));
        continue;
      }
      if ((op >= 21 && op <= 25) || (op >= 26 && op <= 45)) {
        const idx = op <= 25 ? x.idx : (op - 26) % 4;
        const t = T_LOAD[op <= 25 ? op - 21 : Math.floor((op - 26) / 4)];
        push(E(nm(idx), t || 'Object'));
        continue;
      }
      if (op >= 46 && op <= 53) { const i = pop(), a = pop(); push(E(`${paren(a, 100)}[${i.s}]`, T_ARR[op - 46] || (a.t && a.t.endsWith('[]') ? a.t.slice(0, -2) : 'Object'))); continue; }
      if ((op >= 54 && op <= 58) || (op >= 59 && op <= 78)) {
        const idx = op <= 58 ? x.idx : (op - 59) % 4;
        let t = T_LOAD[op <= 58 ? op - 54 : Math.floor((op - 59) / 4)];
        const v = pop();
        if (!t) t = v.t && v.t !== 'null' && v.t !== '?' ? v.t : 'Object';
        if (!declared.has(idx)) { declared.add(idx); emit(`${t} ${nm(idx)} = ${as(v, t).s};`); } else emit(`${nm(idx)} = ${as(v, t).s};`);
        continue;
      }
      if (op >= 79 && op <= 86) {
        const v = pop(), i = pop(), a = pop();
        if (a.arr && i.k !== undefined && st.includes(a)) { a.arr[i.k] = as(v, a.elem); a.render(); continue; }
        emit(`${paren(a, 100)}[${i.s}] = ${v.s};`);
        continue;
      }
      if (op === 87) { const v = pop(); if (v.side) emit(v.s + ';'); continue; }
      if (op === 88) { const v = pop(); if (v.side) emit(v.s + ';'); if (!wide(v.t)) { const w = pop(); if (w.side) emit(w.s + ';'); } continue; }
      if (op === 89) { const v = pop(); push(v); push(v); continue; }
      if (op === 90) { const a = pop(), b = pop(); push(a); push(b); push(a); continue; }
      if (op === 91) { const a = pop(), b = pop(); if (wide(b.t)) { push(a); push(b); push(a); } else { const c3 = pop(); push(a); push(c3); push(b); push(a); } continue; }
      if (op === 92) { const a = pop(); if (wide(a.t)) { push(a); push(a); } else { const b = pop(); push(b); push(a); push(b); push(a); } continue; }
      if (op === 93 || op === 94) { const a = pop(); if (wide(a.t)) { const b = pop(); push(a); push(b); push(a); } else { const b = pop(), c3 = pop(); push(b); push(a); push(c3); push(b); push(a); } continue; }
      if (op === 95) { const a = pop(), b = pop(); push(a); push(b); continue; }
      if (op >= 96 && op <= 131 && !(op >= 116 && op <= 119)) {
        const base = op >= 120 ? op - (op - 120) % 2 : op - (op - 96) % 4;
        const sym = BIN[base];
        const b = pop(), a = pop(), pr = BINP[sym];
        push(E(`${paren(a, pr)} ${sym} ${paren(b, pr + 1)}`, a.t, pr));
        continue;
      }
      if (op >= 116 && op <= 119) { const a = pop(); push(E('-' + paren(a, 90), a.t, 90)); continue; }
      if (op === 132) {
        const n = nm(x.idx);
        emit(x.c === 1 ? `${n}++;` : x.c === -1 ? `${n}--;` : x.c < 0 ? `${n} -= ${-x.c};` : `${n} += ${x.c};`);
        continue;
      }
      if (op >= 133 && op <= 147) {
        const to = ['long', 'float', 'double', 'int', 'float', 'double', 'int', 'long', 'double', 'int', 'long', 'float', 'byte', 'char', 'short'][op - 133];
        const a = pop();
        push(E(`(${to}) ${paren(a, 90)}`, to, 90));
        continue;
      }
      if (op >= 148 && op <= 152) { const b = pop(), a = pop(); push(E('cmp', 'int', 100, { cmp: [a, b] })); continue; }
      if ((op >= 153 && op <= 166) || op === 198 || op === 199) {
        let cond;
        if (op >= 153 && op <= 158) {
          const a = pop(), sym = CMP[op - 153];
          if (a.cmp) cond = `${paren(a.cmp[0], 50)} ${sym} ${paren(a.cmp[1], 51)}`;
          else if (a.t === 'boolean' && (sym === '==' || sym === '!=')) cond = sym === '==' ? '!' + paren(a, 90) : a.s;
          else cond = `${paren(a, 50)} ${sym} 0`;
        } else if (op >= 159 && op <= 166) {
          const b = pop(), a = pop();
          cond = `${paren(a, 50)} ${CMP[(op - 159) % 6]} ${paren(as(b, a.t), 51)}`;
        } else {
          const a = pop();
          cond = `${paren(a, 50)} ${op === 198 ? '==' : '!='} null`;
        }
        flushSide();
        branchTo(x.t);
        emit(`if (${cond}) goto ${L(x.t)};`);
        continue;
      }
      if (op === 167 || op === 200) {
        if (st.length) {
          // value-producing branch (a ? b : c): carry the stack in $s variables
          let sp = spills.get(x.t);
          if (!sp) { sp = st.map(() => '$s' + (spillN++)); spills.set(x.t, sp); entry.set(x.t, sp.map((n, i) => E(n, st[i].t))); st.forEach((e, i) => emit(`${e.t && e.t !== '?' && e.t !== 'null' ? e.t : 'Object'} ${sp[i]} = ${e.s};`)); }
          else st.forEach((e, i) => emit(`${sp[i]} = ${e.s};`));
          st = [];
        } else branchTo(x.t);
        emit(`goto ${L(x.t)};`);
        dead = true;
        continue;
      }
      if (op === 168 || op === 201 || op === 169) { emit(`/* ${OPNAMES[op]} */`); continue; }
      if (op === 170 || op === 171) {
        const v = pop();
        flushSide();
        emit(`switch (${v.s}) {`);
        for (const [k2, t] of x.cases) { branchTo(t); emit(`  case ${k2}: goto ${L(t)};`); }
        branchTo(x.def);
        emit(`  default: goto ${L(x.def)};`);
        emit('}');
        dead = true;
        continue;
      }
      if (op >= 172 && op <= 176) { emit(`return ${as(pop(), sig.ret).s};`); dead = true; continue; }
      if (op === 177) { if (k !== ins.length - 1 || labelOf.has(x.pc)) emit('return;'); dead = true; continue; }
      if (op >= 178 && op <= 181) {
        const r = ref(cp, x.idx), t = typeOf(r.desc);
        const owner = r.owner === c.thisName ? '' : jname(r.owner);
        if (op === 178) push(E(owner ? `${owner}.${r.name}` : r.name, t));
        else if (op === 179) { const v = pop(); emit(`${owner ? owner + '.' : ''}${r.name} = ${as(v, t).s};`); }
        else if (op === 180) { const o = pop(); push(E(`${o.s === 'this' ? 'this' : paren(o, 100)}.${r.name}`, t)); }
        else { const v = pop(), o = pop(); emit(`${o.s === 'this' ? 'this' : paren(o, 100)}.${r.name} = ${as(v, t).s};`); }
        continue;
      }
      if (op >= 182 && op <= 185) {
        const r = ref(cp, x.idx), s2 = methodSig(r.desc);
        const args = [];
        for (let i = s2.args.length - 1; i >= 0; i--) args.unshift(as(pop(), s2.args[i]).s);
        const a = args.join(', ');
        let call;
        if (op === 184) call = `${r.owner === c.thisName ? '' : jname(r.owner) + '.'}${r.name}(${a})`;
        else {
          const o = pop();
          if (r.name === '<init>') {
            if (o.uninit) {
              o.s = `new ${jname(o.t === '?' ? r.owner : r.owner)}(${a})`; o.uninit = false; o.side = true; o.p = 100;
              if (!st.includes(o)) emit(o.s + ';');
              continue;
            }
            emit(`${o.s === 'this' && r.owner !== c.thisName ? 'super' : o.s === 'this' ? 'this' : paren(o, 100) + '.<init>'}(${a});`);
            continue;
          }
          const recv = op === 183 && o.s === 'this' && r.owner !== c.thisName ? 'super' : paren(o, 100);
          call = `${recv}.${r.name}(${a})`;
        }
        if (s2.ret === 'void') { flushSide(); emit(call + ';'); } else push(E(call, s2.ret, 100, { side: true }));
        continue;
      }
      if (op === 186) {
        const e = cp[x.idx], nat = cp[e.b];
        const name = utf(cp, nat.a), s2 = methodSig(utf(cp, nat.b));
        const args = [];
        for (let i = s2.args.length - 1; i >= 0; i--) args.unshift(pop());
        const b = c.bsm[e.a];
        const bref = b && cp[b.ref] ? ref(cp, cp[b.ref].a) : null;
        if (bref && bref.name === 'makeConcatWithConstants' && b.args.length) {
          const recipe = utf(cp, cp[b.args[0]].a);
          const parts = [];
          let lit = '', ai = 0, ci = 1;
          for (const ch of recipe) {
            if (ch === '\u0001' || ch === '\u0002') {
              if (lit) { parts.push(jstr(lit)); lit = ''; }
              if (ch === '\u0001') parts.push(paren(args[ai++] || E('?', '?'), 71));
              else { const cc = cp[b.args[ci++]]; parts.push(cc && cc.tag === 8 ? jstr(utf(cp, cc.a)) : '?'); }
            } else lit += ch;
          }
          if (lit) parts.push(jstr(lit));
          if (!/^"/.test(parts[0] || '')) parts.unshift('""');
          push(E(parts.join(' + '), 'String', 70));
        } else if (bref && /metafactory/i.test(bref.name) && b.args.length >= 2 && cp[b.args[1]] && cp[b.args[1]].tag === 15) {
          const target = ref(cp, cp[b.args[1]].a);
          const own = target.owner === c.thisName ? jname(c.thisName).split('.').pop() : jname(target.owner);
          const bound = args.length ? ` /* captures ${args.map(a => a.s).join(', ')} */` : '';
          push(E(`${own}::${target.name === '<init>' ? 'new' : target.name}${bound}`, s2.ret));
        } else {
          push(E(`invokedynamic ${name}(${args.map(a => a.s).join(', ')})`, s2.ret, 100, { side: true }));
        }
        if (s2.ret === 'void') emit(pop().s + ';');
        continue;
      }
      if (op === 187) { push(E('new ' + jname(cls(cp, x.idx)), jname(cls(cp, x.idx)), 100, { uninit: true })); continue; }
      if (op === 188 || op === 189) {
        const n = pop();
        const elem = op === 188 ? ATYPE[x.v] : jname(cls(cp, x.idx));
        const e = E(`new ${elem}[${n.s}]`, elem + '[]', 100);
        if (n.k !== undefined && n.k >= 0 && n.k <= 4096) {
          e.arr = new Array(n.k).fill(null); e.elem = elem;
          e.render = () => {
            const vals = e.arr.map(v => v ? v.s : (elem === 'boolean' ? 'false' : /^(int|long|short|byte|char|float|double)$/.test(elem) ? '0' : 'null'));
            e.s = `new ${elem}[]{${vals.join(', ')}}`;
            // byte/char arrays that spell text: show it
            if ((elem === 'byte' || elem === 'char' || elem === 'int') && e.arr.length >= 4 && e.arr.every(v => v && v.k !== undefined || v && /^'.*'$/.test(v.s))) {
              const codes = e.arr.map(v => v.k !== undefined ? v.k : v.s.length === 3 ? v.s.charCodeAt(1) : -1);
              if (codes.every(cd => cd >= 32 && cd < 127)) e.s += ` /* "${String.fromCharCode(...codes).replace(/\*\//g, '*\\/')}" */`;
            }
          };
        }
        push(e);
        continue;
      }
      if (op === 190) { const a = pop(); push(E(paren(a, 100) + '.length', 'int')); continue; }
      if (op === 191) { emit(`throw ${pop().s};`); dead = true; continue; }
      if (op === 192) { const a = pop(), t = jname(cls(cp, x.idx)); push(E(`(${t}) ${paren(a, 90)}`, t, 90, { side: a.side })); continue; }
      if (op === 193) { const a = pop(); push(E(`${paren(a, 50)} instanceof ${jname(cls(cp, x.idx))}`, 'boolean', 50)); continue; }
      if (op === 194 || op === 195) { emit(`/* ${op === 194 ? 'synchronized enter' : 'synchronized exit'} ${pop().s} */`); continue; }
      if (op === 197) {
        const dims = [];
        for (let i = 0; i < x.dims; i++) dims.unshift(pop().s);
        const t = typeOf(cls(cp, x.idx)).replace(/(\[\])+$/, '');
        push(E(`new ${t}${dims.map(d => `[${d}]`).join('')}`, typeOf(cls(cp, x.idx))));
        continue;
      }
      emit(`/* ${OPNAMES[op] || 'op ' + op} */`);
    }
    for (const e of st) if (e.side) emit(e.s + ';');
    out.push(...lines);
    return params;
  }

  function codeOf(c, m) {
    const a = m.attrs.Code;
    if (!a) return null;
    const dv = c.dv;
    let p = a.off;
    const len = dv.getUint32(p + 4);
    const bytes = c.u8.subarray(p + 8, p + 8 + len);
    p += 8 + len;
    const ne = dv.getUint16(p); p += 2;
    const exc = [];
    for (let i = 0; i < ne; i++, p += 8) {
      const t = dv.getUint16(p + 6);
      exc.push({ start: dv.getUint16(p), end: dv.getUint16(p + 2), handler: dv.getUint16(p + 4), type: t ? cls(c.cp, t) : null });
    }
    const na = dv.getUint16(p); p += 2;
    let lvt = null;
    for (let i = 0; i < na; i++) {
      const name = utf(c.cp, dv.getUint16(p)), alen = dv.getUint32(p + 2);
      if (name === 'LocalVariableTable') {
        lvt = [];
        const n = dv.getUint16(p + 6);
        for (let k = 0; k < n; k++) { const q = p + 8 + k * 10; lvt.push({ name: utf(c.cp, dv.getUint16(q + 4)), idx: dv.getUint16(q + 8) }); }
      }
      p += 6 + alen;
    }
    return { bytes, exc, lvt };
  }

  // ------------------------------------------------------------ whole class

  function decompileClass(u8) {
    const c = parse(u8);
    ctx = { pkg: c.thisName.includes('/') ? c.thisName.slice(0, c.thisName.lastIndexOf('/')) : '' };
    const out = [];
    const simple = c.thisName.slice(c.thisName.lastIndexOf('/') + 1);
    const isIface = c.access & 0x200, isEnum = c.access & 0x4000, isAnno = c.access & 0x2000;
    const mods = flags(c.access & ~0x20 & ~(isIface ? 0x400 : 0), 'c');
    if ((c.access & 0x400) && !isIface) mods.push('abstract');
    const kind = isAnno ? '@interface' : isIface ? 'interface' : isEnum ? 'enum' : 'class';
    let head = `${mods.join(' ')}${mods.length ? ' ' : ''}${kind} ${simple.replace(/\$/g, '.')}`;
    if (c.superName && c.superName !== 'java/lang/Object' && !(isEnum && c.superName === 'java/lang/Enum')) head += ' extends ' + jname(c.superName);
    const ifs = c.interfaces.filter(i => !(isAnno && i === 'java/lang/annotation/Annotation'));
    if (ifs.length) head += (isIface ? ' extends ' : ' implements ') + ifs.map(jname).join(', ');
    out.push(head + ' {');

    for (const f of c.fields) {
      const fm = flags(f.access, 'f');
      let line = `    ${fm.join(' ')}${fm.length ? ' ' : ''}${typeOf(f.desc)} ${f.name}`;
      const cv = f.attrs.ConstantValue;
      if (cv) {
        const e = c.cp[c.dv.getUint16(cv.off)];
        const t = typeOf(f.desc);
        if (e) line += ' = ' + (e.tag === 8 ? jstr(utf(c.cp, e.a)) : t === 'boolean' ? (e.v ? 'true' : 'false') : t === 'char' ? charLit(e.v) : numLit(e.v, t));
      }
      out.push(line + ';');
    }
    if (c.fields.length) out.push('');

    for (const m of c.methods) {
      const sig = methodSig(m.desc);
      const mm = flags(m.access & ~(isIface && !(m.access & 8) ? 0x400 : 0), 'm');
      if (isIface && !(m.access & 0x400) && !(m.access & 8) && m.attrs.Code) mm.push('default');
      const code = codeOf(c, m);
      const lines = [];
      let params;
      if (code) {
        try { params = body(c, m, code, lines, '        '); } catch (e) { lines.length = 0; lines.push(`        // could not read this method: ${e.message}`); }
      }
      if (!params) {
        params = [];
        let slot = m.access & 8 ? 0 : 1;
        sig.args.forEach((t, i) => { params.push(`${t} p${i + 1}`); slot += wide(t) ? 2 : 1; });
      }
      let decl;
      if (m.name === '<clinit>') decl = '    static';
      else if (m.name === '<init>') decl = `    ${mm.join(' ')}${mm.length ? ' ' : ''}${simple.split('$').pop()}(${params.join(', ')})`;
      else decl = `    ${mm.join(' ')}${mm.length ? ' ' : ''}${sig.ret} ${m.name}(${params.join(', ')})`;
      if (!code) { out.push(decl + ';'); continue; }
      out.push(decl + ' {', ...lines, '    }', '');
    }
    if (out[out.length - 1] === '') out.pop();
    out.push('}');
    const pkg = ctx.pkg ? `package ${ctx.pkg.replace(/\//g, '.')};\n\n` : '';
    return { pkg, text: out.join('\n'), name: c.thisName };
  }

  // classes: [{ name, u8 }] (outer class first). Returns the text for one source file.
  function decompile(classes) {
    const parts = [];
    let pkg = '';
    classes.forEach((k, i) => {
      try {
        const r = decompileClass(k.u8);
        if (i === 0) pkg = r.pkg;
        parts.push((i ? `// ---- inner class ${r.name.replace(/\//g, '.')}\n` : '') + r.text);
      } catch (e) {
        parts.push(`// ${k.name}: could not read (${e.message})`);
      }
    });
    return `// Quick view: EZLARP's built-in decompiler (works on every device, instant).\n// Loops and if/else are shown as labels + goto. Use "full source" for Vineflower's output.\n${pkg}${parts.join('\n\n')}\n`;
  }

  // javap-style listing, for the "bytecode" button without a Java runtime
  function disassemble(classes) {
    const out = [];
    for (const k of classes) {
      try {
        const c = parse(k.u8);
        ctx = { pkg: '' };
        out.push(`// class ${c.thisName.replace(/\//g, '.')}${c.superName ? ' extends ' + c.superName.replace(/\//g, '.') : ''}`);
        for (const m of c.methods) {
          out.push(`\n  ${flags(m.access, 'm').join(' ')} ${m.name}${m.desc}`);
          const code = codeOf(c, m);
          if (!code) continue;
          for (const x of decode(code.bytes)) {
            let arg = '';
            if (x.idx !== undefined && x.op !== 132 && !(x.op >= 21 && x.op <= 25) && !(x.op >= 54 && x.op <= 58) && x.op !== 169) {
              const e = c.cp[x.idx];
              if (e) {
                if (e.tag === 8) arg = jstr(utf(c.cp, e.a));
                else if (e.tag === 7) arg = utf(c.cp, e.a);
                else if (e.tag >= 9 && e.tag <= 11) { const r = ref(c.cp, x.idx); arg = `${r.owner}.${r.name} ${r.desc}`; }
                else if (e.tag === 18) arg = utf(c.cp, c.cp[e.b].a) + utf(c.cp, c.cp[e.b].b);
                else if (e.v !== undefined) arg = String(e.v);
              }
            } else if (x.idx !== undefined) arg = String(x.idx) + (x.c !== undefined ? ' ' + x.c : '');
            if (x.v !== undefined) arg = String(x.v);
            if (x.t !== undefined) arg = String(x.t);
            if (x.cases) arg = `{ ${x.cases.map(cc => cc[0] + ': ' + cc[1]).join(', ')}, default: ${x.def} }`;
            out.push(`    ${String(x.pc).padStart(5)}: ${OPNAMES[x.op] || x.op}${arg ? ' ' + arg : ''}`);
          }
        }
        out.push('');
      } catch (e) { out.push(`// ${k.name}: ${e.message}`); }
    }
    return out.join('\n');
  }

  // Dalvik classes (no bytecode reader yet): structure from parseDex
  function dexSummary(infos) {
    const out = ['// Quick view: Android (Dalvik) class summary, built in. Use "full source" to decompile.'];
    for (const c of infos) {
      out.push(`class ${c.name.replace(/\//g, '.')}${c.superName ? ' extends ' + c.superName.replace(/\//g, '.') : ''} {`);
      if (c.strings.length) { out.push('    // strings'); for (const s of c.strings.slice(0, 400)) out.push('    ' + jstr(s)); }
      const calls = c.refs.filter(r => !r.includes('.') || /\.[\w$<>]+$/.test(r));
      if (calls.length) { out.push('    // calls and fields used'); for (const r of [...new Set(calls)].slice(0, 400)) out.push('    ' + r.replace(/\//g, '.')); }
      out.push('}', '');
    }
    return out.join('\n');
  }

  return { decompile, disassemble, dexSummary, parse };
})();

if (typeof module !== 'undefined') module.exports = JView;
