// EZLARP file inspection: sniffing, .class parsing, PE (.exe/.dll) analysis,
// strings extraction. Pure JS, runs entirely in the browser.
'use strict';

const Inspect = (() => {

  // ------------------------------------------------------------ sniffing

  function sniff(u8, name) {
    const n = (name || '').toLowerCase();
    if (u8.length >= 4 && u8[0] === 0xCA && u8[1] === 0xFE && u8[2] === 0xBA && u8[3] === 0xBE) return 'class';
    if (u8.length >= 2 && u8[0] === 0x4D && u8[1] === 0x5A) return 'pe';
    if (u8.length >= 8 && u8[0] === 0x64 && u8[1] === 0x65 && u8[2] === 0x78 && u8[3] === 0x0A) return 'dex';
    if (u8.length >= 4 && u8[0] === 0x50 && u8[1] === 0x4B && (u8[2] === 3 || u8[2] === 5)) return 'zip';
    if (/\.(jar|zip|war|ear|apk|aar|xapk)$/.test(n)) return 'zip';
    if (/\.dex$/.test(n)) return 'dex';
    if (/\.class$/.test(n)) return 'class';
    if (/\.(exe|dll|scr|sys|ocx|cpl)$/.test(n)) return 'pe';
    return 'unknown';
  }

  // ------------------------------------------------------------ .class

  const JAVA_NAMES = { 45: '1.1', 46: '1.2', 47: '1.3', 48: '1.4', 49: '5', 50: '6', 51: '7', 52: '8' };
  function javaVersion(major) {
    if (JAVA_NAMES[major]) return 'Java ' + JAVA_NAMES[major];
    if (major > 52) return 'Java ' + (major - 44);
    return 'major ' + major;
  }

  // Returns { name, major, minor } or null. With deep=true also returns the
  // constant pool contents used by the scanner:
  //   strings   string constants
  //   classes   referenced class names (internal form)
  //   refs      "owner.member" for every field/method reference
  //   superName, access
  function parseClass(u8, deep) {
    try {
      const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
      if (dv.getUint32(0) !== 0xCAFEBABE) return null;
      const minor = dv.getUint16(4), major = dv.getUint16(6);
      const count = dv.getUint16(8);
      const tags = new Uint8Array(count), a = new Uint16Array(count), b = new Uint16Array(count);
      const utf8 = new Array(count);
      let p = 10;
      for (let i = 1; i < count; i++) {
        const tag = tags[i] = u8[p++];
        switch (tag) {
          case 1: { const len = dv.getUint16(p); utf8[i] = decodeMUTF8(u8, p + 2, len); p += 2 + len; break; }
          case 7: case 8: case 16: case 19: case 20: a[i] = dv.getUint16(p); p += 2; break;
          case 15: p += 3; break;
          case 9: case 10: case 11: case 12: a[i] = dv.getUint16(p); b[i] = dv.getUint16(p + 2); p += 4; break;
          case 3: case 4: case 17: case 18: p += 4; break;
          case 5: case 6: p += 8; i++; break;
          default: return { name: null, major, minor };
        }
      }
      const access = dv.getUint16(p);
      const name = utf8[a[dv.getUint16(p + 2)]] || null;
      const r = { name, major, minor, access };
      if (deep) {
        const superIdx = dv.getUint16(p + 4);
        r.superName = superIdx ? utf8[a[superIdx]] || null : null;
        r.strings = []; r.classes = []; r.refs = [];
        for (let i = 1; i < count; i++) {
          const t = tags[i];
          if (t === 8) { const v = utf8[a[i]]; if (v) r.strings.push(v); }
          else if (t === 7) { const v = utf8[a[i]]; if (v) r.classes.push(v); }
          else if (t === 9 || t === 10 || t === 11) {
            const owner = utf8[a[a[i]]], member = utf8[a[b[i]]];
            if (owner && member) r.refs.push(owner + '.' + member);
          }
        }
      }
      return r;
    } catch (e) {
      return null;
    }
  }

  function decodeMUTF8(u8, start, len) {
    let s = '';
    for (let i = start, end = start + len; i < end;) {
      const a = u8[i++];
      if (a < 0x80) s += String.fromCharCode(a);
      else if ((a & 0xE0) === 0xC0) s += String.fromCharCode(((a & 0x1F) << 6) | (u8[i++] & 0x3F));
      else s += String.fromCharCode(((a & 0x0F) << 12) | ((u8[i++] & 0x3F) << 6) | (u8[i++] & 0x3F));
    }
    return s;
  }

  // ------------------------------------------------------------ PE

  const MACHINES = {
    0x14c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0xaa64: 'ARM64', 0x1c0: 'ARM', 0x1c4: 'ARMv7 Thumb-2', 0x200: 'IA-64'
  };
  const SUBSYSTEMS = {
    1: 'Native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console',
    9: 'Windows CE GUI', 10: 'EFI application', 11: 'EFI boot driver', 12: 'EFI runtime driver', 14: 'Xbox', 16: 'Windows boot app'
  };
  const DIR_NAMES = ['Export', 'Import', 'Resource', 'Exception', 'Security', 'Relocation', 'Debug', 'Architecture',
    'GlobalPtr', 'TLS', 'LoadConfig', 'BoundImport', 'IAT', 'DelayImport', 'CLR runtime', 'Reserved'];

  function parsePE(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const r = { ok: false };
    try {
      if (dv.getUint16(0, true) !== 0x5A4D) return r;
      const pe = dv.getUint32(0x3c, true);
      if (pe + 24 > u8.length || dv.getUint32(pe, true) !== 0x4550) return r;
      r.machine = dv.getUint16(pe + 4, true);
      const nsec = dv.getUint16(pe + 6, true);
      r.timestamp = dv.getUint32(pe + 8, true);
      const optSize = dv.getUint16(pe + 20, true);
      r.characteristics = dv.getUint16(pe + 22, true);
      r.isDll = !!(r.characteristics & 0x2000);
      const opt = pe + 24;
      const magic = dv.getUint16(opt, true);
      r.is64 = magic === 0x20b;
      r.format = r.is64 ? 'PE32+' : 'PE32';
      r.linker = dv.getUint8(opt + 2) + '.' + dv.getUint8(opt + 3);
      r.entryPoint = dv.getUint32(opt + 16, true);
      r.imageBase = r.is64 ? dv.getBigUint64(opt + 24, true) : BigInt(dv.getUint32(opt + 28, true));
      r.subsystem = dv.getUint16(opt + 68, true);
      r.dllCharacteristics = dv.getUint16(opt + 70, true);
      const nDirs = Math.min(16, dv.getUint32(opt + (r.is64 ? 108 : 92), true));
      const ddOff = opt + (r.is64 ? 112 : 96);
      r.dirs = [];
      for (let i = 0; i < nDirs; i++) {
        r.dirs.push({ name: DIR_NAMES[i], rva: dv.getUint32(ddOff + i * 8, true), size: dv.getUint32(ddOff + i * 8 + 4, true) });
      }

      // sections
      const secOff = opt + optSize;
      r.sections = [];
      let rawEnd = 0;
      for (let i = 0; i < nsec && secOff + i * 40 + 40 <= u8.length; i++) {
        const o = secOff + i * 40;
        let name = '';
        for (let k = 0; k < 8 && u8[o + k]; k++) name += String.fromCharCode(u8[o + k]);
        const s = {
          name,
          vsize: dv.getUint32(o + 8, true),
          va: dv.getUint32(o + 12, true),
          rawSize: dv.getUint32(o + 16, true),
          rawPtr: dv.getUint32(o + 20, true),
          chars: dv.getUint32(o + 36, true)
        };
        s.entropy = entropy(u8, s.rawPtr, Math.min(s.rawPtr + s.rawSize, u8.length));
        s.flags = (s.chars & 0x20000000 ? 'X' : '-') + (s.chars & 0x40000000 ? 'R' : '-') + (s.chars & 0x80000000 ? 'W' : '-');
        r.sections.push(s);
        rawEnd = Math.max(rawEnd, s.rawPtr + s.rawSize);
      }
      const sec = r.dirs[4];
      let certStart = (sec && sec.size && sec.rva >= rawEnd) ? sec.rva : u8.length;
      r.overlay = rawEnd < u8.length ? { offset: rawEnd, size: certStart - rawEnd } : null;
      if (r.overlay && r.overlay.size <= 0) r.overlay = null;
      r.signed = !!(sec && sec.size);

      const rva2off = rva => {
        for (const s of r.sections) {
          const span = Math.max(s.vsize, s.rawSize);
          if (rva >= s.va && rva < s.va + span) return s.rawPtr + (rva - s.va);
        }
        return rva < (r.sections[0] ? r.sections[0].rawPtr : u8.length) ? rva : -1;
      };
      const cstr = (off, max = 256) => {
        let s = '';
        for (let i = 0; i < max && off + i < u8.length && u8[off + i]; i++) s += String.fromCharCode(u8[off + i]);
        return s;
      };

      // imports
      r.imports = [];
      const imp = r.dirs[1];
      if (imp && imp.size) {
        let d = rva2off(imp.rva);
        for (let n = 0; d > 0 && n < 512; n++, d += 20) {
          const oft = dv.getUint32(d, true), nameRva = dv.getUint32(d + 12, true), ft = dv.getUint32(d + 16, true);
          if (!nameRva && !ft) break;
          const dll = cstr(rva2off(nameRva));
          const funcs = [];
          let t = rva2off(oft || ft);
          const step = r.is64 ? 8 : 4;
          for (let k = 0; t > 0 && k < 4096; k++, t += step) {
            if (t + step > u8.length) break;
            let ordinal = false, val;
            if (r.is64) {
              const v = dv.getBigUint64(t, true);
              if (v === 0n) break;
              ordinal = (v >> 63n) === 1n;
              val = Number(v & 0x7fffffffn);
              if (ordinal) val = Number(v & 0xffffn);
            } else {
              const v = dv.getUint32(t, true);
              if (v === 0) break;
              ordinal = (v >>> 31) === 1;
              val = ordinal ? (v & 0xffff) : v;
            }
            if (ordinal) funcs.push('#' + val);
            else { const o = rva2off(val); funcs.push(o > 0 ? cstr(o + 2) : '?'); }
          }
          r.imports.push({ dll, funcs });
        }
      }

      // exports (names only)
      r.exports = [];
      const exp = r.dirs[0];
      if (exp && exp.size) {
        const e = rva2off(exp.rva);
        if (e > 0) {
          r.exportName = cstr(rva2off(dv.getUint32(e + 12, true)));
          const nNames = Math.min(dv.getUint32(e + 24, true), 4096);
          const namesOff = rva2off(dv.getUint32(e + 32, true));
          for (let i = 0; namesOff > 0 && i < nNames; i++) r.exports.push(cstr(rva2off(dv.getUint32(namesOff + i * 4, true))));
        }
      }

      // .NET
      const clr = r.dirs[14];
      if (clr && clr.size) {
        r.dotnet = { };
        const c = rva2off(clr.rva);
        if (c > 0) {
          r.dotnet.runtime = dv.getUint16(c + 4, true) + '.' + dv.getUint16(c + 6, true);
          const flags = dv.getUint32(c + 16, true);
          r.dotnet.ilOnly = !!(flags & 1);
          r.dotnet.requires32 = !!(flags & 2);
          const md = rva2off(dv.getUint32(c + 8, true));
          if (md > 0 && dv.getUint32(md, true) === 0x424A5342) {
            const len = dv.getUint32(md + 12, true);
            r.dotnet.version = cstr(md + 16, Math.min(len, 64));
          }
        }
      }

      r.ok = true;
      try { parseResources(u8, dv, r, rva2off); } catch (e) { r.resError = String(e && e.message || e); }
    } catch (e) {
      r.error = String(e && e.message || e);
    }
    return r;
  }

  // ---- PE resources: version info, icon, manifest

  function parseResources(u8, dv, r, rva2off) {
    const dir = r.dirs[2];
    if (!dir || !dir.size) return;
    const base = rva2off(dir.rva);
    if (base <= 0) return;
    const readDir = off => {
      const named = dv.getUint16(off + 12, true), ids = dv.getUint16(off + 14, true);
      const out = [];
      for (let i = 0; i < Math.min(named + ids, 2048); i++) {
        const e = off + 16 + i * 8;
        if (e + 8 > u8.length) break;
        const id = dv.getUint32(e, true), o = dv.getUint32(e + 4, true);
        out.push({ id: id >>> 31 ? null : id, sub: !!(o >>> 31), off: base + (o & 0x7fffffff) });
      }
      return out;
    };
    const leaves = (typeId) => {
      const res = [];
      const t = readDir(base).find(e => e.id === typeId && e.sub);
      if (!t) return res;
      for (const nameEnt of readDir(t.off)) {
        if (!nameEnt.sub) continue;
        const lang = readDir(nameEnt.off)[0];
        if (!lang || lang.sub) continue;
        const off = rva2off(dv.getUint32(lang.off, true)), size = dv.getUint32(lang.off + 4, true);
        if (off > 0 && off + size <= u8.length) res.push({ id: nameEnt.id, off, size });
      }
      return res;
    };
    r.resourceTypes = readDir(base).map(e => e.id).filter(x => x != null);

    // version info
    const ver = leaves(16)[0];
    if (ver) {
      const info = {};
      const start = ver.off, end = ver.off + ver.size;
      const align = x => start + ((x - start + 3) & ~3);
      const u16 = o => dv.getUint16(o, true);
      const wstr = (o, max) => { let s = ''; for (let i = 0; i < max && o + 1 < end; i++, o += 2) { const c = u16(o); if (!c) break; s += String.fromCharCode(c); } return s; };
      const walk = (off, lim, depth) => {
        for (let guard = 0; off + 6 <= lim && guard < 512; guard++) {
          const len = u16(off), vlen = u16(off + 2);
          if (len < 6) break;
          const key = wstr(off + 6, 128);
          const p = align(off + 6 + (key.length + 1) * 2);
          const nodeEnd = Math.min(lim, off + len);
          if (depth === 0) {
            if (vlen >= 16 && dv.getUint32(p, true) === 0xFEEF04BD) {
              const ms = dv.getUint32(p + 8, true), ls = dv.getUint32(p + 12, true);
              info.FixedFileVersion = [ms >>> 16, ms & 0xffff, ls >>> 16, ls & 0xffff].join('.');
            }
            walk(align(p + vlen), nodeEnd, 1);
          } else if (depth === 1) { if (key === 'StringFileInfo') walk(p, nodeEnd, 2); }
          else if (depth === 2) walk(p, nodeEnd, 3);
          else if (vlen) info[key] = wstr(p, vlen).trim();
          off = align(off + len);
        }
      };
      walk(start, end, 0);
      if (Object.keys(info).length) r.version = info;
    }

    // manifest
    const man = leaves(24)[0];
    if (man && man.size < 256 * 1024) {
      r.manifest = new TextDecoder().decode(u8.subarray(man.off, man.off + man.size)).replace(/^\uFEFF/, '');
      const lvl = /requestedExecutionLevel[^>]*level\s*=\s*["']([^"']+)/i.exec(r.manifest);
      if (lvl) r.executionLevel = lvl[1];
    }

    // icon: pick the largest image of the first icon group, wrap it as a .ico
    const grp = leaves(14)[0];
    if (grp && grp.size >= 6) {
      const n = dv.getUint16(grp.off + 4, true);
      let best = null;
      for (let i = 0; i < n && grp.off + 6 + i * 14 + 14 <= u8.length; i++) {
        const e = grp.off + 6 + i * 14;
        const ent = { head: u8.subarray(e, e + 12), w: u8[e] || 256, bits: dv.getUint16(e + 6, true), bytes: dv.getUint32(e + 8, true), id: dv.getUint16(e + 12, true) };
        if (!best || ent.w > best.w || (ent.w === best.w && ent.bits > best.bits)) best = ent;
      }
      const img = best && leaves(3).find(x => x.id === best.id);
      if (img && img.size < 2 * 1024 * 1024) {
        const ico = new Uint8Array(22 + img.size);
        ico.set([0, 0, 1, 0, 1, 0]);
        ico.set(best.head, 6);
        new DataView(ico.buffer).setUint32(14, img.size, true);
        new DataView(ico.buffer).setUint32(18, 22, true);
        ico.set(u8.subarray(img.off, img.off + img.size), 22);
        r.icon = ico;
      }
    }
  }

  // ------------------------------------------------------------ PyInstaller

  // Parses the CArchive appended to PyInstaller executables.
  // Returns { pyver, files: [{ name, off, csize, usize, compressed, type }] } or null.
  function parsePyInstaller(u8) {
    const magic = [0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E];
    const from = Math.max(0, u8.length - 8192);
    let cookie = -1;
    outer: for (let i = u8.length - 8; i >= from; i--) {
      for (let k = 0; k < 8; k++) if (u8[i + k] !== magic[k]) continue outer;
      cookie = i; break;
    }
    if (cookie < 0) return null;
    try {
      const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
      const pkgLen = dv.getUint32(cookie + 8), toc = dv.getUint32(cookie + 12), tocLen = dv.getUint32(cookie + 16), pyver = dv.getUint32(cookie + 20);
      const isNew = cookie + 88 <= u8.length && pyver >= 20 && pyver < 400;
      const cookieSize = isNew ? 88 : 24;
      const start = cookie + cookieSize - pkgLen;
      if (start < 0) return null;
      const files = [];
      let p = start + toc;
      const end = Math.min(u8.length, p + tocLen);
      while (p + 18 <= end && files.length < 20000) {
        const size = dv.getUint32(p);
        if (size < 18 || p + size > end) break;
        let name = '';
        for (let k = p + 18; k < p + size && u8[k]; k++) name += String.fromCharCode(u8[k]);
        files.push({
          name, off: start + dv.getUint32(p + 4), csize: dv.getUint32(p + 8), usize: dv.getUint32(p + 12),
          compressed: u8[p + 16] === 1, type: String.fromCharCode(u8[p + 17])
        });
        p += size;
      }
      return { pyver: pyver >= 100 ? Math.floor(pyver / 100) + '.' + (pyver % 100) : Math.floor(pyver / 10) + '.' + (pyver % 10), files };
    } catch (e) {
      return null;
    }
  }

  // ------------------------------------------------------------ Android

  function dexInfo(u8) {
    if (u8.length < 0x70) return null;
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    return {
      version: String.fromCharCode(u8[4], u8[5], u8[6]),
      strings: dv.getUint32(0x38, true), methods: dv.getUint32(0x58, true), classes: dv.getUint32(0x60, true)
    };
  }

  const ANDROID_ATTRS = {
    0x01010000: 'theme', 0x01010001: 'label', 0x01010002: 'icon', 0x01010003: 'name', 0x01010006: 'permission',
    0x0101000f: 'debuggable', 0x01010010: 'exported', 0x01010011: 'process', 0x01010018: 'authorities',
    0x0101001c: 'priority', 0x01010020: 'persistent', 0x01010024: 'value', 0x01010025: 'resource',
    0x01010026: 'mimeType', 0x01010027: 'scheme', 0x01010028: 'host', 0x01010029: 'port', 0x0101002a: 'path',
    0x0101020c: 'minSdkVersion', 0x0101021b: 'versionCode', 0x0101021c: 'versionName', 0x01010270: 'targetSdkVersion',
    0x01010271: 'maxSdkVersion', 0x01010280: 'allowBackup', 0x0101028e: 'required', 0x010102b7: 'installLocation',
    0x010104ec: 'usesCleartextTraffic', 0x010103af: 'hardwareAccelerated', 0x0101026c: 'largeHeap',
    0x01010572: 'compileSdkVersion', 0x01010573: 'compileSdkVersionCodename'
  };

  // Decodes Android binary XML (AndroidManifest.xml inside an .apk) to text.
  function decodeAXML(u8) {
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    if (dv.getUint16(0, true) !== 0x0003) throw new Error('not binary XML');
    const strings = [];
    let resMap = [];
    let out = '<?xml version="1.0" encoding="utf-8"?>\n';
    let depth = 0, p = dv.getUint16(2, true);
    const nsPrefix = {};
    let pendingNs = [];
    const str = i => (i === 0xffffffff || i >= strings.length) ? null : strings[i];
    const escAttr = s => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    while (p + 8 <= u8.length) {
      const type = dv.getUint16(p, true), hsize = dv.getUint16(p + 2, true), size = dv.getUint32(p + 4, true);
      if (size < 8 || p + size > u8.length) break;
      if (type === 0x0001) {
        const n = dv.getUint32(p + 8, true), flags = dv.getUint32(p + 16, true), sstart = dv.getUint32(p + 20, true);
        const isUtf8 = !!(flags & 0x100);
        for (let i = 0; i < n; i++) {
          let o = p + sstart + dv.getUint32(p + hsize + i * 4, true);
          if (isUtf8) {
            if (u8[o] & 0x80) o += 2; else o += 1;
            let len = u8[o++];
            if (len & 0x80) len = ((len & 0x7f) << 8) | u8[o++];
            strings.push(new TextDecoder().decode(u8.subarray(o, o + len)));
          } else {
            let len = dv.getUint16(o, true); o += 2;
            if (len & 0x8000) { len = ((len & 0x7fff) << 16) | dv.getUint16(o, true); o += 2; }
            let s = '';
            for (let k = 0; k < len; k++) s += String.fromCharCode(dv.getUint16(o + k * 2, true));
            strings.push(s);
          }
        }
      } else if (type === 0x0180) {
        for (let o = p + hsize; o + 4 <= p + size; o += 4) resMap.push(dv.getUint32(o, true));
      } else if (type === 0x0100) {
        const prefix = str(dv.getUint32(p + 16, true)), uri = str(dv.getUint32(p + 20, true));
        if (uri) { nsPrefix[uri] = prefix || 'ns'; pendingNs.push([prefix || 'ns', uri]); }
      } else if (type === 0x0102) {
        const name = str(dv.getUint32(p + 20, true)) || '?';
        const attrStart = dv.getUint16(p + 24, true), attrSize = dv.getUint16(p + 26, true) || 20, attrCount = dv.getUint16(p + 28, true);
        let line = '  '.repeat(depth) + '<' + name;
        for (const [pre, uri] of pendingNs) line += ` xmlns:${pre}="${escAttr(uri)}"`;
        pendingNs = [];
        for (let i = 0; i < attrCount; i++) {
          const o = p + 16 + attrStart + i * attrSize;
          const nsI = dv.getUint32(o, true), nameI = dv.getUint32(o + 4, true), rawI = dv.getUint32(o + 8, true);
          const dataType = u8[o + 15], data = dv.getUint32(o + 16, true);
          let an = str(nameI);
          if (!an && nameI < resMap.length) an = ANDROID_ATTRS[resMap[nameI]] || ('attr_0x' + resMap[nameI].toString(16));
          const ns = str(nsI);
          const pre = ns ? (nsPrefix[ns] || 'android') + ':' : '';
          let val;
          const raw = str(rawI);
          if (dataType === 0x03) val = str(data) != null ? str(data) : (raw || '');
          else if (dataType === 0x12) val = data ? 'true' : 'false';
          else if (dataType === 0x10) val = String(data | 0);
          else if (dataType === 0x11) val = '0x' + data.toString(16);
          else if (dataType === 0x01) val = '@0x' + data.toString(16).padStart(8, '0');
          else if (dataType === 0x02) val = '?0x' + data.toString(16).padStart(8, '0');
          else if (dataType === 0x04) val = String(new DataView(new Uint32Array([data]).buffer).getFloat32(0, true));
          else if (dataType >= 0x1c && dataType <= 0x1f) val = '#' + data.toString(16).padStart(8, '0');
          else val = raw != null ? raw : '0x' + data.toString(16);
          line += ` ${pre}${an || '?'}="${escAttr(val)}"`;
        }
        out += line + '>\n';
        depth++;
      } else if (type === 0x0103) {
        depth = Math.max(0, depth - 1);
        out += '  '.repeat(depth) + '</' + (str(dv.getUint32(p + 20, true)) || '?') + '>\n';
      } else if (type === 0x0104) {
        const t = str(dv.getUint32(p + 16, true));
        if (t && t.trim()) out += '  '.repeat(depth) + t.trim() + '\n';
      }
      p += size;
    }
    // collapse <a>\n</a> into <a/>
    return out.replace(/<([^\/!?][^>]*)>\n\s*<\/[^>]+>/g, '<$1/>');
  }

  // ------------------------------------------------------------ MD5

  function md5(u8) {
    const K = new Int32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
    const n = u8.length, total = ((n + 8) >> 6) + 1;
    const tail = new Uint8Array(total * 64 - (n & ~63));
    tail.set(u8.subarray(n & ~63));
    tail[n & 63] = 0x80;
    const tdv = new DataView(tail.buffer);
    tdv.setUint32(tail.length - 8, (n << 3) >>> 0, true);
    tdv.setUint32(tail.length - 4, Math.floor(n / 536870912), true);
    let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
    const M = new Int32Array(16);
    const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    const block = (view, off) => {
      for (let i = 0; i < 16; i++) M[i] = view.getInt32(off + i * 4, true);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        F = (F + A + K[i] + M[g]) | 0;
        A = D; D = C; C = B;
        const s = S[(i >> 4) * 4 + (i & 3)];
        B = (B + ((F << s) | (F >>> (32 - s)))) | 0;
      }
      a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
    };
    for (let off = 0; off + 64 <= n; off += 64) block(dv, off);
    for (let off = 0; off < tail.length; off += 64) block(tdv, off);
    const out = new DataView(new ArrayBuffer(16));
    [a0, b0, c0, d0].forEach((v, i) => out.setInt32(i * 4, v, true));
    return [...new Uint8Array(out.buffer)].map(x => x.toString(16).padStart(2, '0')).join('');
  }

  function entropy(u8, start, end) {
    const n = end - start;
    if (n <= 0) return 0;
    const f = new Uint32Array(256);
    for (let i = start; i < end; i++) f[u8[i]]++;
    let h = 0;
    for (let i = 0; i < 256; i++) if (f[i]) { const p = f[i] / n; h -= p * Math.log2(p); }
    return h;
  }

  // ------------------------------------------------------------ signatures

  // [label, kind, needle(s)] ; kind: java = jar wrapper, info = just a tag
  const SIGNATURES = [
    ['Launch4j', 'java', ['launch4j']],
    ['exe4j', 'java', ['exe4j']],
    ['JSmooth', 'java', ['jsmooth']],
    ['WinRun4J', 'java', ['winrun4j']],
    ['Packr', 'java', ['packr']],
    ['jpackage launcher', 'java', ['jpackageapplauncher']],
    ['GraalVM native-image', 'info', ['com.oracle.svm', 'graal']],
    ['PyInstaller', 'info', ['pyi-runtime-tmpdir', 'pyinstaller', '_meipass']],
    ['Nuitka', 'info', ['nuitka']],
    ['py2exe', 'info', ['py2exe']],
    ['Electron', 'info', ['electron.asar', 'app.asar']],
    ['AutoIt', 'info', ['au3!', 'autoit']],
    ['UPX packed', 'info', ['upx!']],
    ['Inno Setup', 'info', ['inno setup']],
    ['NSIS installer', 'info', ['nullsoft']],
    ['Go binary', 'info', ['go build id', 'runtime.gopanic']],
    ['Rust binary', 'info', ['rust_panic', '/rustc/']],
    ['Delphi', 'info', ['borland', 'embarcadero']],
    ['Themida/WinLicense', 'info', ['.themida', 'winlicen']],
    ['VMProtect', 'info', ['.vmp0', '.vmp1']],
    ['Enigma Protector', 'info', ['.enigma1', '.enigma2']],
  ];

  function detectSignatures(u8, pe) {
    const found = [];
    // case-insensitive search over a lowercase ASCII view (bounded for speed)
    const lim = Math.min(u8.length, 64 * 1024 * 1024);
    const low = new Uint8Array(lim);
    for (let i = 0; i < lim; i++) { const c = u8[i]; low[i] = (c >= 65 && c <= 90) ? c + 32 : c; }
    const has = needle => indexOfBytes(low, new TextEncoder().encode(needle)) >= 0;
    for (const [label, kind, needles] of SIGNATURES) if (needles.some(has)) found.push({ label, kind });
    if (pe && pe.sections) {
      const names = pe.sections.map(s => s.name.toLowerCase());
      if (names.some(n => n.startsWith('upx')) && !found.some(f => f.label === 'UPX packed')) found.push({ label: 'UPX packed', kind: 'info' });
    }
    if (pe && pe.dotnet) found.unshift({ label: '.NET assembly', kind: 'info' });
    return found;
  }

  function indexOfBytes(hay, needle, from = 0) {
    const n0 = needle[0], nl = needle.length;
    outer: for (let i = hay.indexOf(n0, from); i >= 0 && i <= hay.length - nl; i = hay.indexOf(n0, i + 1)) {
      for (let k = 1; k < nl; k++) if (hay[i + k] !== needle[k]) continue outer;
      return i;
    }
    return -1;
  }

  // Finds an embedded zip/jar (e.g. a jar wrapped by Launch4j) and returns its bytes, or null.
  function findEmbeddedZip(u8) {
    // end-of-central-directory record, scanning backwards
    const eocd = [0x50, 0x4B, 0x05, 0x06];
    for (let i = u8.length - 22; i >= 0; i--) {
      if (u8[i] === eocd[0] && u8[i + 1] === eocd[1] && u8[i + 2] === eocd[2] && u8[i + 3] === eocd[3]) {
        const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
        const cdSize = dv.getUint32(i + 12, true);
        const cdOff = dv.getUint32(i + 16, true);
        const commentLen = dv.getUint16(i + 20, true);
        const cdStart = i - cdSize;
        if (cdStart < 0) continue;
        // central directory must start with a file header signature
        if (!(u8[cdStart] === 0x50 && u8[cdStart + 1] === 0x4B && u8[cdStart + 2] === 1 && u8[cdStart + 3] === 2)) continue;
        const zipStart = cdStart - cdOff; // bytes prepended before the zip
        if (zipStart < 0) continue;
        return u8.subarray(zipStart, Math.min(u8.length, i + 22 + commentLen));
      }
      if (u8.length - i > 70 * 1024 * 1024) break;
    }
    return null;
  }

  // ------------------------------------------------------------ strings

  function extractStrings(u8, min = 6, max = 40000) {
    const out = [];
    const lim = u8.length;
    // ASCII
    let start = -1;
    for (let i = 0; i <= lim; i++) {
      const c = i < lim ? u8[i] : 0;
      const printable = (c >= 0x20 && c < 0x7f) || c === 9;
      if (printable) { if (start < 0) start = i; }
      else if (start >= 0) {
        if (i - start >= min) { out.push({ off: start, enc: 'A', s: latin(u8, start, i) }); if (out.length >= max) return out; }
        start = -1;
      }
    }
    // UTF-16LE
    start = -1;
    for (let i = 0; i + 1 <= lim; i += 2) {
      const c = i + 1 < lim ? u8[i] | (u8[i + 1] << 8) : 0;
      const printable = c >= 0x20 && c < 0x7f;
      if (printable) { if (start < 0) start = i; }
      else if (start >= 0) {
        if ((i - start) / 2 >= min) {
          let s = '';
          for (let k = start; k < i; k += 2) s += String.fromCharCode(u8[k]);
          out.push({ off: start, enc: 'W', s });
          if (out.length >= max) break;
        }
        start = -1;
      }
    }
    out.sort((a, b) => a.off - b.off);
    return out;
  }

  function latin(u8, a, b) {
    let s = '';
    for (let i = a; i < b; i += 8192) s += String.fromCharCode.apply(null, u8.subarray(i, Math.min(b, i + 8192)));
    return s;
  }

  function classifyString(s) {
    if (/https?:\/\/|wss?:\/\//i.test(s)) return 'url';
    if (/discord(app)?\.com\/api\/webhooks/i.test(s)) return 'url';
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(s)) return 'ip';
    if (/^(HKEY_|HKLM|HKCU|SOFTWARE\\)/i.test(s)) return 'reg';
    if (/[a-z]:\\|\\\\|%appdata%|%temp%/i.test(s)) return 'path';
    if (/\.(dll|exe|sys|bat|ps1|vbs|jar)\b/i.test(s)) return 'file';
    return '';
  }

  return { sniff, parseClass, javaVersion, parsePE, parsePyInstaller, dexInfo, decodeAXML, md5, detectSignatures, findEmbeddedZip, extractStrings, classifyString, MACHINES, SUBSYSTEMS };
})();
