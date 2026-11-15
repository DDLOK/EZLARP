// EZLARP file inspection: sniffing, .class parsing, PE (.exe/.dll) analysis,
// strings extraction. Pure JS, runs entirely in the browser.
'use strict';

const Inspect = (() => {

  // ------------------------------------------------------------ sniffing

  function sniff(u8, name) {
    const n = (name || '').toLowerCase();
    if (u8.length >= 4 && u8[0] === 0xCA && u8[1] === 0xFE && u8[2] === 0xBA && u8[3] === 0xBE) return 'class';
    if (u8.length >= 2 && u8[0] === 0x4D && u8[1] === 0x5A) return 'pe';
    if (u8.length >= 4 && u8[0] === 0x50 && u8[1] === 0x4B && (u8[2] === 3 || u8[2] === 5)) return 'zip';
    if (/\.(jar|zip|war|ear)$/.test(n)) return 'zip';
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

  // Returns { name: 'com/foo/Bar', major, minor } or null.
  function parseClass(u8) {
    try {
      const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
      if (dv.getUint32(0) !== 0xCAFEBABE) return null;
      const minor = dv.getUint16(4), major = dv.getUint16(6);
      const count = dv.getUint16(8);
      const utf8 = new Array(count), classIdx = new Array(count);
      let p = 10;
      for (let i = 1; i < count; i++) {
        const tag = u8[p++];
        switch (tag) {
          case 1: { const len = dv.getUint16(p); utf8[i] = decodeMUTF8(u8, p + 2, len); p += 2 + len; break; }
          case 7: classIdx[i] = dv.getUint16(p); p += 2; break;
          case 8: case 16: case 19: case 20: p += 2; break;
          case 15: p += 3; break;
          case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18: p += 4; break;
          case 5: case 6: p += 8; i++; break;
          default: return { name: null, major, minor };
        }
      }
      const thisIdx = dv.getUint16(p + 2);
      return { name: utf8[classIdx[thisIdx]] || null, major, minor };
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
    } catch (e) {
      r.error = String(e && e.message || e);
    }
    return r;
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

  return { sniff, parseClass, javaVersion, parsePE, detectSignatures, findEmbeddedZip, extractStrings, classifyString, MACHINES, SUBSYSTEMS };
})();
