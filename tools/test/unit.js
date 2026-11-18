// Unit tests for public/inspect.js and public/scan.js. Run: node tools/test/unit.js
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm'), crypto = require('crypto'), zlib = require('zlib');
const root = path.join(__dirname, '..', '..');
const ctx = { TextEncoder, TextDecoder, console };
vm.createContext(ctx);
for (const f of ['inspect.js', 'scan.js']) vm.runInContext(fs.readFileSync(path.join(root, 'public', f), 'utf8'), ctx, { filename: f });
vm.runInContext('this.Inspect = Inspect; this.Scan = Scan;', ctx);
const { Inspect: I, Scan } = ctx;
const JSZip = require(path.join(root, 'public', 'vendor', 'jszip.min.js'));

let pass = 0, fail = 0;
const ok = (cond, name, extra) => { if (cond) pass++; else { fail++; console.log('FAIL', name, extra === undefined ? '' : JSON.stringify(extra)); } };
const read = f => new Uint8Array(fs.readFileSync(path.join(root, 'public', 'samples', f)));

(async () => {
  // md5
  for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 70000]) {
    const b = crypto.randomBytes(n);
    ok(I.md5(new Uint8Array(b)) === crypto.createHash('md5').update(b).digest('hex'), 'md5 len ' + n);
  }

  // sample jar: deep class parse + scan
  const jar = read('sample.jar');
  ok(I.sniff(jar, 'x.jar') === 'zip', 'sniff jar');
  const zip = await JSZip.loadAsync(jar);
  const res = Scan.newResult();
  const names = [];
  for (const f of Object.values(zip.files)) {
    if (!f.name.endsWith('.class')) continue;
    const info = I.parseClass(await f.async('uint8array'), true);
    ok(info && info.name === f.name.replace(/\.class$/, ''), 'class name ' + f.name, info && info.name);
    ok(info.major === 61, 'class major', info.major);
    names.push(info.name);
    Scan.scanClass(res, info);
  }
  const sum = Scan.summarize(res);
  const ids = sum.findings.map(f => f.rule.id);
  for (const want of ['webhook', 'mc-session', 'ip-lookup', 'exec', 'net']) ok(ids.includes(want), 'rule ' + want, ids);
  ok(sum.level === 'high', 'level high', sum.level);
  ok(res.hits.get('webhook').where.has('demo/mod/ScanDemo'), 'webhook located in ScanDemo');
  ok([...res.urls.keys()].some(u => u.includes('discord.com/api/webhooks')), 'url list has webhook', [...res.urls.keys()]);
  ok(![...res.urls.keys()].some(u => u.includes('example.com')), 'boring host filtered');

  // clean class set -> no high
  const res2 = Scan.newResult();
  Scan.scanString(res2, 'hello world', 'x'); Scan.scanString(res2, '1.21.4.0', 'x'); Scan.scanString(res2, 'http://www.w3.org/2001/XMLSchema', 'x');
  ok(Scan.summarize(res2).level === 'none' && res2.ips.size === 0 && res2.urls.size === 0, 'clean strings');
  Scan.scanString(res2, 'connect to 45.137.22.9:4444 now', 'x');
  ok(res2.ips.has('45.137.22.9:4444'), 'ip with port', [...res2.ips.keys()]);

  // wrapped exe
  const exe = read('sample-wrapped.exe');
  ok(I.sniff(exe, 'a.exe') === 'pe', 'sniff exe');
  const pe = I.parsePE(exe);
  ok(pe.ok && pe.is64 && pe.sections.length === 1 && pe.sections[0].name === '.text', 'pe parse', pe.error);
  ok(pe.overlay && pe.overlay.offset === 0x400, 'pe overlay', pe.overlay);
  const emb = I.findEmbeddedZip(exe);
  ok(emb && emb.length === jar.length && Buffer.compare(Buffer.from(emb), Buffer.from(jar)) === 0, 'embedded jar identical');
  ok(I.detectSignatures(exe, pe).some(s => s.label === 'Launch4j'), 'launch4j signature');

  // real-world exes if present (resources, imports)
  for (const f of ['/opt/node-tools/node_modules/nodemon/bin/windows-kill.exe', '/opt/node-tools/node_modules/clipboardy/fallbacks/windows/clipboard_x86_64.exe']) {
    if (!fs.existsSync(f)) continue;
    const u8 = new Uint8Array(fs.readFileSync(f));
    const p = I.parsePE(u8);
    ok(p.ok && p.imports.length > 0, 'real pe ' + path.basename(f), p.error || p.resError);
    console.log('  ', path.basename(f), 'version:', JSON.stringify(p.version || null), 'icon:', p.icon ? p.icon.length : null, 'manifest:', p.manifest ? p.manifest.length : null, 'level:', p.executionLevel || null, 'resErr:', p.resError || null);
  }

  // apk: manifest + dex header
  const apk = await JSZip.loadAsync(read('sample.apk'));
  const xml = I.decodeAXML(await apk.file('AndroidManifest.xml').async('uint8array'));
  ok(/package="dev\.ezlarp\.sample"/.test(xml), 'axml package', xml);
  ok(/android:versionName="1\.2\.0"/.test(xml) && /android:versionCode="3"/.test(xml), 'axml version');
  ok(/<uses-permission android:name="android\.permission\.INTERNET"\/>/.test(xml), 'axml permission');
  ok(/android:exported="true"/.test(xml) && /android:minSdkVersion="24"/.test(xml), 'axml bool/int');
  const dex = await apk.file('classes.dex').async('uint8array');
  ok(I.sniff(dex, 'classes.dex') === 'dex' && I.dexInfo(dex).classes === 3, 'dex info', I.dexInfo(dex));

  // pyinstaller: synthetic CArchive
  const entries = [['struct', Buffer.from('pyz-ish data'), 's', false], ['main', Buffer.from('print("hello from python")\n'.repeat(20)), 's', true]];
  let data = Buffer.alloc(0), toc = Buffer.alloc(0);
  for (const [name, raw, type, comp] of entries) {
    const body = comp ? zlib.deflateSync(raw) : raw;
    const nameBuf = Buffer.alloc(Math.ceil((name.length + 1) / 16) * 16); nameBuf.write(name);
    const e = Buffer.alloc(18); e.writeUInt32BE(18 + nameBuf.length, 0); e.writeUInt32BE(data.length, 4); e.writeUInt32BE(body.length, 8); e.writeUInt32BE(raw.length, 12); e[16] = comp ? 1 : 0; e[17] = type.charCodeAt(0);
    toc = Buffer.concat([toc, e, nameBuf]); data = Buffer.concat([data, body]);
  }
  const cookie = Buffer.alloc(88); Buffer.from([0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E]).copy(cookie);
  cookie.writeUInt32BE(data.length + toc.length + 88, 8); cookie.writeUInt32BE(data.length, 12); cookie.writeUInt32BE(toc.length, 16); cookie.writeUInt32BE(311, 20); cookie.write('python311.dll', 24);
  const pyexe = new Uint8Array(Buffer.concat([Buffer.from(exe.subarray(0, 0x400)), data, toc, cookie]));
  const py = I.parsePyInstaller(pyexe);
  ok(py && py.pyver === '3.11' && py.files.length === 2 && py.files[1].name === 'main' && py.files[1].compressed, 'pyinstaller toc', py);
  ok(py && zlib.inflateSync(Buffer.from(pyexe.subarray(py.files[1].off, py.files[1].off + py.files[1].csize))).toString().startsWith('print("hello'), 'pyinstaller data offset');
  ok(I.parsePyInstaller(exe) === null, 'no pyinstaller in plain exe');

  // x86 / x64 disassembler
  {
    const X86 = require(path.join(root, 'public', 'x86.js'));
    const d = (hexs, x64 = true, ip = 0x1000) => { const r = X86.decode(Uint8Array.from(Buffer.from(hexs, 'hex')), 0, ip, x64); return r.len + ' ' + r.mn + (r.ops ? ' ' + r.ops : ''); };
    ok(d('55') === '1 push rbp', 'x86 push rbp', d('55'));
    ok(d('4889e5') === '3 mov rbp, rsp', 'x86 mov', d('4889e5'));
    ok(d('488b05b8130000') === '7 mov rax, qword ptr [rip+0x13b8]', 'x86 rip-relative', d('488b05b8130000'));
    ok(d('e800100000') === '5 call 0x2005', 'x86 call', d('e800100000'));
    ok(d('ff15f2100000') === '6 call qword ptr [rip+0x10f2]', 'x86 call [iat]', d('ff15f2100000'));
    ok(d('48b8efcdab8967452301') === '10 mov rax, 0x123456789abcdef', 'x86 mov imm64', d('48b8efcdab8967452301'));
    ok(d('f30f6f0424') === '5 movdqu xmm0, xmmword ptr [rsp]', 'x86 sse', d('f30f6f0424'));
    ok(d('c5fc77') === '3 vzeroall', 'x86 vex', d('c5fc77'));
    ok(d('6a01', false) === '2 push 0x1', 'x86 32-bit push', d('6a01', false));
    ok(d('ff1500204000', false) === '6 call dword ptr [0x402000]', 'x86 32-bit call [abs]', d('ff1500204000', false));
    ok(d('dbe2', false) === '2 fnclex', 'x86 x87', d('dbe2', false));
    ok(d('f3a4') === '2 rep movsb byte ptr es:[rdi], byte ptr ds:[rsi]', 'x86 rep movsb', d('f3a4'));
    ok(d('0f05') === '2 syscall', 'x86 syscall');
  }
  // .NET metadata reader on a real assembly, if the fixture is there
  {
    const fx = process.env.FX || '/tmp/fx';
    const dll = path.join(fx, 'dotnet.dll');
    if (fs.existsSync(dll)) {
      const Cil = require(path.join(root, 'public', 'cil.js'));
      const A = Cil.load(new Uint8Array(fs.readFileSync(dll)));
      const types = Cil.listTypes(A);
      ok(types.length === 2 && /NaturalSortComparer\.cs$/.test(types[0].path), '.net types', types.map(t => t.path));
      const cs = Cil.decompileType(A, types[0].i);
      ok(/public int Compare\(string str1, string str2\)/.test(cs) && /private const byte TokenDigits = 2;/.test(cs), '.net members', cs.slice(0, 400));
      ok(/c18 = num17 >= num14 \? str1\[num2 \+ num17 - num14\] : 48;/.test(cs), '.net ternary + indexer');
      ok(/num4\+\+;/.test(cs) && /break;/.test(cs), '.net ++ and break');
      ok(/IL_0000: ldarg\.0/.test(Cil.ilType(A, types[0].i)), '.net IL listing');
      ok(/runtime v4\.0\.30319/.test(Cil.assemblyInfo(A)), '.net assembly info');
    }
  }

  console.log(`${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
