#!/usr/bin/env python3
"""Writes rsrc_windows_amd64.syso: the app icon, version info and manifest for EZLARP.exe.
Go links any .syso in the package directory. Run: python3 winres.py <icon.png> <version>"""
import io, struct, sys
from PIL import Image

png_path, version = sys.argv[1], sys.argv[2]
ver = [int(x) for x in (version.split('.') + ['0', '0', '0'])[:4]]

# ---- icons: PNG-compressed entries (Windows Vista and later)
src = Image.open(png_path).convert('RGBA')
icons = []
for size in (16, 24, 32, 48, 64, 128, 256):
    b = io.BytesIO()
    src.resize((size, size), Image.LANCZOS).save(b, 'PNG')
    icons.append((size, b.getvalue()))
group = struct.pack('<HHH', 0, 1, len(icons))
for i, (size, data) in enumerate(icons):
    s = 0 if size >= 256 else size
    group += struct.pack('<BBBBHHIH', s, s, 0, 0, 1, 32, len(data), i + 1)

# ---- version info
def node(key, value=b'', wtype=1, children=b'', value_len=None):
    out = bytearray(struct.pack('<HHH', 0, 0, wtype)) + (key + '\0').encode('utf-16-le')
    out += b'\0' * ((4 - len(out) % 4) % 4)
    out += value
    if children:
        out += b'\0' * ((4 - len(out) % 4) % 4)
        out += children
    struct.pack_into('<HH', out, 0, len(out), value_len if value_len is not None else len(value))
    out += b'\0' * ((4 - len(out) % 4) % 4)
    return bytes(out)

def string(key, val):
    v = (val + '\0').encode('utf-16-le')
    return node(key, v, 1, value_len=len(v) // 2)

vs = '.'.join(map(str, ver))
strings = b''.join(string(k, v) for k, v in [
    ('CompanyName', 'EZLARP'), ('FileDescription', 'EZLARP malware scanner and decompiler'), ('FileVersion', vs),
    ('InternalName', 'EZLARP'), ('LegalCopyright', 'EZLARP'), ('OriginalFilename', 'EZLARP.exe'),
    ('ProductName', 'EZLARP'), ('ProductVersion', vs)])
table = node('040904b0', children=strings)
sfi = node('StringFileInfo', children=table)
var = node('Translation', struct.pack('<HH', 0x0409, 0x04b0), 0)
vfi = node('VarFileInfo', children=var)
fixed = struct.pack('<13I', 0xFEEF04BD, 0x00010000, (ver[0] << 16) | ver[1], (ver[2] << 16) | ver[3], (ver[0] << 16) | ver[1],
                    (ver[2] << 16) | ver[3], 0x3F, 0, 0x40004, 1, 0, 0, 0)
version_res = node('VS_VERSION_INFO', fixed, 0, sfi + vfi)

manifest = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="EZLARP" version="%s" processorArchitecture="amd64"/>
  <description>EZLARP</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges>
    <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
  </requestedPrivileges></security></trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application>
    <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
  </application></compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3"><windowsSettings>
    <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
    <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
  </windowsSettings></application>
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
</assembly>
''' % vs.encode()

# ---- resource tree: type -> id -> language(0x409) -> data
RT_ICON, RT_GROUP_ICON, RT_VERSION, RT_MANIFEST = 3, 14, 16, 24
res = {RT_ICON: {i + 1: d for i, (_, d) in enumerate(icons)}, RT_GROUP_ICON: {1: group}, RT_VERSION: {1: version_res}, RT_MANIFEST: {1: manifest}}

dirs = bytearray()
def dir_header(n):
    return struct.pack('<IIHHHH', 0, 0, 0, 0, 0, n)

# layout: root dir, type dirs, id dirs, lang dirs, data entries, then data
types = sorted(res)
root_size = 16 + 8 * len(types)
type_dirs = {t: 16 + 8 * len(res[t]) for t in types}
lang_dir_size = 16 + 8
offset = root_size
type_off = {}
for t in types:
    type_off[t] = offset; offset += type_dirs[t]
lang_off = {}
for t in types:
    for i in sorted(res[t]):
        lang_off[(t, i)] = offset; offset += lang_dir_size
entry_off = {}
for t in types:
    for i in sorted(res[t]):
        entry_off[(t, i)] = offset; offset += 16
data_off = {}
for t in types:
    for i in sorted(res[t]):
        offset = (offset + 7) & ~7
        data_off[(t, i)] = offset; offset += len(res[t][i])
blob = bytearray(offset)
relocs = []
def put(off, b):
    blob[off:off + len(b)] = b
put(0, dir_header(len(types)) + b''.join(struct.pack('<II', t, 0x80000000 | type_off[t]) for t in types))
for t in types:
    ids = sorted(res[t])
    put(type_off[t], dir_header(len(ids)) + b''.join(struct.pack('<II', i, 0x80000000 | lang_off[(t, i)]) for i in ids))
    for i in ids:
        put(lang_off[(t, i)], dir_header(1) + struct.pack('<II', 0x0409, entry_off[(t, i)]))
        put(entry_off[(t, i)], struct.pack('<IIII', data_off[(t, i)], len(res[t][i]), 0, 0))
        relocs.append(entry_off[(t, i)])  # OffsetToData is an RVA: the linker adds the section's address
        put(data_off[(t, i)], res[t][i])

# ---- COFF object
n_sect = 1
hdr_size = 20 + 40
raw_ptr = hdr_size
reloc_ptr = raw_ptr + len(blob)
sym_ptr = reloc_ptr + 10 * len(relocs)
coff = struct.pack('<HHIIIHH', 0x8664, n_sect, 0, sym_ptr, 1, 0, 0)
sect = struct.pack('<8sIIIIIIHHI', b'.rsrc', 0, 0, len(blob), raw_ptr, reloc_ptr, 0, len(relocs), 0, 0x40000040)
rel = b''.join(struct.pack('<IIH', r, 0, 3) for r in relocs)  # IMAGE_REL_AMD64_ADDR32NB against symbol 0
sym = struct.pack('<8sIhHBB', b'.rsrc', 0, 1, 0, 3, 0)
strtab = struct.pack('<I', 4)
with open('rsrc_windows_amd64.syso', 'wb') as f:
    f.write(coff + sect + bytes(blob) + rel + sym + strtab)
print('wrote rsrc_windows_amd64.syso', len(blob), 'bytes of resources,', len(icons), 'icons')
