#!/usr/bin/env python3
"""Builds the binary sample fixtures in public/samples/ from already-built parts.

  sample-wrapped.exe  = minimal synthetic PE stub + sample.jar appended (Launch4j-style layout)
  sample.apk          = zip of classes.dex + a hand-encoded binary AndroidManifest.xml

usage: make.py <sample.jar> <classes.dex> <out-dir>
"""
import struct, sys, zipfile

def pe_stub():
    text = b'EZLARP sample stub. Not a real launcher: laid out like a launch4j wrapper so the jar extractor has something to find.\0'
    text = text.ljust(512, b'\0')
    dos = bytearray(64); dos[0:2] = b'MZ'; struct.pack_into('<I', dos, 0x3c, 64)
    coff = struct.pack('<HHIIIHH', 0x8664, 1, 0x60000000, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into('<HBB', opt, 0, 0x20b, 14, 0)
    struct.pack_into('<I', opt, 4, 512)            # SizeOfCode
    struct.pack_into('<I', opt, 16, 0x1000)        # AddressOfEntryPoint
    struct.pack_into('<I', opt, 20, 0x1000)        # BaseOfCode
    struct.pack_into('<Q', opt, 24, 0x140000000)   # ImageBase
    struct.pack_into('<II', opt, 32, 0x1000, 0x200)
    struct.pack_into('<HH', opt, 40, 6, 0)
    struct.pack_into('<HH', opt, 48, 6, 0)
    struct.pack_into('<II', opt, 56, 0x2000, 0x200)  # SizeOfImage, SizeOfHeaders
    struct.pack_into('<HH', opt, 68, 3, 0x8160)      # console, ASLR+DEP
    struct.pack_into('<I', opt, 108, 16)             # NumberOfRvaAndSizes
    sec = struct.pack('<8sIIIIIIHHI', b'.text', 512, 0x1000, 512, 0x200, 0, 0, 0, 0, 0x60000020)
    head = bytes(dos) + b'PE\0\0' + coff + bytes(opt) + sec
    return head.ljust(0x200, b'\0') + text

def axml(root):
    """root = (name, {attr: (resid, type, value)}, [children]) -> Android binary XML"""
    NS = 'http://schemas.android.com/apk/res/android'
    strings, resids = [], []
    def collect_attrs(node):
        for a, (rid, _, _) in node[1].items():
            if rid and a not in strings:
                strings.append(a); resids.append(rid)
        for c in node[2]: collect_attrs(c)
    collect_attrs(root)
    def sid(s):
        if s not in strings: strings.append(s)
        return strings.index(s)
    body = bytearray()
    body += struct.pack('<HHI', 0x0100, 16, 24) + struct.pack('<IIII', 1, 0xffffffff, sid('android'), sid(NS))
    def emit(node):
        nonlocal body
        name, attrs, kids = node
        ab = b''
        for a, (rid, typ, val) in attrs.items():
            if typ == 'str':
                ab += struct.pack('<IIIHBBI', sid(NS) if rid else 0xffffffff, sid(a), sid(val), 8, 0, 3, sid(val))
            elif typ == 'int':
                ab += struct.pack('<IIIHBBI', sid(NS) if rid else 0xffffffff, sid(a), 0xffffffff, 8, 0, 0x10, val)
            elif typ == 'bool':
                ab += struct.pack('<IIIHBBI', sid(NS) if rid else 0xffffffff, sid(a), 0xffffffff, 8, 0, 0x12, 0xffffffff if val else 0)
        ext = struct.pack('<IIHHHHHH', 0xffffffff, sid(name), 20, 20, len(attrs), 0, 0, 0) + ab
        body += struct.pack('<HHI', 0x0102, 16, 16 + len(ext)) + struct.pack('<II', 1, 0xffffffff) + ext
        for k in kids: emit(k)
        body += struct.pack('<HHI', 0x0103, 16, 24) + struct.pack('<II', 1, 0xffffffff) + struct.pack('<II', 0xffffffff, sid(name))
    emit(root)
    body += struct.pack('<HHI', 0x0101, 16, 24) + struct.pack('<IIII', 1, 0xffffffff, sid('android'), sid(NS))
    # string pool (UTF-16)
    data, offs = b'', []
    for s in strings:
        offs.append(len(data))
        data += struct.pack('<H', len(s)) + s.encode('utf-16-le') + b'\0\0'
    data = data.ljust((len(data) + 3) & ~3, b'\0')
    off_tab = b''.join(struct.pack('<I', o) for o in offs)
    pool_hdr = struct.pack('<IIIII', len(strings), 0, 0, 28 + len(off_tab), 0)
    pool = struct.pack('<HHI', 0x0001, 28, 28 + len(off_tab) + len(data)) + pool_hdr + off_tab + data
    resmap = struct.pack('<HHI', 0x0180, 8, 8 + 4 * len(resids)) + b''.join(struct.pack('<I', r) for r in resids)
    total = 8 + len(pool) + len(resmap) + len(body)
    return struct.pack('<HHI', 0x0003, 8, total) + pool + resmap + bytes(body)

def main():
    jar, dex, out = sys.argv[1:4]
    with open(out + '/sample-wrapped.exe', 'wb') as f:
        f.write(pe_stub() + open(jar, 'rb').read())
    manifest = axml(('manifest', {
        'versionCode': (0x0101021b, 'int', 3), 'versionName': (0x0101021c, 'str', '1.2.0'),
        'package': (0, 'str', 'dev.ezlarp.sample')}, [
        ('uses-sdk', {'minSdkVersion': (0x0101020c, 'int', 24), 'targetSdkVersion': (0x01010270, 'int', 34)}, []),
        ('uses-permission', {'name': (0x01010003, 'str', 'android.permission.INTERNET')}, []),
        ('uses-permission', {'name': (0x01010003, 'str', 'android.permission.READ_CONTACTS')}, []),
        ('application', {'label': (0x01010001, 'str', 'EZLARP Sample'), 'debuggable': (0x0101000f, 'bool', False)}, [
            ('activity', {'name': (0x01010003, 'str', 'demo.App'), 'exported': (0x01010010, 'bool', True)}, [
                ('intent-filter', {}, [
                    ('action', {'name': (0x01010003, 'str', 'android.intent.action.MAIN')}, []),
                    ('category', {'name': (0x01010003, 'str', 'android.intent.category.LAUNCHER')}, [])])])])]))
    with zipfile.ZipFile(out + '/sample.apk', 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('AndroidManifest.xml', manifest)
        z.write(dex, 'classes.dex')
        z.writestr('res/raw/readme.txt', 'Synthetic sample APK for EZLARP. Not installable.\n')

main()
