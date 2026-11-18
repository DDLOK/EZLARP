// EZLARP x86 / x64 disassembler (Intel syntax). Table driven, covers the general-purpose
// instruction set, x87, MMX/SSE through SSE4.2, and VEX/EVEX lengths. Unknown encodings come
// out as "(bad)" with the right length where possible, like objdump.
'use strict';
const X86 = (() => {
  const R8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh'];
  const R8X = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b'];
  const R16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w'];
  const R32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d'];
  const R64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];
  const SEG = ['es', 'cs', 'ss', 'ds', 'fs', 'gs', '?', '?'];
  const CC = ['o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'];
  const G1 = ['add', 'or', 'adc', 'sbb', 'and', 'sub', 'xor', 'cmp'];
  const G2 = ['rol', 'ror', 'rcl', 'rcr', 'shl', 'shr', 'shl', 'sar'];
  const G3 = ['test', 'test', 'not', 'neg', 'mul', 'imul', 'div', 'idiv'];
  const SZ = { 1: 'byte', 2: 'word', 4: 'dword', 8: 'qword', 10: 'tbyte', 16: 'xmmword', 32: 'ymmword', 64: 'zmmword', 6: 'fword', 0: '' };
  const hx = n => (n < 0 ? '-0x' + (-n).toString(16) : '0x' + n.toString(16));

  // one-byte opcode map. Operand codes:
  // Eb Ev Ew Ed Gb Gv Gw Ib Iw Iz Iv sIb Jb Jz M Sw AL rAX DX CL 1 Zb Zv Ob Ov Ap Xb Xv Yb Yv
  const O1 = new Array(256);
  const def = (op, mn, ops = '', fl = '') => { O1[op] = { mn, ops: ops ? ops.split(',') : [], fl }; };
  G1.forEach((m, i) => {
    const b = i * 8;
    def(b, m, 'Eb,Gb'); def(b + 1, m, 'Ev,Gv'); def(b + 2, m, 'Gb,Eb'); def(b + 3, m, 'Gv,Ev'); def(b + 4, m, 'AL,Ib'); def(b + 5, m, 'rAX,Iz');
  });
  def(0x06, 'push', 'ES', 'i64'); def(0x07, 'pop', 'ES', 'i64'); def(0x0e, 'push', 'CS', 'i64'); def(0x16, 'push', 'SS', 'i64'); def(0x17, 'pop', 'SS', 'i64');
  def(0x1e, 'push', 'DS', 'i64'); def(0x1f, 'pop', 'DS', 'i64'); def(0x27, 'daa', '', 'i64'); def(0x2f, 'das', '', 'i64'); def(0x37, 'aaa', '', 'i64'); def(0x3f, 'aas', '', 'i64');
  for (let i = 0; i < 8; i++) { def(0x40 + i, 'inc', 'Zv'); def(0x48 + i, 'dec', 'Zv'); def(0x50 + i, 'push', 'Zv', 'd64'); def(0x58 + i, 'pop', 'Zv', 'd64'); }
  def(0x60, 'pusha', '', 'i64'); def(0x61, 'popa', '', 'i64'); def(0x62, 'bound', 'Gv,M', 'i64'); def(0x63, 'arpl', 'Ew,Gw');
  def(0x68, 'push', 'Iz', 'd64'); def(0x69, 'imul', 'Gv,Ev,Iz'); def(0x6a, 'push', 'sIb', 'd64'); def(0x6b, 'imul', 'Gv,Ev,sIb');
  def(0x6c, 'ins', 'Yb,DX'); def(0x6d, 'ins', 'Yv,DX'); def(0x6e, 'outs', 'DX,Xb'); def(0x6f, 'outs', 'DX,Xv');
  for (let i = 0; i < 16; i++) def(0x70 + i, 'j' + CC[i], 'Jb', 'br');
  def(0x80, 'G1', 'Eb,Ib'); def(0x81, 'G1', 'Ev,Iz'); def(0x82, 'G1', 'Eb,Ib', 'i64'); def(0x83, 'G1', 'Ev,sIb');
  def(0x84, 'test', 'Eb,Gb'); def(0x85, 'test', 'Ev,Gv'); def(0x86, 'xchg', 'Eb,Gb'); def(0x87, 'xchg', 'Ev,Gv');
  def(0x88, 'mov', 'Eb,Gb'); def(0x89, 'mov', 'Ev,Gv'); def(0x8a, 'mov', 'Gb,Eb'); def(0x8b, 'mov', 'Gv,Ev'); def(0x8c, 'mov', 'Ev,Sw'); def(0x8d, 'lea', 'Gv,M');
  def(0x8e, 'mov', 'Sw,Ew'); def(0x8f, 'pop', 'Ev', 'd64');
  def(0x90, 'nop'); for (let i = 1; i < 8; i++) def(0x90 + i, 'xchg', 'Zv,rAX');
  def(0x98, 'CBW'); def(0x99, 'CWD'); def(0x9a, 'call', 'Ap', 'i64'); def(0x9b, 'fwait'); def(0x9c, 'pushf', '', 'd64'); def(0x9d, 'popf', '', 'd64'); def(0x9e, 'sahf'); def(0x9f, 'lahf');
  def(0xa0, 'mov', 'AL,Ob'); def(0xa1, 'mov', 'rAX,Ov'); def(0xa2, 'mov', 'Ob,AL'); def(0xa3, 'mov', 'Ov,rAX');
  def(0xa4, 'movs', 'Yb,Xb', 'str'); def(0xa5, 'movs', 'Yv,Xv', 'str'); def(0xa6, 'cmps', 'Xb,Yb', 'str'); def(0xa7, 'cmps', 'Xv,Yv', 'str');
  def(0xa8, 'test', 'AL,Ib'); def(0xa9, 'test', 'rAX,Iz'); def(0xaa, 'stos', 'Yb,AL', 'str'); def(0xab, 'stos', 'Yv,rAX', 'str');
  def(0xac, 'lods', 'AL,Xb', 'str'); def(0xad, 'lods', 'rAX,Xv', 'str'); def(0xae, 'scas', 'AL,Yb', 'str'); def(0xaf, 'scas', 'rAX,Yv', 'str');
  for (let i = 0; i < 8; i++) { def(0xb0 + i, 'mov', 'Zb,Ib'); def(0xb8 + i, 'mov', 'Zv,Iv'); }
  def(0xc0, 'G2', 'Eb,Ib'); def(0xc1, 'G2', 'Ev,Ib'); def(0xc2, 'ret', 'Iw', 'd64'); def(0xc3, 'ret', '', 'd64'); def(0xc4, 'les', 'Gv,M', 'i64'); def(0xc5, 'lds', 'Gv,M', 'i64');
  def(0xc6, 'mov', 'Eb,Ib'); def(0xc7, 'mov', 'Ev,Iz'); def(0xc8, 'enter', 'Iw,Ib'); def(0xc9, 'leave', '', 'd64'); def(0xca, 'retf', 'Iw'); def(0xcb, 'retf');
  def(0xcc, 'int3'); def(0xcd, 'int', 'Ib'); def(0xce, 'into', '', 'i64'); def(0xcf, 'iret');
  def(0xd0, 'G2', 'Eb,1'); def(0xd1, 'G2', 'Ev,1'); def(0xd2, 'G2', 'Eb,CL'); def(0xd3, 'G2', 'Ev,CL'); def(0xd4, 'aam', 'Ib', 'i64'); def(0xd5, 'aad', 'Ib', 'i64');
  def(0xd6, 'salc', '', 'i64'); def(0xd7, 'xlat');
  def(0xe0, 'loopne', 'Jb', 'br'); def(0xe1, 'loope', 'Jb', 'br'); def(0xe2, 'loop', 'Jb', 'br'); def(0xe3, 'JCXZ', 'Jb', 'br');
  def(0xe4, 'in', 'AL,Ib'); def(0xe5, 'in', 'eAX,Ib'); def(0xe6, 'out', 'Ib,AL'); def(0xe7, 'out', 'Ib,eAX');
  def(0xe8, 'call', 'Jz', 'br,d64'); def(0xe9, 'jmp', 'Jz', 'br,d64'); def(0xea, 'jmp', 'Ap', 'i64'); def(0xeb, 'jmp', 'Jb', 'br');
  def(0xec, 'in', 'AL,DX'); def(0xed, 'in', 'eAX,DX'); def(0xee, 'out', 'DX,AL'); def(0xef, 'out', 'DX,eAX');
  def(0xf1, 'int1'); def(0xf4, 'hlt'); def(0xf5, 'cmc'); def(0xf6, 'G3', 'Eb'); def(0xf7, 'G3', 'Ev');
  def(0xf8, 'clc'); def(0xf9, 'stc'); def(0xfa, 'cli'); def(0xfb, 'sti'); def(0xfc, 'cld'); def(0xfd, 'std'); def(0xfe, 'G4', 'Eb'); def(0xff, 'G5', 'Ev');

  // two-byte map 0F xx: [mn | {none, 66, F3, F2} variants, ops, flags]
  const O2 = new Array(256);
  const d2 = (op, mn, ops = '', fl = '') => { O2[op] = { mn, ops: ops ? ops.split(',') : [], fl }; };
  d2(0x00, 'G6', 'Ew'); d2(0x01, 'G7', 'M'); d2(0x02, 'lar', 'Gv,Ew'); d2(0x03, 'lsl', 'Gv,Ew'); d2(0x05, 'syscall'); d2(0x06, 'clts'); d2(0x07, 'sysret');
  d2(0x08, 'invd'); d2(0x09, 'wbinvd'); d2(0x0b, 'ud2'); d2(0x0d, 'prefetch', 'M');
  d2(0x10, ['movups', 'movupd', 'movss', 'movsd'], 'V,W'); d2(0x11, ['movups', 'movupd', 'movss', 'movsd'], 'W,V');
  d2(0x12, ['movlps', 'movlpd', 'movsldup', 'movddup'], 'V,W'); d2(0x13, ['movlps', 'movlpd'], 'M,V');
  d2(0x14, ['unpcklps', 'unpcklpd'], 'V,W'); d2(0x15, ['unpckhps', 'unpckhpd'], 'V,W'); d2(0x16, ['movhps', 'movhpd', 'movshdup'], 'V,W'); d2(0x17, ['movhps', 'movhpd'], 'M,V');
  d2(0x18, 'G16', 'M'); for (let i = 0x19; i <= 0x1f; i++) d2(i, 'nop', 'Ev');
  d2(0x20, 'mov', 'Rd,Cd'); d2(0x21, 'mov', 'Rd,Dd'); d2(0x22, 'mov', 'Cd,Rd'); d2(0x23, 'mov', 'Dd,Rd');
  d2(0x28, ['movaps', 'movapd'], 'V,W'); d2(0x29, ['movaps', 'movapd'], 'W,V');
  d2(0x2a, ['cvtpi2ps', 'cvtpi2pd', 'cvtsi2ss', 'cvtsi2sd'], 'V,Ey'); d2(0x2b, ['movntps', 'movntpd'], 'M,V');
  d2(0x2c, ['cvttps2pi', 'cvttpd2pi', 'cvttss2si', 'cvttsd2si'], 'Gy,W'); d2(0x2d, ['cvtps2pi', 'cvtpd2pi', 'cvtss2si', 'cvtsd2si'], 'Gy,W');
  d2(0x2e, ['ucomiss', 'ucomisd'], 'V,W'); d2(0x2f, ['comiss', 'comisd'], 'V,W');
  d2(0x30, 'wrmsr'); d2(0x31, 'rdtsc'); d2(0x32, 'rdmsr'); d2(0x33, 'rdpmc'); d2(0x34, 'sysenter'); d2(0x35, 'sysexit'); d2(0x37, 'getsec');
  for (let i = 0; i < 16; i++) { d2(0x40 + i, 'cmov' + CC[i], 'Gv,Ev'); d2(0x80 + i, 'j' + CC[i], 'Jz', 'br'); d2(0x90 + i, 'set' + CC[i], 'Eb'); }
  d2(0x50, ['movmskps', 'movmskpd'], 'Gd,U');
  const SSEA = (op, base) => d2(op, [base + 'ps', base + 'pd', base + 'ss', base + 'sd'], 'V,W');
  SSEA(0x51, 'sqrt'); d2(0x52, ['rsqrtps', '', 'rsqrtss'], 'V,W'); d2(0x53, ['rcpps', '', 'rcpss'], 'V,W');
  d2(0x54, ['andps', 'andpd'], 'V,W'); d2(0x55, ['andnps', 'andnpd'], 'V,W'); d2(0x56, ['orps', 'orpd'], 'V,W'); d2(0x57, ['xorps', 'xorpd'], 'V,W');
  SSEA(0x58, 'add'); SSEA(0x59, 'mul'); d2(0x5a, ['cvtps2pd', 'cvtpd2ps', 'cvtss2sd', 'cvtsd2ss'], 'V,W'); d2(0x5b, ['cvtdq2ps', 'cvtps2dq', 'cvttps2dq'], 'V,W');
  SSEA(0x5c, 'sub'); SSEA(0x5d, 'min'); SSEA(0x5e, 'div'); SSEA(0x5f, 'max');
  'punpcklbw punpcklwd punpckldq packsswb pcmpgtb pcmpgtw pcmpgtd packuswb punpckhbw punpckhwd punpckhdq packssdw punpcklqdq punpckhqdq'.split(' ').forEach((m, i) => d2(0x60 + i, m, 'P,Q'));
  d2(0x6e, 'MOVD', 'P,Ey'); d2(0x6f, ['movq', 'movdqa', 'movdqu'], 'P,Q');
  d2(0x70, ['pshufw', 'pshufd', 'pshufhw', 'pshuflw'], 'P,Q,Ib'); d2(0x71, 'G12', 'N,Ib'); d2(0x72, 'G13', 'N,Ib'); d2(0x73, 'G14', 'N,Ib');
  d2(0x74, 'pcmpeqb', 'P,Q'); d2(0x75, 'pcmpeqw', 'P,Q'); d2(0x76, 'pcmpeqd', 'P,Q'); d2(0x77, 'emms');
  d2(0x78, 'vmread', 'Ey,Gy'); d2(0x79, 'vmwrite', 'Gy,Ey');
  d2(0x7c, ['', 'haddpd', '', 'haddps'], 'V,W'); d2(0x7d, ['', 'hsubpd', '', 'hsubps'], 'V,W');
  d2(0x7e, 'MOVD7E', 'Ey,P'); d2(0x7f, ['movq', 'movdqa', 'movdqu'], 'Q,P');
  d2(0xa0, 'push', 'FS', 'd64'); d2(0xa1, 'pop', 'FS', 'd64'); d2(0xa2, 'cpuid'); d2(0xa3, 'bt', 'Ev,Gv'); d2(0xa4, 'shld', 'Ev,Gv,Ib'); d2(0xa5, 'shld', 'Ev,Gv,CL');
  d2(0xa8, 'push', 'GS', 'd64'); d2(0xa9, 'pop', 'GS', 'd64'); d2(0xaa, 'rsm'); d2(0xab, 'bts', 'Ev,Gv'); d2(0xac, 'shrd', 'Ev,Gv,Ib'); d2(0xad, 'shrd', 'Ev,Gv,CL');
  d2(0xae, 'G15', 'M'); d2(0xaf, 'imul', 'Gv,Ev');
  d2(0xb0, 'cmpxchg', 'Eb,Gb'); d2(0xb1, 'cmpxchg', 'Ev,Gv'); d2(0xb2, 'lss', 'Gv,M'); d2(0xb3, 'btr', 'Ev,Gv'); d2(0xb4, 'lfs', 'Gv,M'); d2(0xb5, 'lgs', 'Gv,M');
  d2(0xb6, 'movzx', 'Gv,Eb'); d2(0xb7, 'movzx', 'Gv,Ew'); d2(0xb8, ['', '', 'popcnt'], 'Gv,Ev'); d2(0xb9, 'ud1', 'Gv,Ev'); d2(0xba, 'G8', 'Ev,Ib'); d2(0xbb, 'btc', 'Ev,Gv');
  d2(0xbc, ['bsf', 'bsf', 'tzcnt'], 'Gv,Ev'); d2(0xbd, ['bsr', 'bsr', 'lzcnt'], 'Gv,Ev'); d2(0xbe, 'movsx', 'Gv,Eb'); d2(0xbf, 'movsx', 'Gv,Ew');
  d2(0xc0, 'xadd', 'Eb,Gb'); d2(0xc1, 'xadd', 'Ev,Gv'); d2(0xc2, ['cmpps', 'cmppd', 'cmpss', 'cmpsd'], 'V,W,Ib'); d2(0xc3, 'movnti', 'M,Gy');
  d2(0xc4, 'pinsrw', 'P,Ed,Ib'); d2(0xc5, 'pextrw', 'Gd,N,Ib'); d2(0xc6, ['shufps', 'shufpd'], 'V,W,Ib'); d2(0xc7, 'G9', 'M');
  for (let i = 0; i < 8; i++) d2(0xc8 + i, 'bswap', 'Zv');
  const mmx = 'addsubpd psrlw psrld psrlq paddq pmullw MOVQD6 pmovmskb psubusb psubusw pminub pand paddusb paddusw pmaxub pandn pavgb psraw psrad pavgw pmulhuw pmulhw CVTE6 movntq psubsb psubsw pminsw por paddsb paddsw pmaxsw pxor lddqu psllw pslld psllq pmuludq pmaddwd psadbw maskmovq psubb psubw psubd psubq paddb paddw paddd ud0'.split(' ');
  mmx.forEach((m, i) => d2(0xd0 + i, m, 'P,Q'));
  d2(0xd7, 'pmovmskb', 'Gd,N'); d2(0xe7, ['movntq', 'movntdq'], 'M,P'); d2(0xf0, ['', '', '', 'lddqu'], 'V,M'); d2(0xf7, ['maskmovq', 'maskmovdqu'], 'P,N'); d2(0xff, 'ud0', 'Gv,Ev');

  // 0F 38 and 0F 3A: names only; all take ModRM (3A adds imm8)
  const M38 = { 0x00: 'pshufb', 0x01: 'phaddw', 0x02: 'phaddd', 0x03: 'phaddsw', 0x04: 'pmaddubsw', 0x05: 'phsubw', 0x06: 'phsubd', 0x07: 'phsubsw', 0x08: 'psignb', 0x09: 'psignw',
    0x0a: 'psignd', 0x0b: 'pmulhrsw', 0x10: 'pblendvb', 0x14: 'blendvps', 0x15: 'blendvpd', 0x17: 'ptest', 0x1c: 'pabsb', 0x1d: 'pabsw', 0x1e: 'pabsd',
    0x20: 'pmovsxbw', 0x21: 'pmovsxbd', 0x22: 'pmovsxbq', 0x23: 'pmovsxwd', 0x24: 'pmovsxwq', 0x25: 'pmovsxdq', 0x28: 'pmuldq', 0x29: 'pcmpeqq', 0x2a: 'movntdqa', 0x2b: 'packusdw',
    0x30: 'pmovzxbw', 0x31: 'pmovzxbd', 0x32: 'pmovzxbq', 0x33: 'pmovzxwd', 0x34: 'pmovzxwq', 0x35: 'pmovzxdq', 0x37: 'pcmpgtq', 0x38: 'pminsb', 0x39: 'pminsd', 0x3a: 'pminuw',
    0x3b: 'pminud', 0x3c: 'pmaxsb', 0x3d: 'pmaxsd', 0x3e: 'pmaxuw', 0x3f: 'pmaxud', 0x40: 'pmulld', 0x41: 'phminposuw', 0xc8: 'sha1nexte', 0xc9: 'sha1msg1', 0xca: 'sha1msg2',
    0xcb: 'sha256rnds2', 0xcc: 'sha256msg1', 0xcd: 'sha256msg2', 0xdb: 'aesimc', 0xdc: 'aesenc', 0xdd: 'aesenclast', 0xde: 'aesdec', 0xdf: 'aesdeclast',
    0xf0: 'MOVBE', 0xf1: 'MOVBE', 0xf6: 'adcx', 0xf8: 'movdir64b', 0xf9: 'movdiri' };
  const M3A = { 0x08: 'roundps', 0x09: 'roundpd', 0x0a: 'roundss', 0x0b: 'roundsd', 0x0c: 'blendps', 0x0d: 'blendpd', 0x0e: 'pblendw', 0x0f: 'palignr', 0x14: 'pextrb', 0x15: 'pextrw',
    0x16: 'pextrd', 0x17: 'extractps', 0x20: 'pinsrb', 0x21: 'insertps', 0x22: 'pinsrd', 0x40: 'dpps', 0x41: 'dppd', 0x42: 'mpsadbw', 0x44: 'pclmulqdq', 0x60: 'pcmpestrm',
    0x61: 'pcmpestri', 0x62: 'pcmpistrm', 0x63: 'pcmpistri', 0xcc: 'sha1rnds4', 0xdf: 'aeskeygenassist' };
  // VEX names for the common AVX moves/logic; others are named after their SSE twin with a "v"
  const X87M = [['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'], ['fld', '', 'fst', 'fstp', 'fldenv', 'fldcw', 'fnstenv', 'fnstcw'],
    ['fiadd', 'fimul', 'ficom', 'ficomp', 'fisub', 'fisubr', 'fidiv', 'fidivr'], ['fild', 'fisttp', 'fist', 'fistp', '', 'fld', '', 'fstp'],
    ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'], ['fld', 'fisttp', 'fst', 'fstp', 'frstor', '', 'fnsave', 'fnstsw'],
    ['fiadd', 'fimul', 'ficom', 'ficomp', 'fisub', 'fisubr', 'fidiv', 'fidivr'], ['fild', 'fisttp', 'fist', 'fistp', 'fbld', 'fild', 'fbstp', 'fistp']];
  const X87S = [[4, 4, 4, 4, 4, 4, 4, 4], [4, 0, 4, 4, 0, 2, 0, 2], [4, 4, 4, 4, 4, 4, 4, 4], [4, 4, 4, 4, 0, 10, 0, 10], [8, 8, 8, 8, 8, 8, 8, 8], [8, 8, 8, 8, 0, 0, 0, 2], [2, 2, 2, 2, 2, 2, 2, 2], [2, 2, 2, 2, 10, 8, 10, 8]];
  const X87R = { 0xd9: { 0xd0: 'fnop', 0xe0: 'fchs', 0xe1: 'fabs', 0xe4: 'ftst', 0xe5: 'fxam', 0xe8: 'fld1', 0xe9: 'fldl2t', 0xea: 'fldl2e', 0xeb: 'fldpi', 0xec: 'fldlg2', 0xed: 'fldln2', 0xee: 'fldz',
    0xf0: 'f2xm1', 0xf1: 'fyl2x', 0xf2: 'fptan', 0xf3: 'fpatan', 0xf4: 'fxtract', 0xf5: 'fprem1', 0xf6: 'fdecstp', 0xf7: 'fincstp', 0xf8: 'fprem', 0xf9: 'fyl2xp1', 0xfa: 'fsqrt',
    0xfb: 'fsincos', 0xfc: 'frndint', 0xfd: 'fscale', 0xfe: 'fsin', 0xff: 'fcos' }, 0xda: { 0xe9: 'fucompp' }, 0xdb: { 0xe2: 'fnclex', 0xe3: 'fninit' }, 0xde: { 0xd9: 'fcompp' }, 0xdf: { 0xe0: 'fnstsw ax' } };
  const X87RR = { 0xd8: ['fadd', 'fmul', 'fcom', 'fcomp', 'fsub', 'fsubr', 'fdiv', 'fdivr'], 0xd9: ['fld', 'fxch'], 0xda: ['fcmovb', 'fcmove', 'fcmovbe', 'fcmovu'],
    0xdb: ['fcmovnb', 'fcmovne', 'fcmovnbe', 'fcmovnu', '', 'fucomi', 'fcomi'], 0xdc: ['fadd', 'fmul', 'fcom', 'fcomp', 'fsubr', 'fsub', 'fdivr', 'fdiv'],
    0xdd: ['ffree', '', 'fst', 'fstp', 'fucom', 'fucomp'], 0xde: ['faddp', 'fmulp', '', '', 'fsubrp', 'fsubp', 'fdivrp', 'fdivp'], 0xdf: ['', '', '', '', '', 'fucomip', 'fcomip'] };

  function decode(b, pos, ip, x64) {
    const start = pos;
    const end = Math.min(b.length, pos + 15);
    const r = { len: 1, mn: '(bad)', ops: '', target: null, rip: null, imm: null };
    let opsz = 0, adsz = 0, seg = -1, rep = 0, lock = false, rex = 0, pfx66 = false;
    // prefixes
    for (; pos < end; pos++) {
      const c = b[pos];
      if (c === 0x66) { opsz = 1; pfx66 = true; } else if (c === 0x67) adsz = 1;
      else if (c === 0xf2 || c === 0xf3) rep = c;
      else if (c === 0xf0) lock = true;
      else if (c === 0x26 || c === 0x2e || c === 0x36 || c === 0x3e) seg = [0x26, 0x2e, 0x36, 0x3e].indexOf(c) === 0 ? 0 : c === 0x2e ? 1 : c === 0x36 ? 2 : 3;
      else if (c === 0x64) seg = 4; else if (c === 0x65) seg = 5;
      else break;
    }
    if (x64 && pos < end && (b[pos] & 0xf0) === 0x40) rex = b[pos++];
    if (pos >= end) return r;
    const W = !!(rex & 8), Rx = rex & 4 ? 8 : 0, Xx = rex & 2 ? 8 : 0, Bx = rex & 1 ? 8 : 0;
    const asz = x64 ? (adsz ? 4 : 8) : (adsz ? 2 : 4);
    let osz = x64 ? (W ? 8 : opsz ? 2 : 4) : (opsz ? 2 : 4);
    let op = b[pos++], map = 1, spec;
    let vex = null;
    // VEX / EVEX (in 32-bit mode only when the next byte has mod == 11)
    if ((op === 0xc4 || op === 0xc5) && pos < end && (x64 || (b[pos] & 0xc0) === 0xc0)) {
      if (op === 0xc5) { const v = b[pos++]; vex = { R: !(v & 0x80), vvvv: (~v >> 3) & 15, L: (v >> 2) & 1, pp: v & 3, mmmmm: 1, W: 0 }; }
      else { const v1 = b[pos++], v2 = b[pos++]; vex = { R: !(v1 & 0x80), X: !(v1 & 0x40), B: !(v1 & 0x20), mmmmm: v1 & 31, W: v2 >> 7, vvvv: (~v2 >> 3) & 15, L: (v2 >> 2) & 1, pp: v2 & 3 }; }
    } else if (op === 0x62 && pos + 3 < end && (x64 || (b[pos] & 0xc0) === 0xc0)) {
      const p0 = b[pos++], p1 = b[pos++], p2 = b[pos++];
      vex = { R: !(p0 & 0x80), X: !(p0 & 0x40), B: !(p0 & 0x20), mmmmm: p0 & 3, W: p1 >> 7, vvvv: (~p1 >> 3) & 15, pp: p1 & 3, L: (p2 >> 5) & 3, evex: true };
    }
    if (vex) {
      if (pos >= end) return r;
      op = b[pos++];
      const vmap = vex.mmmmm;
      if (vmap === 1 && op === 0x77) { r.len = pos - start; r.mn = vex.L ? 'vzeroall' : 'vzeroupper'; r.ops = ''; return r; }
      const rexv = (vex.W ? 8 : 0) | (vex.R ? 4 : 0) | (vex.X ? 2 : 0) | (vex.B ? 1 : 0);
      const m = modrm(b, pos, end, rexv, x64, x64 ? 8 : 4);
      if (!m) return r;
      pos = m.next;
      if (vmap === 3 || (vmap === 1 && [0x70, 0x71, 0x72, 0x73, 0xc2, 0xc4, 0xc5, 0xc6].includes(op))) pos++;
      if (pos > end) return r;
      const pfx = [0, 1, 3, 2][vex.pp];
      let name = '';
      if (vmap === 1) { const e = O2[op]; if (e) name = Array.isArray(e.mn) ? e.mn[pfx] || e.mn[0] : e.mn; if (op === 0x77) name = vex.L ? 'zeroall' : 'zeroupper'; }
      else if (vmap === 2) name = M38[op] || 'op38_' + op.toString(16); else if (vmap === 3) name = M3A[op] || 'op3a_' + op.toString(16);
      if (vmap === 1 && op >= 0x71 && op <= 0x73) name = ({ 0x71: ['', '', 'psrlw', '', 'psraw', '', 'psllw', ''], 0x72: ['', '', 'psrld', '', 'psrad', '', 'pslld', ''], 0x73: ['', '', 'psrlq', 'psrldq', '', '', 'psllq', 'pslldq'] }[op])[m.reg] || name;
      if (vmap === 1 && (op === 0x6e || op === 0x7e)) name = vex.W ? 'movq' : 'movd';
      if (/^[A-Z]|^G\d/.test(name) || !name) name = 'op_' + op.toString(16);
      const xr = vex.L ? (vex.evex && vex.L === 2 ? 'zmm' : 'ymm') : 'xmm';
      const reg = xr + (m.reg + (vex.R ? 8 : 0));
      const vv = xr + vex.vvvv;
      const rm = m.mod === 3 ? xr + (m.rm + (vex.B ? 8 : 0)) : mem(m, vex.L ? 32 : 16);
      r.len = pos - start;
      r.mn = 'v' + name.replace(/^v/, '');
      r.ops = op === 0x77 ? '' : [reg, vv, rm].join(', ');
      if (m.rip != null) r.rip = ip + r.len + m.rip;
      return fix(r, m, ip);
    }
    if (op === 0x0f) {
      if (pos >= end) return r;
      op = b[pos++];
      if (op === 0x38 || op === 0x3a) {
        const tbl = op === 0x38 ? M38 : M3A; const three = op === 0x3a;
        if (pos >= end) return r;
        const o3 = b[pos++];
        const m = modrm(b, pos, end, rex, x64, asz);
        if (!m) return r;
        pos = m.next;
        let imm = null;
        if (three) { if (pos >= end) return r; imm = b[pos++]; }
        r.len = pos - start;
        let name = tbl[o3] || ('op' + (three ? '3a' : '38') + '_' + o3.toString(16));
        if (name === 'MOVBE') name = rep === 0xf2 ? 'crc32' : 'movbe';
        if (o3 === 0xf6 && rep === 0xf3) name = 'adox';
        const xm = pfx66 || three ? 'xmm' : 'mm';
        const regN = name === 'crc32' || name === 'movbe' || name === 'adcx' || name === 'adox' ? gpr(m.reg + Rx, name === 'crc32' ? (W ? 8 : 4) : osz, rex) : xm + (m.reg + (xm === 'xmm' ? Rx : 0));
        const rmN = m.mod === 3 ? (name === 'crc32' || name === 'movbe' ? gpr(m.rm + Bx, o3 === 0xf0 ? 1 : osz, rex) : xm + (m.rm + (xm === 'xmm' ? Bx : 0))) : mem(m, xm === 'xmm' ? 16 : 8);
        r.mn = name;
        const opsList = o3 === 0xf1 && name === 'movbe' ? [rmN, regN] : [regN, rmN];
        if (three && /^p(extr|insr)|extractps/.test(name)) { /* gpr/mem forms */ }
        if (imm != null) opsList.push(hx(imm));
        r.ops = opsList.join(', ');
        if (m.rip != null) r.rip = ip + r.len + m.rip;
        return fix(r, m, ip);
      }
      map = 2;
      spec = O2[op];
    } else spec = O1[op];
    // x87 (no table entry: decoded here)
    if (map === 1 && op >= 0xd8 && op <= 0xdf) {
      const m = modrm(b, pos, end, rex, x64, asz);
      if (!m) return r;
      pos = m.next;
      r.len = pos - start;
      const k = op - 0xd8;
      if (m.mod !== 3) { r.mn = X87M[k][m.reg] || '(bad)'; r.ops = mem(m, X87S[k][m.reg]); return fix(r, m, ip); }
      const byte = b[pos - 1];
      const named = X87R[op] && X87R[op][byte];
      if (named) { const sp = named.split(' '); r.mn = sp[0]; r.ops = sp[1] || ''; return r; }
      const nm = X87RR[op] && X87RR[op][m.reg];
      if (!nm) return r;
      r.mn = nm;
      r.ops = op === 0xd8 || op === 0xd9 || op === 0xda || op === 0xdb || /^fcom|fucomi/.test(nm) && op !== 0xdc ? (op === 0xd9 && m.reg === 1 ? 'st(' + m.rm + ')' : (op === 0xdd ? 'st(' + m.rm + ')' : 'st, st(' + m.rm + ')')) : op === 0xdd ? 'st(' + m.rm + ')' : 'st(' + m.rm + '), st';
      return r;
    }
    if (!spec) { r.len = pos - start; return r; }
    if (x64 && spec.fl.includes('i64')) { r.len = pos - start; return r; }
    if (x64 && (spec.fl.includes('d64') || (map === 1 && op >= 0x50 && op <= 0x5f))) osz = opsz ? 2 : 8;
    if (map === 1 && x64 && (op === 0xe8 || op === 0xe9)) osz = 4;
    let mn = spec.mn;
    // mandatory-prefix SSE variants
    let ssePfx = 0;
    if (Array.isArray(mn)) {
      ssePfx = rep === 0xf3 ? 2 : rep === 0xf2 ? 3 : pfx66 ? 1 : 0;
      mn = mn[ssePfx] || mn[0];
      if (ssePfx === 1) osz = x64 ? (W ? 8 : 4) : 4;
    }
    let ops = spec.ops;
    let m = null;
    const needModrm = ops.some(o => /^(E|G|M|S|V|W|P|Q|U|N|R|C|D)/.test(o)) || /^G\d/.test(mn);
    if (needModrm) {
      m = modrm(b, pos, end, rex, x64, asz);
      if (!m) { r.len = pos - start; return r; }
      pos = m.next;
    }
    const isXmm = map === 2 && (pfx66 || ssePfx || /^(movaps|movups|xorps|andps|andnps|orps|addps|mulps|subps|divps|minps|maxps|sqrtps|unpck|movhps|movlps|cvt|ucomis|comis|movmskps|shufps|cmpps|movntps|rsqrtps|rcpps)/.test(mn));
    // groups
    if (mn === 'G1') mn = G1[m.reg];
    else if (mn === 'G2') mn = G2[m.reg];
    else if (mn === 'G3') { mn = G3[m.reg]; ops = m.reg < 2 ? [ops[0], op === 0xf6 ? 'Ib' : 'Iz'] : [ops[0]]; }
    else if (mn === 'G4') mn = ['inc', 'dec'][m.reg] || '(bad)';
    else if (mn === 'G5') { mn = ['inc', 'dec', 'call', 'call', 'jmp', 'jmp', 'push', '(bad)'][m.reg]; if (x64 && (m.reg === 2 || m.reg === 4 || m.reg === 6)) osz = opsz ? 2 : 8; }
    else if (mn === 'G6') mn = ['sldt', 'str', 'lldt', 'ltr', 'verr', 'verw', '(bad)', '(bad)'][m.reg];
    else if (mn === 'G7') {
      if (m.mod === 3) {
        const k = (m.reg << 3) | m.rm;
        mn = { 0o10: 'monitor', 0o11: 'mwait', 0o12: 'clac', 0o13: 'stac', 0o20: 'xgetbv', 0o21: 'xsetbv', 0o26: 'xend', 0o27: 'xtest', 0o70: 'swapgs', 0o71: 'rdtscp', 0o01: 'vmcall', 0o02: 'vmlaunch', 0o03: 'vmresume', 0o04: 'vmxoff' }[k] || '(bad)';
        r.len = pos - start; r.mn = mn; return r;
      }
      mn = ['sgdt', 'sidt', 'lgdt', 'lidt', 'smsw', '(bad)', 'lmsw', 'invlpg'][m.reg];
    } else if (mn === 'G8') mn = ['(bad)', '(bad)', '(bad)', '(bad)', 'bt', 'bts', 'btr', 'btc'][m.reg];
    else if (mn === 'G9') {
      if (m.mod === 3) { mn = m.reg === 6 ? 'rdrand' : m.reg === 7 ? (rep === 0xf3 ? 'rdpid' : 'rdseed') : '(bad)'; r.len = pos - start; r.mn = mn; r.ops = gpr(m.rm + Bx, osz, rex); return r; }
      mn = m.reg === 1 ? (W ? 'cmpxchg16b' : 'cmpxchg8b') : ['', '', '', 'xrstors', 'xsavec', 'xsaves', 'vmptrld', 'vmptrst'][m.reg] || '(bad)';
      r.len = pos - start; r.mn = mn; r.ops = mem(m, mn === 'cmpxchg16b' ? 16 : 8); return fix(r, m, ip);
    } else if (mn === 'G12' || mn === 'G13' || mn === 'G14') {
      const t = { G12: ['', '', 'psrlw', '', 'psraw', '', 'psllw', ''], G13: ['', '', 'psrld', '', 'psrad', '', 'pslld', ''], G14: ['', '', 'psrlq', 'psrldq', '', '', 'psllq', 'pslldq'] }[mn];
      mn = t[m.reg] || '(bad)';
      const imm = b[pos++];
      r.len = pos - start; r.mn = mn; r.ops = (pfx66 ? 'xmm' + (m.rm + Bx) : 'mm' + m.rm) + ', ' + hx(imm); return r;
    } else if (mn === 'G15') {
      if (m.mod === 3) {
        mn = rep === 0xf3 ? ['rdfsbase', 'rdgsbase', 'wrfsbase', 'wrgsbase', '', 'incsspd', '', ''][m.reg] : ['', '', '', '', '', 'lfence', 'mfence', 'sfence'][m.reg];
        r.len = pos - start; r.mn = mn || '(bad)'; r.ops = rep === 0xf3 ? gpr(m.rm + Bx, W ? 8 : 4, rex) : ''; return r;
      }
      mn = ['fxsave', 'fxrstor', 'ldmxcsr', 'stmxcsr', 'xsave', 'xrstor', 'xsaveopt', 'clflush'][m.reg];
    } else if (mn === 'G16') mn = ['prefetchnta', 'prefetcht0', 'prefetcht1', 'prefetcht2', 'nop', 'nop', 'nop', 'nop'][m.reg];
    else if (mn === 'MOVD') { mn = W ? 'movq' : 'movd'; }
    else if (mn === 'MOVD7E') { if (rep === 0xf3) { mn = 'movq'; ops = ['V', 'W8']; } else mn = W ? 'movq' : 'movd'; }
    else if (mn === 'MOVQD6') { mn = pfx66 ? 'movq' : rep === 0xf3 ? 'movq2dq' : rep === 0xf2 ? 'movdq2q' : '(bad)'; if (pfx66) ops = ['W8', 'V']; }
    else if (mn === 'CVTE6') mn = pfx66 ? 'cvttpd2dq' : rep === 0xf3 ? 'cvtdq2pd' : rep === 0xf2 ? 'cvtpd2dq' : '(bad)';
    else if (mn === 'CBW') mn = osz === 8 ? 'cdqe' : osz === 2 ? 'cbw' : 'cwde';
    else if (mn === 'CWD') mn = osz === 8 ? 'cqo' : osz === 2 ? 'cwd' : 'cdq';
    else if (mn === 'JCXZ') mn = x64 ? (adsz ? 'jecxz' : 'jrcxz') : (adsz ? 'jcxz' : 'jecxz');
    if (map === 1 && op === 0x90) { if (rep === 0xf3) mn = 'pause'; else if (Bx) { mn = 'xchg'; ops = ['Zv', 'rAX']; } }
    if (map === 1 && op === 0x63 && x64) { mn = 'movsxd'; ops = ['Gv', 'Ed']; }
    if (map === 2 && op === 0x1e && rep === 0xf3 && m && m.mod === 3 && (m.rm === 2 || m.rm === 3) && m.reg === 7) { r.len = pos - start; r.mn = m.rm === 2 ? 'endbr64' : 'endbr32'; return r; }
    if (map === 2 && op === 0xc7 && m && m.mod === 3 && m.reg === 6) { mn = 'rdrand'; }
    if (mn === 'nop' && map === 1 && op === 0x90 && !Bx) { r.len = pos - start; r.mn = rep === 0xf3 ? 'pause' : 'nop'; return r; }
    // operands
    const out = [];
    let immSigned = false;
    for (let o of ops) {
      let s;
      switch (o) {
        case 'Eb': s = m.mod === 3 ? gpr(m.rm + Bx, 1, rex) : mem(m, 1); break;
        case 'Ev': s = m.mod === 3 ? gpr(m.rm + Bx, osz, rex) : mem(m, /^(lea|call|jmp)$/.test(mn) && map === 1 && op === 0xff && (m.reg === 3 || m.reg === 5) ? 6 : osz); break;
        case 'Ew': s = m.mod === 3 ? gpr(m.rm + Bx, map === 1 && op === 0x8e ? osz : 2, rex) : mem(m, 2); break;
        case 'W8': s = m.mod === 3 ? 'xmm' + (m.rm + Bx) : mem(m, 8); break;
        case 'Ed': s = m.mod === 3 ? gpr(m.rm + Bx, 4, rex) : mem(m, 4); break;
        case 'Ey': s = m.mod === 3 ? gpr(m.rm + Bx, W ? 8 : 4, rex) : mem(m, W ? 8 : 4); break;
        case 'Gb': s = gpr(m.reg + Rx, 1, rex); break;
        case 'Gv': s = gpr(m.reg + Rx, osz, rex); break;
        case 'Gw': s = gpr(m.reg + Rx, 2, rex); break;
        case 'Gd': s = gpr(m.reg + Rx, 4, rex); break;
        case 'Gy': s = gpr(m.reg + Rx, W ? 8 : 4, rex); break;
        case 'M': s = m.mod === 3 ? gpr(m.rm + Bx, osz, rex) : mem(m, mn === 'lea' || /^(prefetch|clflush|fx|xsave|xrstor|lgdt|lidt|sgdt|sidt|invlpg|nop)/.test(mn) ? 0 : /^(bound|lds|les|lss|lfs|lgs)$/.test(mn) ? 0 : 8); break;
        case 'Sw': s = SEG[m.reg] || '?'; break;
        case 'Cd': s = 'cr' + (m.reg + Rx); break;
        case 'Dd': s = 'dr' + (m.reg + Rx); break;
        case 'Rd': s = gpr(m.rm + Bx, x64 ? 8 : 4, rex); break;
        case 'V': s = 'xmm' + (m.reg + Rx); break;
        case 'W': s = m.mod === 3 ? 'xmm' + (m.rm + Bx) : mem(m, /ss$|^movd$|^cvtss|^cvtsi2ss|^ucomiss|^comiss|^rcpss|^rsqrtss/.test(mn) ? 4 : /sd$|^movsd$|^movlp|^movhp|^cvtsd|^ucomisd|^comisd|^cvtps2pd|^movddup/.test(mn) ? 8 : 16); break;
        case 'P': s = isXmm || pfx66 || rep ? 'xmm' + (m.reg + Rx) : 'mm' + m.reg; break;
        case 'Q': s = m.mod === 3 ? (isXmm || pfx66 || rep ? 'xmm' + (m.rm + Bx) : 'mm' + m.rm) : mem(m, isXmm || pfx66 || rep ? (mn === 'movq' ? 8 : 16) : 8); break;
        case 'U': case 'N': s = isXmm || pfx66 ? 'xmm' + (m.rm + Bx) : 'mm' + m.rm; break;
        case 'Ib': if (pos >= end) return badLen(); r.imm = b[pos]; s = hx(b[pos++]); break;
        case 'sIb': { if (pos >= end) return badLen(); let v = b[pos++]; if (v > 127) v -= 256; r.imm = v; s = immFmt(v, osz); immSigned = true; break; }
        case 'Iw': if (pos + 2 > end) return badLen(); s = hx(b[pos] | (b[pos + 1] << 8)); pos += 2; break;
        case 'Iz': {
          const n = osz === 2 ? 2 : 4;
          if (pos + n > end) return badLen();
          let v = n === 2 ? (b[pos] | (b[pos + 1] << 8)) : (b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24));
          pos += n;
          if (n === 4 && osz === 8) { r.imm = v; s = immFmt(v, 8); }
          else { if (n === 4) v >>>= 0; r.imm = v; s = hx(v); }
          break;
        }
        case 'Iv': {
          const n = osz;
          if (pos + n > end) return badLen();
          if (n === 8) {
            const lo = (b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24)) >>> 0, hi = (b[pos + 4] | (b[pos + 5] << 8) | (b[pos + 6] << 16) | (b[pos + 7] << 24)) >>> 0;
            const v = (BigInt(hi) << 32n) | BigInt(lo);
            s = '0x' + v.toString(16); r.imm = Number(v);
          } else {
            const v = n === 2 ? (b[pos] | (b[pos + 1] << 8)) : ((b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24)) >>> 0);
            s = hx(v); r.imm = v;
          }
          pos += n;
          break;
        }
        case 'Jb': { if (pos >= end) return badLen(); let v = b[pos++]; if (v > 127) v -= 256; r.target = ip + (pos - start) + v; s = hx(r.target); break; }
        case 'Jz': {
          const n = !x64 && opsz ? 2 : 4;
          if (pos + n > end) return badLen();
          let v = n === 2 ? ((b[pos] | (b[pos + 1] << 8)) << 16 >> 16) : (b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24));
          pos += n;
          r.target = ip + (pos - start) + v;
          if (!x64) r.target >>>= 0;
          s = hx(r.target);
          break;
        }
        case 'Ob': case 'Ov': {
          const n = asz;
          if (pos + n > end) return badLen();
          let v = 0;
          for (let k = n - 1; k >= 0; k--) v = v * 256 + b[pos + k];
          pos += n;
          s = (SZ[o === 'Ob' ? 1 : osz]) + ' ptr ' + (seg >= 0 ? SEG[seg] : 'ds') + ':' + hx(v);
          r.abs = v;
          break;
        }
        case 'Ap': { const n = opsz ? 2 : 4; if (pos + n + 2 > end) return badLen(); let v = 0; for (let k = n - 1; k >= 0; k--) v = v * 256 + b[pos + k]; pos += n; const sel = b[pos] | (b[pos + 1] << 8); pos += 2; s = hx(sel) + ':' + hx(v); break; }
        case 'AL': s = 'al'; break;
        case 'eAX': s = opsz ? 'ax' : 'eax'; break;
        case 'rAX': s = gpr(0, osz, rex); break;
        case 'DX': s = 'dx'; break;
        case 'CL': s = 'cl'; break;
        case '1': s = '1'; break;
        case 'ES': case 'CS': case 'SS': case 'DS': case 'FS': case 'GS': s = o.toLowerCase(); break;
        case 'Zb': s = gpr((op & 7) + Bx, 1, rex); break;
        case 'Zv': s = gpr((op & 7) + Bx, osz, rex); break;
        case 'Xb': case 'Xv': s = SZ[o === 'Xb' ? 1 : osz] + ' ptr ' + (seg >= 0 ? SEG[seg] : 'ds') + ':[' + (asz === 8 ? 'rsi' : asz === 4 ? 'esi' : 'si') + ']'; break;
        case 'Yb': case 'Yv': s = SZ[o === 'Yb' ? 1 : osz] + ' ptr es:[' + (asz === 8 ? 'rdi' : asz === 4 ? 'edi' : 'di') + ']'; break;
        default: s = o;
      }
      out.push(s);
    }
    if (spec.fl.includes('str')) {
      const sfx = /Xb|Yb/.test(ops.join()) ? 'b' : { 2: 'w', 4: 'd', 8: 'q' }[osz];
      mn = mn + sfx;
      if (rep) mn = (rep === 0xf3 ? (/^(cmps|scas)/.test(mn) ? 'repz ' : 'rep ') : 'repnz ') + mn;
    } else if (rep === 0xf2 && map === 1 && /^(call|jmp|ret|j)/.test(mn)) mn = 'bnd ' + mn;
    if (lock) mn = 'lock ' + mn;
    r.len = pos - start;
    r.mn = mn;
    r.ops = out.join(', ');
    if (m && m.rip != null) r.rip = ip + r.len + m.rip;
    return fix(r, m, ip);

    function badLen() { r.len = Math.max(1, pos - start); r.mn = '(bad)'; r.ops = ''; return r; }
    function immFmt(v, size) {
      if (v >= 0) return hx(v);
      if (size === 8) return '0x' + (BigInt.asUintN(64, BigInt(v))).toString(16);
      if (size === 2) return hx(v & 0xffff);
      return hx(v >>> 0);
    }
    function gpr(n, size, rx) {
      if (size === 1) return rx ? R8X[n] : (n < 8 ? R8[n] : R8X[n]);
      return (size === 2 ? R16 : size === 8 ? R64 : R32)[n] || '?';
    }
    function mem(mm, size) {
      const p = [];
      const regs = asz === 8 ? R64 : asz === 4 ? R32 : R16;
      if (mm.r16) p.push(mm.r16);
      else {
        if (mm.base != null) p.push(mm.base === 'rip' ? 'rip' : regs[mm.base]);
        if (mm.index != null) p.push(regs[mm.index] + '*' + mm.scale);
      }
      let d = mm.disp;
      let s = p.join('+');
      if (d || !s) s = s ? s + (d < 0 ? '-' + hx(-d) : '+' + hx(d)) : hx(d >>> 0);
      const sz = SZ[size] ? SZ[size] + ' ptr ' : '';
      return sz + (seg >= 0 ? SEG[seg] + ':' : '') + '[' + s + ']';
    }
    function fix(rr, mm) { if (mm && mm.mod !== 3 && mm.base == null && mm.index == null && !mm.r16 && !mm.ripRel) rr.abs = mm.disp >>> 0; return rr; }
  }

  function modrm(b, pos, end, rex, x64, asz) {
    if (pos >= end) return null;
    const c = b[pos++];
    const mod = c >> 6, reg = (c >> 3) & 7, rm = c & 7;
    const m = { mod, reg, rm, base: null, index: null, scale: 1, disp: 0, rip: null };
    if (mod === 3) { m.next = pos; return m; }
    const Bx = rex & 1 ? 8 : 0, Xx = rex & 2 ? 8 : 0;
    if (asz === 2) {
      m.r16 = ['bx+si', 'bx+di', 'bp+si', 'bp+di', 'si', 'di', 'bp', 'bx'][rm];
      if (mod === 0 && rm === 6) { m.r16 = null; if (pos + 2 > end) return null; m.disp = b[pos] | (b[pos + 1] << 8); pos += 2; }
      else if (mod === 1) { if (pos >= end) return null; m.disp = (b[pos++] << 24) >> 24; }
      else if (mod === 2) { if (pos + 2 > end) return null; m.disp = ((b[pos] | (b[pos + 1] << 8)) << 16) >> 16; pos += 2; }
      m.next = pos; return m;
    }
    if (rm === 4) {
      if (pos >= end) return null;
      const sib = b[pos++];
      const ss = sib >> 6, idx = ((sib >> 3) & 7) + Xx, base = sib & 7;
      if (idx !== 4) { m.index = idx; m.scale = 1 << ss; }
      if (base === 5 && mod === 0) { if (pos + 4 > end) return null; m.disp = b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24); pos += 4; }
      else m.base = base + Bx;
    } else if (rm === 5 && mod === 0) {
      if (pos + 4 > end) return null;
      m.disp = b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24); pos += 4;
      if (x64) { m.base = 'rip'; m.rip = m.disp; m.ripRel = true; }
    } else m.base = rm + Bx;
    if (mod === 1) { if (pos >= end) return null; m.disp = (b[pos++] << 24) >> 24; }
    else if (mod === 2) { if (pos + 4 > end) return null; m.disp = b[pos] | (b[pos + 1] << 8) | (b[pos + 2] << 16) | (b[pos + 3] << 24); pos += 4; }
    m.next = pos;
    return m;
  }

  return { decode };
})();
if (typeof module !== 'undefined') module.exports = X86;
